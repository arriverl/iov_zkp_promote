# -*- coding: utf-8 -*-
"""
物理层安全 (PLS)：基于信道状态信息 (CSI) 的指纹认证。
利用无线信道的空间唯一性与时变性，实现第二因子认证，防止远程冒充（窃取证书无法复现物理信道）。
参考：CSI-RFF、车联网物理层认证等文献。
"""
from __future__ import annotations

import numpy as np
from pathlib import Path
from typing import Tuple, Optional, Literal
from dataclasses import dataclass

from .real_csi_repository import RealCSIRepository, DEFAULT_DATA_DIR


@dataclass
class CSIFingerprintModel:
    """
    CSI 信道模型参数（用于仿真）。
    实际部署中可由 SDR 或 WiFi CSI 工具获取真实 CSI。
    """
    # 子载波/径数
    dim: int
    # 多径数量（影响相关性结构）
    num_multipath: int
    # 每径功率衰减指数
    decay: float
    # 随机种子（可复现）
    seed: Optional[int] = None


def _rayleigh_fading(
    n: int,
    num_paths: int,
    decay: float,
    rng: np.random.Generator,
    *,
    jitter_scale: float = 0.1,
) -> np.ndarray:
    """生成 Rayleigh 衰落的多径信道系数（复数），幅度为实数用于指纹。"""
    gains = np.exp(-decay * np.arange(num_paths))
    gains = gains / np.sqrt(np.sum(gains ** 2))
    phases = rng.uniform(0, 2 * np.pi, num_paths)
    h_paths = gains * np.exp(1j * phases)
    if n >= num_paths:
        idx = np.linspace(0, num_paths - 1, n, dtype=int)
        h = h_paths[idx] + jitter_scale * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    else:
        h = h_paths[:n] + jitter_scale * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    return np.abs(h)


class PLSAuthenticator:
    """
    基于 CSI 指纹的物理层认证器。
    提取 CSI 特征、计算相似度（皮尔逊相关系数），与阈值比较。
    """

    def __init__(
        self,
        threshold: float = 0.85,
        csi_dim: int = 64,
        channel_noise_std: float = 0.05,
        num_multipath: int = 8,
        multipath_decay: float = 0.3,
        use_float32: bool = True,
        rel_dist_max: float = 0.42,
        csi_mode: Literal["simulation", "real"] = "simulation",
        csi_data_dir: Optional[Path] = None,
        rng: Optional[np.random.Generator] = None,
    ):
        self.threshold = threshold
        self.rel_dist_max = rel_dist_max
        self.csi_dim = csi_dim
        self.channel_noise_std = channel_noise_std
        self.num_multipath = num_multipath
        self.multipath_decay = multipath_decay
        self.use_float32 = use_float32
        self.csi_mode = csi_mode
        self._csi_repo: Optional[RealCSIRepository] = None
        if csi_mode == "real":
            self._csi_repo = RealCSIRepository(
                data_dir=csi_data_dir or DEFAULT_DATA_DIR,
                csi_dim=csi_dim,
            )
            if not self._csi_repo.available:
                raise FileNotFoundError(
                    f"PLS real 模式需要 CSI 数据，请先运行: python scripts/prepare_v2x_csi.py"
                )
        self._rng = rng or np.random.default_rng()
        self._model = CSIFingerprintModel(
            dim=csi_dim,
            num_multipath=num_multipath,
            decay=multipath_decay,
        )
        # 异地/中继攻击仿真：明显不同的多径环境，降低随机向量偶然高相关
        self._remote_multipath = max(num_multipath + 4, 12)
        self._remote_decay = min(multipath_decay + 0.55, 0.95)

    def session_seed_from_message(self, message: bytes) -> int:
        import hashlib
        if not hasattr(self, "_seed_cache"):
            self._seed_cache: dict[bytes, int] = {}
        cached = self._seed_cache.get(message)
        if cached is not None:
            return cached
        seed = int.from_bytes(hashlib.sha256(message).digest()[:8], "big")
        if len(self._seed_cache) < 512:
            self._seed_cache[message] = seed
        return seed

    def _dtype(self) -> np.dtype:
        return np.float32 if self.use_float32 else np.float64

    def extract_csi_fingerprint(self, seed: Optional[int] = None) -> np.ndarray:
        """
        从信道模型提取 CSI 指纹（仿真）。
        实际中替换为从 PHY 层获取的 CSI 向量。
        """
        rng = np.random.default_rng(seed) if seed is not None else self._rng
        return _rayleigh_fading(
            self.csi_dim,
            self.num_multipath,
            self.multipath_decay,
            rng,
        ).astype(self._dtype())

    def extract_session_csi(self, message: bytes) -> np.ndarray:
        """同一会话消息绑定种子，OBU/RSU 合法链路一致。"""
        if self.csi_mode == "real" and self._csi_repo is not None:
            obu, _ = self._csi_repo.pick_legitimate(message)
            return obu
        return self.extract_csi_fingerprint(seed=self.session_seed_from_message(message))

    def measure_session_csi(self, message: bytes) -> np.ndarray:
        """RSU 侧同链路测量 CSI（real 模式用配对 RSU 向量 + 可选噪声）。"""
        if self.csi_mode == "real" and self._csi_repo is not None:
            _, rsu = self._csi_repo.pick_legitimate(message)
            # 真实 V2X 数据集中 OBU/RSU 已为同链路估计，噪声宜小于仿真模式
            return rsu.astype(self._dtype())
        return self.add_channel_noise(self.extract_session_csi(message))

    def extract_remote_csi(self, message: bytes) -> np.ndarray:
        """异地盗证：不同多径剖面 + 独立种子，与合法 CSI 低相关。"""
        if self.csi_mode == "real" and self._csi_repo is not None:
            _, rsu_foreign = self._csi_repo.pick_theft(message)
            return rsu_foreign
        base = self.session_seed_from_message(message)
        remote_seed = base ^ 0xA5A5_5A5A_DEAD_BEEF
        rng = np.random.default_rng(remote_seed)
        return _rayleigh_fading(
            self.csi_dim,
            self._remote_multipath,
            self._remote_decay,
            rng,
            jitter_scale=0.25,
        ).astype(self._dtype())

    def pack_csi(self, csi: np.ndarray) -> bytes:
        return np.asarray(csi, dtype=self._dtype()).tobytes()

    def unpack_csi(self, data: bytes) -> np.ndarray:
        return np.frombuffer(data, dtype=self._dtype()).copy()

    def add_channel_noise(self, csi: np.ndarray, noise_std: Optional[float] = None) -> np.ndarray:
        """模拟 RSU 侧测量时的信道噪声（时变、位置微变）。"""
        std = noise_std if noise_std is not None else self.channel_noise_std
        return csi + self._rng.normal(0, std, csi.shape)

    def compute_similarity(self, fp1: np.ndarray, fp2: np.ndarray) -> float:
        """皮尔逊相关系数 ρ（float32 快速路径）。"""
        if fp1.shape != fp2.shape:
            raise ValueError("指纹维度不一致")
        r = np.asarray(fp1, dtype=np.float32).ravel()
        m = np.asarray(fp2, dtype=np.float32).ravel()
        r -= r.mean(dtype=np.float32)
        m -= m.mean(dtype=np.float32)
        denom = float(np.linalg.norm(r) * np.linalg.norm(m))
        if denom < 1e-9:
            return 1.0 if np.allclose(r, m) else 0.0
        return float(np.dot(r, m) / denom)

    def authenticate(
        self,
        reported_fp: np.ndarray,
        measured_fp: np.ndarray,
        threshold: Optional[float] = None,
    ) -> Tuple[bool, float]:
        """
        认证：比较 OBU 上报的指纹与 RSU 测量指纹。
        reported_fp: OBU 侧提取并上报的 CSI；
        measured_fp: RSU 侧对同一链路测量的 CSI（仿真中 = reported + 噪声）。
        """
        gamma = threshold if threshold is not None else self.threshold
        r = np.asarray(reported_fp, dtype=np.float32).ravel()
        m = np.asarray(measured_fp, dtype=np.float32).ravel()
        rho = self.compute_similarity(r, m)
        nr = float(np.linalg.norm(r)) + 1e-9
        nm = float(np.linalg.norm(m)) + 1e-9
        rel_dist = float(np.linalg.norm(r / nr - m / nm))
        ok = rho >= gamma and rel_dist <= self.rel_dist_max
        return (ok, rho)
