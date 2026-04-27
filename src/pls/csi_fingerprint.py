# -*- coding: utf-8 -*-
"""
物理层安全 (PLS)：基于信道状态信息 (CSI) 的指纹认证。
利用无线信道的空间唯一性与时变性，实现第二因子认证，防止远程冒充（窃取证书无法复现物理信道）。
参考：CSI-RFF、车联网物理层认证等文献。
"""
from __future__ import annotations

import numpy as np
from typing import Tuple, Optional
from dataclasses import dataclass


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


def _rayleigh_fading(n: int, num_paths: int, decay: float, rng: np.random.Generator) -> np.ndarray:
    """生成 Rayleigh 衰落的多径信道系数（复数），幅度为实数用于指纹。"""
    # 多径增益随径索引衰减
    gains = np.exp(-decay * np.arange(num_paths))
    gains = gains / np.sqrt(np.sum(gains ** 2))
    # 每径随机相位
    phases = rng.uniform(0, 2 * np.pi, num_paths)
    h_paths = gains * np.exp(1j * phases)
    # 映射到 n 维（如 OFDM 子载波）：线性插值或随机线性组合
    if n >= num_paths:
        idx = np.linspace(0, num_paths - 1, n, dtype=int)
        h = h_paths[idx] + 0.1 * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    else:
        h = h_paths[:n] + 0.1 * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    # 指纹取幅度（或幅度+相位统计），与文献一致
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
        rng: Optional[np.random.Generator] = None,
    ):
        self.threshold = threshold
        self.csi_dim = csi_dim
        self.channel_noise_std = channel_noise_std
        self.num_multipath = num_multipath
        self.multipath_decay = multipath_decay
        self._rng = rng or np.random.default_rng()
        self._model = CSIFingerprintModel(
            dim=csi_dim,
            num_multipath=num_multipath,
            decay=multipath_decay,
        )

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
        ).astype(np.float64)

    def add_channel_noise(self, csi: np.ndarray, noise_std: Optional[float] = None) -> np.ndarray:
        """模拟 RSU 侧测量时的信道噪声（时变、位置微变）。"""
        std = noise_std if noise_std is not None else self.channel_noise_std
        return csi + self._rng.normal(0, std, csi.shape)

    def compute_similarity(self, fp1: np.ndarray, fp2: np.ndarray) -> float:
        """皮尔逊相关系数 ρ = Cov(Φ_V, Φ_R) / (σ_V σ_R)。"""
        if fp1.shape != fp2.shape:
            raise ValueError("指纹维度不一致")
        if np.std(fp1) == 0 or np.std(fp2) == 0:
            return 1.0 if np.allclose(fp1, fp2) else 0.0
        return float(np.corrcoef(fp1.ravel(), fp2.ravel())[0, 1])

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
        rho = self.compute_similarity(reported_fp, measured_fp)
        return (rho >= gamma, rho)
