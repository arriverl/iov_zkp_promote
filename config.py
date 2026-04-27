# -*- coding: utf-8 -*-
"""
ZKP-PQC-PLS 融合认证协议全局配置。
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class PQCConfig:
    """后量子格签名 (Dilithium) 配置。"""
    # NIST 安全级别: 2 (≈128-bit), 3 (≈192-bit), 5 (≈256-bit)
    security_level: int = 2
    # 使用 ML-DSA 还是 CRYSTALS-Dilithium（API 兼容）
    use_ml_dsa: bool = False


@dataclass
class ZKPConfig:
    """零知识证明配置。"""
    # 安全参数：挑战/随机数字节长度
    challenge_bytes: int = 32
    # 标量域大小（用于 Schnorr 型证明）
    scalar_bits: int = 256


@dataclass
class PLSConfig:
    """物理层安全 (CSI 指纹) 配置。"""
    # 子载波/CSI 维度（如 64 子载波）
    csi_dim: int = 64
    # 相关系数阈值 ρ >= γ 通过认证
    similarity_threshold: float = 0.85
    # 仿真时 OBU-RSU 信道噪声标准差（相对）
    channel_noise_std: float = 0.05
    # 多径数量（仿真用）
    num_multipath: int = 8


@dataclass
class ProtocolConfig:
    """融合协议整体配置。"""
    pqc: PQCConfig
    zkp: ZKPConfig
    pls: PLSConfig
    # IoV 实时性阈值 (ms)
    latency_threshold_ms: float = 50.0


def get_default_config() -> ProtocolConfig:
    return ProtocolConfig(
        pqc=PQCConfig(),
        zkp=ZKPConfig(),
        pls=PLSConfig(),
    )
