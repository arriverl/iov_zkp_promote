# -*- coding: utf-8 -*-
"""
3GPP TR 37.885 风格的 V2X 信道幅度指纹（Jakes 多径 + 车速多普勒）。
用于在无 IEEE .mat 原始文件时，按文献场景（0–40 km/h）生成可复现的 V2X 类 CSI。
"""
from __future__ import annotations

import numpy as np


def jakes_v2x_csi_amplitude(
    dim: int,
    speed_kmh: float,
    carrier_ghz: float = 5.91,
    num_paths: int = 8,
    rng: np.random.Generator | None = None,
) -> np.ndarray:
    """
    生成 V2X 场景 CSI 幅度向量（实数，用于皮尔逊相关）。
    speed_kmh: 相对速度，影响多普勒展宽与快衰落起伏。
    """
    rng = rng or np.random.default_rng()
    v_mps = max(float(speed_kmh), 0.0) / 3.6
    fd = v_mps * carrier_ghz * 1e9 / 3e8  # 最大多普勒 Hz 量级

    t = np.linspace(0, 1.0, dim, dtype=np.float64)
    h = np.zeros(dim, dtype=np.complex128)
    for p in range(num_paths):
        delay = rng.uniform(0.0, 2.0)
        gain = np.exp(-0.35 * p) * (1.0 + 0.15 * rng.standard_normal())
        phase0 = rng.uniform(0, 2 * np.pi)
        doppler = fd * np.cos(rng.uniform(0, 2 * np.pi))
        h += gain * np.exp(1j * (phase0 + 2 * np.pi * doppler * (t + delay)))

    amp = np.abs(h)
    # 子载波选择性衰落，避免归一化后退化为常数向量（皮尔逊相关无定义）
    ripple = 1.0 + 0.25 * np.sin(2 * np.pi * np.arange(dim) / max(dim, 1) + rng.uniform(0, 2 * np.pi))
    amp = amp * ripple + 0.05 * rng.standard_normal(dim)
    amp = np.maximum(amp, 1e-6)
    amp = amp / (np.linalg.norm(amp) + 1e-9)
    return amp.astype(np.float32)


def rsu_measurement(obu_csi: np.ndarray, noise_std: float, rng: np.random.Generator) -> np.ndarray:
    """RSU 侧同链路测量：合法对端 CSI + 小噪声（保持高皮尔逊相关）。"""
    return (obu_csi.astype(np.float32) + rng.normal(0, noise_std, obu_csi.shape).astype(np.float32))
