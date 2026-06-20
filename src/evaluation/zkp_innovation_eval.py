# -*- coding: utf-8 -*-
"""
ZKP 算法创新对比：Sigma（HMAC 骨架）vs SIS-Σ-NIZK（格短向量关系证明）。

对照实验：
1. 良性认证率
2. 伪造证明（随机 response）通过率 — 仅 SIS 应严格拒绝
3. 无密钥伪造（错误 sk 导出）— 线性关系不满足
"""
from __future__ import annotations

import os
from copy import deepcopy
from typing import Dict, List

from ..config import load_profile, protocol_from_config
from ..protocol import FusionAuthProtocol, IoVAuthFrame
from ..zkp import ZKProof


def _benign_rate(protocol: FusionAuthProtocol, rounds: int) -> float:
    ok = 0
    for _ in range(rounds):
        req = protocol.obu_build_request(frame=IoVAuthFrame.fresh(b"RSU-ZKP-BENIGN"))
        ok += int(protocol.rsu_verify(req).success)
    return ok / rounds


def _forgery_rate(protocol: FusionAuthProtocol, rounds: int) -> float:
    """随机篡改 response 字段，检验验证方程是否可伪造。"""
    ok = 0
    for _ in range(rounds):
        req = protocol.obu_build_request(frame=IoVAuthFrame.fresh(b"RSU-ZKP-FORGE"))
        bad = dict(req)
        bad["zkp_response"] = os.urandom(len(req["zkp_response"]))
        ok += int(protocol.rsu_verify(bad).zkp_ok)
    return ok / rounds


def run_zkp_innovation_comparison(
    profile: str = "balanced",
    rounds: int = 30,
) -> List[Dict[str, object]]:
    base = load_profile(profile)
    rows: List[Dict[str, object]] = []

    for mode in ("sigma", "sis_lattice_nizk"):
        cfg = deepcopy(base)
        cfg["zkp_mode"] = mode
        protocol = protocol_from_config(cfg)
        protocol.obu_setup()

        rows.append(
            {
                "experiment": "zkp_algorithm_innovation",
                "zkp_mode": mode,
                "rounds": rounds,
                "benign_auth_rate": _benign_rate(protocol, rounds),
                "forged_response_zkp_pass_rate": _forgery_rate(protocol, rounds),
                "algorithm_family": "HMAC-Sigma" if mode == "sigma" else "SIS-Lyubashevsky-NIZK",
            }
        )
    return rows
