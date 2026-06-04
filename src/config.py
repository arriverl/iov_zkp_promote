# -*- coding: utf-8 -*-
"""从 configs/*.json 构建协议与实验参数。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .protocol import FusionAuthProtocol

ROOT = Path(__file__).resolve().parents[1]


def load_profile(profile: str = "balanced") -> Dict[str, Any]:
    path = ROOT / "configs" / f"{profile}.json"
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def protocol_from_config(config: Dict[str, Any]) -> FusionAuthProtocol:
    pls = config.get("pls", {})
    return FusionAuthProtocol(
        pqc_level=int(config.get("pqc_level", 2)),
        zkp_challenge_bytes=int(config.get("zkp_challenge_bytes", 16)),
        pls_threshold=float(pls.get("threshold", 0.85)),
        pls_csi_dim=int(pls.get("csi_dim", 32)),
        pls_noise_std=float(pls.get("noise_std", 0.05)),
        pls_use_float32=bool(pls.get("use_float32", True)),
        pls_num_multipath=int(pls.get("num_multipath", 8)),
        pls_rel_dist_max=float(pls.get("rel_dist_max", 0.42)),
        pqc_sign_digest=bool(config.get("pqc_sign_digest", True)),
        zkp_witness_digest=bool(config.get("zkp_witness_digest", True)),
        replay_cleanup_interval=int(config.get("replay_cleanup_interval", 32)),
    )
