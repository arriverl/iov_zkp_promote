# -*- coding: utf-8 -*-
"""仿真 CSI vs 真实/文献校准 V2X CSI 对比实验（Group 6）。"""
from __future__ import annotations

import statistics
from copy import deepcopy
from typing import Dict, List

from ..config import load_profile, protocol_from_config
from ..protocol import FusionAuthProtocol, IoVAuthFrame
from ..pls import PLSAuthenticator


def _benign_rounds(protocol: FusionAuthProtocol, rounds: int) -> Dict[str, float]:
    ok = 0
    rhos: List[float] = []
    for _ in range(rounds):
        req = protocol.obu_build_request(frame=IoVAuthFrame.fresh(b"RSU-REAL-CSI"))
        r = protocol.rsu_verify(req)
        ok += int(r.success)
        rhos.append(r.pls_similarity)
    return {
        "benign_auth_rate": ok / rounds,
        "benign_rho_mean": statistics.mean(rhos) if rhos else 0.0,
        "benign_rho_min": min(rhos) if rhos else 0.0,
    }


def _theft_rounds(protocol: FusionAuthProtocol, rounds: int) -> Dict[str, float]:
    ok = 0
    rhos: List[float] = []
    for _ in range(rounds):
        req = protocol.obu_build_request(frame=IoVAuthFrame.fresh(b"RSU-THEFT-REAL"))
        remote = protocol.pls.extract_remote_csi(req["message"])
        r = protocol.rsu_verify(req, measured_csi=remote)
        ok += int(r.success)
        rhos.append(r.pls_similarity)
    return {
        "theft_success_rate": ok / rounds,
        "theft_rho_mean": statistics.mean(rhos) if rhos else 0.0,
        "theft_rho_max": max(rhos) if rhos else 0.0,
    }


def _rho_distribution(pls: PLSAuthenticator, rounds: int, *, theft: bool) -> Dict[str, float]:
    rhos: List[float] = []
    for i in range(rounds):
        msg = f"CSI-EVAL-{i}".encode()
        if theft:
            obu = pls.extract_session_csi(msg)
            remote = pls.extract_remote_csi(msg)
            _, rho = pls.authenticate(obu, remote)
        else:
            obu = pls.extract_session_csi(msg)
            rsu = pls.measure_session_csi(msg)
            _, rho = pls.authenticate(obu, rsu)
        rhos.append(rho)
    return {
        "rho_mean": statistics.mean(rhos),
        "rho_stdev": statistics.stdev(rhos) if len(rhos) > 1 else 0.0,
        "rho_p05": sorted(rhos)[max(0, int(0.05 * len(rhos)) - 1)],
        "rho_p95": sorted(rhos)[min(len(rhos) - 1, int(0.95 * len(rhos)))],
    }


def run_real_csi_comparison(
    profile: str = "balanced",
    rounds: int = 30,
) -> List[Dict[str, object]]:
    base = load_profile(profile)
    rows: List[Dict[str, object]] = []

    for mode in ("simulation", "real"):
        cfg = deepcopy(base)
        cfg.setdefault("pls", {})["mode"] = mode
        if mode == "real":
            # 真实 V2X CSI 幅度分布更分散，阈值按文献校准配置略放宽
            real_prof = load_profile("balanced_real")
            cfg["pls"]["threshold"] = real_prof["pls"]["threshold"]
            cfg["pls"]["rel_dist_max"] = real_prof["pls"]["rel_dist_max"]
            cfg["pls"]["noise_std"] = real_prof["pls"]["noise_std"]
        pls_cfg = cfg["pls"]
        protocol = protocol_from_config(cfg)
        protocol.obu_setup()

        benign = _benign_rounds(protocol, rounds)
        theft = _theft_rounds(protocol, rounds)
        dist_legit = _rho_distribution(protocol.pls, rounds, theft=False)
        dist_theft = _rho_distribution(protocol.pls, rounds, theft=True)

        source = "rayleigh_sim"
        if mode == "real":
            source = protocol.pls._csi_repo.source if protocol.pls._csi_repo else "real_unknown"

        rows.append(
            {
                "experiment": "real_csi_comparison",
                "pls_mode": mode,
                "csi_source": source,
                "csi_dim": int(pls_cfg.get("csi_dim", 32)),
                "threshold": float(pls_cfg.get("threshold", 0.88)),
                "rounds": rounds,
                **benign,
                **theft,
                "legit_rho_mean": dist_legit["rho_mean"],
                "legit_rho_p05": dist_legit["rho_p05"],
                "theft_rho_p95": dist_theft["rho_p95"],
            }
        )
    return rows
