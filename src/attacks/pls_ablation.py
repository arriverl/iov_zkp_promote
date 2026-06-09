# -*- coding: utf-8 -*-
"""攻击条件下 PLS 消融：对比开启/关闭 PLS 时异地盗证通过率（供 PPT Slide 12）。"""
from __future__ import annotations

from typing import Dict, List

from ..protocol import FusionAuthProtocol, IoVAuthFrame
from ..zkp import ZKProof


def run_pls_theft_ablation(
    rounds: int = 30,
    protocol: FusionAuthProtocol | None = None,
) -> List[Dict[str, float]]:
    p = protocol or FusionAuthProtocol()
    p.obu_setup()

    with_pls_ok = 0
    without_pls_ok = 0

    for _ in range(rounds):
        frame = IoVAuthFrame.fresh(b"RSU-THEFT-ABL")
        req = p.obu_build_request(frame=frame)
        remote = p.pls.extract_remote_csi(req["message"])

        if p.rsu_verify(req, measured_csi=remote).success:
            with_pls_ok += 1

        msg = req["message"]
        pk = req["pk"]
        zkp_ok = p.zkp_verifier.verify(
            pk,
            msg,
            ZKProof(
                commitment=req["zkp_commitment"],
                response=req["zkp_response"],
                challenge_digest=req["zkp_challenge_digest"],
            ),
        )
        pqc_ok = p.pqc.verify(req.get("pqc_payload") or p._pqc_payload(msg), req["signature"], pk)
        if zkp_ok and pqc_ok:
            without_pls_ok += 1

    return [
        {
            "scenario": "certificate_theft_with_pls",
            "auth_success_rate": with_pls_ok / rounds,
            "rounds": float(rounds),
        },
        {
            "scenario": "certificate_theft_without_pls",
            "auth_success_rate": without_pls_ok / rounds,
            "rounds": float(rounds),
        },
    ]
