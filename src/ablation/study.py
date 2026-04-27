# -*- coding: utf-8 -*-
from __future__ import annotations

import statistics
from typing import Dict, List

from ..protocol import FusionAuthProtocol, IoVAuthFrame
from ..zkp import ZKProof


def _verify_with_toggles(protocol: FusionAuthProtocol, req: dict, *, use_zkp: bool, use_pls: bool) -> Dict[str, float]:
    msg = req["message"]
    pk = req["pk"]

    zkp_ok = True
    if use_zkp:
        zkp_ok = protocol.zkp_verifier.verify(
            pk,
            msg,
            ZKProof(
                commitment=req["zkp_commitment"],
                response=req["zkp_response"],
                challenge_digest=req["zkp_challenge_digest"],
            ),
        )

    pqc_ok = protocol.pqc.verify(msg, req["signature"], pk)

    pls_ok = True
    sim = 1.0
    if use_pls:
        measured = protocol.pls.add_channel_noise(req["reported_csi"])
        pls_ok, sim = protocol.pls.authenticate(req["reported_csi"], measured)

    success = zkp_ok and pqc_ok and pls_ok
    return {"success": float(success), "similarity": float(sim)}


def run_ablation_study(rounds: int = 30) -> List[Dict[str, float]]:
    variants = [
        ("full", True, True, True),
        ("no_zkp", False, True, True),
        ("no_pls", True, False, True),
        ("no_session_binding", True, True, False),
        ("pqc_only", False, False, False),
    ]

    outputs: List[Dict[str, float]] = []

    for name, use_zkp, use_pls, use_frame in variants:
        protocol = FusionAuthProtocol()
        protocol.obu_setup()
        success = []
        similarities = []

        for _ in range(rounds):
            if use_frame:
                req = protocol.obu_build_request(frame=IoVAuthFrame.fresh(b"RSU-ABL"))
            else:
                req = protocol.obu_build_request(message=b"STATIC_AUTH_MESSAGE")

            result = _verify_with_toggles(protocol, req, use_zkp=use_zkp, use_pls=use_pls)
            success.append(result["success"])
            similarities.append(result["similarity"])

        outputs.append(
            {
                "variant": name,
                "auth_success_rate": statistics.mean(success) if success else 0.0,
                "avg_similarity": statistics.mean(similarities) if similarities else 0.0,
                "use_zkp": float(use_zkp),
                "use_pls": float(use_pls),
                "use_session_binding": float(use_frame),
            }
        )

    return outputs
