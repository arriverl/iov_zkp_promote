# -*- coding: utf-8 -*-
"""真算一轮融合认证：分步计时，供 live demo API 与前端动画驱动。"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..protocol import FusionAuthProtocol, IoVAuthFrame
from ..zkp import ZKProof, prove_request, verify_request


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def _packet_sizes(req: dict) -> Dict[str, int]:
    zkp_b = (
        len(req["zkp_commitment"])
        + len(req["zkp_response"])
        + len(req["zkp_challenge_digest"])
    )
    return {
        "frame": len(req["message"]),
        "zkp": zkp_b,
        "csi": req["reported_csi"].nbytes,
        "pk": len(req["pk"]),
        "sig": len(req["signature"]),
        "total": (
            len(req["message"])
            + len(req["pk"])
            + len(req["signature"])
            + zkp_b
            + req["reported_csi"].nbytes
        ),
    }


def obu_build_timed(protocol: FusionAuthProtocol, rsu_id: bytes = b"RSU-LIVE-DEMO") -> tuple[dict, List[dict]]:
    """与 fusion_protocol.obu_build_request 等价，但返回分步耗时。"""
    steps: List[dict] = []
    if protocol._sk is None or protocol._pk is None:
        protocol.obu_setup()

    pk, sk = protocol._pk, protocol._sk

    t = time.perf_counter()
    frame = IoVAuthFrame.fresh(rsu_id)
    msg = frame.canonical_bytes()
    steps.append({
        "phase": "obu",
        "action": "IoVAuthFrame.fresh → canonical_bytes",
        "ms": round(_ms(t), 3),
        "bytes": len(msg),
        "detail": f"rsu_id={rsu_id.decode('utf-8', errors='replace')}, nonce=16B",
    })

    t = time.perf_counter()
    csi = protocol.pls.extract_session_csi(msg)
    steps.append({
        "phase": "obu",
        "action": "PLS.extract_session_csi",
        "ms": round(_ms(t), 3),
        "bytes": csi.nbytes,
    })

    pqc_msg = protocol._pqc_payload(msg)
    zkp_w = protocol._zkp_prove_secret(sk)

    t = time.perf_counter()
    proof = prove_request(
        protocol.zkp_prover,
        witness=zkp_w,
        public_input=pk,
        message=msg,
        reported_csi=csi,
    )
    steps.append({
        "phase": "obu",
        "action": f"ZKP prove ({protocol.zkp_mode})",
        "ms": round(_ms(t), 3),
        "bytes": len(proof.commitment) + len(proof.response) + len(proof.challenge_digest),
    })

    t = time.perf_counter()
    signature = protocol.pqc.sign(pqc_msg, sk)
    steps.append({
        "phase": "obu",
        "action": "PQC Dilithium2 sign",
        "ms": round(_ms(t), 3),
        "bytes": len(signature),
    })

    req = {
        "message": msg,
        "pqc_payload": pqc_msg,
        "pk": pk,
        "zkp_commitment": proof.commitment,
        "zkp_response": proof.response,
        "zkp_challenge_digest": proof.challenge_digest,
        "signature": signature,
        "reported_csi": csi,
    }
    sizes = _packet_sizes(req)
    steps.append({
        "phase": "obu",
        "action": "AuthRequest 组装完成",
        "ms": 0.0,
        "bytes": sizes["total"],
        "detail": f"pk={sizes['pk']} sig={sizes['sig']} zkp={sizes['zkp']} csi={sizes['csi']}",
    })
    return req, steps


def rsu_verify_timed(
    protocol: FusionAuthProtocol,
    req: dict,
    *,
    measured_csi: Optional[bytes] = None,
    pls_enabled: bool = True,
) -> tuple[Any, List[dict]]:
    """分步 RSU 验证，返回 AuthResult 与 steps。"""
    from ..protocol.fusion_protocol import AuthResult

    steps: List[dict] = []
    msg = req["message"]
    pk = req["pk"]
    now_ms = time.time() * 1000.0
    t_total = time.perf_counter()

    t = time.perf_counter()
    replay_hit = protocol._check_and_mark_replay(msg, now_ms)
    replay_ms = _ms(t)
    if replay_hit:
        steps.append({
            "phase": "rsu",
            "step": "replay",
            "action": "Replay Guard",
            "ms": round(replay_ms, 3),
            "ok": False,
            "detail": "重复 message 指纹",
        })
        latency = _ms(t_total)
        return AuthResult(
            success=False,
            latency_ms=latency,
            zkp_ok=False,
            pls_ok=False,
            pqc_ok=False,
            pls_similarity=0.0,
            details="REJECTED: replay detected",
        ), steps

    steps.append({
        "phase": "rsu",
        "step": "replay",
        "action": "Replay Guard",
        "ms": round(replay_ms, 3),
        "ok": True,
        "detail": "新 nonce，未命中重放",
    })

    reported_csi = req["reported_csi"]
    t = time.perf_counter()
    zkp_ok = verify_request(
        protocol.zkp_verifier,
        pk,
        msg,
        ZKProof(
            commitment=req["zkp_commitment"],
            response=req["zkp_response"],
            challenge_digest=req["zkp_challenge_digest"],
        ),
        reported_csi,
    )
    steps.append({
        "phase": "rsu",
        "step": "zkp",
        "action": "ZKP verify",
        "ms": round(_ms(t), 3),
        "ok": zkp_ok,
    })
    if not zkp_ok:
        latency = _ms(t_total)
        return AuthResult(
            success=False,
            latency_ms=latency,
            zkp_ok=False,
            pls_ok=False,
            pqc_ok=False,
            pls_similarity=0.0,
            details="ZKP=FAIL (early exit)",
        ), steps

    if not pls_enabled:
        pls_ok, similarity = True, 1.0
        steps.append({
            "phase": "rsu",
            "step": "pls",
            "action": "PLS (disabled)",
            "ms": 0.0,
            "ok": True,
            "detail": "对照实验跳过 CSI",
            "rho": None,
        })
    else:
        t = time.perf_counter()
        if measured_csi is not None:
            import numpy as np
            if isinstance(measured_csi, bytes):
                measured = protocol.pls.unpack_csi(measured_csi)
            else:
                measured = np.asarray(measured_csi)
        else:
            measured = protocol.pls.measure_session_csi(msg)
        pls_ok, similarity = protocol.pls.authenticate(reported_csi, measured)
        steps.append({
            "phase": "rsu",
            "step": "pls",
            "action": "PLS authenticate",
            "ms": round(_ms(t), 3),
            "ok": pls_ok,
            "rho": round(float(similarity), 4),
            "detail": f"γ={protocol.pls.threshold}, rel_dist_max={protocol.pls.rel_dist_max}",
        })
        if not pls_ok:
            latency = _ms(t_total)
            return AuthResult(
                success=False,
                latency_ms=latency,
                zkp_ok=True,
                pls_ok=False,
                pqc_ok=False,
                pls_similarity=float(similarity),
                details=f"PLS=FAIL (ρ={similarity:.4f}, early exit)",
            ), steps

    t = time.perf_counter()
    pqc_msg = req.get("pqc_payload") or protocol._pqc_payload(msg)
    pqc_ok = protocol.pqc.verify(pqc_msg, req["signature"], pk)
    steps.append({
        "phase": "rsu",
        "step": "pqc",
        "action": "PQC Dilithium2 verify",
        "ms": round(_ms(t), 3),
        "ok": pqc_ok,
    })

    latency = _ms(t_total)
    similarity_val = float(similarity) if pls_enabled else 0.0
    return AuthResult(
        success=pqc_ok,
        latency_ms=latency,
        zkp_ok=zkp_ok,
        pls_ok=pls_ok if pls_enabled else True,
        pqc_ok=pqc_ok,
        pls_similarity=similarity_val if pls_enabled else 0.0,
        details=(
            f"ZKP={'PASS' if zkp_ok else 'FAIL'}, "
            f"PQC={'PASS' if pqc_ok else 'FAIL'}, "
            f"PLS={'PASS' if (pls_ok if pls_enabled else True) else 'FAIL'} "
            f"(ρ={similarity_val:.4f})"
        ),
    ), steps


def run_live_round(
    protocol: FusionAuthProtocol,
    scenario: str = "normal",
) -> Dict[str, Any]:
    """
    真算一轮（或盗证/重放/篡改/中继场景），返回前端可动画化的 JSON。
    scenario: normal | theft | replay | tamper | relay
    """
    all_steps: List[dict] = []
    t0 = time.perf_counter()

    req, obu_steps = obu_build_timed(protocol)
    all_steps.extend(obu_steps)
    sizes = _packet_sizes(req)
    msg = req["message"]

    all_steps.append({
        "phase": "tx",
        "action": "V2I 逻辑传输",
        "ms": 0.0,
        "bytes": sizes["total"],
        "detail": "Python dict 传递（无 NS-3）",
    })

    if scenario == "normal":
        result, rsu_steps = rsu_verify_timed(protocol, req)
        all_steps.extend(rsu_steps)

    elif scenario == "theft":
        remote = protocol.pls.extract_remote_csi(msg)
        result, rsu_steps = rsu_verify_timed(protocol, req, measured_csi=remote)
        all_steps.extend(rsu_steps)
        all_steps.insert(-len(rsu_steps), {
            "phase": "tx",
            "action": "攻击：盗证异地使用",
            "ms": 0.0,
            "detail": "RSU 侧 measured_csi = extract_remote_csi()",
        })

    elif scenario == "replay":
        r1, s1 = rsu_verify_timed(protocol, req)
        all_steps.extend(s1)
        all_steps.append({
            "phase": "tx",
            "action": "攻击：重放同一 AuthRequest",
            "ms": 0.0,
            "detail": "第二次提交相同 message/nonce",
        })
        r2, s2 = rsu_verify_timed(protocol, req)
        all_steps.extend(s2)
        result = r2
        all_steps.append({
            "phase": "info",
            "action": "首次合法认证",
            "ok": r1.success,
            "detail": r1.details,
        })

    elif scenario == "tamper":
        req2 = dict(req)
        req2["message"] = req["message"] + b"|MITM"
        all_steps.append({
            "phase": "tx",
            "action": "攻击：篡改 message",
            "ms": 0.0,
            "detail": "保留原 signature，修改会话帧",
        })
        result, rsu_steps = rsu_verify_timed(protocol, req2)
        all_steps.extend(rsu_steps)

    elif scenario == "relay":
        reported = req["reported_csi"]
        if isinstance(reported, bytes):
            reported = protocol.pls.unpack_csi(reported)
        relay_csi = protocol.pls.add_channel_noise(reported, noise_std=0.35)
        all_steps.append({
            "phase": "tx",
            "action": "攻击：远程中继 CSI 失真",
            "ms": 0.0,
            "detail": "noise_std=0.35",
        })
        result, rsu_steps = rsu_verify_timed(protocol, req, measured_csi=relay_csi)
        all_steps.extend(rsu_steps)

    else:
        raise ValueError(f"未知场景: {scenario}")

    e2e_ms = _ms(t0)
    obu_ms = sum(s["ms"] for s in all_steps if s.get("phase") == "obu")

    return {
        "scenario": scenario,
        "success": result.success,
        "details": result.details,
        "zkp_ok": result.zkp_ok,
        "pls_ok": result.pls_ok,
        "pqc_ok": result.pqc_ok,
        "pls_rho": round(result.pls_similarity, 4),
        "rsu_latency_ms": round(result.latency_ms, 3),
        "obu_build_ms": round(obu_ms, 3),
        "e2e_ms": round(e2e_ms, 3),
        "packet": sizes,
        "steps": all_steps,
        "real_compute": True,
    }
