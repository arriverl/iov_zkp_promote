# -*- coding: utf-8 -*-
"""
ZKP-PQC-PLS 性能评估：认证延迟、通信开销、与基线/改进协议对比。
"""
from __future__ import annotations

import os
import sys
import time
import statistics

# 项目根目录加入 path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baselines.yang2023 import Yang2023IoVAuth, benchmark_yang2023_round
from src.baselines.ecdh_aes_pseudonym import EcdhAesPseudonymAuth, benchmark_ecdh_aes_round
from src.pqc.lattice_signing import measure_pqc_latency
from src.protocol.fusion_protocol import FusionAuthProtocol
from src.protocol.iov_auth_frame import IoVAuthFrame
from src.evaluation.security_rubric import (
    preset_baseline_yang,
    preset_improved_ecdh_aes,
    preset_innovation_zkp_pqc_pls,
    explain_score,
)


def _rounds(config: dict | None = None) -> int:
    if config:
        return int(config.get("benchmark_rounds", config.get("rounds", 50)))
    return 50


def benchmark_fusion_protocol(config: dict | None = None) -> dict:
    """融合协议单轮认证延迟与通信开销。"""
    if config:
        from src.config import protocol_from_config
        protocol = protocol_from_config(config)
    else:
        protocol = FusionAuthProtocol()
    protocol.obu_setup()
    n_rounds = _rounds(config)
    frm = IoVAuthFrame.fresh(b"RSU-BENCH-001")
    req = protocol.obu_build_request(frame=frm)

    # 通信开销（字节）
    pk_len = len(req["pk"])
    sig_len = len(req["signature"])
    zkp_comm = len(req["zkp_commitment"]) + len(req["zkp_response"]) + len(req["zkp_challenge_digest"])
    csi_bytes = req["reported_csi"].nbytes
    total_bytes = len(req["message"]) + pk_len + sig_len + zkp_comm + csi_bytes

    rsu_latencies = []
    e2e_latencies = []
    for _ in range(n_rounds):
        t0 = time.perf_counter()
        req_i = protocol.obu_build_request(frame=IoVAuthFrame.fresh(b"RSU-BENCH-001"))
        r = protocol.rsu_verify(req_i)
        e2e_latencies.append((time.perf_counter() - t0) * 1000)
        rsu_latencies.append(r.latency_ms)

    return {
        "latency_ms_mean": statistics.mean(rsu_latencies),
        "latency_ms_median": statistics.median(rsu_latencies),
        "latency_ms_stdev": statistics.stdev(rsu_latencies) if len(rsu_latencies) > 1 else 0,
        "e2e_latency_ms_mean": statistics.mean(e2e_latencies),
        "e2e_latency_ms_median": statistics.median(e2e_latencies),
        "comm_bytes_total": total_bytes,
        "comm_bytes_pk": pk_len,
        "comm_bytes_sig": sig_len,
        "comm_bytes_zkp": zkp_comm,
        "comm_bytes_csi": csi_bytes,
    }


def benchmark_baseline_yang(config: dict | None = None) -> dict:
    """
    基线 Yang et al. (2023) FGCS — ECC 认证/密钥协商 + XOR 假名掩码。
    本机 cryptography 原语实测（非 time.sleep）；非 NS-3 网络仿真。
    """
    n_rounds = _rounds(config)
    proto = Yang2023IoVAuth()
    rsu_id = b"RSU-YANG-BENCH"
    route = b"ROUTE_SEGMENT_SH_A_TO_RSU_001"

    rsu_latencies = []
    e2e_latencies = []
    comm_bytes = 0
    for _ in range(n_rounds):
        rsu_ms, e2e_ms, comm_bytes = benchmark_yang2023_round(proto, route, rsu_id)
        rsu_latencies.append(rsu_ms)
        e2e_latencies.append(e2e_ms)

    return {
        "latency_ms_mean": statistics.mean(rsu_latencies),
        "latency_ms_median": statistics.median(rsu_latencies),
        "e2e_latency_ms_mean": statistics.mean(e2e_latencies),
        "comm_bytes_total": comm_bytes,
        "implementation": "yang2023_crypto_replica",
        "reference": "Yang et al. FGCS 145:415-428 (2023), DOI 10.1016/j.future.2023.04.004",
        "security_note": "ECC+XOR, no PQC/ZKP/PLS",
    }


def benchmark_improved_ecdh_aes(config: dict | None = None) -> dict:
    """
    改进基线 ECDH+AES-GCM 假名方案 — 本机 cryptography 实测。
    """
    n_rounds = _rounds(config)
    proto = EcdhAesPseudonymAuth()
    rsu_id = b"RSU-ECDH-BENCH"

    rsu_latencies = []
    e2e_latencies = []
    comm_bytes = 0
    for _ in range(n_rounds):
        rsu_ms, e2e_ms, comm_bytes = benchmark_ecdh_aes_round(proto, rsu_id)
        rsu_latencies.append(rsu_ms)
        e2e_latencies.append(e2e_ms)

    return {
        "latency_ms_mean": statistics.mean(rsu_latencies),
        "latency_ms_median": statistics.median(rsu_latencies),
        "e2e_latency_ms_mean": statistics.mean(e2e_latencies),
        "comm_bytes_total": comm_bytes,
        "implementation": "ecdh_aes_gcm_replica",
        "reference": "ECDH+AES-GCM pseudonym improvement over Yang XOR baseline",
        "security_note": "ECDH+AES, no PQC, pseudonym",
    }


def main() -> None:
    print("=" * 60)
    print("ZKP-PQC-PLS 融合架构 性能评估")
    print("=" * 60)

    print("\n[1] 基线协议 (Yang et al. 2023) 密码学复现")
    b1 = benchmark_baseline_yang()
    print(f"    认证延迟: {b1['latency_ms_mean']:.2f} ms (median: {b1['latency_ms_median']:.2f})")
    print(f"    通信开销: {b1['comm_bytes_total']} Bytes")

    print("\n[2] 改进协议 (ECDH+AES-GCM) 密码学复现")
    b2 = benchmark_improved_ecdh_aes()
    print(f"    认证延迟: {b2['latency_ms_mean']:.2f} ms (median: {b2['latency_ms_median']:.2f})")
    print(f"    通信开销: {b2['comm_bytes_total']} Bytes")

    print("\n[3] 创新协议 (ZKP-PQC-PLS) 实测")
    b3 = benchmark_fusion_protocol()
    print(f"    认证延迟: {b3['latency_ms_mean']:.2f} ms (median: {b3['latency_ms_median']:.2f}, stdev: {b3['latency_ms_stdev']:.2f})")
    print(f"    通信开销: {b3['comm_bytes_total']} Bytes (pk={b3['comm_bytes_pk']}, sig={b3['comm_bytes_sig']}, zkp={b3['comm_bytes_zkp']}, csi={b3['comm_bytes_csi']})")

    print("\n[4] PQC (Dilithium2) 分项延迟")
    try:
        pqc = measure_pqc_latency(security_level=2, rounds=30)
        print(f"    KeyGen: {pqc['keygen_ms_median']:.2f} ms (median)")
        print(f"    Sign:   {pqc['sign_ms_median']:.2f} ms (median)")
        print(f"    Verify: {pqc['verify_ms_median']:.2f} ms (median)")
        print(f"    pk={pqc['pk_bytes']} B, sig={pqc['sig_bytes']} B")
    except Exception as e:
        print(f"    (PQC 未可用: {e})")

    print("\n[5] 可解释安全分 (SecurityRubric, 0–100)")
    s1, r1 = preset_baseline_yang()
    s2, r2 = preset_improved_ecdh_aes()
    s3, r3 = preset_innovation_zkp_pqc_pls()
    print(f"    基线 (Yang+XOR 假设): {s1}")
    for line in explain_score(r1):
        print(line)
    print(f"    改进 (ECDH+AES+会话绑定): {s2}")
    for line in explain_score(r2):
        print(line)
    print(f"    创新 (ZKP+PQC+PLS+IoVAuthFrame): {s3}")
    for line in explain_score(r3):
        print(line)
    print("    详见 src/evaluation/security_rubric.py 与 docs/PROJECT.md")

    print("\n--- 对比小结 ---")
    print(f"  创新协议延迟 < 50 ms (IoV 实时性阈值): {b3['latency_ms_mean'] < 50}")
    print("=" * 60)


if __name__ == "__main__":
    main()
