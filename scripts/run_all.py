# -*- coding: utf-8 -*-
from __future__ import annotations

import csv
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.run_benchmarks import (
    benchmark_baseline_yang,
    benchmark_improved_ecdh_aes,
    benchmark_fusion_protocol,
)
from src.ablation import run_ablation_study
from src.attacks import run_attack_suite
from src.config import protocol_from_config
from src.protocol import FusionAuthProtocol, IoVAuthFrame


def _write_csv(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    rows = list(rows)
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = sorted({k for r in rows for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def _run_main_comparison(config: Dict[str, object]) -> List[Dict[str, object]]:
    b = benchmark_baseline_yang(config)
    i = benchmark_improved_ecdh_aes(config)
    n = benchmark_fusion_protocol(config)
    return [
        {"protocol": "baseline_yang", **b},
        {"protocol": "improved_ecdh_aes", **i},
        {"protocol": "innovation_zkp_pqc_pls", **n},
    ]


def _run_sensitivity(config: Dict[str, object], rounds: int = 12) -> List[Dict[str, object]]:
    pls_cfg = config.get("pls", {})
    default_noise = float(pls_cfg.get("noise_std", 0.05))
    rows: List[Dict[str, object]] = []
    csi_dims = [16, 32, 64]
    thresholds = [0.85, 0.9]
    pqc_levels = [2, 3]

    for csi_dim in csi_dims:
        for th in thresholds:
            for pqc_level in pqc_levels:
                protocol = FusionAuthProtocol(
                    pqc_level=pqc_level,
                    pls_csi_dim=csi_dim,
                    pls_threshold=th,
                    pls_noise_std=default_noise,
                    pls_use_float32=bool(pls_cfg.get("use_float32", True)),
                )
                protocol.obu_setup()
                lat = []
                ok = 0
                comm = []
                for _ in range(rounds):
                    frm = IoVAuthFrame.fresh(b"RSU-SENS")
                    req = protocol.obu_build_request(frame=frm)
                    r = protocol.rsu_verify(req)
                    ok += int(r.success)
                    lat.append(r.latency_ms)
                    comm.append(
                        len(req["message"]) + len(req["pk"]) + len(req["signature"]) +
                        len(req["zkp_commitment"]) + len(req["zkp_response"]) + len(req["zkp_challenge_digest"]) +
                        req["reported_csi"].nbytes
                    )
                rows.append(
                    {
                        "experiment": "sensitivity",
                        "pqc_level": pqc_level,
                        "csi_dim": csi_dim,
                        "threshold": th,
                        "latency_ms_mean": statistics.mean(lat),
                        "auth_success_rate": ok / rounds,
                        "comm_bytes_mean": statistics.mean(comm),
                    }
                )
    return rows


def _run_scalability(
    config: Dict[str, object],
    vehicle_counts: List[int],
    rounds_each: int = 3,
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    protocol = protocol_from_config(config)
    protocol.obu_setup()

    for n in vehicle_counts:
        elapsed = []
        success_rates = []
        for _ in range(rounds_each):
            t0 = time.perf_counter()
            ok = 0
            for _idx in range(n):
                frm = IoVAuthFrame.fresh(b"RSU-SCALE")
                req = protocol.obu_build_request(frame=frm)
                r = protocol.rsu_verify(req)
                ok += int(r.success)
            total_s = time.perf_counter() - t0
            elapsed.append(total_s)
            success_rates.append(ok / n)

        mean_elapsed = statistics.mean(elapsed)
        rows.append(
            {
                "experiment": "scalability",
                "vehicles": n,
                "batch_elapsed_s": mean_elapsed,
                "throughput_auth_per_s": n / mean_elapsed if mean_elapsed > 0 else 0.0,
                "avg_auth_latency_ms": (mean_elapsed / n) * 1000 if n > 0 else 0.0,
                "auth_success_rate": statistics.mean(success_rates),
            }
        )
    return rows


def run_all(config_profile: str = "balanced") -> None:
    cfg_path = ROOT / "configs" / f"{config_profile}.json"
    if not cfg_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {cfg_path}")

    config = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
    results_dir = ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    print(f"[RUN] profile={config_profile}")

    proto = protocol_from_config(config)
    rounds = int(config.get("rounds", 30))

    # Group 1: 主对比
    g1 = _run_main_comparison(config)
    _write_csv(results_dir / "group1_main_comparison.csv", g1)
    print("[OK] group1_main_comparison.csv")

    # Group 2: 消融
    g2 = run_ablation_study(rounds=rounds, protocol=proto)
    _write_csv(results_dir / "group2_ablation.csv", g2)
    print("[OK] group2_ablation.csv")

    # Group 3: 攻击
    g3 = run_attack_suite(rounds=rounds, protocol=protocol_from_config(config))
    _write_csv(results_dir / "group3_attacks.csv", g3)
    print("[OK] group3_attacks.csv")

    # Group 4: 参数敏感性
    g4 = _run_sensitivity(config, rounds=max(8, rounds // 2))
    _write_csv(results_dir / "group4_sensitivity.csv", g4)
    print("[OK] group4_sensitivity.csv")

    # Group 5: 规模实验
    counts = list(config.get("scalability_vehicle_counts", [50, 100, 200]))
    g5 = _run_scalability(config, counts, rounds_each=2)
    _write_csv(results_dir / "group5_scalability.csv", g5)
    print("[OK] group5_scalability.csv")

    summary = [
        {"group": 1, "name": "main_comparison", "rows": len(g1)},
        {"group": 2, "name": "ablation", "rows": len(g2)},
        {"group": 3, "name": "attacks", "rows": len(g3)},
        {"group": 4, "name": "sensitivity", "rows": len(g4)},
        {"group": 5, "name": "scalability", "rows": len(g5)},
    ]
    _write_csv(results_dir / "summary.csv", summary)
    print("[DONE] 所有五组实验已导出到 results/")


if __name__ == "__main__":
    profile = "balanced"
    if len(sys.argv) > 1:
        profile = sys.argv[1].strip()
    run_all(profile)

