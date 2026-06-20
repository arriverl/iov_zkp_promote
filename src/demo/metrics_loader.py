# -*- coding: utf-8 -*-
"""从 results/*.csv 加载实验指标，供演示大屏 API 使用。"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[2]


def _read_csv(name: str) -> list[dict]:
    path = ROOT / "results" / name
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _f(row: dict, key: str, default: float = 0.0) -> float:
    v = row.get(key, "")
    try:
        return float(v) if v not in ("", None) else default
    except ValueError:
        return default


def load_experiment_metrics() -> Dict[str, Any]:
    g1 = {r["protocol"]: r for r in _read_csv("group1_main_comparison.csv")}
    g3 = _read_csv("group3_attacks.csv")
    g6 = _read_csv("group6_real_csi_comparison.csv")
    g7 = _read_csv("group7_zkp_innovation.csv")
    theft = _read_csv("group_pls_theft_ablation.csv")

    inn = g1.get("innovation_zkp_pqc_pls", {})
    yang = g1.get("baseline_yang", {})
    ecdh = g1.get("improved_ecdh_aes", {})

    attacks = {r["attack"]: {"success_rate": _f(r, "success_rate"), "notes": r.get("notes", "")} for r in g3}

    theft_rows = {
        r.get("experiment_role", r.get("scenario", "")): _f(r, "auth_success_rate")
        for r in theft
    }

    csi_modes = []
    for r in g6:
        csi_modes.append({
            "mode": r.get("pls_mode", ""),
            "source": r.get("csi_source", ""),
            "benign_rate": _f(r, "benign_auth_rate"),
            "theft_rate": _f(r, "theft_success_rate"),
            "legit_rho": _f(r, "legit_rho_mean"),
            "theft_rho": _f(r, "theft_rho_mean"),
        })

    zkp_cmp = []
    for r in g7:
        zkp_cmp.append({
            "family": r.get("algorithm_family", ""),
            "forged_pass_rate": _f(r, "forged_response_zkp_pass_rate"),
            "benign_rate": _f(r, "benign_auth_rate"),
        })

    ppt_path = ROOT / "docs" / "PPT_METRICS.json"
    rubric = {"baseline": 35, "improved": 75, "innovation": 95}
    if ppt_path.exists():
        try:
            rubric = json.loads(ppt_path.read_text(encoding="utf-8")).get("security_rubric", rubric)
        except Exception:
            pass

    return {
        "source": "results/*.csv",
        "main_comparison": {
            "protocols": [
                {
                    "name": "Yang 2023",
                    "key": "baseline_yang",
                    "rsu_ms": _f(yang, "latency_ms_mean"),
                    "e2e_ms": _f(yang, "e2e_latency_ms_mean"),
                    "comm_bytes": int(_f(yang, "comm_bytes_total")),
                },
                {
                    "name": "ECDH+AES",
                    "key": "improved_ecdh_aes",
                    "rsu_ms": _f(ecdh, "latency_ms_mean"),
                    "e2e_ms": _f(ecdh, "e2e_latency_ms_mean"),
                    "comm_bytes": int(_f(ecdh, "comm_bytes_total")),
                },
                {
                    "name": "本方案",
                    "key": "innovation",
                    "rsu_ms": _f(inn, "latency_ms_mean"),
                    "e2e_ms": _f(inn, "e2e_latency_ms_mean"),
                    "comm_bytes": int(_f(inn, "comm_bytes_total")),
                    "comm_breakdown": {
                        "pk": int(_f(inn, "comm_bytes_pk")),
                        "sig": int(_f(inn, "comm_bytes_sig")),
                        "zkp": int(_f(inn, "comm_bytes_zkp")),
                        "csi": int(_f(inn, "comm_bytes_csi")),
                    },
                },
            ],
        },
        "attacks": attacks,
        "theft_ablation": {
            "primary_pls_enabled": theft_rows.get("primary", 0.0),
            "control_pls_disabled": theft_rows.get("control_counterfactual", 1.0),
        },
        "csi_comparison": csi_modes,
        "zkp_innovation": zkp_cmp,
        "security_rubric": rubric,
    }
