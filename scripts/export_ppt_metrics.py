# -*- coding: utf-8 -*-
"""从 results/*.csv 导出指标 JSON（供演示大屏与插图脚本使用）。"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
DOCS = ROOT / "docs"


def _read(name: str) -> list[dict]:
    path = RESULTS / name
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


def build_metrics() -> dict:
    g1 = {r["protocol"]: r for r in _read("group1_main_comparison.csv")}
    g3 = _read("group3_attacks.csv")
    g2 = _read("group2_ablation.csv")
    g_pls = _read("group_pls_theft_ablation.csv")
    inn = g1.get("innovation_zkp_pqc_pls", {})

    attacks = {r["attack"]: {"success_rate": _f(r, "success_rate"), "notes": r.get("notes", "")} for r in g3}
    ablation = {r["variant"]: _f(r, "auth_success_rate") for r in g2}
    pls_primary = next((r for r in g_pls if r.get("experiment_role") == "primary"), {})
    pls_control = next((r for r in g_pls if r.get("experiment_role") == "control_counterfactual"), {})

    return {
        "profile_hint": "运行 python scripts/run_all.py balanced 后导出",
        "main_comparison": {
            "baseline_yang_ms": round(_f(g1.get("baseline_yang", {}), "latency_ms_mean"), 2),
            "improved_ecdh_aes_ms": round(_f(g1.get("improved_ecdh_aes", {}), "latency_ms_mean"), 2),
            "innovation_rsu_ms_mean": round(_f(inn, "latency_ms_mean"), 2),
            "innovation_rsu_ms_median": round(_f(inn, "latency_ms_median"), 2),
            "innovation_e2e_ms_mean": round(_f(inn, "e2e_latency_ms_mean"), 2),
            "innovation_e2e_ms_median": round(_f(inn, "e2e_latency_ms_median"), 2),
            "innovation_comm_bytes": int(_f(inn, "comm_bytes_total")),
            "comm_breakdown": {
                "pk": int(_f(inn, "comm_bytes_pk")),
                "sig": int(_f(inn, "comm_bytes_sig")),
                "zkp": int(_f(inn, "comm_bytes_zkp")),
                "csi": int(_f(inn, "comm_bytes_csi")),
            },
        },
        "attacks": attacks,
        "ablation_benign": ablation,
        "theft_ablation": {
            "primary_pls_enabled_rate": _f(pls_primary, "auth_success_rate"),
            "control_pls_disabled_rate": _f(pls_control, "auth_success_rate"),
        },
        "security_rubric": {"baseline": 35, "improved": 75, "innovation": 95},
        "ppt_bullets": {
            "slide13_rsu": f"RSU 验证延迟约 {round(_f(inn, 'latency_ms_mean'), 1)} ms（中位 {round(_f(inn, 'latency_ms_median'), 1)} ms）",
            "slide13_e2e": f"端到端约 {round(_f(inn, 'e2e_latency_ms_median'), 1)}–{round(_f(inn, 'e2e_latency_ms_mean'), 1)} ms（含 OBU 签名）",
            "slide13_comm": f"通信约 {int(_f(inn, 'comm_bytes_total'))} B（pk+sig+zkp+csi）",
            "slide11_theft": (
                f"盗证主实验（PLS开启）成功率 {_f(pls_primary, 'auth_success_rate') * 100:.0f}%"
                f"（Group3 同类攻击 {_f(attacks.get('certificate_theft_impersonation', {}), 'success_rate') * 100:.0f}%）"
            ),
            "slide11_theft_control": (
                f"盗证对照组（PLS关闭，counterfactual）成功率 "
                f"{_f(pls_control, 'auth_success_rate') * 100:.0f}% — 答辩前先说明对照设计"
            ),
        },
    }


def write_outputs() -> None:
    metrics = build_metrics()
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "PPT_METRICS.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Wrote {DOCS / 'PPT_METRICS.json'}")


if __name__ == "__main__":
    write_outputs()
