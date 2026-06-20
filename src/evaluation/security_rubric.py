# -*- coding: utf-8 -*-
"""
可解释的安全评分模型（研究/对比用，非国际标准等级）。

维度与默认权重见 docs/PROJECT.md 第五节 SecurityRubric。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class SecurityRubric:
    """各维度满分与权重（权重之和应为 1.0）。"""

    max_scores: Dict[str, float] = field(
        default_factory=lambda: {
            "post_quantum": 25.0,
            "privacy_zkp": 25.0,
            "physical_layer": 20.0,
            "freshness_binding": 15.0,
            "integrity_non_repudiation": 15.0,
        }
    )
    weights: Dict[str, float] = field(
        default_factory=lambda: {
            "post_quantum": 0.25,
            "privacy_zkp": 0.25,
            "physical_layer": 0.20,
            "freshness_binding": 0.15,
            "integrity_non_repudiation": 0.15,
        }
    )

    def normalized_total(self, raw: Dict[str, float]) -> float:
        """raw[d] 为维度 d 上的得分（0..max_scores[d]），返回 0..100。"""
        total = 0.0
        for d, w in self.weights.items():
            cap = self.max_scores[d]
            x = max(0.0, min(cap, raw.get(d, 0.0)))
            total += w * (x / cap) * 100.0
        return round(total, 2)


def score_protocol(
    *,
    has_pqc: bool,
    has_zkp_layer: bool,
    has_pls: bool,
    has_session_frame: bool,
    has_digital_signature: bool,
    baseline_xor_only: bool = False,
) -> Tuple[float, Dict[str, float]]:
    """
    为三类协议制表用的典型打分（可据论文调整）。

    - baseline_xor_only: 若为 True，隐私与完整性按“弱 XOR”给低分。
    """
    rubric = SecurityRubric()
    raw: Dict[str, float] = {}

    raw["post_quantum"] = rubric.max_scores["post_quantum"] if has_pqc else 0.0

    if baseline_xor_only:
        raw["privacy_zkp"] = 5.0
        raw["integrity_non_repudiation"] = 8.0
    elif has_zkp_layer:
        raw["privacy_zkp"] = rubric.max_scores["privacy_zkp"]
        raw["integrity_non_repudiation"] = (
            rubric.max_scores["integrity_non_repudiation"] if has_digital_signature else 10.0
        )
    else:
        raw["privacy_zkp"] = 12.0
        raw["integrity_non_repudiation"] = 12.0 if has_digital_signature else 6.0

    raw["physical_layer"] = rubric.max_scores["physical_layer"] if has_pls else 0.0
    raw["freshness_binding"] = rubric.max_scores["freshness_binding"] if has_session_frame else 5.0

    total = rubric.normalized_total(raw)
    return total, raw


def explain_score(raw: Dict[str, float]) -> List[str]:
    rubric = SecurityRubric()
    lines = []
    for d, x in raw.items():
        cap = rubric.max_scores.get(d, 0)
        lines.append(f"  {d}: {x:.1f} / {cap:.1f}")
    return lines


# 与报告表格一致的预设（便于 benchmark 打印）
def preset_baseline_yang() -> Tuple[float, Dict[str, float]]:
    return score_protocol(
        has_pqc=False,
        has_zkp_layer=False,
        has_pls=False,
        has_session_frame=False,
        has_digital_signature=True,
        baseline_xor_only=True,
    )


def preset_improved_ecdh_aes() -> Tuple[float, Dict[str, float]]:
    return score_protocol(
        has_pqc=False,
        has_zkp_layer=False,
        has_pls=False,
        has_session_frame=True,
        has_digital_signature=True,
        baseline_xor_only=False,
    )


def preset_innovation_zkp_pqc_pls() -> Tuple[float, Dict[str, float]]:
    return score_protocol(
        has_pqc=True,
        has_zkp_layer=True,
        has_pls=True,
        has_session_frame=True,
        has_digital_signature=True,
        baseline_xor_only=False,
    )
