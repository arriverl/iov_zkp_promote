# -*- coding: utf-8 -*-
"""生成论文用精美图表 → docs/paper/figures/"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
OUT = ROOT / "docs" / "paper" / "figures"
OUT.mkdir(parents=True, exist_ok=True)

# 论文配色（低饱和、印刷友好）
C = {
    "pqc": "#2E6F9E",
    "zkp": "#3A8F7B",
    "pls": "#C47A2D",
    "session": "#6B5B95",
    "base": "#8E9AAF",
    "improved": "#5C7AEA",
    "innov": "#D64550",
    "grid": "#E8ECF1",
    "text": "#2D3142",
}


def _fonts():
    plt.rcParams.update({
        "font.sans-serif": ["Microsoft YaHei", "SimHei", "DejaVu Sans"],
        "axes.unicode_minus": False,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": C["grid"],
        "axes.labelcolor": C["text"],
        "text.color": C["text"],
        "font.size": 10,
    })


def _read_csv(name: str) -> list[dict]:
    p = RESULTS / name
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def fig1_system_architecture() -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")
    ax.set_title("图1  ZKP-PQC-PLS 融合认证系统总体架构", fontsize=13, fontweight="bold", pad=16)

    def box(x, y, w, h, title, lines, color):
        rect = FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
            linewidth=1.2, edgecolor=color, facecolor=(*plt.matplotlib.colors.to_rgb(color), 0.12),
        )
        ax.add_patch(rect)
        ax.text(x + w / 2, y + h - 0.35, title, ha="center", va="top", fontsize=11, fontweight="bold", color=color)
        ax.text(x + 0.15, y + h - 0.75, "\n".join(lines), ha="left", va="top", fontsize=8.5, linespacing=1.35)

    box(0.5, 4.8, 2.7, 1.6, "OBU 车载单元", ["PQC 密钥对", "ZKP 证明生成", "CSI 指纹提取"], C["pqc"])
    box(3.6, 4.8, 2.7, 1.6, "无线信道", ["Rayleigh 多径仿真", "上报/测量 CSI", "V2X 报文传输"], C["pls"])
    box(6.7, 4.8, 2.8, 1.6, "RSU 路侧单元", ["Replay Guard", "ZKP→PLS→PQC", "认证决策"], C["session"])

    box(0.8, 2.5, 2.5, 1.5, "PQC 层", ["CRYSTALS-Dilithium2", "ML-DSA / FIPS 204", "摘要签名优化"], C["pqc"])
    box(3.75, 2.5, 2.5, 1.5, "ZKP 层", ["Sigma + Fiat–Shamir", "非交互证明", "最小披露骨架"], C["zkp"])
    box(6.7, 2.5, 2.5, 1.5, "PLS 层", ["CSI 会话绑定", "ρ + rel_dist", "异地剖面拒识"], C["pls"])

    box(2.2, 0.4, 5.6, 1.5, "会话绑定层 IoVAuthFrame", [
        "rsu_id | timestamp | nonce | policy_flags",
        "canonical_bytes() 绑定签名与 ZKP",
        "epoch_id = timestamp // 5000ms",
    ], C["session"])

    for x1, x2, y in [(1.85, 3.6, 5.6), (6.3, 8.1, 5.6), (2.05, 5.0, 4.0), (5.0, 7.95, 4.0)]:
        ax.annotate("", xy=(x2, y), xytext=(x1, y), arrowprops=dict(arrowstyle="-|>", color="#666", lw=1.2))

    fig.tight_layout()
    fig.savefig(OUT / "fig1_system_architecture.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig2_protocol_flow() -> None:
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 10)
    ax.axis("off")
    ax.set_title("图2  融合认证协议交互流程", fontsize=13, fontweight="bold", pad=14)

    ax.plot([2.5, 2.5], [0.5, 9.5], "--", color=C["pqc"], lw=1.5)
    ax.plot([8.5, 8.5], [0.5, 9.5], "--", color=C["session"], lw=1.5)
    ax.text(2.5, 9.7, "OBU", ha="center", fontweight="bold", color=C["pqc"])
    ax.text(8.5, 9.7, "RSU", ha="center", fontweight="bold", color=C["session"])

    steps = [
        (9.2, "(1) KeyGen(pk, sk)", "left"),
        (8.6, "(2) IoVAuthFrame.fresh()", "left"),
        (8.0, "(3) ZKP.prove(sk_hash, pk, msg)", "left"),
        (7.4, "(4) PQC.sign(H(msg), sk)", "left"),
        (6.8, "(5) CSI = session(msg)", "left"),
        (6.2, "(6) AuthRequest ->", "left"),
        (5.6, "<- (6) 接收请求", "right"),
        (5.0, "(7) Replay Guard", "right"),
        (4.4, "(8) ZKP verify", "right"),
        (3.8, "(9) PLS(rho, rel_dist)", "right"),
        (3.2, "(10) PQC verify", "right"),
        (2.6, "(11) Auth PASS / FAIL", "right"),
    ]
    for y, txt, side in steps:
        x = 2.5 if side == "left" else 8.5
        ha = "left" if side == "left" else "right"
        offset = 0.15 if side == "left" else -0.15
        ax.text(x + offset, y, txt, ha=ha, va="center", fontsize=9,
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec=C["grid"], lw=0.8))

    ax.annotate("", xy=(8.2, 6.2), xytext=(2.8, 6.2),
                arrowprops=dict(arrowstyle="-|>", color=C["innov"], lw=2))
    ax.text(5.5, 6.45, "认证请求", ha="center", fontsize=8, color=C["innov"])

    fig.tight_layout()
    fig.savefig(OUT / "fig2_protocol_flow.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig3_threat_model() -> None:
    threats = ["量子破解\n(RSA/ECC)", "身份追踪", "证书窃取\n+异地冒充", "重放攻击", "消息篡改"]
    mitigations = ["PQC\nDilithium2", "ZKP\nSigma+FS", "PLS\nCSI 指纹", "IoVAuthFrame\nReplay Guard", "PQC\n验签"]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    y = np.arange(len(threats))
    ax.barh(y - 0.2, [1] * 5, height=0.35, color=C["innov"], alpha=0.85, label="威胁")
    ax.barh(y + 0.2, [1] * 5, height=0.35, color=C["zkp"], alpha=0.85, label="缓解模块")
    for i, (t, m) in enumerate(zip(threats, mitigations)):
        ax.text(0.02, i - 0.2, t, va="center", fontsize=9, color="white", fontweight="bold")
        ax.text(0.02, i + 0.2, m, va="center", fontsize=9, color="white", fontweight="bold")
    ax.set_yticks([])
    ax.set_xticks([])
    ax.set_xlim(0, 1)
    ax.legend(loc="upper right")
    ax.set_title("图3  威胁模型与分层缓解映射", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(OUT / "fig3_threat_model.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig4_main_comparison() -> None:
    rows = _read_csv("group1_main_comparison.csv")
    if not rows:
        return
    labels = ["基线\n(Yang)", "改进\n(ECDH+AES)", "创新方案\n(ZKP-PQC-PLS)"]
    lat = [float(r.get("latency_ms_mean") or 0) for r in rows]
    comm = [float(r.get("comm_bytes_total") or 0) for r in rows]
    e2e = [float(r.get("e2e_latency_ms_mean") or 0) for r in rows]
    colors = [C["base"], C["improved"], C["innov"]]

    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    for ax, data, title, ylab in zip(
        axes,
        [lat, e2e, comm],
        ["RSU 验证延迟", "端到端延迟", "通信开销"],
        ["延迟 (ms)", "延迟 (ms)", "字节 (B)"],
    ):
        bars = ax.bar(labels, data, color=colors, edgecolor="white", linewidth=0.8)
        ax.set_title(title, fontweight="bold")
        ax.set_ylabel(ylab)
        ax.axhline(50, color=C["innov"], ls="--", lw=1, alpha=0.6, label="50ms 阈值" if "RSU" in title else None)
        for b, v in zip(bars, data):
            if v > 0:
                ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.1f}", ha="center", va="bottom", fontsize=9)
        if "RSU" in title:
            ax.legend(fontsize=8)
        ax.grid(axis="y", alpha=0.3)
    fig.suptitle("图4  三类协议性能对比（balanced 配置）", fontsize=13, fontweight="bold", y=1.02)
    fig.tight_layout()
    fig.savefig(OUT / "fig4_main_comparison.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig5_comm_breakdown() -> None:
    m = json.loads((ROOT / "docs" / "PPT_METRICS.json").read_text(encoding="utf-8"))
    bd = m["main_comparison"]["comm_breakdown"]
    labels = ["公钥 pk", "签名 sig", "ZKP", "CSI"]
    sizes = [bd["pk"], bd["sig"], bd["zkp"], bd["csi"]]
    colors = [C["pqc"], C["pqc"], C["zkp"], C["pls"]]

    fig, ax = plt.subplots(figsize=(7, 5))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.1f%%",
        startangle=90, pctdistance=0.75, wedgeprops=dict(width=0.45, edgecolor="white"),
    )
    ax.text(0, 0, f"总计\n{sum(sizes)} B", ha="center", va="center", fontsize=12, fontweight="bold")
    ax.set_title("图5  创新方案通信开销构成（4014 B）", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(OUT / "fig5_comm_breakdown.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig6_security_radar() -> None:
    dims = ["后量子\n抗性", "ZKP\n隐私", "物理层\n防伪", "会话\n绑定", "完整性\n校验"]
    baseline = [0, 20, 0, 33, 53]
    improved = [0, 48, 0, 100, 80]
    innov = [100, 100, 100, 100, 100]
    angles = np.linspace(0, 2 * np.pi, len(dims), endpoint=False).tolist()
    angles += angles[:1]

    def _close(vals: list) -> list:
        return vals + [vals[0]]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    ax.plot(angles, _close(baseline), "o-", color=C["base"], label="基线 (~35)")
    ax.fill(angles, _close(baseline), alpha=0.15, color=C["base"])
    ax.plot(angles, _close(improved), "o-", color=C["improved"], label="改进 (~75)")
    ax.fill(angles, _close(improved), alpha=0.15, color=C["improved"])
    ax.plot(angles, _close(innov), "o-", color=C["innov"], label="创新 (~95)")
    ax.fill(angles, _close(innov), alpha=0.12, color=C["innov"])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(dims, fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_title("图6  可解释安全评分雷达图（SecurityRubric）", fontsize=12, fontweight="bold", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1), fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "fig6_security_radar.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig7_attacks() -> None:
    rows = _read_csv("group3_attacks.csv")
    if not rows:
        return
    names = ["重放", "盗证冒充", "远程中继", "消息篡改"]
    key_map = {
        "replay": 0, "certificate_theft_impersonation": 1,
        "remote_relay": 2, "message_tampering_mitm": 3,
    }
    vals = [0.0] * 4
    for r in rows:
        vals[key_map[r["attack"]]] = float(r["success_rate"]) * 100

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(names, vals, color=[C["innov"] if v > 0 else C["zkp"] for v in vals], edgecolor="white")
    ax.set_ylim(0, max(5, max(vals) + 2))
    ax.set_ylabel("攻击成功率 (%)")
    ax.set_title("图7  攻击仿真结果（越低越好）", fontsize=13, fontweight="bold")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.1, f"{v:.0f}%", ha="center", fontsize=10, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / "fig7_attacks.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig8_pls_theft_ablation() -> None:
    rows = _read_csv("group_pls_theft_ablation.csv")
    if not rows:
        return
    labels = ["有 PLS\n(完整方案)", "无 PLS\n(仅ZKP+PQC)"]
    vals = [float(r["auth_success_rate"]) * 100 for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    bars = ax.bar(labels, vals, color=[C["zkp"], C["innov"]], edgecolor="white")
    ax.set_ylim(0, 110)
    ax.set_ylabel("盗证场景认证通过率 (%)")
    ax.set_title("图8  证书窃取场景 PLS 消融对比", fontsize=13, fontweight="bold")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / "fig8_pls_theft_ablation.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig9_sensitivity() -> None:
    rows = _read_csv("group4_sensitivity.csv")
    if not rows:
        return
    l2 = [r for r in rows if r["pqc_level"] == "2" and r["threshold"] == "0.88"]
    dims = sorted({int(r["csi_dim"]) for r in l2})
    lat = [float(next(r for r in l2 if int(r["csi_dim"]) == d)["latency_ms_mean"]) for d in dims]
    comm = [float(next(r for r in l2 if int(r["csi_dim"]) == d)["comm_bytes_mean"]) for d in dims]

    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    ax2 = ax1.twinx()
    ax1.plot(dims, lat, "o-", color=C["pqc"], lw=2, markersize=8, label="RSU 延迟 (ms)")
    ax2.bar([d + 0.15 for d in dims], comm, width=0.3, color=C["pls"], alpha=0.7, label="通信 (B)")
    ax1.set_xlabel("CSI 维度")
    ax1.set_ylabel("延迟 (ms)", color=C["pqc"])
    ax2.set_ylabel("通信 (B)", color=C["pls"])
    ax1.set_title("图9  参数敏感性（Dilithium2, γ=0.88）", fontsize=13, fontweight="bold")
    lines1, lab1 = ax1.get_legend_handles_labels()
    lines2, lab2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, lab1 + lab2, loc="upper left")
    ax1.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / "fig9_sensitivity.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig10_literature_compare() -> None:
    schemes = ["Yang\n2023", "PQ-TDAA\n2026", "Hermes'\nSeal", "本方案"]
    pq = [0, 1, 0.5, 1]
    zkp = [0.3, 0.9, 1.0, 0.6]
    pls = [0, 0, 0, 1]
    x = np.arange(len(schemes))
    w = 0.25
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w, pq, w, label="抗量子", color=C["pqc"])
    ax.bar(x, zkp, w, label="ZKP/隐私", color=C["zkp"])
    ax.bar(x + w, pls, w, label="物理层第二因子", color=C["pls"])
    ax.set_xticks(x)
    ax.set_xticklabels(schemes)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("能力覆盖度（归一化示意）")
    ax.set_title("图10  与代表性文献方案能力对比（示意）", fontsize=13, fontweight="bold")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / "fig10_literature_compare.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    _fonts()
    fig1_system_architecture()
    fig2_protocol_flow()
    fig3_threat_model()
    fig4_main_comparison()
    fig5_comm_breakdown()
    fig6_security_radar()
    fig7_attacks()
    fig8_pls_theft_ablation()
    fig9_sensitivity()
    fig10_literature_compare()
    print(f"论文图表已输出: {OUT}")


if __name__ == "__main__":
    main()
