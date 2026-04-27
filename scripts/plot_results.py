# -*- coding: utf-8 -*-
from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib import rcParams

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
PLOTS = ROOT / "results" / "plots"
PLOTS.mkdir(parents=True, exist_ok=True)


def _configure_fonts() -> None:
    """
    配置中文字体，避免 Windows 下中文标题/坐标轴乱码。
    """
    # 按优先级给出常见可用中文字体
    rcParams["font.sans-serif"] = [
        "Microsoft YaHei",
        "SimHei",
        "Noto Sans CJK SC",
        "Source Han Sans SC",
        "Arial Unicode MS",
        "DejaVu Sans",
    ]
    # 负号显示修复
    rcParams["axes.unicode_minus"] = False


def _read_csv(path: Path):
    with path.open("r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def plot_main_comparison() -> None:
    rows = _read_csv(RESULTS / "group1_main_comparison.csv")
    names = [r["protocol"] for r in rows]
    lat = [float(r.get("latency_ms_mean", 0) or 0) for r in rows]
    comm = [float(r.get("comm_bytes_total", 0) or 0) for r in rows]

    fig, ax = plt.subplots(1, 2, figsize=(10, 4))
    ax[0].bar(names, lat)
    ax[0].set_title("认证延迟均值 (ms)")
    ax[0].tick_params(axis="x", rotation=20)
    ax[1].bar(names, comm)
    ax[1].set_title("通信开销 (Bytes)")
    ax[1].tick_params(axis="x", rotation=20)
    fig.tight_layout()
    fig.savefig(PLOTS / "group1_main_comparison.png", dpi=150)
    plt.close(fig)


def plot_ablation() -> None:
    rows = _read_csv(RESULTS / "group2_ablation.csv")
    names = [r["variant"] for r in rows]
    succ = [float(r["auth_success_rate"]) for r in rows]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(names, succ)
    ax.set_ylim(0, 1.05)
    ax.set_title("消融：认证成功率")
    ax.tick_params(axis="x", rotation=20)
    fig.tight_layout()
    fig.savefig(PLOTS / "group2_ablation.png", dpi=150)
    plt.close(fig)


def plot_attacks() -> None:
    rows = _read_csv(RESULTS / "group3_attacks.csv")
    names = [r["attack"] for r in rows]
    succ = [float(r["success_rate"]) for r in rows]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, succ)
    ax.set_ylim(0, 1.05)
    ax.set_title("攻击成功率（越低越好）")
    ax.tick_params(axis="x", rotation=20)
    fig.tight_layout()
    fig.savefig(PLOTS / "group3_attacks.png", dpi=150)
    plt.close(fig)


def plot_scalability() -> None:
    rows = _read_csv(RESULTS / "group5_scalability.csv")
    vehicles = [int(float(r["vehicles"])) for r in rows]
    throughput = [float(r["throughput_auth_per_s"]) for r in rows]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(vehicles, throughput, marker="o")
    ax.set_title("规模实验：吞吐量")
    ax.set_xlabel("车辆数")
    ax.set_ylabel("认证吞吐 (auth/s)")
    fig.tight_layout()
    fig.savefig(PLOTS / "group5_scalability.png", dpi=150)
    plt.close(fig)


def main() -> None:
    _configure_fonts()
    plot_main_comparison()
    plot_ablation()
    plot_attacks()
    plot_scalability()
    print(f"图表已输出到: {PLOTS}")


if __name__ == "__main__":
    main()

