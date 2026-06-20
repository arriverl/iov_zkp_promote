# -*- coding: utf-8 -*-
"""
一键复现「诚实边界」四条表述，供答辩现场演示。

用法:
    python scripts/reproduce_honest_boundaries.py
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.run_benchmarks import (
    benchmark_baseline_yang,
    benchmark_improved_ecdh_aes,
    benchmark_fusion_protocol,
)
from src.attacks.pls_ablation import run_pls_theft_ablation
from src.attacks.simulations import run_attack_suite
from src.config import load_profile, protocol_from_config


def _section(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def main() -> None:
    cfg = load_profile("balanced")
    proto = protocol_from_config(cfg)

    # 1) 基线：密码学复现（非 sleep）
    _section("边界 1：Yang / ECDH 为本机密码学原语复现（非 NS-3）")
    from benchmarks import run_benchmarks as rb

    yang_src = inspect.getsource(rb.benchmark_baseline_yang)
    ecdh_src = inspect.getsource(rb.benchmark_improved_ecdh_aes)
    print("代码位置: src/baselines/yang2023.py, src/baselines/ecdh_aes_pseudonym.py")
    print("  Yang:  time.sleep 占位 →", "time.sleep" in yang_src)
    print("  ECDH:  time.sleep 占位 →", "time.sleep" in ecdh_src)
    y = benchmark_baseline_yang(cfg)
    e = benchmark_improved_ecdh_aes(cfg)
    n = benchmark_fusion_protocol(cfg)
    print(f"  本机 Yang  延迟: {y['latency_ms_mean']:.3f} ms  通信: {y['comm_bytes_total']} B (crypto 实测)")
    print(f"  本机 ECDH 延迟: {e['latency_ms_mean']:.3f} ms  通信: {e['comm_bytes_total']} B (crypto 实测)")
    print(f"  本方案     延迟: {n['latency_ms_mean']:.3f} ms  通信: {n['comm_bytes_total']} B (真实 Dilithium+协议)")

    # 2) 攻击脚本
    _section("边界 2：攻击 0% 来自自建威胁脚本（非第三方渗透）")
    print("代码位置: src/attacks/simulations.py → run_attack_suite()")
    print("输出文件: results/group3_attacks.csv")
    atk = run_attack_suite(rounds=10, protocol=proto)
    for row in atk:
        print(f"  {row['attack']:35s} success_rate={row['success_rate']:.0%}")

    # 3) 盗证消融：主实验启用 PLS；对照组显式关闭并写入 CSV 元数据
    _section("边界 3：盗证 — 主实验启用物理层校验；对照组事先标注")
    print("代码位置: src/attacks/pls_ablation.py")
    print("  主实验: rsu_verify(..., pls_enabled=True)  + 异地 CSI")
    print("  对照组: rsu_verify(..., pls_enabled=False) + 异地 CSI (control_counterfactual)")
    print("输出文件: results/group_pls_theft_ablation.csv（含 pls_verification / experiment_role）")
    abl = run_pls_theft_ablation(rounds=10, protocol=proto)
    for row in abl:
        role = row.get("experiment_role", "")
        pls = row.get("pls_verification", "")
        print(
            f"  {row['scenario']:40s} role={role:25s} pls={pls:8s} "
            f"rate={row['auth_success_rate']:.0%}"
        )

    # 4) ZKP 原型
    _section("边界 4：ZKP 为格 Σ 协议原型（非 Groth16/SNARK）")
    print(f"  当前配置 zkp_mode: {cfg.get('zkp_mode')}")
    print(f"  实际 Prover 类: {type(proto.zkp_prover).__name__}")
    print(f"  实现文件: src/zkp/sis_lattice_nizk.py")
    print(f"  对照骨架: src/zkp/sigma_proof.py (zkp_mode=sigma)")
    has_snark = any(ROOT.glob("src/zkp/*snark*")) or (ROOT / "src/zkp/groth16.py").exists()
    print(f"  仓库内 Groth16/SNARK 实现: {'有' if has_snark else '无'}")

    _section("完成 — 以上四条均可由本脚本与 run_all.py 直接复现")
    print("完整实验: python scripts/run_all.py balanced")


if __name__ == "__main__":
    main()
