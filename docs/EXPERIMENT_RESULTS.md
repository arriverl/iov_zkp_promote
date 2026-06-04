# 实验结果说明（与 `results/` CSV 同步）

**配置：** `configs/balanced.json`  
**复现：** `python scripts/run_all.py balanced`  
**更新：** 2026-06（含 PQC 摘要签名、RSU 短路验证、PLS 异地剖面等优化）

---

## 1. 配置参数摘要

```json
{
  "rounds": 30,
  "pqc_level": 2,
  "zkp_challenge_bytes": 16,
  "pqc_sign_digest": true,
  "zkp_witness_digest": true,
  "pls": {
    "csi_dim": 32,
    "threshold": 0.88,
    "noise_std": 0.06,
    "use_float32": true,
    "num_multipath": 4,
    "rel_dist_max": 0.42
  }
}
```

---

## 2. Group 1 — 主对比

| 协议 | RSU 均值 (ms) | RSU 中位 (ms) | 端到端均值 (ms) | 通信 (B) |
|------|---------------|---------------|-----------------|----------|
| baseline_yang | 0.55 | 0.55 | — | 256 |
| improved_ecdh_aes | 3.00 | 3.01 | — | 512 |
| innovation_zkp_pqc_pls | **5.19** | **5.01** | **36.17**（中位 25.81） | **4014** |

**创新方案字节分解：** message + pk(1312) + sig(2420) + zkp(80) + csi(128)。

**解读：**

- RSU **~5 ms**，远低于 IoV 常见 **50 ms** 实时阈值。  
- 端到端 **~26–36 ms**，瓶颈在 OBU 每次 `sign` + `prove` + CSI。  
- 通信较早期 4414 B 略降（float32 CSI + 16B ZKP challenge）。

---

## 3. Group 2 — 消融（良性）

| variant | auth_success_rate | 说明 |
|---------|-------------------|------|
| full | 0.90 | ZKP + PQC + PLS + 会话帧 |
| no_zkp | 0.97 | 关闭 ZKP 验证 |
| no_pls | 1.0 | 跳过 PLS |
| no_session_binding | 1.0 | 固定 message，无 IoVAuthFrame |
| pqc_only | 1.0 | 仅 PQC |

**注意：** 消融在**正常噪声仿真**下统计通过率，不等同于 Rubric 安全分。模块安全贡献请对照 Group 3 与 `security_rubric.py`（baseline ~35，improved ~75，innovation ~95）。

---

## 4. Group 3 — 攻击仿真

| attack | success_rate | notes（辅助） |
|--------|--------------|---------------|
| replay | **0.0** | 首包 baseline |
| certificate_theft_impersonation | **0.0** | 异地 CSI |
| remote_relay | **0.0** | 平均 ρ≈0.43 |
| message_tampering_mitm | **0.0** | — |

---

## 5. Group 4 — 参数敏感性（节选）

| pqc_level | csi_dim | threshold | RSU 延迟 (ms) | 通信 (B) | 成功率 |
|-----------|---------|-----------|---------------|----------|--------|
| 2 | 32 | 0.88 | ~8.2 | 4025 | 1.0 |
| 2 | 32 | 0.90 | ~8.5 | 4025 | 1.0 |
| 3 | 32 | 0.88 | ~13.0 | 5538 | 1.0 |
| 2 | 64 | 0.88 | ~9.0 | 4153 | 1.0 |

**结论：** level3 延迟与体积上升明显；默认 balanced 使用 level2 + 32 维 CSI。

---

## 6. Group 5 — 可扩展性

| vehicles | 吞吐 (auth/s) | 单车平均延迟 (ms) | 批次成功率 |
|----------|---------------|-------------------|------------|
| 50 | ~24.0 | ~41.6 | ~0.93 |
| 100 | ~20.5 | ~48.7 | ~0.93 |
| 200 | ~21.5 | ~46.5 | ~0.94 |

**说明：** 批量实验为单进程串行模拟多车，延迟含完整 OBU+RSU，高于 Group1 的 RSU-only 指标。

---

## 7. 指标定义

| 字段 | 含义 |
|------|------|
| `latency_ms_mean` | RSU `rsu_verify` 平均耗时 |
| `e2e_latency_ms_mean` | `obu_build_request` + `rsu_verify` |
| `comm_bytes_*` | 单次认证请求载荷分项 |

---

## 8. 复现与出图

```bash
python scripts/run_all.py balanced
python scripts/plot_results.py
```

图表输出：`results/plots/*.png`
