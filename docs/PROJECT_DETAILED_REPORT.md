# ZKP-PQC-PLS 项目详细技术报告

**更新：** 2026-06 · 实验配置 `balanced` · 数据见 `docs/EXPERIMENT_RESULTS.md`

---

## 1. 项目概述

面向 IoV/V2X 的多因子认证系统：**PQC 抗量子签名** + **ZKP 最小披露证明骨架** + **PLS 信道指纹第二因子** + **IoVAuthFrame 会话绑定**。

具备五组可复现实验：主对比、消融、攻击、灵敏度、规模。

---

## 2. 算法与实现

### 2.1 PQC（`src/pqc/lattice_signing.py`）

- Dilithium2/3/5，默认 level 2。  
- 融合协议中对 `canonical_bytes()` 先做 `SHA256(PQC-Bind|v1| || frame)` 再签名/验签（`pqc_sign_digest`），降低对长消息的签名延迟。

### 2.2 ZKP（`src/zkp/sigma_proof.py`）

- Commit → Fiat–Shamir challenge → Response。  
- 默认 `challenge_bytes=16`；witness 可为 `SHA256(sk)`（`zkp_witness_digest`）。  
- **非** Groth16/PLONK；用于演示“持有私钥不泄露 sk”流程。

### 2.3 PLS（`src/pls/csi_fingerprint.py`）

- Rayleigh 多径仿真；`extract_session_csi(message)` 绑定会话。  
- `extract_remote_csi(message)`：异地多径剖面，防盗证。  
- 认证：皮尔逊 ρ ≥ γ 且归一化距离 ≤ `rel_dist_max`（balanced 默认 0.42）。  
- CSI 默认 **float32**，可配置 `csi_dim`、`num_multipath`。

### 2.4 融合协议（`src/protocol/fusion_protocol.py`）

**OBU：** KeyGen → ZKP prove → PQC sign(digest) → CSI → 请求包（含 `pqc_payload` 缓存字段）。

**RSU：**

1. Replay Guard（`SHA256(message)` 指纹，周期清理）  
2. ZKP verify — 失败则返回  
3. PLS（合法：上报 CSI + 噪声）— 失败则返回  
4. PQC verify(digest)

### 2.5 配置驱动（`src/config.py`）

`protocol_from_config(load_profile("balanced"))` 统一注入 PQC/ZKP/PLS/重放参数；`scripts/run_all.py` 全实验链使用同一配置。

---

## 3. 实验体系

| 脚本/目录 | 作用 |
|-----------|------|
| `scripts/run_all.py` | 导出五组 CSV |
| `scripts/plot_results.py` | `results/plots/*.png` |
| `benchmarks/run_benchmarks.py` | Group1 主对比（输出 RSU + e2e） |
| `src/attacks/simulations.py` | Group3 |
| `src/ablation/study.py` | Group2 |

---

## 4. 实验结果（balanced，当前 `results/`）

### 4.1 主对比

| 协议 | RSU (ms) | 端到端 (ms) | 通信 (B) |
|------|----------|-------------|----------|
| baseline_yang | 0.55 | — | 256 |
| improved_ecdh_aes | 3.0 | — | 512 |
| innovation | **5.2** | **36.2** | **4014** |

### 4.2 攻击（成功率均为 0）

- replay、certificate_theft、remote_relay、message_tampering  

盗证场景 RSU 使用 `extract_remote_csi()`；中继平均 ρ≈0.43 < γ。

### 4.3 消融（良性）

- full **90%**；no_pls **100%** — PLS 为正常链路主要失败来源（阈值/距离判据），攻击场景证明其必要性。

### 4.4 灵敏度

- level2 + csi32：RSU ~8 ms，通信 ~4025 B，成功率多为 100%  
- level3：延迟 ~12–14 ms，通信 ~5538 B  

### 4.5 规模

- 50–200 车：吞吐 ~20–24 auth/s；批次成功率 ~93–94%  

---

## 5. 安全评分（Rubric）

`src/evaluation/security_rubric.py` 五维加权（各 25/25/20/15/15）：

- baseline_yang ≈ **35**  
- improved_ecdh_aes ≈ **75**  
- innovation ≈ **95**  

用于论文/答辩**横向对比**，非渗透测试等级。

---

## 6. 相对基线的改进点

1. 抗量子：Dilithium/ML-DSA 路线  
2. 隐私：ZKP 层（Sigma 骨架）  
3. 物理防伪：PLS + 异地剖面  
4. 新鲜度：IoVAuthFrame + Replay Guard  
5. 可复现：配置化五组实验 + 文档/图表  

---

## 7. 局限与后续

| 局限 | 后续 |
|------|------|
| dilithium-py 较慢 | liboqs / 硬件加速 |
| 端到端 ~30ms 级 | 会话票据、仅首包全量签名 |
| PLS 仿真 | 802.11p / 5G CSI 实测 |
| ZKP 非 SNARK | 电路化证明、对齐 Hermes' Seal |
| 消融良性 <100% | 调 γ / rel_dist 或多样本 CSI 投票 |

---

## 8. 相关文档

- `README.md` — 快速上手  
- `docs/EXPERIMENT_RESULTS.md` — 数据表  
- `docs/LITERATURE_AND_INNOVATION.md` — 文献  
- `docs/PPT_REVISION_ANALYSIS.md` — PPT 改稿  
