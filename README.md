# ZKP-PQC-PLS 融合架构：创新型 IoV 安全认证

面向车联网（IoV/V2X）身份认证的 **后量子密码（PQC）+ 零知识证明（ZKP）+ 物理层安全（PLS）** 融合原型，含五组可复现实验、攻击仿真与文档体系。

---

## 核心能力

| 模块 | 实现 | 作用 |
|------|------|------|
| **PQC** | CRYSTALS-Dilithium2 / ML-DSA（`dilithium-py`） | 抗量子签名与完整性 |
| **ZKP** | Sigma + Fiat–Shamir（`src/zkp/sigma_proof.py`） | 最小披露式“持有私钥”证明骨架 |
| **PLS** | Rayleigh 仿真 CSI + 皮尔逊相关 + 归一化距离（`src/pls/csi_fingerprint.py`） | 防异地盗证/远程冒充第二因子 |
| **会话** | `IoVAuthFrame` + Replay Guard（`src/protocol/`） | RSU/nonce/时间窗绑定，防重放 |

**工程优化（当前默认 `balanced`）：**

- `pqc_sign_digest`：对会话帧做域分离 SHA256 后再签名，降低 Dilithium 对长消息签名耗时  
- RSU 验证顺序：**ZKP → PLS → PQC**（失败短路）  
- CSI：`float32`、`csi_dim=32`、会话种子绑定、异地 `extract_remote_csi()`  

---

## 快速开始

```bash
cd iov_zkp_pqc_pls
pip install -r requirements.txt
python run_protocol.py
```

## 五组实验（推荐 `balanced`）

```bash
python scripts/run_all.py balanced
python scripts/plot_results.py
```

| 配置 | 说明 |
|------|------|
| `configs/fast.json` | 更少轮次、CSI 16 维，快速冒烟 |
| `configs/balanced.json` | **默认答辩/论文数据** |
| `configs/high_security.json` | Dilithium3、CSI 64 维 |

**输出：** `results/group*.csv`、`results/summary.csv`、`results/plots/*.png`

---

## 最新实验结果（`balanced`，`python scripts/run_all.py balanced`）

> 环境：Python + `dilithium-py`（纯 Python 教育实现）；指标以仓库内 CSV 为准。  
> **RSU 延迟** = 仅 RSU `rsu_verify`；**端到端** = OBU `obu_build_request` + RSU 验证（含 Dilithium 签名）。

### 主对比（`group1_main_comparison.csv`）

| 协议 | RSU 延迟 (ms) | 端到端 (ms) | 通信 (B) |
|------|---------------|-------------|----------|
| baseline_yang（ECC 模拟） | ~0.55 | — | 256 |
| improved_ecdh_aes | ~3.0 | — | 512 |
| **innovation_zkp_pqc_pls** | **~5.2**（中位 ~5.0） | **~36**（中位 ~26） | **4014** |

创新方案通信分解：**pk 1312 + sig 2420 + zkp 80 + csi 128**（+ message）。

### 攻击仿真（`group3_attacks.csv`）

| 攻击 | 攻击成功率 |
|------|------------|
| 重放 replay | **0%** |
| 证书窃取+异地冒充 | **0%** |
| 远程中继（ρ≈0.43） | **0%** |
| 消息篡改 MITM | **0%** |

### 消融（`group2_ablation.csv`，良性路径）

| 变体 | 认证成功率 |
|------|------------|
| full | ~90% |
| no_zkp | ~97% |
| no_pls | 100% |
| no_session_binding | 100% |
| pqc_only | 100% |

说明：启用 PLS 时受阈值 γ 与 `rel_dist_max` 影响，良性通过率略低于 100%；**安全价值请结合攻击实验**（去 PLS 时无法防御异地盗证）。理论维度扣分见 `src/evaluation/security_rubric.py`（创新方案约 **95/100**，非国标等级）。

### 灵敏度 / 规模

- **灵敏度**：Dilithium2 RSU 延迟约 **8–9 ms**；Dilithium3 约 **12–14 ms**（见 `group4`）  
- **规模**：50/100/200 车批量吞吐约 **20–24 auth/s**，单车平均延迟约 **42–49 ms**（含 OBU 签名，见 `group5`）

更细表格见 **`docs/EXPERIMENT_RESULTS.md`**。

---

## 文档索引

| 文档 | 内容 |
|------|------|
| [docs/EXPERIMENT_RESULTS.md](docs/EXPERIMENT_RESULTS.md) | 五组实验完整数据与解读（与 CSV 同步） |
| [docs/PROJECT_DETAILED_REPORT.md](docs/PROJECT_DETAILED_REPORT.md) | 算法、协议流程、模块说明 |
| [docs/RESEARCH_REPORT.md](docs/RESEARCH_REPORT.md) | 研究背景、方案与结论 |
| [docs/LITERATURE_AND_INNOVATION.md](docs/LITERATURE_AND_INNOVATION.md) | 2024–2026 文献与创新定位 |
| [docs/PPT_REVISION_ANALYSIS.md](docs/PPT_REVISION_ANALYSIS.md) | 汇报 PPT 修改建议 |
| [docs/ppt_extracted.txt](docs/ppt_extracted.txt) | PPT 全文提取 |

---

## 目录结构

```
iov_zkp_pqc_pls/
├── src/pqc/          # Dilithium 格签名
├── src/zkp/          # Sigma + Fiat–Shamir
├── src/pls/          # CSI 指纹
├── src/protocol/     # 融合协议 + IoVAuthFrame
├── src/attacks/      # 攻击仿真
├── src/ablation/     # 消融
├── src/config.py     # 配置 → 协议实例
├── benchmarks/       # 主对比基准
├── scripts/          # run_all.py, plot_results.py
├── configs/          # fast / balanced / high_security
└── results/          # CSV + plots
```

---

## 说明与局限

- 本项目用于**研究与教学**；`dilithium-py` 为教育实现，生产建议 **liboqs / OQS** 或硬件加速。  
- ZKP 为 **Sigma 演示骨架**，非 Groth16/PLONK 级 zk-SNARK。  
- PLS 为 **Rayleigh 信道仿真**，可替换 802.11p / 5G NR 实测 CSI。  
- 端到端延迟主要由 **OBU 侧 Dilithium 签名** 主导；进一步降低需会话级签名或 C 后端。

---

## 参考文献入口

见 `docs/LITERATURE_AND_INNOVATION.md`（含 PQ-TDAA、Hermes' Seal、NIST ML-DSA 等链接）。
