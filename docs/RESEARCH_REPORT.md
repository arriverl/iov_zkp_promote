# 创新型 IoV 安全认证研究报告：ZKP-PQC-PLS 融合架构与评估

**项目：** `iov_zkp_pqc_pls`  
**更新：** 2026-06（实验数据对应 `configs/balanced` + `results/` 最新 CSV）

---

## 1. 创新背景与技术演进

### 1.1 调研结论（2023–2026）

- **量子威胁**：Shor 算法威胁 RSA/ECC；车联网长期证书面临“先存储、后解密”风险。NIST **FIPS 204 (ML-DSA)** 已发布，宜迁移至格基 PQC。
- **隐私需求**：轨迹关联与假名泄露风险；ZKP 支持最小披露认证（本实现为 Sigma 骨架，可演进 zk-SNARK）。
- **物理层防伪**：盗证 + 远程冒充需 **CSI/信道第二因子** 与数字凭证协同。

### 1.2 现有方案局限性

| 方案 | 抗量子 | 隐私 | 物理层 | 主要问题 |
|------|--------|------|--------|----------|
| Yang et al. (2023) 基线 | 否 (ECC) | 弱 | 无 | 量子与隐私短板 |
| ECDH+AES 改进 | 否 | 中 (假名) | 无 | 非抗量子 |
| PQ-TDAA 等 (2026) | 是 | 强 (凭证+ZKP) | 无 | 无 PLS；工程复杂 |
| **本方案** | **是** | **中高** | **是 (CSI)** | 通信与 SNARK 级匿名仍有差距 |

---

## 2. 创新方案：ZKP-PQC-PLS 融合架构

### 2.1 三支柱

1. **PQC** — CRYSTALS-Dilithium2（`dilithium-py`），默认对会话帧 **SHA256 摘要** 后签名（`PQC-Bind|v1|` 域分离）。  
2. **ZKP** — Sigma + Fiat–Shamir，challenge 16B；witness 默认用 `SHA256(sk)` 摘要。  
3. **PLS** — 会话绑定 CSI 种子；合法链路加噪比对；异地 `extract_remote_csi()`；ρ + `rel_dist_max` 双判据。

### 2.2 协议要点

- OBU：`IoVAuthFrame` → ZKP prove → PQC sign(digest) → CSI 上报。  
- RSU：Replay Guard → **ZKP → PLS → PQC**（短路）。  
- 详见 `docs/PROJECT_DETAILED_REPORT.md`。

### 2.3 实现依赖

| 组件 | 路径 | 依赖 |
|------|------|------|
| PQC | `src/pqc/lattice_signing.py` | dilithium-py |
| ZKP | `src/zkp/sigma_proof.py` | stdlib hash/hmac |
| PLS | `src/pls/csi_fingerprint.py` | numpy |
| 配置 | `src/config.py` + `configs/*.json` | — |

---

## 3. 实验复现与性能评估

### 3.1 复现方法

```bash
pip install -r requirements.txt
python run_protocol.py
python scripts/run_all.py balanced
python scripts/plot_results.py
```

完整数据表：**`docs/EXPERIMENT_RESULTS.md`**。

### 3.2 主对比结果（balanced）

| 维度 | 基线 Yang | ECDH+AES | 创新 ZKP-PQC-PLS |
|------|-----------|----------|------------------|
| RSU 延迟 (ms) | ~0.55 | ~3.0 | **~5.2** |
| 端到端 (ms) | — | — | **~36**（中位 ~26） |
| 通信 (B) | 256 | 512 | **4014** |
| 抗量子 | 无 | 无 | **有** |
| Rubric 安全分 (0–100) | ~35 | ~75 | **~95** |

### 3.3 攻击与消融

- **攻击：** 重放、盗证、中继、篡改成功率均为 **0%**（`group3_attacks.csv`）。  
- **消融：** 良性路径 `full` 约 **90%**（PLS 双判据下）；`no_pls` 为 100% — 说明 PLS 为防盗证关键模块。  

### 3.4 结果分析

- **安全性：** 融合架构在抗量子、防重放、防异地盗证方面相对基线显著提升；95 分为**研究用加权模型**，非 CC/FIPS 等级。  
- **延迟：** RSU 侧满足实时性；端到端需区分 OBU 签名开销。  
- **开销：** 主要来自 Dilithium pk/sig；已通过 float32 CSI 与 ZKP 压缩略降通信。

---

## 4. 结论与后续工作

本研究实现并评估了 ZKP-PQC-PLS 融合 IoV 认证原型，在可接受 RSU 延迟下提供抗量子、隐私证明骨架与物理层第二因子，并通过五组实验与攻击仿真验证。

**后续：**

- liboqs/C 后端与**会话级签名**降低端到端延迟  
- PLS 接入真实 CSI；多窗口一致性  
- ZKP 演进至 zk-SNARK（对齐 Hermes' Seal / PQ-TDAA 路线）  
- 与 ETSI ITS 报文字段正式映射  

---

## 5. 参考文献

- NIST FIPS 204 (ML-DSA)；CRYSTALS-Dilithium  
- `docs/LITERATURE_AND_INNOVATION.md`（含 MDPI/Springer/arXiv 2025–2026 链接）  
- dilithium-py: https://github.com/GiacomoPope/dilithium-py  
