# PPT 改稿正文（可直接粘贴到腾讯文档）

> 数据来自 `configs/balanced` + `python scripts/run_all.py balanced`  
> 自动指标：`docs/PPT_METRICS.md`

---

## Slide 1 封面
ZKP-PQC-PLS 融合架构创新型 IoV 安全认证系统  
身份认证与访问控制 — 课程小组作业汇报  
零知识验证 · 后量子密码 · 物理层安全

---

## Slide 2 大纲
1. 项目背景与动机  
2. 技术演进与现有方案  
3. 核心方案：三支柱融合  
4. 关键技术详解  
5. 协议设计与安全机制  
6. 实验与评估（五组 + 攻击）  
7. 创新定位与总结  

---

## Slide 3 背景
- **量子威胁**：Shor → RSA/ECC 风险；NIST **FIPS 204 (ML-DSA)**  
- **隐私**：ZKP 最小披露（本实现：Sigma 骨架）  
- **物理层**：CSI 第二因子防盗证+远程冒充  

---

## Slide 4 方案对比

| 方案 | 抗量子 | 隐私 | 物理层 |
|------|--------|------|--------|
| Yang (2023) | ✗ | 弱 | ✗ |
| ECDH+AES | ✗ | 中 | ✗ |
| PQ-TDAA (2026) | ✓ | 强 | ✗ |
| **本方案** | ✓ | **中高** | ✓ |

威胁映射：PQC→抗量子；ZKP→隐私；PLS→防盗证；IoVAuthFrame→防重放

---

## Slide 5 三支柱
- **PQC**：Dilithium2 / ML-DSA；**对会话帧摘要签名**  
- **ZKP**：Sigma + Fiat–Shamir（16B challenge）  
- **PLS**：会话绑定 CSI；float32；γ=0.88（balanced）  

---

## Slide 6 PQC
- pk 1312B / sig 2420B（L2）  
- 实现：`dilithium-py`；生产建议 **liboqs**  
- 优化：`pqc_sign_digest` 降低签名延迟  

---

## Slide 7 ZKP
- 流程：Commit → Hash 挑战 → Response  
- **说明：演示级 Sigma，非 Groth16/PLONK**  
- witness 默认 `SHA256(sk)` 摘要  

---

## Slide 8 PLS
- Rayleigh 仿真；**csi_dim=32**；ρ + **rel_dist** 双判据  
- 合法：`extract_session_csi(msg)`  
- 盗证：`extract_remote_csi(msg)` → 拒绝  

---

## Slide 9 协议流程

**OBU：** KeyGen → ZKP → PQC sign(digest) → CSI → 请求  

**RSU：** Replay → **ZKP → PLS → PQC**（失败短路）  

载荷：{pk, zkp, sig, csi, msg}

---

## Slide 10 IoVAuthFrame
- 字段：rsu_id、timestamp、nonce、policy_flags  
- epoch：**epoch_id = timestamp // 5000ms**  
- Replay：SHA256(msg) 窗口去重  

---

## Slide 11 攻击实验（balanced）

| 攻击 | 成功率 |
|------|--------|
| 重放 | **0%** |
| 盗证+异地 | **0%** |
| 远程中继 | **0%**（ρ≈0.43） |
| 篡改 | **0%** |

---

## Slide 12 消融

**Rubric：** full 95；去 ZKP −30；去 PLS −23；去会话 −17  

**实验：**  
- 良性 full：**~90%**  
- 盗证：**有 PLS 0% / 无 PLS ~100%**（`group_pls_theft_ablation.csv`）

---

## Slide 13 性能

- **RSU：~5.2 ms**（中位 ~5.0）≪ 50 ms  
- **端到端：~26–36 ms**（含 OBU 签名）  
- **通信：4014 B**（pk 1312 + sig 2420 + zkp 80 + csi 128）  
- Rubric：**35 → 75 → 95**（研究用）

---

## Slide 14 五组实验
```bash
python scripts/run_all.py balanced
python scripts/plot_results.py
```
输出：`results/group*.csv`、`results/plots/*.png`

---

## Slide 15 Rubric 权重
后量子 **25%** | ZKP **25%** | PLS **20%** | 会话 **15%** | 完整性 **15%**  
总分 95/100 — **非 CC/FIPS 等级**

---

## Slide 16 文献
- Chen IoT ZKP 综述 (2023)  
- Chen 区块链+ZKP VANET (2025)  
- **PQ-TDAA (2026)**  
- Hermes' Seal (2026)  
- NIST ML-DSA / 附加签名轮  

**定位：** PQC+Sigma-ZKP+PLS+会话帧 **可复现融合原型**

---

## Slide 17 总结
- RSU **~5 ms**；攻击 **0%**；五组实验可复现  
- 短期：liboqs、会话级签名降端到端  
- 长期：zk-SNARK（Hermes' Seal）

---

## Slide 18 致谢
谢谢！  
仓库：`iov_zkp_pqc_pls`  
文档：`docs/PPT_PROJECT_GAP_ANALYSIS.md`
