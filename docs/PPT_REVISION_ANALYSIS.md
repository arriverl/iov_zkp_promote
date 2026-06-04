# ZKP-PQC-PLS IoV 安全认证汇报 PPT：深度分析与修改意见

> 对照：`ZKP-PQC-PLS_IoV安全认证汇报.pptx`（18 页，`docs/ppt_extracted.txt`）  
> **实验数据：** `configs/balanced` → `python scripts/run_all.py balanced`（2026-06 更新）  
> 完整表格：`docs/EXPERIMENT_RESULTS.md`

---

## 一、总体评价

| 维度 | 评价 |
|------|------|
| 结构 | 清晰，适合课程/答辩 |
| 与代码一致性 | 架构一致；**Slide 13/17 数字需按下文更新** |
| 答辩风险 | 需区分 RSU 延迟 vs 端到端；Rubric 非国标；Sigma/仿真 PLS 需脚注 |

---

## 二、2026 年 6 月前文献对标（摘要）

| 工作 | 链接/出处 | 与本方案 |
|------|-----------|----------|
| PQ-TDAA | [MDPI JCP 2026](https://www.mdpi.com/2624-800X/6/2/44) | 同 PQC+ZKP；无 PLS |
| Hermes' Seal | [arXiv:2603.26343](https://arxiv.org/abs/2603.26343) | 本方案为 Sigma，其为目标 SNARK |
| CAAP | [arXiv:2602.01342](https://arxiv.org/abs/2602.01342) | 自适应 PQC，本方案固定 Dilithium2 |
| Chen ZKP IoT 综述 | [Electronics 2023](https://www.mdpi.com/2079-9292/12/5/1145) | 背景 |
| NIST ML-DSA | FIPS 204 | Slide 6 必提 |

---

## 三、实验数据：PPT 应写入的最新数字（balanced）

### Slide 13 / 17 — 性能（必改）

| 指标 | 旧 PPT | **当前实测** |
|------|--------|--------------|
| RSU 延迟 | ~15.42 ms | **~5.2 ms**（中位 ~5.0） |
| 端到端 | （未写） | **~36 ms**（中位 ~26），含 OBU 签名 |
| 通信 | ~1280+ B | **4014 B**（pk 1312 + sig 2420 + zkp 80 + csi 128） |
| 基线/改进 | — | 0.55 ms / 256 B；3.0 ms / 512 B |

**建议表述：** “RSU 验证约 5 ms，满足 50 ms 实时阈值；端到端约 26–36 ms，瓶颈在 OBU 侧 Dilithium 签名。”

### Slide 11 — 攻击（必改）

| 攻击 | 旧 PPT | **当前** |
|------|--------|----------|
| 重放 | 拦截 | 成功率 **0%** |
| 盗证+异地 | 偶有 5% | 成功率 **0%** |
| 中继 | 拦截 | **0%**（ρ≈0.43） |
| 篡改 | 拦截 | **0%** |

### Slide 12 — 消融

- 旧：良性全 1.0 + Rubric 扣分  
- **新：** 良性 `full` 约 **90%**（PLS 双判据）；`no_pls` **100%** → 强调 **攻击实验** 说明 PLS 价值  
- Rubric：35 → 75 → **95**（研究用，页脚注明）

### Slide 15 — 权重

与 `security_rubric.py` 一致：**25% / 25% / 20% / 15% / 15%**（非 30/25/20/15/10）

### Slide 5 / 7 / 8 — 实现边界（脚注）

- PQC：对会话帧 **摘要后签名**  
- ZKP：Sigma + FS，**非** zk-SNARK  
- PLS：Rayleigh **仿真**，可换真实 CSI  

### Slide 18

- GitHub 与仓库名 **`iov_zkp_pqc_pls`** 一致  

---

## 四、建议新增页

1. **RSU vs 端到端** 双指标说明  
2. **竞品对比表**（PQ-TDAA / Hermes' Seal / 本方案）  
3. **复现命令**：`run_all.py balanced` + `plot_results.py`  

---

## 五、答辩 Q&A（更新）

| 问题 | 要点 |
|------|------|
| 延迟多少？ | RSU **~5 ms**；端到端 **~30 ms** 因 OBU 签名 |
| 95 分？ | Rubric 加权，非 CC/FIPS |
| 与 PQ-TDAA？ | 同 PQC+ZKP 族；本方案多 **PLS**；通信含完整 Dilithium |
| 盗证为何能防？ | `extract_remote_csi` + ρ + rel_dist |

---

## 六、P0 修改清单

- [x] 代码与实验已更新（见 `results/`）  
- [ ] PPT Slide 13/17：5 ms RSU、4014 B、端到端说明  
- [ ] PPT Slide 11：盗证 0%  
- [ ] PPT Slide 12：消融 + 攻击联合叙事  
- [ ] PPT Slide 15：Rubric 权重  
- [ ] Slide 18：仓库链接  

---

*文档与 `results/group*.csv` 同步；复现后若 CSV 变化请同步改 Slide。*
