# ZKP-PQC-PLS IoV 安全认证汇报 PPT：深度分析与修改意见

> 对照文件：`ZKP-PQC-PLS_IoV安全认证汇报.pptx`（18 页，全文见 `docs/ppt_extracted.txt`）  
> 实验数据：`results/group*.csv`（`fast` 配置，Replay Guard 已启用）  
> 文献窗口：**2025 年 1 月 — 2026 年 6 月前** 公开发表/预印本

---

## 一、总体评价

| 维度 | 评价 |
|------|------|
| 结构 | 背景→演进→架构→技术→协议→实验→定位→总结，逻辑清晰，适合课程/组会汇报 |
| 技术叙事 | PQC / ZKP / PLS 三支柱与 IoVAuthFrame 会话绑定表述准确，与代码 `iov_zkp_pqc_pls` 一致 |
| 主要风险 | **性能数字过时**、**消融与攻击实验叙事不足**、**ZKP/PLS 实现边界未写清**、**2026 竞品文献偏少** |
| 答辩易被追问 | “95 分是否国际标准？”“Sigma 是否真零知识？”“CSI 是否实测？”“与 PQ-TDAA 差异？” |

---

## 二、与 2026 年 6 月前最新研究的对照

### 2.1 建议新增/强化的代表性工作

| 工作 | 时间/出处 | 核心贡献 | 与本 PPT 方案的关系 |
|------|-----------|----------|---------------------|
| **PQ-TDAA** | *J. Cybersecur. Priv.* 2026, 6(2):44 | Dilithium2 + Falcon-512 + Fiat–Shamir 简化 Schnorr；证明约 **8 kB**（较 V-LDAA **−69%**）；ETSI TS 102 941 可追溯；NS-3 + Pi5 嵌入式评估 | **同族**：PQC+轻量 ZKP；**差异**：本方案加 **PLS(CSI)** 与 IoVAuthFrame，无 TDAA/盲签/假名凭证体系 |
| **Hermes' Seal** | arXiv:2603.26343, 2026 | V2V/V2I **zk-SNARK**、隐私与 RSU 时延预算 | 本方案 ZKP 为 **Sigma 骨架**；长期演进应对标此路线 |
| **CAAP** | arXiv:2602.01342, 2026 | 6G 车联网 **上下文自适应 PQC**（格/码/哈希切换）、单调版本防降级 | 本方案为 **固定 Dilithium2**；可引用为“未来动态 PQC 选型” |
| **CAT / CLAT + TEE** | *Ad Hoc Networks* 2026 (S1570870526001708) | 后量子 V2V + **TEE 密钥保护**；Scyther 形式化验证 | 本方案无 TEE；可写“互补：TEE 保护 sk，PLS 防异地盗证” |
| **Tsai & Yang 格基 VANET** | *Future Internet* 2025, 17(10):458 | 伪 ID + 格身份认证 + TA 追溯 | 同 **格+PQC** 族；本方案多 ZKP+PLS |
| **双区块链格匿名认证** | *JISA* 2026, 97:104369 | 格 + 双链 + 前向安全/撤销 | 本方案未做链上撤销；中期路线图可对接 |
| **UAV 辅助 VANET PQ-AKE** | *Mathematics* 2026, 14(5):820 | MLWE KEM + **PUF**；UAV 不可信中继模型 | PLS 与 PUF 同属“物理不可克隆/信道绑定”思路，可并列讨论 |
| **RRSC (Dilithium 可撤销环签)** | Springer 2025 会议章 | CRYSTALS-Dilithium 环签 + 可追溯匿名 | 本方案匿名语义弱于环签；中期可对比 |

### 2.2 产业与标准（答辩一句话）

- **NIST FIPS 204 (ML-DSA)**：Slide 6 已写，建议注明 **2024 年 8 月发布**，与 IoV 长期 PKI 迁移时间表挂钩。  
- **ETSI ITS / 国内 V2X**：Slide 10 已提字段对标；可补充 **CAM/BSM 周期 100 ms** 与 PQ-TDAA 的 beacon 约束对照。  
- **NIST 附加签名第二轮 (2024-10)**：Slide 16 已有；可一句说明“生产仍以 ML-DSA 为主，体积优化看 Falcon/MAYO 等”。

### 2.3 竞品对比表（建议新增 1 页）

| 方案 | 抗量子 | 强匿名/ZKP | 物理层第二因子 | 可追溯/撤销 | 典型端到端延迟（文献） |
|------|--------|------------|----------------|-------------|------------------------|
| Yang et al. (2023) | ✗ | 弱 | ✗ | 部分 | 亚毫秒级（仿真） |
| PQ-TDAA (2026) | ✓ | ✓ (FS Schnorr, ~8kB) | ✗ | ✓ (RSU) | 8.1 ms @10 车；49.7 ms @20 车 |
| Hermes' Seal (2026) | 视电路 | ✓ (zk-SNARK) | ✗ | 策略相关 | 需引用原文 RSU 预算 |
| CAT/CLAT+TEE (2026) | ✓ | 证书/无证书 | ✗ (TEE) | ✓ | 形式化为主 |
| **本方案 ZKP-PQC-PLS** | ✓ (Dilithium2) | 中 (Sigma+FS) | ✓ (CSI, 仿真) | 未实现 | **~4.9 ms**（本仓库 fast） |

**差异化一句话（建议放在 Slide 16）：**  
在 2026 年 PQ+ZKP 文献已较多的背景下，本工作的可陈述创新点是 **“ML-DSA 格签名 + 非交互 Sigma 隐私层 + CSI 物理第二因子 + V2X 风格会话帧”的四层融合原型**，而非单独发明新原语。

---

## 三、实验数据与 PPT 不一致项（必须修改）

当前 `results/group1_main_comparison.csv`（创新方案）：

| 指标 | PPT Slide 13 | 实测 (fast) | 修改建议 |
|------|----------------|-------------|----------|
| 平均延迟 | **~15.42 ms** | **4.87 ms** | 全文统一为 **~5 ms**（注明配置 `configs/fast.json`、Python + dilithium-py） |
| 通信总量 | “额外 ~1280+ B” | **4414 B**（pk 1312 + sig 2420 + zkp 96 + csi 512） | 改为 **~4.4 KB/次**，并分解四段；对比基线 256/512 B |
| 安全性 | 35→95，2.5× 延迟换 3× 安全 | 延迟实为基线 0.55 ms、改进 2.9 ms、本方案 4.9 ms | 改为 **“约 9× 基线延迟，仍 <50 ms”**；安全分注明为 **自研 rubric** |

攻击实验 `group3_attacks.csv`：

| 攻击 | PPT Slide 11 | 实测 success_rate | 修改建议 |
|------|--------------|-------------------|----------|
| 重放 | “hash 去重拦截” | **0.0** | ✓ 可加脚注：**修复 Replay Guard 后** |
| 证书窃取+异地 | “CSI 拒绝” | **0.05**（5% 仍通过） | **必须诚实写出**；说明 γ=0.85 与仿真 CSI 随机性导致边界 case；改进：提高 γ / 多天线 / 真实 PHY |
| 远程中继 | “PLS 降分拒绝” | avg_similarity≈0.53，success **0.0** | ✓ 可配一张 ρ 分布图 |
| 篡改 | 验签失败 | **0.0** | ✓ |

消融 `group2_ablation.csv`：**良性条件下成功率均为 1.0**。  
Slide 12 的 “去 ZKP −30 分” 等来自 **security_rubric 理论扣分**，不是 attack 实验。  
**修改建议：** 标题改为 **“理论安全维度贡献（Rubric）”**；另增半页 **“攻击条件下消融（待做/示意）”** 或引用 `group3` 说明去 PLS 时 `certificate_theft` 会上升。

---

## 四、逐页修改意见（18 页）

### Slide 1 封面
- 可副标题注明：**课程作业 + 可复现原型**（降低“产品级系统”预期）。
- GitHub：Slide 18 为 `iov_zkp_promote`，与仓库名 **iov_zkp_pqc_pls** 不一致 → **统一链接**。

### Slide 2 大纲
- 在 “文献” 前插入：**「相关工作与 2026 竞品对比」**（1 页）。

### Slide 3 背景
- 量子威胁：补充 **“存储现在、解密以后”(Harvest-now-decrypt-later)** 一句，呼应 IoV 长期证书。
- 隐私：区分 **“Sigma 证明不直接传 sk”** 与 **“真匿名凭证/不可链接”**（后者未完全实现）。

### Slide 4 现有方案局限
- 表格很好；建议增加一行 **PQ-TDAA (2026)**，标 ✓✓✗(无 PLS)，突出本方案 **PLS 列唯一打勾**。
- “极高 (ZKP)” 改为 **“中高（Sigma 骨架，可演进 SNARK）”**，避免答辩被质疑。

### Slide 5 三支柱架构
- 在底部小字注明：**ZKP = 教育级 Sigma；PLS = Rayleigh 仿真，可换 802.11p/5G CSI**。

### Slide 6 PQC
- 内容扎实；增加一句：**本实验签名验证耗时占主导，生产建议 liboqs + ARM NEON**。
- 可选：对比 PQ-TDAA 选用 **Falcon-512** 时签名更短的权衡。

### Slide 7 ZKP
- **关键修改：** 标题或脚注写清 **“基于离散对数/Schnorr 类型的 Sigma 演示骨架，非 Groth16/plonk SNARK”**。
- 说明 **challenge 由 Hash 导出** 即 Fiat–Shamir，与 PQ-TDAA 的 FS Schnorr **同技术族**。
- 若写 “零第三方 ZK 库”：优点是可复现；缺点是 **未经过成熟 ZK 审计**。

### Slide 8 PLS
- 强调 **仿真 ≠ 路测**；引用 1 篇 CSI 物理层认证综述或 V2X 信道测量论文（可选）。
- 公式页可补充：**攻击时 ρ 降至 ~0.53（relay）仍可能 >γ 的边界** → 解释 5% 盗证成功率。

### Slide 9 协议流程
- 建议配 **时序图**（Mermaid/Visio）：与代码 `FusionAuthProtocol` / `IoVAuthFrame` 一致。
- 第⑥步 “重放检测” 放在验签前 ✓，与实现一致。

### Slide 10 IoVAuthFrame
- 很好；可补充 **canonical_bytes() 字段顺序** 防止跨实现歧义（答辩加分）。
- “V2X 无缝对接” 改为 **“字段设计可对齐 ETSI ITS，尚需标准映射表”**（更严谨）。

### Slide 11 攻击仿真
- 按第三节更新 **证书窃取 5%** 与 **重放 0%**。
- 增加 **实验配置**：`python scripts/run_all.py fast`，100 次蒙特卡洛（若与代码一致）。

### Slide 12 消融
- **拆分两栏：** (A) Rubric 维度扣分；(B) 良性实验成功率 100%。
- 避免听众误以为 “去 ZKP 后实验成功率下降”。

### Slide 13 性能对比 ⭐重点改页
- 数字全部按 **第四节表格** 更新。
- 增加柱状图：`results/plots/` 中已有图可直接插入。
- 脚注：**Intel/Windows, Python 3.x, dilithium-py, n=…**

### Slide 14 五组实验
- 很好；补充 **group4 灵敏度（γ/threshold）**、**group5 可扩展性（OBU 数）** 各一句结论。

### Slide 15 安全评分
- **必须在页脚加粗：** “**研究用加权模型，非 Common Criteria / FIPS 等级**”。
- 权重与 `security_rubric.py` 一致：25%+25%+20%+15%+15%（PPT 写 30/25/20/15/10 与代码 **不一致** → **以代码为准改 PPT** 或改代码与文档统一）。

### Slide 16 文献定位
- 增补 **PQ-TDAA、CAAP、CAT/CLAT、Tsai&Yang 2025、JISA 2026 双链**（见 2.1 表）。
- “填补空白” 改为：**“在课程原型尺度上探索 PQC+ZKP+PLS 协同，与 2026 PQ-TDAA 等形成互补对比”**。

### Slide 17 总结与展望
- 延迟改为 **~5 ms**；通信 **~4.4 KB**。
- 短期：加 **“修复 rubric 权重与 PPT 一致”**、**“降低 certificate_theft 成功率”**。
- 中期：对标 **PQ-TDAA 假名凭证** 或 **环签 (RRSC)**。
- 长期：**Hermes' Seal 类 zk-SNARK**（写清证明生成时延风险）。

### Slide 18 致谢
- 修正 GitHub URL；可加二维码指向 `docs/PROJECT_DETAILED_REPORT.md`。

---

## 五、建议新增幻灯片（可选 3–4 页）

1. **相关工作对比表**（第二节 2.3）  
2. **实现边界与诚实声明**（Sigma 演示级、CSI 仿真、Rubric 非标准）  
3. **攻击实验结果页**（表格 + ρ 直方图，含 5% 盗证 case 分析）  
4. **复现指南**（两条命令 + `results/` 目录结构截图）

---

## 六、答辩预设 Q&A（写入备注区）

| 问题 | 建议回答要点 |
|------|----------------|
| 是标准零知识吗？ | 实现为 Fiat–Shamir 非交互 Sigma **演示骨架**；完整 ZK 需明确 relation 与模拟器证明；演进方向 zk-SNARK / PQ-TDAA 式 FS Schnorr。 |
| 为何比 PQ-TDAA 通信大？ | 单次携带 **完整 Dilithium 签名 + pk + CSI 向量**；PQ-TDAA 优化在 **凭证与 8kB 证明**；本方案未做凭证压缩。 |
| 95 分含义？ | 五维加权 **对比表**，用于课程方案横向比较，**不是**渗透测试评级。 |
| PLS 真实吗？ | 当前 **Rayleigh 仿真**；接口可换真实 CSI；路测是下一步。 |
| 盗证为何 5% 成功？ | 仿真 CSI 随机波动使 ρ 偶发 ≥0.85；调高 γ 或多次采样可压降。 |

---

## 七、优先修改清单（按优先级）

1. **P0** — Slide 13/17：延迟 **15.42→~5 ms**，通信 **4414 B 分解**，安全分脚注 **Rubric**。  
2. **P0** — Slide 11：证书窃取 **5%** + 改进计划。  
3. **P1** — Slide 15：权重与 `security_rubric.py` 对齐。  
4. **P1** — Slide 7/8/16：实现边界 + 2026 文献 4–5 篇。  
5. **P2** — 新增竞品对比页、攻击结果页、复现页。  
6. **P2** — Slide 18：GitHub 链接修正。

---

## 八、与项目文档的交叉引用

- 全文提取：`docs/ppt_extracted.txt`  
- 文献与创新：`docs/LITERATURE_AND_INNOVATION.md`  
- 算法与实验解读：`docs/PROJECT_DETAILED_REPORT.md`  
- 一键复现：`python scripts/run_all.py fast` → `python scripts/plot_results.py`

---

*文档生成日期：2026-05-31；实验数据对应仓库当前 `results/` 快照。*
