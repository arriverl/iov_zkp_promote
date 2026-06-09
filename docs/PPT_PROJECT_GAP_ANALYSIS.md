# 腾讯文档 PPT「修改版」与 `iov_zkp_pqc_pls` 项目差距分析

> **在线文档：** [ZKP-PQC-PLS_IoV安全认证汇报-修改](https://docs.qq.com/slide/DYm9yd3pXV2tHWVpD)  
> **说明：** 该链接需腾讯账号登录，自动化无法读取正文；本分析对照 **原版 18 页提取稿**（`docs/ppt_extracted.txt`）、**当前代码** 与 **`results/`（balanced）**。若你已在腾讯文档改过部分页，请用 `docs/PPT_SLIDE_COPY.md` 逐页核对。

---

## 1. 总体差距矩阵

| 维度 | PPT 原版/常见表述 | 项目现状 | 差距等级 | 处理 |
|------|-------------------|----------|----------|------|
| RSU 延迟 | ~15.42 ms | **~5.2 ms** | 🔴 高 | Slide 13/17 必改 |
| 端到端延迟 | 未区分 | **~26–36 ms** | 🔴 高 | 新增说明页 |
| 通信开销 | ~1280+ B | **4014 B**（分解见下） | 🔴 高 | Slide 13 必改 |
| RSU 验证顺序 | ZKP→PQC→CSI | **ZKP→PLS→PQC**（短路） | 🟡 中 | Slide 9 改序 |
| PQC 签名对象 | `sign(message)` | **`sign(SHA256(PQC-Bind‖frame))`** | 🟡 中 | Slide 9 脚注 |
| CSI 提取 | `extract_csi_fingerprint()` | **`extract_session_csi(msg)`** | 🟡 中 | Slide 8/9 |
| PLS 参数 | 64 维、γ=0.85 | **32 维 float32、γ=0.88、rel_dist** | 🟡 中 | Slide 8 |
| ZKP 隐私 | 「极高」 | **中高（Sigma 骨架）** | 🟡 中 | Slide 4/5 |
| 攻击成功率 | 未写数字 | **全部 0%** | 🟡 中 | Slide 11 |
| 消融叙事 | 仅 Rubric 扣分 | **良性 ~90% + 盗证 PLS 消融** | 🟡 中 | Slide 12 |
| Rubric 权重 | 30/25/20/15/10 | **25/25/20/15/15** | 🟡 中 | Slide 15 |
| IoVAuthFrame.epoch | 独立字段 | **由 `epoch_id(window_ms)` 推导** | 🟢 低 | Slide 10 脚注 |
| 文献 | 缺 PQ-TDAA 等 | 见 `LITERATURE_AND_INNOVATION.md` | 🟡 中 | Slide 16 |
| GitHub | iov_zkp_promote | **iov_zkp_pqc_pls** | 🟢 低 | Slide 18 |
| 「填补空白」 | 过强表述 | 与 2026 PQ-TDAA 等同族 | 🟡 中 | Slide 16/17 弱化 |

---

## 2. 分页差距与改稿要点

### Slide 4 — 对比表
- **改：** 隐私列「极高」→ **「中高（Sigma，可演进 SNARK）」**
- **增：** 一行 **PQ-TDAA (2026)**：抗量子✓ 隐私✓ 物理层✗

### Slide 5 — 架构
- **脚注：** ZKP=演示级 Sigma；PLS=Rayleigh 仿真；PQC=摘要签名优化

### Slide 8 — PLS
- **改：** 默认 **csi_dim=32（balanced）**、γ=**0.88**、float32
- **增：** 异地盗证 `extract_remote_csi()` + 归一化距离 `rel_dist_max`

### Slide 9 — 协议流程（与代码对齐）

**OBU（不变顺序）：** KeyGen → ZKP → PQC sign(**digest**) → CSI(session) → 发包

**RSU（按实现）：**
1. Replay Guard  
2. ZKP verify → 失败退出  
3. PLS（上报 CSI + 测量噪声）→ 失败退出  
4. PQC verify(**digest**)

### Slide 10 — IoVAuthFrame
- **改：** epoch 写为 **`epoch_id = timestamp // 5000ms`**（`iov_auth_frame.py` 已提供）
- **改：** 「无缝对接 ETSI」→ **「字段可对齐，需映射表」**

### Slide 11 — 攻击（写入实测）

| 攻击 | 攻击成功率 |
|------|------------|
| replay | **0%** |
| certificate_theft | **0%** |
| remote_relay | **0%**（ρ≈0.43） |
| tampering | **0%** |

### Slide 12 — 消融（双栏）

**A. Rubric 理论贡献：** full 95；去 ZKP −30…（同现稿）

**B. 实验数据：**
- 良性 `full`：**~90%**（`group2_ablation.csv`）
- 盗证场景：**有 PLS 0% / 无 PLS ~100%**（`group_pls_theft_ablation.csv`，`run_all` 自动生成）

### Slide 13 — 性能（必改）

```
RSU 验证：~5.2 ms（中位 ~5.0 ms）≪ 50 ms
端到端：~26–36 ms（OBU Dilithium 签名主导）
通信：4014 B = pk 1312 + sig 2420 + zkp 80 + csi 128
基线 0.55 ms / 256 B；改进 3.0 ms / 512 B
Rubric：35 → 75 → 95（研究用，非国标）
```

### Slide 15 — Rubric 权重
改为：**25% / 25% / 20% / 15% / 15%**

### Slide 16 — 文献
增补：**PQ-TDAA (2026)**、**CAAP (arXiv:2602)**、**Tsai&Yang FI 2025**

### Slide 17 — 总结
- 延迟用 **5 ms（RSU）** + 端到端说明  
- 弱化「填补空白」→ **「四层融合可复现原型」**

### Slide 18
- 仓库：**iov_zkp_pqc_pls**  
- 复现：`python scripts/run_all.py balanced`

---

## 3. 项目侧已做优化（对齐 PPT）

| 优化 | 文件 |
|------|------|
| PPT 指标自动导出 | `scripts/export_ppt_metrics.py` → `docs/PPT_METRICS.json` |
| 盗证 PLS 消融实验 | `src/attacks/pls_ablation.py` → `results/group_pls_theft_ablation.csv` |
| epoch 语义对齐 | `IoVAuthFrame.epoch_id()` |
| `run_all` 末尾自动导出 PPT 指标 | `scripts/run_all.py` |

---

## 4. 建议你这样同步腾讯文档

1. 本地运行：`python scripts/run_all.py balanced`  
2. 打开 `docs/PPT_METRICS.md` 与 `docs/PPT_SLIDE_COPY.md` 复制到对应页  
3. 插入 `results/plots/*.png` 到 Slide 13/11  
4. 若修改版与上表仍有出入，把 **导出 PDF 或 pptx** 放到仓库，可再跑 `scripts/extract_ppt.py` 做二次 diff

---

## 5. 答辩时如何解释「PPT vs 代码」

| 追问 | 回答 |
|------|------|
| 延迟到底多少？ | **RSU ~5 ms** 是路侧纯验证；**端到端 ~30 ms** 含车载签名 |
| 为何通信 4KB？ | Dilithium 签名 2420B 占大头；已用 float32 CSI 压到 128B |
| Sigma 算强隐私吗？ | **演示骨架**；对标 Hermes' Seal / PQ-TDAA 的演进路线 |
| 去 PLS 会怎样？ | 盗证实验 **无 PLS 可通过 ZKP+PQC**，见 `group_pls_theft_ablation.csv` |
