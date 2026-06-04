# IoV 身份认证与零知识：文献综述与本项目创新定位（2024–2026）

本文档在 `iov_zkp_pqc_pls` 工程实现基础上，结合近年车联网（IoV/V2X）、零知识证明（ZKP）、后量子密码（PQC）与物理层安全（PLS）相关研究，说明**零信息/零知识认证**的系统化实现路径与本仓库的**创新落点**。

---

## 1. 术语：零知识 vs “零信息”

- **零知识证明（ZKP）**：证明者向验证者证明某陈述为真，且不泄露除“陈述为真”之外的额外信息（经典定义见 Goldwasser–Micali–Rackoff）。
- **工程语境下的“零信息认证”**：常指**最小披露身份**（minimal disclosure）：不暴露长期标识、位置轨迹、证书明文等，仅证明“属于某合法集合/持有某属性”。本项目中与 **匿名凭证、假名、环签名、zk-SNARK 断言** 等方向一致。

---

## 2. 近年代表性研究方向（与 IoV 强相关）

### 2.1 物联网零知识认证综述

- **Chen 等，*Electronics* (MDPI)，2023** — “A Survey on Zero-Knowledge Authentication for Internet of Things”：系统梳理 ZKP 在 IoT（含车载场景）中的身份认证与隐私保护框架，强调**资源约束**与**非交互证明**需求。  
  - 链接：<https://www.mdpi.com/2079-9292/12/5/1145>

### 2.2 车联网 + 区块链 + ZKP

- **Chen 等，*The Journal of Supercomputing*，2025** — 基于区块链与零知识证明的车载自组网匿名认证：突出**不泄露具体身份**前提下的车辆用户认证。  
  - 链接：<https://link.springer.com/article/10.1007/s11227-025-07912-5>

### 2.3 V2V/V2I 中的 zk-SNARK 框架（带宽与延迟敏感）

- **Hermes’ Seal（arXiv:2603.26343，2026）** — 面向自动驾驶通信的 **zk-SNARK** 框架，强调 V2V/V2I **可验证通信**、**隐私**与 **RSU 侧严格时延预算**，与“证明断言而非暴露原始传感/模型数据”一致。  
  - 链接：<https://arxiv.org/abs/2603.26343>（PDF：<https://arxiv.org/pdf/2603.26343>）

### 2.4 协同感知与 V2X 安全大综述（2025）

- **IEEE Communications Surveys & Tutorials，2025** — 智能网联车辆协同感知与通信综述（文中引用链涵盖 V2X 安全与隐私趋势），可作为**系统级需求**（低时延、协作验证）的背景。  
  - DOI：`10.1109/COMST.2025.3626504`

### 2.5 IoV 取证与后量子区块链 + 格环签名

- **Zhang 等，*Sensors*，2025** — 基于后量子区块链的 IoV 取证系统，引入 **DualRing** 等结构降低格环签名开销，体现 **PQC + 匿名/环签名** 在车载环境中的工程折中。  
  - 链接：<https://www.mdpi.com/1424-8220/25/19/6038>

### 2.6 V2X 与 PQC 韧性（交通信息物理系统）

- **arXiv:2510.08496** — AI 驱动 PQC 在交通 CPS 中 V2X 弹性的讨论，强调**签名体积与延迟权衡**（与本仓库 `benchmarks` 结论一致）。  
  - 链接：<https://arxiv.org/abs/2510.08496>

### 2.7 NIST 附加数字签名第二轮（2024）

- **NIST CSRC，2024-10** — 14 个候选进入**附加 PQC 签名**第二轮，反映业界对 **“比 ML-DSA 更小/更快”** 签名的持续需求；当前生产可仍以 **ML-DSA/Dilithium** 为主，长期可关注 MAYO、SQIsign 等路线。  
  - 链接：<https://csrc.nist.gov/news/2024/pqc-digital-signature-second-round-announcement>

### 2.8 身份共享中的 ZKP 综述

- **Zhou 等，*JISA*，2024** — 区块链身份共享中 ZKP 的进展与挑战（可迁移到“车-云-路侧”身份联邦场景）。  
  - DOI：`10.1016/j.jisa.2023.103678`

---

## 3. 威胁模型与能力边界（建议写进论文/报告）

| 攻击面 | 典型威胁 | 本架构对应缓解 |
|--------|----------|----------------|
| 长期密钥泄露（经典） | 伪造签名 | PQC 签名（抗量子） |
| 身份追踪 | 轨迹关联 | ZKP + 假名/凭证（当前实现为 Sigma；进阶为 SNARK/环签名） |
| 远程冒充 | 盗证 + 异地重放 | PLS（CSI/信道指纹）第二因子 |
| 重放 | 旧消息重用 | 会话帧：RSU ID、时间窗、nonce（见 `IoVAuthFrame`） |
| RSU/TA 作恶 | 中央监视 | 需制度+分布式信任（区块链/联邦注册）；超出本代码范围 |

---

## 4. 本项目在文献谱系中的定位

1. **PQC 层**：对齐 NIST ML-DSA/Dilithium 路线，与 Zhang 等（2025）等 **格基 IoV** 工作同族；实现上可用 `dilithium-py` 做研究原型，生产建议 **liboqs / 硬件加速**。  
2. **ZKP 层**：当前为 **Sigma + Fiat–Shamir** 的“知识证明”骨架，与 MDPI 综述中“非交互、轻量”方向一致；向 **Hermes’ Seal** 类 **zk-SNARK** 演进时，需引入电路/可信设置或透明 SNARK，并单独做 **证明生成时延** 评估。  
3. **PLS 层**：与 CSI 指纹、物理层认证文献一致（本仓库为 **可替换的仿真模块**，便于接真实 PHY）。  
4. **会话与 freshness**：通过 `IoVAuthFrame` 将 **挑战-响应** 与 **V2X 风格上下文** 显式化，便于与 ETSI ITS / 国内 V2X 报文字段对照扩展。

---

## 5. 可落地的“创新”路线图（工程优先级）

1. **短期（保持安全目标，降延迟/体积）**  
   - PQC：C/OQS 实现 + 仍用 Dilithium2。  
   - PLS：降 CSI 维度 + 量化 + 略提阈值 γ。  
   - 会话：全面使用 `IoVAuthFrame.canonical_bytes()` 作为签名与 ZKP 绑定输入。

2. **中期（增强匿名语义）**  
   - 引入 **注册表假名**：线路上传 `handle = H(pk \Vert epoch)`，RSU 本地查表得 `pk`（演示级）；或采用 **匿名凭证**（如 Camenisch–Lysyanskaya 风格，需专门库）。  
   - 评估 **环签名 / 群签名**（与 Sensors 2025 路线对话）。

3. **长期（与 Hermes’ Seal 对齐）**  
   - 将“属性/成员资格”编码为 **电路**，用 **zk-SNARK** 证明 `C(x,w)=1`，`x` 含 RSU 挑战、策略版本；证明体积恒定，适合带宽受限 V2X。

---

## 6. 参考文献（Bib 片段，便于论文引用）

```bibtex
@article{chen2023zkp_iot_survey,
  title={A Survey on Zero-Knowledge Authentication for Internet of Things},
  journal={Electronics},
  year={2023},
  note={MDPI, Vol.12 No.5}
}
@article{chen2025blockchain_zkp_vanet,
  title={Anonymous authentication based on blockchain and zero-knowledge proof for vehicular ad hoc networks},
  journal={The Journal of Supercomputing},
  year={2025}
}
@misc{hermes_seal2026,
  title={Hermes' Seal: Zero-Knowledge Assurance for Autonomous Vehicle Communications},
  year={2026},
  note={arXiv:2603.26343}
}
@article{zhang2025pq_blockchain_iov,
  title={Forensics System for Internet of Vehicles Based on Post-Quantum Blockchain},
  journal={Sensors},
  year={2025}
}
```

---

## 7. 与本仓库文件的对应关系

| 文献概念 | 代码/文档 |
|----------|-----------|
| 非交互 ZKP、挑战绑定 | `src/zkp/sigma_proof.py` |
| PQC 签名（含摘要签名优化） | `src/pqc/lattice_signing.py`, `fusion_protocol._pqc_payload` |
| CSI 第二因子 | `src/pls/csi_fingerprint.py` |
| 融合协议 | `src/protocol/fusion_protocol.py` |
| 会话 freshness / V2X 风格绑定 | `src/protocol/iov_auth_frame.py` |
| 配置化实验 | `src/config.py`, `configs/balanced.json` |
| 可解释安全分 | `src/evaluation/security_rubric.py` |
| **最新实验数据** | `docs/EXPERIMENT_RESULTS.md`, `results/group*.csv` |
| 本综述 | `docs/LITERATURE_AND_INNOVATION.md` |

### 7.1 与竞品文献的实测对比（`balanced` 配置）

| 指标 | 本仓库原型 | 文献典型（供答辩引用） |
|------|------------|------------------------|
| RSU 验证延迟 | **~5 ms** | PQ-TDAA：8.1 ms @10 车（NS-3） |
| 单次通信 | **~4.0 KB** | PQ-TDAA 证明 ~8 KB；本方案含完整 Dilithium sig |
| 物理层第二因子 | **有（CSI 仿真）** | PQ-TDAA / Hermes' Seal：通常无 PLS |
| 盗证+异地攻击成功率 | **0%**（仿真） | 需对照各文威胁模型 |

差异化表述：在 PQ+ZKP 已较多的 2026 文献中，本原型强调 **PQC + Sigma-ZKP + PLS + IoVAuthFrame** 四层融合与可复现攻击实验，而非单一新原语。
