# ZKP-PQC-PLS 车联网融合身份认证 — 项目完整文档

> **唯一项目文档** · 版本与 `configs/balanced` + `python scripts/run_all.py balanced` 最新 CSV 同步  
> **项目路径**：`iov_zkp_pqc_pls/`  
> **演示大屏**：[`demo/showcase.html`](demo/showcase.html)（需 `python scripts/live_demo_server.py`）

---

## 摘要

车联网（IoV/V2X）身份认证面临三类结构性挑战：**量子计算对经典 ECC 的长期威胁**、**身份与轨迹隐私泄露**、**凭证被盗后的异地冒充**。现有代表性方案——如 Yang 等人（2023）的 ECC+XOR 基线、ECDH+AES 假名改进方案，以及近年 PQ-TDAA 等后量子路线——往往在「抗量子、最小披露、物理层防盗证」中至少缺一项。

本项目提出并实现了 **ZKP-PQC-PLS 四层融合认证架构**：以 NIST ML-DSA（Dilithium2）提供抗量子完整性；以 **SIS-Σ-NIZK** 格零知识证明实现与 PQC 同族的最小披露；以 **CSI 信道指纹** 作为物理层第二因子防御盗证；以 **IoVAuthFrame** 会话帧绑定 RSU、时间窗与 nonce 防御重放。在可复现 Python 原型上完成七组实验：RSU 验证延迟约 **4.9 ms**，端到端约 **27 ms**，通信约 **4158 B**；五类攻击成功率均为 **0%**；启用物理层校验时盗证 **0%**；V2X 文献校准 CSI 下盗证仍为 **0%**。

---

## 一、快速开始

### 1.1 环境与单次演示

```bash
cd iov_zkp_pqc_pls
pip install -r requirements.txt
python run_protocol.py
```

### 1.2 七组实验（答辩/论文默认数据）

```bash
python scripts/run_all.py balanced
python scripts/plot_results.py
python scripts/export_ppt_metrics.py   # 导出 docs/PPT_METRICS.json
```

| 配置 | 说明 |
|------|------|
| `configs/fast.json` | 更少轮次、CSI 16 维，快速冒烟 |
| `configs/balanced.json` | **默认答辩/论文数据** |
| `configs/high_security.json` | Dilithium3、CSI 64 维 |

**输出**：`results/group*.csv`、`results/summary.csv`、`results/plots/*.png`

### 1.3 演示大屏（真算）

```bash
pip install flask
python scripts/live_demo_server.py
# http://127.0.0.1:8765/showcase.html
```

⚠️ 真算演示必须通过上述服务打开，不能双击 HTML。

### 1.4 目录结构

```
iov_zkp_pqc_pls/
├── src/pqc/          # Dilithium 格签名
├── src/zkp/          # SIS-Σ-NIZK + Sigma 骨架
├── src/pls/          # CSI 指纹
├── src/protocol/     # 融合协议 + IoVAuthFrame
├── src/baselines/    # Yang / ECDH 密码学复现
├── src/attacks/      # 攻击仿真
├── src/ablation/     # 消融
├── src/demo/         # live_round、metrics_loader
├── benchmarks/       # Group1 主对比
├── scripts/          # run_all、live_demo_server、plot_results
├── configs/          # fast / balanced / high_security
├── docs/demo/        # showcase / traffic_simulator / index
└── results/          # CSV + plots
```

---

## 二、研究背景与动机

### 2.1 产业与学术背景

智能网联汽车通过 V2V/V2I 实现协同感知、安全预警与交通调度。身份认证是 V2X 安全的第一道门。与此同时：

- **量子威胁**：Shor 算法可在多项式时间内破解 RSA/ECC；车载长期证书存在「现在截获、将来解密」风险。
- **隐私需求**：频繁上报位置与身份关联可还原行驶轨迹；ETSI/C-V2X 框架强调假名与最小披露。
- **物理安全盲区**：纯密码学验证无法证明「终端在指定地理位置」；OBU 凭证被盗后，攻击者可在异地 RSU 前通过验签。

### 2.2 问题陈述

| 威胁 | 典型场景 | 纯 ECC/假名方案短板 |
|------|----------|---------------------|
| 量子攻击 | 长期存储密文，未来解密 | ECC 不抗量子 |
| 身份追踪 | RSU 关联假名与轨迹 | XOR 弱掩码、假名可链接 |
| 盗证异地用 | 偷 OBU 凭证异地认证 | 无物理层第二因子 |
| 重放攻击 | 重复提交旧认证包 | 无会话/nonce 绑定 |

### 2.3 研究目标

构建可复现、可量化评估的 IoV 融合认证原型，在**可接受的车联网时延预算**（RSU 侧 < 50 ms 讨论门槛）内，同时补齐抗量子、零知识隐私与物理层防盗证能力，并与文献基线进行公平对比。

### 2.4 答辩核心叙事（约 3 分钟）

**立项动机：** 车联网不能只看「签名验证通过」。我们归纳三类结构性缺口：量子威胁（Harvest-Now, Decrypt-Later）、隐私与最小披露（不能长期暴露可关联身份）、远程盗证（偷走合法凭证异地冒充——纯密码学证明不了「车在现场」）。

**改进思路：** 按「威胁 → 文献 → 可实现」推导——PQC 抗量子、SIS-ZKP 最小披露、PLS 物理第二因子、IoVAuthFrame 防重放。相对 PQ-TDAA 等 PQ+ZKP 路线，本项额外补上 **PLS 与盗证消融实验**。

**相对原方案：** +抗量子（Dilithium2）、+格 ZKP（SIS-Σ-NIZK）、+PLS（CSI 双判据）、+会话绑定；性能上用约 5 ms RSU 延迟和 4 KB 通信换取四层安全能力。

---

## 三、文献综述与创新定位（2024–2026）

### 3.1 术语

- **零知识证明（ZKP）**：证明陈述为真且不泄露额外信息（Goldwasser–Micali–Rackoff）。
- **工程语境「零信息认证」**：最小披露身份——不暴露长期标识、轨迹、证书明文，仅证明「属于合法集合」。

### 3.2 代表性文献

| 文献 | 贡献 | 链接 |
|------|------|------|
| Chen et al., *Electronics* 2023 | IoT 零知识认证综述 | https://www.mdpi.com/2079-9292/12/5/1145 |
| Chen et al., *J. Supercomputing* 2025 | 区块链+ZKP 车载匿名认证 | https://link.springer.com/article/10.1007/s11227-025-07912-5 |
| Hermes' Seal, arXiv 2026 | V2V/V2I zk-SNARK，RSU 时延预算 | https://arxiv.org/abs/2603.26343 |
| IEEE COMST 2025 | 协同感知与 V2X 安全综述 | DOI 10.1109/COMST.2025.3626504 |
| Zhang et al., *Sensors* 2025 | 后量子区块链 IoV 取证 | https://www.mdpi.com/1424-8220/25/19/6038 |
| PQ-TDAA, MDPI 2026 | Dilithium + 轻量 ZKP，NS-3 ~8.1 ms | https://www.mdpi.com/2624-800X/6/2/44 |
| NIST FIPS 204 | ML-DSA / Dilithium 标准 | https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf |
| Yang et al., FGCS 2023 | ECC+XOR IoV 基线 | DOI 10.1016/j.future.2023.04.004 |

### 3.3 基线方案（本项目对照组）

**Yang 2023**：ECC 认证 + XOR 掩码假名。局限：无抗量子、无 PLS、XOR 隐私弱。复现：`src/baselines/yang2023.py`。

**ECDH+AES-GCM**：假名加密改进。局限：仍基于经典 ECC，无 ZKP/PLS。复现：`src/baselines/ecdh_aes_pseudonym.py`。

### 3.4 威胁模型

| 攻击面 | 威胁 | 本架构缓解 |
|--------|------|------------|
| 长期密钥泄露 | 伪造签名 | PQC（Dilithium2） |
| 身份追踪 | 轨迹关联 | ZKP + 假名（当前 SIS-NIZK；进阶 SNARK/环签名） |
| 远程冒充 | 盗证+异地 | PLS（CSI 第二因子） |
| 重放 | 旧消息重用 | IoVAuthFrame + Replay Guard |
| RSU/TA 作恶 | 中央监视 | 需区块链/联邦信任（超出本代码范围） |

### 3.5 文献谱系中的定位

1. **PQC**：对齐 NIST ML-DSA；生产建议 liboqs / 硬件加速。
2. **ZKP**：默认 **SIS-Σ-NIZK**（格短向量关系）；Sigma-HMAC 骨架保留作 Group7 对照；长期可对齐 Hermes' Seal 演进 zk-SNARK。
3. **PLS**：CSI 指纹，可接 IEEE DataPort V2X 实测。
4. **差异化**：在 PQ+ZKP 已有较多工作的背景下，强调 **PQC + SIS-ZKP + PLS + IoVAuthFrame** 四层融合与盗证可量化对照。

### 3.6 与竞品实测对比（答辩引用）

| 指标 | 本仓库（balanced） | 文献典型 |
|------|-------------------|----------|
| RSU 验证延迟 | **~4.9 ms** | PQ-TDAA：8.1 ms @10 车（NS-3） |
| 单次通信 | **~4158 B** | PQ-TDAA 证明 ~8 KB |
| 物理层第二因子 | **有** | PQ-TDAA / Hermes' Seal 通常无 PLS |
| 盗证攻击成功率 | **0%**（主实验） | 需对照各文威胁模型 |

---

## 四、创新点

### 4.1 架构创新：四层融合

```
PQC（抗量子完整性） + ZKP（最小披露） + PLS（物理防盗证） + IoVAuthFrame（会话新鲜度）
```

### 4.2 算法创新：SIS-Σ-NIZK

- **问题**：HMAC-Sigma 骨架可被伪造 response **100%** 通过（Group7）。
- **方案**：Lyubashevsky 式 **SIS 短向量关系** NIZK（`A·s ≡ t (mod q)`），与 Dilithium 密钥同族绑定。
- **效果**：伪造 response 通过率 **0%**。实现：`src/zkp/sis_lattice_nizk.py`。

### 4.3 实验方法论创新

| 实验组 | 创新点 |
|--------|--------|
| Group1 | 基线改为密码学原语复现（非 sleep 占位） |
| Group3 | 五类威胁脚本化、30 轮可复现 |
| 盗证消融 | 主实验 PLS 开（0%）+ 显式标注对照组 counterfactual（100%） |
| Group6 | Rayleigh 仿真 vs V2X 文献校准 CSI |
| Group7 | Sigma vs SIS-NIZK 算法层对照 |

### 4.4 工程优化

- `pqc_sign_digest`：域分离 SHA256 后签名，降低 Dilithium 对长消息耗时。
- RSU **短路验证**：Replay → ZKP → PLS → PQC，失败即退出。
- CSI `float32` + 32 维 + 会话种子绑定；异地 `extract_remote_csi()` 防盗证。

---

## 五、理论基础与实现

### 5.1 PQC 层 — CRYSTALS-Dilithium / ML-DSA

- **数学基础**：格上 SIS/LWE；NIST **FIPS 204（ML-DSA）**。
- **作用**：对会话帧摘要签名，抗量子完整性与不可否认性。
- **实现**：`src/pqc/lattice_signing.py`，Dilithium2（pk 1312 B，sig 2420 B）。
- **优化**：`fusion_protocol._pqc_payload` 对 `canonical_bytes()` 做 `SHA256(PQC-Bind|v1| || frame)` 再签/验。

### 5.2 ZKP 层 — SIS-Σ-NIZK

- **数学基础**：证明者知晓短向量 **s** 使得 `A·s ≡ t (mod q)`，不泄露 s（Lyubashevsky 拒绝采样 + Fiat–Shamir 非交互化）。
- **与 PQC 关系**：与 Dilithium 私钥/公钥在同一格代数结构下导出。
- **实现**：`src/zkp/sis_lattice_nizk.py`，`zkp_mode=sis_lattice_nizk`（`configs/balanced.json`）。
- **对照**：`src/zkp/sigma_proof.py`（Sigma 演示骨架，非 Groth16/PLONK）。

### 5.3 PLS 层 — CSI 信道指纹

- **物理原理**：OBU 与 RSU 间 CSI 具有位置相关、难以远程伪造特性。
- **判决**：皮尔逊 ρ ≥ γ **且** 归一化欧氏距离 ≤ `rel_dist_max`（双判据）。
- **盗证模型**：攻击者持有合法 ZKP+PQC+reported_csi，RSU 测量异地 CSI → ρ 低 → 拒绝。
- **实现**：`src/pls/csi_fingerprint.py`；`literature_calibrated_v2x` 模式（Group6）。

### 5.4 会话层 — IoVAuthFrame

- **内容**：`protocol_version || rsu_id || timestamp_ms || nonce || policy_flags` 确定性编码。
- **作用**：绑定 RSU 挑战与时间窗；Replay Guard 对 `SHA256(message)` 在 **5 s** 窗口去重。
- **实现**：`src/protocol/iov_auth_frame.py`。

### 5.5 融合协议流程

**OBU（`FusionAuthProtocol.obu_build_request`）：**

1. KeyGen（首次）→ `IoVAuthFrame.fresh(rsu_id)` → canonical message  
2. `PLS.extract_session_csi(message)` → reported_csi  
3. `ZKP.prove(witness, pk, message, reported_csi)`  
4. `PQC.sign(digest(frame), sk)` → 组装 AuthRequest  

**RSU（`FusionAuthProtocol.rsu_verify`）：**

1. Replay Guard — 失败则返回  
2. ZKP verify — 失败短路  
3. PLS authenticate（reported vs measured CSI）— 失败短路  
4. PQC verify(digest)  

**配置驱动**：`protocol_from_config(load_profile("balanced"))` 统一注入参数；`scripts/run_all.py` 全实验链使用同一配置。

### 5.6 SecurityRubric（可解释安全分，非国标）

`src/evaluation/security_rubric.py` 五维加权（抗量子 25、隐私 25、物理层 20、新鲜度 15、实现成熟度 15）：

| 方案 | 得分 |
|------|------|
| Yang 基线 | ~35 |
| ECDH+AES | ~75 |
| **本方案** | ~**95** |

用于横向对比，非渗透测试等级。

---

## 六、系统架构

```
┌──────────── OBU（车载）────────────────────────────────────┐
│  IoVAuthFrame.fresh(rsu_id)                                │
│       ↓                                                    │
│  PLS.extract_session_csi(message)  → reported_csi          │
│       ↓                                                    │
│  ZKP.prove(witness, pk, message)   → commitment/response   │
│       ↓                                                    │
│  PQC.sign(SHA256(PQC-Bind|frame))  → signature             │
│       ↓                                                    │
│  认证请求 {message, pk, zkp_*, signature, reported_csi}    │
└───────────────────────────┬────────────────────────────────┘
                            │ 无线信道（V2I PDU）
┌───────────────────────────▼────────────────────────────────┐
│  RSU（路侧）                                                │
│  ① Replay Guard（5s 指纹窗口）                             │
│  ② ZKP verify        — 失败短路                            │
│  ③ PLS authenticate  — ρ ≥ γ 且 rel_dist ≤ 阈值            │
│  ④ PQC verify        — Dilithium 验签                      │
└────────────────────────────────────────────────────────────┘
```

### 代码模块映射

| 层级 | 目录 | 核心类/函数 |
|------|------|-------------|
| 协议编排 | `src/protocol/` | `FusionAuthProtocol` |
| PQC | `src/pqc/` | `PQCLatticeSigner` |
| ZKP | `src/zkp/` | `create_zkp_system`, `sis_lattice_nizk` |
| PLS | `src/pls/` | `PLSAuthenticator` |
| 基线 | `src/baselines/` | `Yang2023IoVAuth`, `EcdhAesPseudonymAuth` |
| 真算演示 | `src/demo/` | `run_live_round`, `load_experiment_metrics` |
| 评估 | `src/attacks/`, `src/ablation/` | `run_attack_suite`, `run_ablation_study` |
| 实验 | `scripts/run_all.py` | 七组 CSV 一键导出 |

### 默认配置（`configs/balanced.json`）

```json
{
  "rounds": 30,
  "pqc_level": 2,
  "zkp_mode": "sis_lattice_nizk",
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

## 七、实验设计与完整结果

> 数据：`results/group*.csv` · 复现：`python scripts/run_all.py balanced`

### 7.1 指标定义

| 字段 | 含义 |
|------|------|
| `latency_ms_mean` | RSU `rsu_verify` 平均耗时 |
| `e2e_latency_ms_mean` | `obu_build_request` + `rsu_verify` |
| `comm_bytes_*` | 单次认证请求载荷分项 |

### 7.2 Group1 — 主性能对比

| 协议 | RSU 延迟 (ms) | 端到端 (ms) | 通信 (B) | 说明 |
|------|---------------|-------------|----------|------|
| Yang 2023 基线 | **0.07** | 0.18 | 227 | ECC+XOR 密码学复现 |
| ECDH+AES 改进 | **0.09** | 0.18 | 117 | ECDH+AES-GCM 复现 |
| **本方案** | **4.90** | **27.4** | **4158** | PQC+ZKP+PLS |

通信分解（本方案）：pk 1312 + sig 2420 + zkp 224 + csi 128 B。

**结论**：RSU ~5 ms 远低于 50 ms 门槛；端到端瓶颈在 OBU 侧 Dilithium 签名。

### 7.3 Group2 — 消融（良性路径）

| 变体 | 认证成功率 | 说明 |
|------|-----------|------|
| full | 96.7% | ZKP + PQC + PLS + 会话帧 |
| no_zkp | 96.7% | 关闭 ZKP |
| no_pls | 100% | 跳过 PLS |
| no_session_binding | 96.7% | 无 IoVAuthFrame |
| pqc_only | 100% | 仅 PQC |

说明：full 略低于 100% 是 PLS 双判据偶发误拒，**非被攻破**；安全价值见 Group3 与盗证消融。

### 7.4 Group3 — 攻击仿真（攻击者成功率，30 轮）

| 攻击 | 成功率 | 拦截机制 |
|------|--------|----------|
| 重放 replay | **0%** | Replay Guard |
| 证书窃取+异地冒充 | **0%** | PLS（异地 CSI，ρ≈0.35） |
| 远程中继 | **0%** | PLS（ρ≈0.46 < 0.88） |
| 消息篡改 MITM | **0%** | PQC 验签失败 |
| ZKP-CSI 解耦 | **0%** | PLS 绑定 |

### 7.5 盗证消融

| 组别 | 物理层校验 | 盗证通过率 | 说明 |
|------|-----------|-----------|------|
| 主实验 `primary` | **启用** | **0%** | 本融合协议正常配置 |
| 对照 `control_counterfactual` | 关闭 | 100% | **反事实对照**：模拟无 PLS 的 legacy 方案，非本协议被攻破 |

### 7.6 Group6 — CSI 数据源对比

| 模式 | 数据源 | 良性认证 | 盗证 | 合法 ρ | 盗证 ρ |
|------|--------|----------|------|--------|--------|
| simulation | Rayleigh | 96.7% | **0%** | 0.94 | 0.32 |
| real | V2X 文献校准 | **100%** | **0%** | 0.81 | -0.13 |

### 7.7 Group7 — ZKP 算法对照

| 算法 | 伪造 response 通过率 | 良性通过率 |
|------|---------------------|-----------|
| HMAC-Sigma | **100%** | 93.3% |
| **SIS-Σ-NIZK** | **0%** | 93.3% |

### 7.8 Group4 — 参数敏感性（节选）

| pqc_level | csi_dim | threshold | RSU (ms) | 通信 (B) | 成功率 |
|-----------|---------|-----------|----------|----------|--------|
| 2 | 32 | 0.88 | ~5.1 | 4169 | 100% |
| 3 | 32 | 0.88 | ~7.9 | 5682 | 100% |
| 2 | 64 | 0.88 | ~5.1 | 4297 | 100% |

### 7.9 Group5 — 可扩展性

| 车辆数 | 吞吐 (auth/s) | 单车平均延迟 (ms) | 批次成功率 |
|--------|---------------|-------------------|------------|
| 50 | ~33 | ~30 | ~93% |
| 100 | ~32 | ~31 | ~93% |
| 200 | ~29 | ~34 | ~94% |

### 7.10 实验脚本索引

| 脚本/目录 | 作用 |
|-----------|------|
| `scripts/run_all.py` | 导出全部 CSV |
| `scripts/plot_results.py` | `results/plots/*.png` |
| `scripts/export_ppt_metrics.py` | `docs/PPT_METRICS.json` |
| `scripts/live_demo_server.py` | 真算演示 API |
| `scripts/reproduce_honest_boundaries.py` | 答辩边界演示 |
| `benchmarks/run_benchmarks.py` | Group1 主对比 |
| `src/attacks/simulations.py` | Group3 |
| `src/ablation/study.py` | Group2 |

---

## 八、数据集与文献基准说明

### 8.1 三类数据来源

| 类型 | 用途 | 说明 |
|------|------|------|
| A. 公开实测 | 替换 PLS/CSI | IEEE DataPort V2X CSI（需注册下载） |
| B. 文献 Table | 对比基线 | 引用原文，注明非本机复现 |
| C. PQC 官方基准 | PQC 延迟对照 | NIST FIPS 204、liboqs |
| 本仓库 `results/` | 自研原型 | 仿真 CSI + 真 Dilithium（dilithium-py） |

### 8.2 推荐公开数据集（PLS 升级）

**IEEE DataPort — V2X 双向 CSI**

- 链接：https://ieee-dataport.org/documents/bidirectional-csi-measurement-v2x-communications  
- DOI：10.21227/3mkx-aq02  
- 场景：RSU + OBU，5.91 GHz，0–40 km/h，约 1.22 GB  
- 用途：替换 Rayleigh 仿真，验证 ρ 分布与盗证拦截率  

### 8.3 文献报告数值（引用，非下载）

| 来源 | 指标 | 说明 |
|------|------|------|
| PQ-TDAA 2026 | E2E 8.1 ms @10 车 | NS-3，802.11p |
| PQ-TDAA 2026 | 证明 ~8 kB | Falcon-512 等 |
| Hermes' Seal 2026 | RSU 时延预算 | 见 arXiv PDF |
| NIST FIPS 204 | pk/sig 长度 | 与本文 1312/2420 B 一致 |

### 8.4 论文/答辩诚实表述

| 实验项 | 数据来源 |
|--------|----------|
| 创新方案延迟/通信 | **本机实测**（`run_all.py balanced`） |
| Yang / ECDH 基线 | **本机密码学复现**（`src/baselines/`） |
| 攻击成功率 | **本机攻击脚本**（30 轮） |
| PLS CSI（当前） | **Rayleigh 仿真** + Group6 文献校准 |
| PQ-TDAA 8.1 ms 等 | **文献引用**，非本机 |
| 盗证对照 100% | **反事实对照**（`pls_verification=disabled`） |

推荐表述：

> 性能对比中，本方案为可复现原型实测；PQ-TDAA 等指标引自原文 NS-3 实验。PLS 当前含 Rayleigh 仿真与 V2X 文献校准 CSI；可扩展 IEEE DataPort 实测。

### 8.5 本课题「没有」什么

- Yang 2023 / PQ-TDAA **官方实验 CSV**（无统一公开包）  
- ZKP-PQC-PLS **端到端标注数据集**（课题为原型融合）  
- 第三方权威 **攻击测试认证**（当前为 `src/attacks/` 脚本）

---

## 九、可视化演示与现场演讲稿

### 9.1 演示页面

| 页面 | 路径 | 说明 |
|------|------|------|
| **演示大屏**（主入口） | `demo/showcase.html` | 三 Tab：流程 / 攻击 / 图表 |
| 传输动画 | `demo/traffic_simulator.html` | 更细粒度步进，同 API |
| 静态总览 | `demo/index.html` | `/report.html`，无需真算 |

**API：**

- `POST /api/round` — 真算一轮（scenario: normal|theft|replay|tamper|relay）
- `GET /api/metrics` — 读取 `results/*.csv` 聚合
- `GET /api/health` — 服务状态

### 9.2 大屏三 Tab 与口播（建议 8–12 分钟）

**开场（约 1 分钟）**

> 各位老师好。我们访问 `showcase.html`，右上角 **LIVE** 表示正在执行真实的 Dilithium2、SIS-ZKP 和 PLS 运算。大屏分三块：协议流程、攻击防御、实验数据。

---

**Tab ① 动态流程仿真（约 3–4 分钟）**

左侧 OBU 分层构包：

| 层级 | 口播要点 |
|------|----------|
| IoVAuthFrame | RSU_ID、时间戳、nonce——防重放 |
| PLS | extract_session_csi → reported_csi |
| ZKP | SIS-Σ-NIZK prove，A·s≡t，不泄露 sk |
| PQC | Dilithium2 sign |

右侧 RSU 短路验证：Replay Guard → ZKP → PLS（ρ≥γ）→ PQC。

点击 **「▶ 真算：正常认证全流程」**：每层高亮显示实测毫秒数；日志滚动 `[obu]`/`[rsu]` 各阶段；成功时 ρ 接近 1。

---

**Tab ② 攻击实验室（约 3–4 分钟）**

| 按钮 | 口播 |
|------|------|
| 🔁 重放 | 同一 AuthRequest 再发 → Replay Guard 5s 内拒绝，成功率 0% |
| 🕵️ 异地盗证 | 合法凭证+异地 CSI → PLS ρ 不足，成功率 0%；对照组关 PLS 为反事实 100% |
| ✂️ 篡改 | 改 message 保留签名 → PQC 失败，0% |
| 📶 远程中继 | CSI 强噪声 → PLS 失败，0% |

盾牌显示 **RSU 已拦截** 或拦截层日志。

---

**Tab ③ 数据可视化（约 2–3 分钟）**

| 图表 | 口播 |
|------|------|
| KPI 四格 | RSU ~4.9 ms、通信 4158 B、Rubric ~95、攻击 0% |
| 延迟对比 | Yang/ECDH 亚毫秒但无 PQC/ZKP/PLS；本方案 ~5 ms RSU、~27 ms E2E |
| 通信分解 | 签名 2420 B + 公钥 1312 B 为主；ZKP 224 B、CSI 128 B |
| 攻击柱图 | 五类攻击全部 0% |
| Rubric 雷达 | 35 / 75 / 95 |
| 盗证消融 | PLS 开 0%、关 100%（对照）；SIS 伪造 0% vs Sigma 100% |

---

**收尾与 FAQ**

| 问题 | 回答 |
|------|------|
| 仿真还是真算？ | `/api/round` 后端真算；图表来自 CSV |
| 通信为何比 Yang 大？ | Dilithium 签名/公钥体积；可会话签名优化 |
| 无 PLS 盗证 100%？ | 反事实对照组，非本协议缺陷 |
| ZKP 是 SNARK？ | 当前 SIS-Σ-NIZK；长期可演进 SNARK |
| CSI 实测？ | Rayleigh + Group6 文献校准；可接 IEEE DataPort |

**三人分工（可选）**：A 开场+流程导览（~2 min）→ B 真算+攻击（~5 min）→ C 数据图表+收尾（~4 min）。

---

## 十、结论与展望

### 10.1 结论

1. **ZKP-PQC-PLS 四层融合**在可复现原型上同时应对量子威胁、隐私披露与盗证异地用。
2. **SIS-Σ-NIZK** 相对 Sigma 骨架伪造通过率 0% vs 100%。
3. **PLS 为防盗证必要条件**：主实验 0%，无 PLS 对照 100%（反事实）。
4. RSU ~5 ms 满足实时性讨论门槛；通信 ~4 KB 需与 V2X 带宽权衡。

### 10.2 局限

- `dilithium-py` 为教育实现；生产建议 liboqs / 硬件加速。
- PLS 默认 Rayleigh 仿真；已接入 V2X 文献校准 CSI，待扩展 IEEE DataPort 实测。
- 非 NS-3 全网仿真；基线与本方案均为 Python 密码学原型 benchmark。
- ZKP 为 SIS-Σ-NIZK，匿名语义弱于 SNARK/环签名。

### 10.3 展望

| 阶段 | 方向 |
|------|------|
| 短期 | liboqs 后端、CSI 量化压缩、会话级签名降 OBU 延迟 |
| 中期 | 匿名凭证 / 环签名增强隐私语义 |
| 长期 | zk-SNARK 电路化策略断言（对齐 Hermes' Seal） |

---

## 十一、复现清单

```bash
cd iov_zkp_pqc_pls
pip install -r requirements.txt
python run_protocol.py                         # 单次演示
python scripts/run_all.py balanced             # 七组实验
python scripts/reproduce_honest_boundaries.py  # 答辩边界
python scripts/live_demo_server.py             # 演示大屏
python scripts/generate_paper_figures.py       # 论文插图（可选）
```

**关键输出**：`results/group1_main_comparison.csv` … `group7_zkp_innovation.csv`、`group_pls_theft_ablation.csv`

---

## 十二、参考文献

1. Yang Q. et al. A novel authentication and key agreement scheme for Internet of Vehicles. *Future Generation Computer Systems*, 145:415–428, 2023. DOI 10.1016/j.future.2023.04.004  
2. Chen et al. A Survey on Zero-Knowledge Authentication for IoT. *Electronics*, 2023. https://www.mdpi.com/2079-9292/12/5/1145  
3. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA). https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf  
4. Lyubashevsky V. Fiat-Shamir with aborts. CRYPTO 2009.  
5. PQ-TDAA. Post-Quantum Traceable Device Authentication. *J. Cybersecur. Priv.*, 2026. https://www.mdpi.com/2624-800X/6/2/44  
6. Hermes' Seal. arXiv:2603.26343, 2026. https://arxiv.org/abs/2603.26343  
7. Zhang et al. Forensics System for IoV Based on Post-Quantum Blockchain. *Sensors*, 2025.  
8. IEEE DataPort V2X CSI. DOI 10.21227/3mkx-aq02.  
9. Open Quantum Safe (liboqs). https://github.com/open-quantum-safe/liboqs  

---

*实验数字来自 `results/*.csv`（balanced 配置）；架构与算法描述与 `src/` 源码一致。本文档为项目唯一说明文档。*
