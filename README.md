# ZKP-PQC-PLS 融合架构：创新型 IoV 安全认证

本仓库实现了面向车联网身份认证的 ZKP + PQC + PLS 融合方案，并补充为可复现研究系统。

## 核心能力

- PQC：Dilithium/ML-DSA 格签名（抗量子）
- ZKP：Sigma + Fiat–Shamir 非交互证明（匿名认证骨架）
- PLS：CSI 指纹第二因子（防远程冒充）
- 会话绑定：`IoVAuthFrame` 绑定 RSU、时间窗、nonce

## 新增研究模块

- `src/attacks/`：攻击仿真（重放、冒充、证书窃取、远程中继、篡改）
- `src/ablation/`：消融实验（去 ZKP / 去 PLS / 去会话绑定 / PQC only）
- `configs/`：`fast`、`balanced`、`high_security` 三套参数
- `scripts/`：`run_all.py` 一键五组实验，`plot_results.py` 导出图表

## 快速开始

```bash
cd iov_zkp_pqc_pls
pip install -r requirements.txt
python run_protocol.py
```

## 五组实验一键运行

```bash
python scripts/run_all.py balanced
python scripts/plot_results.py
```

输出目录：`results/`

- `group1_main_comparison.csv`
- `group2_ablation.csv`
- `group3_attacks.csv`
- `group4_sensitivity.csv`
- `group5_scalability.csv`
- `summary.csv`
- `plots/*.png`

## 论文调研文档

- `docs/RESEARCH_REPORT.md`
- `docs/LITERATURE_AND_INNOVATION.md`

## 说明

本项目用于研究与教学。`dilithium-py` 为教育实现，生产环境建议替换为 OQS/C 后端。
