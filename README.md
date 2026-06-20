# ZKP-PQC-PLS 融合架构：创新型 IoV 安全认证

面向车联网（IoV/V2X）身份认证的 **后量子密码（PQC）+ 零知识证明（ZKP）+ 物理层安全（PLS）** 融合原型，含七组可复现实验、攻击仿真、真算演示大屏。

**完整项目文档（唯一）**：[docs/PROJECT.md](docs/PROJECT.md)

---

## 核心能力

| 模块 | 实现 | 作用 |
|------|------|------|
| **PQC** | CRYSTALS-Dilithium2 / ML-DSA | 抗量子签名与完整性 |
| **ZKP** | SIS-Σ-NIZK（默认）+ Sigma 对照 | 最小披露式格零知识证明 |
| **PLS** | CSI 指纹 + 皮尔逊相关 | 防异地盗证第二因子 |
| **会话** | `IoVAuthFrame` + Replay Guard | RSU/nonce/时间窗绑定，防重放 |

---

## 快速开始

```bash
cd iov_zkp_pqc_pls
pip install -r requirements.txt
python run_protocol.py
python scripts/run_all.py balanced
```

## 演示大屏

```bash
pip install flask
python scripts/live_demo_server.py
# http://127.0.0.1:8765/showcase.html
```

| 页面 | 说明 |
|------|------|
| `docs/demo/showcase.html` | 流程仿真 / 攻击实验室 / 数据可视化 |
| `docs/demo/traffic_simulator.html` | 真算传输动画 |
| `docs/demo/index.html` | 静态总览 |

---

## 最新结果速览（`balanced`）

| 协议 | RSU (ms) | 端到端 (ms) | 通信 (B) |
|------|----------|-------------|----------|
| Yang 基线 | ~0.07 | ~0.18 | 227 |
| ECDH+AES | ~0.09 | ~0.18 | 117 |
| **本方案** | **~4.9** | **~27** | **4158** |

五类攻击成功率 **0%**；盗证主实验（PLS 开）**0%**。详见 [docs/PROJECT.md](docs/PROJECT.md)。

---

## 目录结构

```
iov_zkp_pqc_pls/
├── src/              # pqc, zkp, pls, protocol, baselines, attacks, demo
├── scripts/          # run_all, live_demo_server, plot_results
├── configs/          # fast / balanced / high_security
├── docs/PROJECT.md   # 唯一项目文档
├── docs/demo/        # 演示网页
└── results/          # CSV + plots
```

---

## 说明与局限

- 研究/教学原型；`dilithium-py` 为教育实现，生产建议 **liboqs**。
- PLS 默认 Rayleigh 仿真 + V2X 文献校准 CSI（Group6）。
- 详细背景、文献、实验、演讲稿见 **[docs/PROJECT.md](docs/PROJECT.md)**。
