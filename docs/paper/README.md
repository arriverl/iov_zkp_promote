# 学术论文材料包

## 主文档

**[ZKP-PQC-PLS_IoV_学术论文.md](ZKP-PQC-PLS_IoV_学术论文.md)** — 整合全部项目文档的完整论文（中英文摘要、10 幅图、实验表、参考文献）。

### 公式显示说明

| 现象 | 原因 | 解决办法 |
|------|------|----------|
| 公式显示 `\text{...}`、`$$` 等乱码 | 原稿使用 **LaTeX 数学语法**，GitHub README、普通 Markdown 预览**不支持** MathJax | 已改为 **代码块 + Unicode**（ρ、γ、σ、π、←），任意 Markdown 阅读器均可正常显示 |
| 需要印刷级公式 | 导出 Word/PDF 时用 Typora/Pandoc，或自行改回 LaTeX 版 | 见下方 Pandoc 命令 |

当前论文**不再使用** `$$...$$` 与 `$...$` 包裹的 LaTeX 公式。

## 图表（300 DPI 级）

运行：

```bash
python scripts/generate_paper_figures.py
```

输出目录：`docs/paper/figures/`

| 图 | 内容 |
|----|------|
| fig1 | 系统总体架构 |
| fig2 | 协议交互流程 |
| fig3 | 威胁模型映射 |
| fig4 | 性能主对比（RSU/端到端/通信） |
| fig5 | 通信开销环形图 |
| fig6 | SecurityRubric 雷达图 |
| fig7 | 攻击仿真 |
| fig8 | PLS 盗证消融 |
| fig9 | 参数敏感性 |
| fig10 | 文献能力对比 |

## 导出 Word/PDF 建议

1. 用 Typora / VS Code Markdown PDF 插件打开 `ZKP-PQC-PLS_IoV_学术论文.md`
2. 或 Pandoc：`pandoc ZKP-PQC-PLS_IoV_学术论文.md -o paper.docx --resource-path=.:figures`
3. 插图已使用相对路径 `figures/fig*.png`，导出时保持目录结构
