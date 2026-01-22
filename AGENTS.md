<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# 项目助手指南（evidence_chain）

## 项目概述
- **定位**：`evidence_chain` 是一个 Python 3.11 CLI，用于扫描输入目录、生成证据清单/哈希树/报告，并将每次取证结果追加到全局的不可变链（`chain.jsonl` + `HEAD.json`）。
- **依赖**：仅使用 Python 标准库；TSA 交互依赖系统 `openssl` 与 `curl`。

## 关键约束
- **不可变链**：链条为 append-only；避免修改或重写已有链条与 case 目录内容。
- **哈希格式**：所有 SHA256 输出为 `sha256:<hex>` 前缀格式。
- **TSA 强制**：默认收集过程要求 TSA 时间戳；若不可达会返回失败并不追加链条。
- **路径安全**：使用规范化相对路径；禁止 `..` 逃逸路径。

## 典型命令
- 取证收集：`python -m evidence_chain collect <input_dir> --repo <repo_path>`
- 验证单案：`python -m evidence_chain verify-case --repo <repo_path> --case-id <case_id>`
- 验证链：`python -m evidence_chain verify-chain --repo <repo_path>`
- 测试：`python -m unittest`

