<div align="center">

# 🔬 XTrace

### 通用 JavaScript 虚拟机保护(JSVMP)与混淆分析的运行时追踪工具

*给 Chromium 打一次补丁,加载任意页面,即可把混淆代码的运行时——API 调用、调用栈、值、加密材料、JSVMP hook 家族——以干净、结构化的 NDJSON 流式导出。*

[![release](https://img.shields.io/badge/release-v1.0.0-brightgreen)](https://github.com/linn0x/xtrace/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![platform](https://img.shields.io/badge/platform-macOS-lightgrey)]()
[![engine](https://img.shields.io/badge/engine-Chromium%20%2B%20V8-orange)]()

**中文** · [English](README.en.md)

</div>

---

## XTrace 是什么?

现代反分析代码往往藏身于 **JavaScript 虚拟机保护(JSVMP)** 和重度混淆之下:自定义字节码解释器、动态派发、Proxy 陷阱、字符串状态机、反调试计时器等等。直接读压缩后的源码几乎得不到任何信息——逻辑只在**运行时**才会显形。

XTrace 是一套**内建于打过补丁的 Chromium/V8 中的原生追踪工具**。它对 Blink 和 V8 做插桩,使得**正常加载一个页面**(无需断点单步、无需对目标做源码补丁)就能产出一份忠实的 **schema v1 NDJSON** 日志,记录被保护代码实际做的每一件事。你得到的是混淆运行时的数据流记录,可以离线校验、对比与分析。

它刻意做到**站点无关、通用**:同一套工具适用于任意混淆 JS 或 JSVMP 场景——从本地测试页,到你有权研究的任意 URL。

> ⚖️ **仅限授权使用。** XTrace 面向安全研究、反混淆学习,以及对**你有权测试**的系统与内容做防御性分析。它**不是**爬虫工具,**不是**反爬绕过产品,也**不会**生成绕过代码或签名。你需自行遵守适用的法律与服务条款。

---

## 为什么选 XTrace

- 🧩 **看穿 JSVMP** —— V8 运行时 hook 揭示源码级工具看不到的解释器行为:动态派发、Proxy 陷阱、字节缓冲、字符串编解码等。
- 🎯 **九类 JSVMP 相关 hook 家族** —— 每次抓取都可被校验,证明每个家族都有真实证据(值 / 引用 / 结果),而不只是名字。
- 🔐 **明文捕获加密材料** —— 抓取 digest/AES/HMAC 的**输入与输出**,涵盖 CryptoJS 风格的 `charCodeAt` 哈希以及 WASM 边界,并按时钟对齐到同一条 trace。
- 📏 **结构化且可验证** —— 稳定的 **schema v1 NDJSON**,配严格校验器:可拒绝被截断的值、不透明的引用,或无证据的家族命中。
- 🕵️ **数据流报告,而非黑魔法** —— 签名分析流水线把一次请求签名流程还原为 **输入 → 运算 → 输出** 的可审计报告。
- 🖥️ **由浏览器进程持有 trace** —— 渲染进程沙箱保持**开启**;事件经 `blink.mojom.XTraceHost`(Mojo IPC)传出,由浏览器进程负责写文件。
- 🧪 **开箱即用的实验环境** —— 自带混淆 / 逆向 / VMP 场景的测试页,外加 Python CLI 和 Electron 工作台。

### JSVMP hook 家族

`base64` · `text_codec` · `byte_buffer` · `dynamic_dispatch` · `proxy_trap` · `hash_crypto` · `int_bitwise` · `anti_debug_timing` · `source_probe`

---

## 工作原理

```
        ┌──────────────────────────────────────────────┐
        │   打补丁的 Chromium.app(由 patches/ 构建)      │
        │                                                │
        │   渲染进程(沙箱)              浏览器进程        │
        │   ┌─────────────────┐          ┌────────────┐  │
  任意   │   │ Blink + V8 hooks │──Mojo──▶ │  持有 trace │──┼──▶  trace.ndjson
  页面 ─┼──▶│ schema v1 NDJSON │  IPC     │    文件     │  │     (schema v1)
        │   └─────────────────┘          └────────────┘  │
        └──────────────────────────────────────────────┘
                                                   │
              xtrace-launcher(CLI)  ┌─────────────┴─────────────┐
              xtrace-gui(Electron)  │  校验 · 分析 · 对比 (diff) │
                                    └───────────────────────────┘
```

**兼容字段:** `t`、`api`、`args`、`stack`、`pid`、`tid`。
**扩展字段:** `event_id`、`session_id`、`seq`、`wall_time_us`、`mono_time_us`、`category`、`phase`、`frame_url`、`origin`、`result`、`error`、`truncated`。

详见 [`docs/runtime-trace-plan.md`](docs/runtime-trace-plan.md) 与 [`docs/trace-schema-v1.md`](docs/trace-schema-v1.md)。

---

## 快速开始

```bash
# 0. 前置:Python 3.10+(仅标准库),以及用于工作台的较新 Node/npm。
#    随时运行完整本地测试套件:  scripts/run_tests.sh

# 1. 拉取 depot_tools + Chromium(补丁对应的固定 revision)
scripts/bootstrap_chromium.sh

# 2. 应用补丁(0001 → chromium/src,0002 → chromium/src/v8)
scripts/apply_patches.sh

# 3. 构建打过补丁的浏览器
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/gn_gen_xtrace.sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/build_chromium.sh
# → chromium/src/out/XTrace/Chromium.app
```

> 🛠️ **构建前置条件:** macOS + 完整 Xcode(不能只装 Command Line Tools),约 **~100 GB** 空闲磁盘,以及数小时的干净 Chromium 构建时间。XTrace 以**补丁 + 构建脚本**形式发布,而非一份 Chromium 检出——`chromium/` 与 `depot_tools/` 已被 gitignore,只在你本机生成。固定 revision 与细节见 [`docs/chromium-build.md`](docs/chromium-build.md)。

### 抓取一条 trace

```bash
# 启动本地测试页服务
python3 scripts/serve_test_page.py --port 8765

# 用打过补丁的浏览器抓取
cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium ../chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8765/reverse-smoke.html \
  --log-dir ../logs \
  --xtrace-categories reverse,fingerprint \
  --xtrace-capture-values full \
  --xtrace-capture-assets full \
  --capture-seconds 60 \
  --validate-after-exit
```

[`test-pages/`](test-pages/) 下还有更多自包含测试页:`obfuscation-smoke.html`、`fingerprint-smoke.html`、`json-parse-smoke.html`,以及 worker/fetch 变体。

---

## 校验与分析

### 严格校验一条 JSVMP 相关的 trace

```bash
python3 scripts/validate_trace.py \
  --profile reverse \
  --schema-version 1 \
  --expect SubtleCrypto.importKey \
  --expect SubtleCrypto.sign \
  --require-vmp-family base64 \
  --require-vmp-family text_codec \
  --require-vmp-family byte_buffer \
  --require-vmp-family dynamic_dispatch \
  --require-vmp-family proxy_trap \
  --require-vmp-family hash_crypto \
  --require-vmp-family int_bitwise \
  --require-vmp-family anti_debug_timing \
  --require-vmp-family source_probe \
  --require-complete-values \
  --require-material-refs \
  --require-vmp-family-evidence \
  logs/your-capture.ndjson
```

| 参数 | 含义 |
|------|------|
| `--require-vmp-family NAME` | 若该 JSVMP 家族从未出现则判失败 |
| `--require-vmp-family-evidence` | 家族命中必须携带真实的值/引用/结果证据,而非仅有名字 |
| `--require-complete-values` | 拒绝被截断 / 预览 / 打码的值证据 |
| `--require-material-refs` | 拒绝仅有长度或不透明、缺少原始材料的引用 |

针对通用 VMP 抓取的严格 launcher 预设(默认 `--profile generic-vmp --strict-capture`):

```bash
cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher validate ../logs/your-capture.ndjson
```

### 分析(通用 VMP profile)

```bash
python3 scripts/analyze_vmp_trace.py \
  path/to/trace.ndjson \
  --profile generic-vmp \
  --json-output logs/vmp_summary.json

# 针对你自行提供、且有权研究的任意 URL:
scripts/run_generic_vmp_readonly.sh 'https://example.invalid/your-page'
```

可选的参数物化(materialization)检查(任意你关心的名字,并非绑定特定产品):

```bash
python3 scripts/validate_trace.py \
  path/to/trace.ndjson \
  --require-signature-param-materialization SOME_PARAM
```

### 签名分析流水线(输入 → 运算 → 输出)

一套可审计、站点无关的工作流,借助原生 trace 加免补丁注入的 API hook,把一次请求签名流程还原成**数据流报告**。`--inject-api-hooks` 会把 JS 层的明文 I/O(TextEncoder、`crypto.subtle.*` 的输入**与**输出、JSON、btoa、WASM 边界,以及用于 CryptoJS 风格哈希的 `String.scan`)并入同一份 NDJSON,并与原生 trace 按时钟对齐。它是**报告,而非 token 生成器**——详见 [`docs/sign-analysis-recipe.md`](docs/sign-analysis-recipe.md)。

---

## Electron 工作台

```bash
cd xtrace-gui
npm install
npm start
```

选择 Chromium、URL 与日志目录;开始/停止抓取;列出 NDJSON 文件;按 category/API 过滤实时跟踪(live-tail)。

---

## Trace 数据与隐私

Trace 默认以**全保真**捕获,以保证混淆与 JSVMP 的还原忠实——当抓取参数允许时,请求头、Cookie、令牌与请求体材料可能以明文出现。

- 存放于 `logs/`(**已 gitignore**),请保留在本机。
- 🚫 **未经审阅,请勿发布原始 `.ndjson`。**
- 导出时脱敏(redaction)已在计划中([`docs/trace-log-improvements.md`](docs/trace-log-improvements.md))。

---

## 仓库结构

```
patches/           # 0001 原生日志器,0002 V8 JSVMP hooks
scripts/           # 引导、构建、服务、校验、分析、sign_pipeline
xtrace-launcher/   # Python CLI:运行打补丁 Chromium,抓取 NDJSON
xtrace-gui/        # Electron 抓取 + 审阅工作台
test-pages/        # 本地测试用 HTML/JS(混淆 / 逆向 / VMP 场景)
docs/              # 设计、schema、构建说明
tests/             # 脚本 / 分析器的单元测试
```

**公开包中不包含:** 完整 Chromium 树、构建产物、`logs/` 下的原始 trace,以及 `local/` 下的本地压测材料(均 gitignore)。

### 增量重链接(进阶)

若 ninja 图已损坏但目标文件仍完好,`scripts/solink_xtrace_dylibs.py` 可只重新编译 XTrace 触及的编译单元,并 solink 出 `libv8.dylib` / `libchrome_dll.dylib`,无需完整重建 `chrome`。ninja 图健康时,仍优先走常规 ninja 构建。

---

## 文档

| 文档 | 内容 |
|------|------|
| [`docs/superpowers/specs/2026-06-27-chromium-xtrace-design.md`](docs/superpowers/specs/2026-06-27-chromium-xtrace-design.md) | 设计方案 |
| [`docs/superpowers/plans/2026-06-27-chromium-xtrace-proof-of-life.md`](docs/superpowers/plans/2026-06-27-chromium-xtrace-proof-of-life.md) | 实施计划 |
| [`docs/chromium-build.md`](docs/chromium-build.md) | 构建说明、固定 revision、GN 参数、排错 |
| [`docs/trace-schema-v1.md`](docs/trace-schema-v1.md) | Trace schema |
| [`docs/trace-schema-v2.md`](docs/trace-schema-v2.md) | 因果 schema v2(`--xtrace-causality=sync` opt-in) |
| [`docs/sign-analysis-recipe.md`](docs/sign-analysis-recipe.md) | 签名分析 recipe |
| [`docs/trace-log-improvements.md`](docs/trace-log-improvements.md) | Trace 日志改进 |
| [`docs/runtime-trace-plan.md`](docs/runtime-trace-plan.md) | 运行时 trace 路线图 |

### 补丁

- `patches/0001-xtrace-native-logger.patch` → `chromium/src`(Blink / 浏览器网络日志)
- `patches/0002-xtrace-v8-vmp-hooks.patch` → `chromium/src/v8`(JSVMP 相关运行时 hooks)
- `patches/0003-xtrace-schema-v2-renderer.patch` → `chromium/src`(渲染器同步因果身份,opt-in)
- `patches/0004-xtrace-schema-v2-browser.patch` → `chromium/src`(网络边界记录标记 external)

---

## 许可证

**MIT** —— 见 [`LICENSE`](LICENSE)。打过补丁的 Chromium / Blink / V8 部分仍遵循 The Chromium Authors 的 BSD 3-Clause 许可;详见 Chromium 与 V8 上游的 `LICENSE` 文件。
