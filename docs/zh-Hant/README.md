<p align="center"><img src="../../res/logo.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>逆向工程工具庫：靜態拆解出可讀的 C，活體會話裡讀、掃、凍結，打包成各平台的注入庫</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](../../LICENSE)

</div>

<br />

<div align="center">

[English](../../README.md) · [简体中文](../zh-Hans/README.md) · **繁體中文** · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Русский](../ru/README.md) · [العربية](../ar/README.md)

</div>

名字來自《蔚藍檔案》千年科學學園 Veritas 社團的**音瀬コタマ**——Veritas 的通訊與情報擔當，
擅長竊聽。對這個倉的語義是「把程式看清，把它說的話錄下來」。既是 CLI 也是庫，
同時是 shittim-chest / hikari 的一個檢視。

## 目前狀態

**P0 靜態管線已跑通**（2026-11-23 首提交，`master` 單主幹）。
`kotama analyze <檔案>` 對一個 ELF/PE 檔做載入 → 函式發現 → 基本塊級反編譯。

**Windows 原生車道已落地**（2026-11-23，Win10 Pro x64）：原生 host attach/scan/write/freeze、
命名管道或回環 TCP 的 LoadLibrary 注入、PE exception/unwind 與 MSVC RTTI、RSDS 身分驗證
PDB 並以 dbghelp 交叉驗證、GNU/MSVC 夾具與打包車道。Windows 上執行 `just bench-windows`
（追加 `--oracle` 納入 Ghidra、設定 `KOTAMA_IDA` 後追加 `--ida` 納入 IDA）。

已實證的範圍：

| 維度 | 現狀 |
| --- | --- |
| 容器 | ELF32 / ELF64 / PE32 / PE64（x86 與 x64） |
| 函式發現 | 五路證據（symtab / dynsym / PE64 `.pdata` / entry / 直接 call 目標），每列帶 provenance |
| 邊界 | 精確邊界優先（符號長度、`.pdata`）；推斷邊界用線性掃描精化，共享尾塊不再切斷真函式 |
| 反編譯 | 基本塊 + 位址錨註釋；**稠密 switch 的跳轉表可恢復**（ELF64 夾具 10/10 分支、置信度 100%） |
| 確定性 | 同一輸入兩次輸出逐位元組相同（差分與知識庫複用的前提） |
| 已驗證 | 24 個矩陣夾具 + `/bin/true`、`/bin/ls` 等 strip 系統二進位檔 |

已知邊界（P1 範圍）：PE 的精確函式邊界依賴 PDB（當前 mingw 夾具無 PDB，靠 call 目標 + 線性掃描）；
Ghidra / IDA 差分 oracle 已接入。型別推斷、結構體恢復與 GUI/服務面尚未開始。

設計決策與過程記錄在 PR 描述中（設計文件不進倉樹）。

## 能力地圖

| 塊 | 內容 | 階段 |
| --- | --- | --- |
| 靜態 | 載入 → 函式發現 → 基本塊反編譯 → SEH/RTTI/PDB 證據與 Ghidra/IDA 差分 ✅ / 類型推斷 · 結構體 | P0 ✅ / P1 |
| 動態 | 注入（Windows / Linux 雙線）→ 記憶體/堆疊/快照 → 掃描/凍結 → hook / trace | P2–P4 |
| 打包 | `hooks.toml` + hook 原始碼 → 各平台注入庫 + 清單（ABI / 能力 / 摘要） | P4 |
| 面 | 服務（REST / WS / MCP）+ hikari web UI + evernight 遠端節點 | P5–P6 |

兩條地基，其它一切建在其上：

1. **一套位址空間抽象**：檔案映像、活體處理程序、記憶體快照實現同一個 `AddressSpace`，函式發現與
   反編譯對三者跑同一條管線。
1. **內容定址的函式身分**：`kotama://<模組指紋>/<rva>` 跨 ASLR / 重啟 / 換機器穩定，註釋與結論因此
   能在節點之間共享。

## 快速上手

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # 版本 + 載荷 ABI 版本
cargo run -p kotama-cli -- analyze <檔案>  # 函式表 JSON（帶證據）
cargo run -p kotama-cli -- analyze <檔案> --decompile --limit 8   # 附偽 C
python3 tools/build_fixtures.py --run --host-samples   # 四目標靶子矩陣 + 執行冒煙
```

夾具矩陣：`x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0` × 6 個靶子（loops / switch / indirect / strings / float / recurs）。ELF 本機直跑，
PE 預設經 wine（`KOTAMA_WINE`，見倉內 AGENTS「本機執行時期依賴」）。

## 邊界

只對授權目標使用：自有軟體、自有裝置、或使用者顯式指定的研究樣本。本倉**不做**免殺 / 反偵測 /
持久化 / 憑證竊取 / 反作弊繞過；寫記憶體與凍結預設關閉，需要顯式能力宣告——只讀分析是預設態。

## 參與

合併門檻高，歡迎聚焦的貢獻——見 [CONTRIBUTING.md](../../CONTRIBUTING.md)。
安全問題**不要**開公開 issue——見 [SECURITY.md](../../SECURITY.md)。

## 授權

[SySL 1.0](../../LICENSE)。
