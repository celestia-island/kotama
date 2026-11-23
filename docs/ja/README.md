<p align="center"><img src="../../res/logo.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>リバースエンジニアリング・ツールキット：バイナリを静的に読める C へ分解し、ライブセッションで読み・走査・凍結、プラットフォーム別のインジェクションライブラリへパッケージング</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](../../LICENSE)

</div>

<br />

<div align="center">

[English](../../README.md) · [简体中文](../zh-Hans/README.md) · [繁體中文](../zh-Hant/README.md) · **日本語** · [한국어](../ko/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Русский](../ru/README.md) · [العربية](../ar/README.md)

</div>

名前は『ブルーアーカイブ』ミレニアム科学学校 Veritas の**音瀬コタマ**から —— Veritas の通信・情報
担当で、盗聴の専門家。このリポジトリでの意味は「プログラムをはっきり見る、そしてその言葉を記録する」。
CLI でもライブラリでもあり、shittim-chest / hikari のビューのひとつでもあります。

## 現在の状態

**P0 静的パイプラインは動作済み**（2026-11-23 の初回コミット、`master` 単一トランク）。
`kotama analyze <ファイル>` が ELF/PE ファイルをロード → 関数発見 → 基本ブロック単位の
デコンパイルまで実行します。

**ネイティブ Windows レーンは実装済み**（2026-11-23、Win10 Pro x64）：ネイティブ host の
attach/scan/write/freeze、named pipe またはループバック TCP 経由の LoadLibrary 注入、
PE exception/unwind と MSVC RTTI、RSDS 認証 PDB と dbghelp 照合、GNU/MSVC フィクスチャと
パッケージング。Windows では `just bench-windows` を実行（`--oracle` で Ghidra、
`KOTAMA_IDA` と `--ida` で IDA 差分）。

実証済みの範囲：

| 次元 | 現状 |
| --- | --- |
| コンテナ | ELF32 / ELF64 / PE32 / PE64（x86 と x64） |
| 関数発見 | 5 つの証拠経路（symtab / dynsym / PE64 `.pdata` / entry / 直接 call 先）、各行に provenance を付与 |
| 境界 | 正確な境界を優先（シンボル長、`.pdata`）。推定境界は線形走査で精緻化——共有テールブロックが真の関数を切断しなくなりました |
| デコンパイル | 基本ブロック + アドレスアンカー付きコメント。**密な switch のジャンプテーブルを復元**（ELF64 フィクスチャで 10/10 分岐、信頼度 100%） |
| 決定性 | 同一入力なら毎回バイト単位で同一の出力（差分と知識再利用の前提） |
| 検証済み | 24 個のマトリクスフィクスチャ + `/bin/true`、`/bin/ls` など strip されたシステムバイナリ |

既知の限界：PE の正確な関数境界は PDB に依存（zig -g が伴生 PDB を生成。PDB なしでは
call 先 + 線形走査でカバー）。Ghidra / IDA 差分オラクルは接続済みです。型推論・
構造体復元・GUI/サービス面は未着手です。

設計決定と経過の記録は PR の説明に残します（設計ドキュメントはソースツリーに入れません）。

## ケイパビリティマップ

| 領域 | 内容 | 段階 |
| --- | --- | --- |
| 静的 | ロード → 関数発見 → 基本ブロック デコンパイル → SEH/RTTI/PDB 証拠と Ghidra/IDA 差分 ✅ / 型推論 · 構造体 | P0 ✅ / P1 |
| 動的 | インジェクション（Windows / Linux 両線）→ メモリ/スタック/スナップショット → 走査/凍結 → hook / trace | P2–P4 |
| パッケージ | `hooks.toml` + hook ソース → プラットフォーム別インジェクションライブラリ + マニフェスト（ABI / ケイパビリティ / ダイジェスト） | P4 |
| 面 | サービス（REST / WS / MCP）+ hikari web UI + evernight リモートノード | P5–P6 |

すべての土台は二つ：

1. **アドレス空間抽象の一本化**：ファイルイメージ、ライブプロセス、メモリスナップショットが同じ
   `AddressSpace` を実装し、関数発見とデコンパイルは三つに対して同一パイプラインで走ります。
1. **コンテンツアドレス方式の関数同一性**：`kotama://<モジュール指紋>/<rva>` は ASLR / 再起動 /
   マシン移行を跨いで安定——注釈と結論がノード間を移動できます。

## クイックスタート

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # バージョン + ペイロード ABI バージョン
cargo run -p kotama-cli -- analyze <ファイル>  # 関数テーブル JSON（証拠付き）
cargo run -p kotama-cli -- analyze <ファイル> --decompile --limit 8   # 疑似 C 付き
python3 tools/build_fixtures.py --run --host-samples   # フィクスチャマトリクス + 実行スモーク
```

フィクスチャマトリクス：`x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0` × 6 ターゲット（loops / switch / indirect / strings / float / recurs）。ELF はネイティブ
実行、PE は既定で wine 経由（`KOTAMA_WINE`、リポジトリ AGENTS「ローカル実行時依存」参照）。

## 境界

許可されたターゲットにのみ使用：自分のソフトウェア、自分のデバイス、明示的に許可された研究サンプル。
本リポジトリはアンチ検知（検出回避）・永続化・認証情報窃取・アンチチート回避を**行いません**。
メモリ書き込みと凍結は既定で無効で、明示的なケイパビリティ宣言が必要——読み取り専用解析が
既定の姿勢です。

## コントリビュート

マージ基準は高めですが、焦点の絞られた貢献を歓迎します——[CONTRIBUTING.md](../../CONTRIBUTING.md)。
セキュリティ問題は公開 issue を立て**ないで**ください——[SECURITY.md](../../SECURITY.md)。

## ライセンス

[SySL 1.0](../../LICENSE)。
