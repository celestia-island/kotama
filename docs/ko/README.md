<p align="center"><img src="../../res/logo.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>리버스 엔지니어링 도구 모음: 바이너리를 정적으로 읽을 수 있는 C로 분해하고, 라이브 세션에서 읽고·스캔하고·고정하며, 플랫폼별 인젝션 라이브러리로 패키징합니다</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](../../LICENSE)

</div>

<br />

<div align="center">

[English](../../README.md) · [简体中文](../zh-Hans/README.md) · [繁體中文](../zh-Hant/README.md) · [日本語](../ja/README.md) · **한국어** · [Español](../es/README.md) · [Français](../fr/README.md) · [Русский](../ru/README.md) · [العربية](../ar/README.md)

</div>

이름은 《블루 아카이브》 밀레니엄 과학학교 Veritas의 **오토세 코타마(音瀬コタマ)**에서
왔습니다 — Veritas의 통신·정보 담당이자 도청 전문가. 이 저장소에서의 의미는
"프로그램을 또렷이 보고, 그가 하는 말을 기록한다"입니다. CLI이자 라이브러리이며,
shittim-chest / hikari의 뷰이기도 합니다.

## 현재 상태

**P0 정적 파이프라인이 동작합니다**(2026-11-23 첫 커밋, `master` 단일 트렁크).
`kotama analyze <파일>`이 ELF/PE 파일을 로드 → 함수 발견 → 기본 블록 단위 디컴파일까지
수행합니다.

**네이티브 Windows 레인 구현 완료**(2026-11-23, Win10 Pro x64): 네이티브 host
attach/scan/write/freeze, named pipe 또는 루프백 TCP를 통한 LoadLibrary 주입,
PE exception/unwind와 MSVC RTTI, RSDS 인증 PDB와 dbghelp 대조, GNU/MSVC 픽스처 및
패키징. Windows에서 `just bench-windows` 실행(`--oracle`는 Ghidra, `KOTAMA_IDA`와
`--ida`는 IDA 차등).

검증된 범위:

| 차원 | 현황 |
| --- | --- |
| 컨테이너 | ELF32 / ELF64 / PE32 / PE64 (x86 및 x64) |
| 함수 발견 | 다섯 갈래 증거(symtab / dynsym / PE64 `.pdata` / entry / 직접 call 대상), 각 행에 provenance |
| 경계 | 정확한 경계 우선(심볼 길이, `.pdata`). 추정 경계는 선형 스캔으로 정제 — 꼬리 블록 공유가 진짜 함수를 잘라내지 않습니다 |
| 디컴파일 | 기본 블록 + 주소 앵커 주석. **밀집 switch의 점프 테이블 복원**(ELF64 픽스처 10/10 분기, 신뢰도 100%) |
| 결정성 | 같은 입력이면 매 실행 바이트 단위로 동일한 출력(차등 비교와 지식 재사용의 전제) |
| 검증 대상 | 전체 픽스처 매트릭스 + `/bin/true`, `/bin/ls` 등 strip된 시스템 바이너리 |

알려진 한계: PE의 정확한 함수 경계는 PDB에 의존(zig -g가 loops.pdb를 생성하며, 없으면
call 대상 + 선형 스캔으로 커버). Ghidra / IDA 차등 오라클은 연결되었습니다. 타입 추론,
구조체 복원, GUI/서비스 면은 미착수입니다.

설계 결정과 진행 기록은 PR 설명에 남깁니다(설계 문서는 소스 트리에 넣지 않습니다).

## 기능 맵

| 영역 | 내용 | 단계 |
| --- | --- | --- |
| 정적 | 로드 → 함수 발견 → 기본 블록 디컴파일 → SEH/RTTI/PDB 증거와 Ghidra/IDA 차등 ✅ / 타입 추론 · 구조체 | P0 ✅ / P1 |
| 동적 | 인젝션 (Windows / Linux 양선) → 메모리/스택/스냅샷 → 스캔/고정 → hook / trace | P2–P4 |
| 패키징 | `hooks.toml` + hook 소스 → 플랫폼별 인젝션 라이브러리 + 매니페스트(ABI / 기능 / 다이제스트) | P4 |
| 서비스면 | 서비스 (REST / WS / MCP) + hikari web UI + evernight 원격 노드 | P5–P6 |

모든 것의 두 가지 기초:

1. **하나의 주소 공간 추상화**: 파일 이미지, 라이브 프로세스, 메모리 스냅샷이 같은 `AddressSpace`를
   구현하며, 함수 발견과 디컴파일은 셋에 동일 파이프라인으로 실행됩니다.
1. **내용 주소 함수 식별자**: `kotama://<모듈 지문>/<rva>`는 ASLR / 재시작 / 장비 교체를 넘어 안정 —
   주석과 결론이 노드 사이를 이동할 수 있습니다.

## 빠른 시작

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # 버전 + 페이로드 ABI 버전
cargo run -p kotama-cli -- analyze <파일>  # 함수 테이블 JSON (증거 포함)
cargo run -p kotama-cli -- analyze <파일> --decompile --limit 8   # 의사 C 포함
python3 tools/build_fixtures.py --run --host-samples   # 픽스처 매트릭스 + 실행 스모크
```

픽스처 매트릭스: `x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0` × 6개 대상(loops / switch / indirect / strings / float / recurs). ELF는 네이티브 실행,
PE는 기본값으로 wine 경유(`KOTAMA_WINE`, 저장소 AGENTS "로컬 런타임 의존성" 참조).

## 경계

허가된 대상에만 사용: 자신의 소프트웨어, 자신의 장치, 명시적으로 허가된 연구 샘플. 이 저장소는
회피·탐지 회피·퍼시스턴스·자격 증명 탈취·안티치트 우회를 **하지 않습니다**. 메모리 쓰기와 고정은
기본값으로 꺼져 있고 명시적 기능 선언이 필요 — 읽기 전용 분석이 기본 자세입니다.

## 기여

병합 기준은 높지만 집중된 기여를 환영합니다 — [CONTRIBUTING.md](../../CONTRIBUTING.md).
보안 문제는 공개 issue로 열지 **마세요** — [SECURITY.md](../../SECURITY.md).

## 라이선스

[SySL 1.0](../../LICENSE).
