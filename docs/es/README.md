<p align="center"><img src="../../res/logo.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>Kit de ingeniería inversa: disecciona binarios estáticamente hacia C legible, lee, escanea y congela sesiones en vivo, y lo empaqueta todo en librerías de inyección por plataforma</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](../../LICENSE)

</div>

<br />

<div align="center">

[English](../../README.md) · [简体中文](../zh-Hans/README.md) · [繁體中文](../zh-Hant/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · **Español** · [Français](../fr/README.md) · [Русский](../ru/README.md) · [العربية](../ar/README.md)

</div>

El nombre viene de **Kotama** (音瀬コタマ), del club Veritas de la Millennium Science School en
*Blue Archive* — especialista en comunicaciones e inteligencia del club, experta en escuchas.
Para este repositorio se lee como: *ver el programa con claridad y grabar lo que dice*.
Es CLI y biblioteca a la vez — y una vista dentro de shittim-chest / hikari.

## Estado

**La tubería estática P0 funciona** (primer commit 2026-11-23, tronco único `master`).
`kotama analyze <archivo>` carga un fichero ELF/PE → descubre funciones → las decompila a
pseudo-C a nivel de bloques básicos.

Alcance demostrado:

| Dimensión | Estado |
| --- | --- |
| Contenedores | ELF32 / ELF64 / PE32 / PE64 (x86 y x64) |
| Descubrimiento de funciones | Cinco canales de evidencia (symtab / dynsym / `.pdata` PE64 / entry / destinos de llamada directos), cada fila con su provenance |
| Límites | Primero los límites exactos (longitudes de símbolos, `.pdata`); los inferidos se refinan con barrido lineal — los bloques de cola compartidos ya no truncan funciones reales |
| Decompilación | Bloques básicos + comentarios con anclas de dirección; **las tablas de salto de los switch densos se recuperan** (10/10 ramas en la matriz ELF64, confianza 100%) |
| Determinismo | Misma entrada, salida byte a byte idéntica en cada ejecución (la condición previa para el diff y la reutilización de conocimiento) |
| Verificado en | 24 objetivos de la matriz de fixtures más binarios del sistema despojados como `/bin/true` y `/bin/ls` |

Límites conocidos (alcance P1): los límites exactos de funciones PE dependen de PDB (los fixtures
mingw no traen hoy; los cubren destinos de llamada + barrido lineal); la inferencia de tipos, la
recuperación de structs y el oráculo diferencial de Ghidra aún no están conectados.

Las decisiones de diseño y los registros de proceso viven en las descripciones de los PR
(los documentos de diseño no entran en el árbol fuente).

## Mapa de capacidades

| Área | Contenido | Etapa |
| --- | --- | --- |
| Estático | carga → descubrimiento → decompilación de bloques básicos ✅ / inferencia de tipos · structs · oráculo diferencial | P0 ✅ / P1 |
| Dinámico | inyección (Windows / Linux) → memoria / pila / instantáneas → escaneo / congelación → hook / trace | P2–P4 |
| Empaquetado | `hooks.toml` + fuentes de hooks → librerías de inyección por plataforma + manifiestos (ABI / capacidades / resúmenes) | P4 |
| Superficie | servicios (REST / WS / MCP) + interfaz web hikari + nodos remotos evernight | P5–P6 |

Dos cimientos sobre los que se apoya todo lo demás:

1. **Una sola abstracción de espacio de direcciones**: imágenes de fichero, procesos vivos e
   instantáneas de memoria implementan la misma `AddressSpace`; el descubrimiento y la
   decompilación ejecutan una sola tubería contra las tres.
1. **Identidad de funciones por contenido**: `kotama://<huella-del-módulo>/<rva>` permanece
   estable frente a ASLR, reinicios y cambios de máquina — las anotaciones y conclusiones
   pueden viajar entre nodos.

## Inicio rápido

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # versión + versión ABI del payload
cargo run -p kotama-cli -- analyze <archivo>  # tabla de funciones como JSON (con evidencia)
cargo run -p kotama-cli -- analyze <archivo> --decompile --limit 8   # más pseudo-C
python3 tools/build_fixtures.py --run --host-samples   # matriz de fixtures + humo de ejecución
```

Matriz de fixtures: `x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0` × 6 objetivos (loops / switch / indirect / strings / float / recurs). ELF corre
nativo; PE corre bajo wine por defecto (`KOTAMA_WINE`, véase el AGENTS del repositorio,
"dependencias locales de ejecución").

## Límites

Úsalo solo sobre objetivos autorizados: tu propio software, tus propios dispositivos, o muestras
de investigación que te hayan sido concedidas explícitamente. Este repositorio **no** hace
evasión, antidetección, persistencia, robo de credenciales ni bypass de anticheat. La escritura
en memoria y la congelación están desactivadas por defecto y requieren una concesión explícita
de capacidad — el análisis de solo lectura es la postura predeterminada.

## Contribuir

Barra de fusión alta; se agradecen las contribuciones enfocadas — véase
[CONTRIBUTING.md](../../CONTRIBUTING.md). Para temas de seguridad **no** abras issues
públicos — véase [SECURITY.md](../../SECURITY.md).

## Licencia

[SySL 1.0](../../LICENSE).
