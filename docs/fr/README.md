<p align="center"><img src="../../res/logo.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>Boîte à outils d'ingénierie inverse : disséquer statiquement les binaires en C lisible, puis lire, scanner et figer les sessions vivantes — empaqueté en bibliothèques d'injection par plateforme</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](../../LICENSE)

</div>

<br />

<div align="center">

[English](../../README.md) · [简体中文](../zh-Hans/README.md) · [繁體中文](../zh-Hant/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [Español](../es/README.md) · **Français** · [Русский](../ru/README.md) · [العربية](../ar/README.md)

</div>

Le nom vient de **Kotama** (音瀬コタマ), du club Veritas de la Millennium Science School dans
*Blue Archive* — spécialiste des communications et du renseignement du club, experte en écoute.
Pour ce dépôt, cela se lit : *voir le programme clairement, et enregistrer ce qu'il dit*.
À la fois CLI et bibliothèque — et une vue au sein de shittim-chest / hikari.

## État

**Le pipeline statique P0 fonctionne** (premier commit 2026-11-23, tronc unique `master`).
`kotama analyze <fichier>` charge un fichier ELF/PE → découvre les fonctions → les décompile
en pseudo-C au niveau des blocs de base.

Périmètre démontré :

| Dimension | État |
| --- | --- |
| Conteneurs | ELF32 / ELF64 / PE32 / PE64 (x86 et x64) |
| Découverte de fonctions | Cinq canaux de preuve (symtab / dynsym / `.pdata` PE64 / entry / cibles d'appel directes), chaque ligne porte sa provenance |
| Frontières | D'abord les frontières exactes (longueurs de symboles, `.pdata`) ; les inférées sont affinées par balayage linéaire — les blocs de queue partagés ne tronquent plus les vraies fonctions |
| Décompilation | Blocs de base + commentaires avec ancres d'adresse ; **les tables de saut des switch denses sont récupérées** (10/10 branches sur la matrice ELF64, confiance 100 %) |
| Déterminisme | Même entrée, sortie identique octet par octet à chaque exécution (le prérequis du diff et de la réutilisation des connaissances) |
| Vérifié sur | 24 cibles de la matrice de fixtures plus des binaires système dénudés comme `/bin/true` et `/bin/ls` |

Limites connues (périmètre P1) : les frontières exactes des fonctions PE dépendent du PDB (les
fixtures mingw n'en embarquent pas aujourd'hui ; cibles d'appel + balayage linéaire les couvrent) ;
l'inférence de types, la récupération de structs et l'oracle différentiel Ghidra ne sont pas
encore câblés.

Les décisions de conception et les registres de processus vivent dans les descriptions de PR
(les documents de conception n'entrent pas dans l'arbre source).

## Carte des capacités

| Domaine | Contenu | Étape |
| --- | --- | --- |
| Statique | chargement → découverte → décompilation en blocs de base ✅ / inférence de types · structs · oracle différentiel | P0 ✅ / P1 |
| Dynamique | injection (Windows / Linux) → mémoire / pile / instantanés → scan / gel → hook / trace | P2–P4 |
| Empaquetage | `hooks.toml` + sources de hooks → bibliothèques d'injection par plateforme + manifestes (ABI / capacités / empreintes) | P4 |
| Surface | services (REST / WS / MCP) + interface web hikari + nœuds distants evernight | P5–P6 |

Deux fondations sur lesquelles tout le reste s'appuie :

1. **Une seule abstraction d'espace d'adressage** : images de fichiers, processus vivants et
   instantanés mémoire implémentent la même `AddressSpace` ; la découverte et la décompilation
   exécutent un seul pipeline sur les trois.
1. **Identité de fonction par contenu** : `kotama://<empreinte-du-module>/<rva>` reste stable à
   travers ASLR, redémarrages et changements de machine — annotations et conclusions peuvent
   voyager entre les nœuds.

## Démarrage rapide

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # version + version ABI du payload
cargo run -p kotama-cli -- analyze <fichier>  # table des fonctions en JSON (avec preuves)
cargo run -p kotama-cli -- analyze <fichier> --decompile --limit 8   # avec pseudo-C
python3 tools/build_fixtures.py --run --host-samples   # matrice de fixtures + fumée d'exécution
```

Matrice de fixtures : `x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0` × 6 cibles (loops / switch / indirect / strings / float / recurs). L'ELF tourne
nativement ; le PE passe par wine par défaut (`KOTAMA_WINE`, voir l'AGENTS du dépôt,
« dépendances locales d'exécution »).

## Limites

À utiliser uniquement sur des cibles autorisées : vos propres logiciels, vos propres machines,
ou des échantillons de recherche qui vous ont été explicitement confiés. Ce dépôt **ne fait**
pas d'evasion, d'anti-détection, de persistance, de vol d'identifiants ni de contournement
d'anticheat. L'écriture mémoire et le gel sont désactivés par défaut et exigent une concession
explicite de capacité — l'analyse en lecture seule est la posture par défaut.

## Contribuer

Barre de fusion haute ; les contributions ciblées sont bienvenues — voir
[CONTRIBUTING.md](../../CONTRIBUTING.md). Pour les problèmes de sécurité, **n'ouvrez pas**
d'issue publique — voir [SECURITY.md](../../SECURITY.md).

## Licence

[SySL 1.0](../../LICENSE).
