<p align="center"><img src="../../res/logo.webp" alt="Kotama" width="180"/></p>

<h1 align="center">Kotama</h1>

<div align="center">
<strong>مجموعة أدوات للهندسة العكسية: تفكيك الملفات التنفيذية ساكنًا إلى C مقروء، ثم قراءة الجلسات الحية ومسحها وتجميدها — مع تغليف كل ذلك في مكتبات حقن لكل منصة</strong>
</div>

<br />

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/ci.yml?label=CI)](https://github.com/celestia-island/kotama/actions/workflows/ci.yml)
[![depspec](https://img.shields.io/github/actions/workflow/status/celestia-island/kotama/depspec-lint.yml?label=depspec)](https://github.com/celestia-island/kotama/actions/workflows/depspec-lint.yml)
[![License: SySL 1.0](https://img.shields.io/badge/license-SySL%201.0-blue)](../../LICENSE)

</div>

<br />

<div align="center">

[English](../../README.md) · [简体中文](../zh-Hans/README.md) · [繁體中文](../zh-Hant/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Русский](../ru/README.md) · **العربية**

</div>

الاسم من **كوتاما** (音瀬コタマ) من نادي Veritas في مدرسة ميلينيوم العلمية في *Blue Archive* —
مسؤولة الاتصالات والمعلومات في النادي وخبيرة التنصت. دلالتها لهذا المستودع:
*انظر إلى البرنامج بوضوح، وسجّل ما يقوله*. وهي أداة سطر أوامر ومكتبة في آن —
وواجهة عرض داخل shittim-chest / hikari.

## الحالة

**خط الأنابيب الساكن P0 يعمل** (الالتقاط الأول 2026-11-23، جذع `master` واحد).
ينفّذ `kotama analyze <ملف>` تحميل ملف ELF/PE → اكتشاف الدوال → تفكيكًا إلى شبه-C
على مستوى الكتل الأساسية.

**مسارات Windows الأصلية منجزة** (2026-11-23، Win10 Pro x64): host أصلي
attach/scan/write/freeze، حقن LoadLibrary عبر named pipe أو TCP محلي، PE exception/unwind
و MSVC RTTI، PDB موثّق بـ RSDS ومقارن بـ dbghelp، ومصفوفة GNU/MSVC وحزم. شغّل
`just bench-windows` على Windows (أضف `--oracle` لـ Ghidra و`--ida` مع `KOTAMA_IDA` لـ IDA).

النطاق المُثبت:

| البعد | الحالة |
| --- | --- |
| الحاويات | ELF32 / ELF64 / PE32 / PE64 (x86 و x64) |
| اكتشاف الدوال | خمس قنوات أدلة (symtab / dynsym / `.pdata` في PE64 / entry / أهداف call المباشرة)، ولكل سطر مصدر دليلها |
| الحدود | الحدود الدقيقة أولًا (أطوال الرموز، `.pdata`)؛ والمستنتجة تُصقَل بمسح خطي — الكتل الخلفية المشتركة لم تعد تقطع الدوال الحقيقية |
| التفكيك | كتل أساسية + تعليقات بمراسٍ عنوانية؛ **جداول القفز لبيانات switch الكثيفة تُستعاد** (10/10 تفريعات على مصفوفة ELF64، ثقة 100٪) |
| الحتمية | المدخل نفسه يعطي مخرجات متطابقة بايتًا بايت في كل تشغيل (شرط المقارنة وإعادة استخدام المعرفة) |
| تم التحقق على | مصفوفة الفيكستشر الكاملة بالإضافة إلى تنفيذات نظام مجردة مثل `/bin/true` و `/bin/ls` |

حدود معروفة: الحدود الدقيقة لدوال PE تعتمد على PDB (ينتج zig -g ملف loops.pdb؛ وبدونه
تغطيها أهداف call والمسح الخطي)؛ أوراكل Ghidra/IDA موصولة الآن. استدلال الأنواع
واستعادة البِنى وواجهة GUI/الخدمة لم تبدأ بعد.

قرارات التصميم وسجلات العملية تسكن في أوصاف طلبات الدمج (وثائق التصميم لا تدخل شجرة المصادر).

## خريطة القدرات

| المجال | المحتوى | المرحلة |
| --- | --- | --- |
| الساكن | تحميل → اكتشاف دوال → تفكيك كتل أساسية → أدلة SEH/RTTI/PDB وفرق Ghidra/IDA ✅ / استدلال أنواع · بِنى | P0 ✅ / P1 |
| الديناميكي | حقن (Windows / Linux) → ذاكرة / مكدس / لقطات → مسح / تجميد → hook / trace | P2–P4 |
| التغليف | `hooks.toml` + مصادر hook → مكتبات حقن لكل منصة + بيانات وصفية (ABI / قدرات / بصمات) | P4 |
| الواجهة | خدمات (REST / WS / MCP) + واجهة hikari ويب + عُقد evernight البعيدة | P5–P6 |

أساسان يقف عليهما كل شيء آخر:

1. **تجريد واحد لفضاء العناوين**: صور الملفات والعمليات الحية ولقطات الذاكرة تنفّذ `AddressSpace`
   نفسه؛ اكتشاف الدوال والتفكيك يشغّلان خط أنابيب واحدًا على الثلاثة.
1. **هوية دالة بالعنونة بالمحتوى**: `kotama://<بصمة-الوحدة>/<rva>` مستقر عبر ASLR وإعادة
   التشغيل وتغيّر الأجهزة — لذلك تنتقل التعليقات والاستنتاجات بين العُقد.

## البدء السريع

```bash
just gate                                  # fmt + clippy + test + deny
cargo run -p kotama-cli -- --version       # الإصدار + إصدار ABI للحمل
cargo run -p kotama-cli -- analyze <ملف>  # جدول الدوال JSON (مع الأدلة)
cargo run -p kotama-cli -- analyze <ملف> --decompile --limit 8   # مع شبه-C
python3 tools/build_fixtures.py --run --host-samples   # مصفوفة الفيكستشر + دخان تشغيل
```

مصفوفة الفيكستشر: `x86_64-linux-gnu / x86-linux-gnu / x86_64-windows-gnu / x86-windows-gnu`
× `-O2/-O0` × 6 أهداف (loops / switch / indirect / strings / float / recurs). تعمل ELF محليًا
مباشرة؛ وتعمل PE عبر wine افتراضيًا (`KOTAMA_WINE`، راجع AGENTS المستودع، «الاعتماديات
المحلية وقت التشغيل»).

## الحدود

استخدمه على أهداف مصرّح بها فقط: برمجياتك الخاصة، وأجهزتك الخاصة، أو عينات بحث أُودعت إليك
صراحةً. هذا المستودع **لا** يقوم بالتخفّي أو مكافحة الكشف أو الاستمرارية أو سرقة بيانات الاعتماد
أو تجاوز مكافحة الغش. الكتابة في الذاكرة والتجميد معطّلان افتراضيًا ويتطلبان منح قدرة صريحًا —
والتحليل للقراءة فقط هو الوقفة الافتراضية.

## المساهمة

عتبة الدمج عالية؛ والمساهمات المركّزة موضع ترحيب — راجع
[CONTRIBUTING.md](../../CONTRIBUTING.md). قضايا الأمان: **لا** تفتح issue عموميًا —
راجع [SECURITY.md](../../SECURITY.md).

## الرخصة

[SySL 1.0](../../LICENSE).
