//! 活体会话宿主：Linux `/proc` 与原生 Windows Win32 共用一份会话 facade。
//!
//! 两条平台车道都只替换进程、模块与内存区域原语：
//! - Linux 读 `/proc/<pid>/mem`、解析 maps，并把 wine 宿主 PE 当一等公民；
//! - Windows 用 `OpenProcess` / `ReadProcessMemory` / Toolhelp / `VirtualQueryEx`，
//!   原生 PE 以 `ModuleKind::NativePe` 诚实上报；
//! - [`ProcessImage`] 在两侧都把整个映像**缓存成一份字节**（上限 64 MiB），因此
//!   `AddressSpace::read` 是纯切片借用，scan/discover/decomp 跑同一条静态管线。
//!
//! 地址约定：RVA = 进程绝对地址 − 映像基址，与静态侧（文件映像归一）同口径——
//! 内容寻址身份因此跨静态/活体成立。写内存、冻结与远程注入仍由
//! `control::Session` 的 capability 门禁显式开放；Windows 外部栈回溯（Toolhelp 线程 +
//! StackWalk64 + dbghelp 符号）见 [`stack`]，它只做短暂挂起、**不是**冻结机制。
//!
//! Windows 原生车道的传输有两种：命名管道（默认，见 [`pipe`]）与回环 TCP（保留给
//! wine）。两者与 Linux 的 unix socket 共用 [`wire`] 的帧编解码与只读巡检步骤。

pub mod control;
#[cfg(target_os = "windows")]
pub mod inject;
#[cfg(target_os = "linux")]
pub mod launch;
#[cfg(target_os = "windows")]
pub mod pipe;
pub mod scanner;
#[cfg(target_os = "windows")]
pub mod stack;
#[cfg(target_os = "linux")]
pub mod trace;
#[cfg(target_os = "windows")]
mod windows;
pub mod wire;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;

use kotama::AddressSpace;
use kotama::ModuleId;
use kotama::Perms;
use kotama::Segment;
use kotama_image::SectionInfo;
use kotama_image::SymbolInfo;
#[cfg(target_os = "linux")]
use kotama_proto::ModuleInfo;
#[cfg(target_os = "linux")]
use kotama_proto::ModuleKind;

/// 缓存整个映像的上限（超出报错——超大映像的分片读取随 P2 后续轮引入）。
pub const MAX_IMAGE_CACHE: u64 = 64 * 1024 * 1024;

/// 宿主侧错误。
#[derive(Debug)]
pub enum HostError {
    /// 进程不存在 / 无权访问。
    Process(String),
    /// `/proc/<pid>/maps` 或 `mem` 读失败。
    Proc(String),
    /// Win32 API 调用失败。
    Win32(String),
    /// PE 头解析失败。
    PeParse(String),
    /// 远程注入前置校验失败或远程线程未按预期完成。
    Inject(String),
    /// 写操作未获授权（capability 门禁；负对照钉的就是它）。
    CapabilityDenied(&'static str),
    /// 外部栈回溯失败（线程枚举 / 挂起恢复 / StackWalk64 / dbghelp 符号会话）。
    Stack(String),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Process(msg) => write!(f, "process: {msg}"),
            Self::Proc(msg) => write!(f, "proc: {msg}"),
            Self::Win32(msg) => write!(f, "win32: {msg}"),
            Self::PeParse(msg) => write!(f, "pe parse: {msg}"),
            Self::Inject(msg) => write!(f, "inject: {msg}"),
            Self::CapabilityDenied(msg) => write!(f, "capability denied: {msg}"),
            Self::Stack(msg) => write!(f, "stack: {msg}"),
        }
    }
}

impl std::error::Error for HostError {}

/// 一个已打开的目标进程（只读句柄）。
pub struct TargetProcess {
    pid: i32,
    #[cfg(target_os = "linux")]
    mem: File,
    #[cfg(target_os = "windows")]
    handle: std::os::windows::io::OwnedHandle,
}

impl TargetProcess {
    /// 打开目标进程的内存读取通道。
    ///
    /// # Errors
    /// 进程不存在或无权（Yama 口径：同 uid 且（祖先后代或 `ptrace_scope=0`））。
    #[cfg(target_os = "linux")]
    pub fn open(pid: i32) -> Result<Self, HostError> {
        let mem = File::open(format!("/proc/{pid}/mem"))
            .map_err(|e| HostError::Process(format!("pid {pid}: {e}")))?;
        Ok(Self { pid, mem })
    }

    /// 目标 PID。
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    /// 读一段进程内存（绝对地址）。
    ///
    /// # Errors
    /// 地址未映射或跨入未映射页。
    #[cfg(target_os = "linux")]
    pub fn read_absolute(&self, address: u64, length: usize) -> Result<Vec<u8>, HostError> {
        let mut buffer = vec![0u8; length];
        self.mem
            .read_exact_at(&mut buffer, address)
            .map_err(|e| HostError::Proc(format!("read {address:#x}+{length}: {e}")))?;
        Ok(buffer)
    }

    /// 枚举目标进程里的模块（ELF 映像 + wine 宿主 PE 映像）。
    ///
    /// # Errors
    /// maps 读取或解析失败。
    #[cfg(target_os = "linux")]
    pub fn modules(&self) -> Result<Vec<ModuleInfo>, HostError> {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid))
            .map_err(|e| HostError::Proc(format!("maps: {e}")))?;
        Ok(parse_modules(&maps, |address, length| {
            self.read_absolute(address, length)
        }))
    }

    /// 取第一个（或指定基址的）wine PE 模块的活体映像（整像缓存）。
    ///
    /// # Errors
    /// 无 PE 模块、头解析失败或映像超过 [`MAX_IMAGE_CACHE`]。
    #[cfg(target_os = "linux")]
    pub fn wine_pe(&self, base_hint: Option<u64>) -> Result<ProcessImage<'_>, HostError> {
        let modules = self.modules()?;
        let module = match base_hint {
            Some(base) => modules
                .iter()
                .find(|m| m.kind == ModuleKind::WinePe && m.base == base)
                .ok_or_else(|| HostError::PeParse(format!("no wine PE at {base:#x}")))?,
            None => modules
                .iter()
                .filter(|m| m.kind == ModuleKind::WinePe)
                // 主映像优先：wine 内建 DLL（ntdll/kernel32 一族）在 wine 安装目录下，
                // 主 exe 的映射路径不在。第一个 MZ 映像往往是内建 DLL（e2e 实抓）。
                .find(|m| !m.path.is_empty() && !is_wine_builtin(&m.path))
                .or_else(|| modules.iter().find(|m| m.kind == ModuleKind::WinePe))
                .ok_or_else(|| HostError::PeParse("no wine PE module found".into()))?,
        };
        ProcessImage::from_pe(self, module.base)
    }

    /// 取当前平台的 PE 活体映像（Linux 上即 wine PE）。
    ///
    /// # Errors
    /// 与 [`Self::wine_pe`] 相同。
    #[cfg(target_os = "linux")]
    pub fn pe_image(&self, base_hint: Option<u64>) -> Result<ProcessImage<'_>, HostError> {
        self.wine_pe(base_hint)
    }
}

/// 一条 `/proc/<pid>/maps` 映射。
#[derive(Clone, Debug)]
pub struct MapEntry {
    /// 起始绝对地址。
    pub start: u64,
    /// 结束（不含）。
    pub end: u64,
    /// 读权限。
    pub readable: bool,
    /// 写权限。
    pub writable: bool,
    /// 执行权限。
    pub executable: bool,
    /// 文件映射偏移。
    pub offset: u64,
    /// 映射路径（匿名映射为空）。
    pub path: String,
}

/// 解析 `/proc/<pid>/maps` 文本。
#[must_use]
pub fn parse_maps(text: &str) -> Vec<MapEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(2, ' ');
        let Some(range) = parts.next() else { continue };
        let Some((Some(start), Some(end))) = range.split_once('-').map(|(s, e)| {
            (
                u64::from_str_radix(s, 16).ok(),
                u64::from_str_radix(e, 16).ok(),
            )
        }) else {
            continue;
        };
        let rest = parts.next().unwrap_or_default();
        let mut fields = rest.split_whitespace();
        let perms = fields.next().unwrap_or_default();
        let offset = fields
            .next()
            .and_then(|v| u64::from_str_radix(v, 16).ok())
            .unwrap_or(0);
        let path = fields.nth(2).unwrap_or("").to_string();
        let bytes = perms.as_bytes();
        out.push(MapEntry {
            start,
            end,
            readable: bytes.first() == Some(&b'r'),
            writable: bytes.get(1) == Some(&b'w'),
            executable: bytes.get(2) == Some(&b'x'),
            offset,
            path,
        });
    }
    out
}

/// 从 maps + 现场探测枚举模块。`read` 是内存读取回调（探测 `MZ` 头用）。
#[cfg(target_os = "linux")]
fn parse_modules(
    maps_text: &str,
    read: impl Fn(u64, usize) -> Result<Vec<u8>, HostError>,
) -> Vec<ModuleInfo> {
    let entries = parse_maps(maps_text);
    let mut out: Vec<ModuleInfo> = Vec::new();

    // 1) ELF：按路径分组（可执行映射为准），基址 = 最小起始。
    let mut elf: std::collections::BTreeMap<String, (u64, u64)> = std::collections::BTreeMap::new();
    for entry in &entries {
        if entry.path.is_empty() || !entry.executable {
            continue;
        }
        let slot = elf
            .entry(entry.path.clone())
            .or_insert((entry.start, entry.end));
        slot.0 = slot.0.min(entry.start);
        slot.1 = slot.1.max(entry.end);
    }
    for (path, (base, end)) in elf {
        out.push(ModuleInfo {
            base,
            size: end.saturating_sub(base),
            kind: ModuleKind::Elf,
            path,
        });
    }

    // 2) wine PE：每个可读映射的起始页探 `MZ`，现场解析 PE 头拿 SizeOfImage。
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for entry in &entries {
        if !entry.readable || entry.offset != 0 || !seen.insert(entry.start) {
            continue;
        }
        let Ok(header) = read(entry.start, 0x400) else {
            continue;
        };
        let Some(pe) = PeImageHeader::parse(&header) else {
            continue;
        };
        out.push(ModuleInfo {
            base: entry.start,
            size: u64::from(pe.size_of_image),
            kind: ModuleKind::WinePe,
            // 主映像与内建 DLL 都可能文件映射；靠路径区分（e2e / CLI 按名选主映像）。
            path: entry.path.clone(),
        });
    }
    out.sort_by_key(|m| (m.base, m.path.clone()));
    out
}

/// wine 内建 DLL 的路径特征（Debian 布局与通用 /usr/lib/wine 布局都命中）。
#[cfg(target_os = "linux")]
fn is_wine_builtin(path: &str) -> bool {
    path.contains("/wine/")
        || path.contains("\\wine\\")
        || path.ends_with(".dll")
        || path.ends_with(".DLL")
}

/// 活体 PE 头（现场解析的最小集合）。
#[derive(Clone, Copy, Debug)]
pub struct PeImageHeader {
    /// `SizeOfImage`。
    pub size_of_image: u32,
    /// `AddressOfEntryPoint`（RVA）。
    pub entry_rva: u32,
}

impl PeImageHeader {
    /// 从映像基址处的头字节解析（读到节表即可，0x400 通常够）。
    ///
    /// 返回 `None` = 这不是 PE（探测语义，不是错误）。
    #[must_use]
    pub fn parse(header: &[u8]) -> Option<Self> {
        let read_u32 = |offset: usize| -> Option<u32> {
            header
                .get(offset..offset + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        if header.first() != Some(&b'M') || header.get(1) != Some(&b'Z') {
            return None;
        }
        let lfanew = read_u32(0x3c)? as usize;
        if header.get(lfanew..lfanew + 4) != Some(b"PE\0\0") {
            return None;
        }
        let optional = lfanew + 4 + 20;
        let size_of_image = read_u32(optional + 56)?;
        let entry_rva = read_u32(optional + 16)?;
        (size_of_image > 0 && size_of_image < 0x1000_0000).then_some(Self {
            size_of_image,
            entry_rva,
        })
    }
}

/// 活体进程里的一个 PE 映像：整像缓存 + RVA 寻址的 [`AddressSpace`]。
pub struct ProcessImage<'a> {
    /// 来源进程（诊断用；读取都走缓存映像）。
    pub process: &'a TargetProcess,
    /// 映像绝对基址。
    pub base: u64,
    /// `SizeOfImage`。
    pub size: u64,
    /// 入口 RVA。
    pub entry_rva: Option<u64>,
    /// 现场解析的节表（PE 节头）。
    pub sections: Vec<SectionInfo>,
    /// 由节表导出的段表（`AddressSpace::segments` 的返回来源）。
    segments: Vec<Segment>,
    /// 整像缓存（RVA 寻址：`image[rva..rva+len]`）。
    image: Vec<u8>,
}

impl<'a> ProcessImage<'a> {
    /// 兼容旧名的 wine PE 入口；实现与 [`Self::from_pe`] 完全相同。
    ///
    /// # Errors
    /// 与 [`Self::from_pe`] 相同。
    #[cfg(target_os = "linux")]
    pub fn from_wine_pe(process: &'a TargetProcess, base: u64) -> Result<Self, HostError> {
        Self::from_pe(process, base)
    }

    /// 现场解析并缓存一个 PE 模块（读取整个 `SizeOfImage`）。
    ///
    /// # Errors
    /// 头读取 / 解析失败，或映像超过 [`MAX_IMAGE_CACHE`]。
    pub fn from_pe(process: &'a TargetProcess, base: u64) -> Result<Self, HostError> {
        let header = process
            .read_absolute(base, 0x400)
            .map_err(|e| HostError::PeParse(format!("{base:#x}: {e}")))?;
        let pe = PeImageHeader::parse(&header)
            .ok_or_else(|| HostError::PeParse(format!("no PE header at {base:#x}")))?;
        let lfanew =
            u32::from_le_bytes([header[0x3c], header[0x3d], header[0x3e], header[0x3f]]) as usize;
        let num_sections = u16::from_le_bytes([header[lfanew + 6], header[lfanew + 7]]) as usize;
        let optional_size = u16::from_le_bytes([header[lfanew + 20], header[lfanew + 21]]) as usize;
        let table = lfanew + 4 + 20 + optional_size;

        let mut sections = Vec::with_capacity(num_sections);
        for index in 0..num_sections {
            let Some(raw) = header.get(table + index * 40..table + index * 40 + 40) else {
                break;
            };
            let name = raw
                .iter()
                .take(8)
                .take_while(|b| **b != 0)
                .copied()
                .collect::<Vec<u8>>();
            let name = String::from_utf8_lossy(&name).into_owned();
            let virtual_size = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
            let rva = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
            let characteristics = u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]);
            if virtual_size == 0 || rva == 0 {
                continue;
            }
            sections.push(SectionInfo {
                rva: u64::from(rva),
                size: u64::from(virtual_size),
                name,
                executable: characteristics & 0x2000_0000 != 0,
            });
        }
        sections.sort_by_key(|s| (s.rva, s.name.clone()));

        let size = u64::from(pe.size_of_image);
        if size > MAX_IMAGE_CACHE {
            return Err(HostError::PeParse(format!(
                "image {size:#x} exceeds cache cap {MAX_IMAGE_CACHE:#x}"
            )));
        }
        let image = process
            .read_absolute(base, usize::try_from(size).unwrap_or(usize::MAX))
            .map_err(|e| HostError::Proc(format!("image read at {base:#x}: {e}")))?;

        let segments = sections
            .iter()
            .map(|s| Segment {
                rva: s.rva,
                size: s.size,
                perms: Perms {
                    read: true,
                    write: false,
                    execute: s.executable,
                },
            })
            .collect();

        Ok(Self {
            process,
            base,
            size,
            entry_rva: (pe.entry_rva != 0).then(|| u64::from(pe.entry_rva)),
            sections,
            segments,
            image,
        })
    }

    /// 活体内容寻址指纹：与静态侧同一配方（identity v1，经
    /// [`kotama_image::module_id_from_sections`]）。
    ///
    /// 静态 = 文件映像（执行节按虚拟尺寸零填充），活体 = 进程内存直接读——
    /// 两侧应产出**同一个** [`ModuleId`]，这是「身份跨静态/动态成立」的验收断言。
    #[must_use]
    pub fn module_id(&self) -> ModuleId {
        let sections: Vec<(String, u64, u64, Vec<u8>)> = self
            .sections
            .iter()
            .filter(|s| s.executable)
            .map(|s| {
                (
                    s.name.clone(),
                    s.rva,
                    s.size,
                    self.read(s.rva, usize::try_from(s.size).unwrap_or(usize::MAX))
                        .unwrap_or(&[])
                        .to_vec(),
                )
            })
            .collect();
        kotama_image::module_id_from_sections(&sections)
    }

    /// 供 scan 用的视图字段：活体 PE 无符号表 / 调试信息（那是静态侧的强项），
    /// 函数发现靠 `.pdata` / 入口 / call 目标。
    #[must_use]
    pub fn empty_symbols(&self) -> &[SymbolInfo] {
        &[]
    }
}

impl AddressSpace for ProcessImage<'_> {
    fn segments(&self) -> &[Segment] {
        &self.segments
    }

    fn read(&self, rva: u64, length: usize) -> Option<&[u8]> {
        let start = usize::try_from(rva).ok()?;
        let end = start.checked_add(length)?;
        self.image.get(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_lines() {
        let text = "7f0a00000000-7f0a00010000 r-xp 00000000 08:01 1234 /usr/lib/libc.so\n\
                    7f0a00010000-7f0a00011000 rw-p 00000000 00:00 0\n";
        let entries = parse_maps(text);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].executable && entries[0].path.contains("libc"));
        assert!(entries[1].writable && entries[1].path.is_empty());
    }

    #[test]
    fn pe_header_probe_rejects_non_pe() {
        assert!(PeImageHeader::parse(b"ELF\x00garbage").is_none());
        assert!(PeImageHeader::parse(&[0u8; 0x400]).is_none());
    }

    #[test]
    fn pe_header_probe_accepts_synthetic_pe() {
        let mut header = [0u8; 0x400];
        header[0] = b'M';
        header[1] = b'Z';
        let lfanew = 0x80usize;
        header[0x3c..0x40].copy_from_slice(&u32::to_le_bytes(lfanew as u32));
        header[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
        let optional = lfanew + 4 + 20;
        header[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        header[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        header[optional + 56..optional + 60].copy_from_slice(&0x2_0000_u32.to_le_bytes());
        let pe = PeImageHeader::parse(&header).unwrap();
        assert_eq!(pe.entry_rva, 0x1000);
        assert_eq!(pe.size_of_image, 0x2_0000);
    }

    /// 环境门控的活体 e2e（宿主机跑：`KOTAMA_LIVE_E2E=1` + wine + 夹具在位）。
    ///
    /// 流程：wine 拉起 spin.exe → 等心跳 → /proc 探测 PE 模块 → 活体 ModuleId ==
    /// 静态文件 ModuleId（内容寻址身份跨静态/活体的验收断言）→ discover 出函数表。
    #[test]
    #[cfg(target_os = "linux")]
    fn live_e2e_wine_pe_identity() {
        if std::env::var_os("KOTAMA_LIVE_E2E").is_none() {
            eprintln!("skip: set KOTAMA_LIVE_E2E=1 to run the live e2e");
            return;
        }
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/spin.exe");
        if !fixture.exists() {
            panic!("fixture missing: run tools/build_fixtures.py first");
        }
        let wine = "/usr/lib/wine/wine64";

        let mut child = std::process::Command::new(wine)
            .arg(&fixture)
            .arg("20")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn wine");
        let pid = child.id() as i32;

        // 等待 PE 映像映射完成（循环探测，最多 15s）。
        let target = loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let Ok(process) = TargetProcess::open(pid) else {
                continue;
            };
            if let Ok(modules) = process.modules() {
                if modules.iter().any(|m| m.kind == ModuleKind::WinePe) {
                    break process;
                }
            }
            drop(process);
        };

        // 显式选主映像（maps 里第一个 MZ 是 wine 内建 DLL——首轮 e2e 实抓的坑）。
        let modules = target.modules().expect("modules");
        let main = modules
            .iter()
            .find(|m| m.kind == ModuleKind::WinePe && m.path.ends_with("spin.exe"))
            .expect("spin.exe image module");
        let image = target.wine_pe(Some(main.base)).expect("wine pe image");
        let live_id = image.module_id();
        let static_id = kotama_image::LoadedModule::parse(&std::fs::read(&fixture).unwrap())
            .unwrap()
            .module_id();
        assert_eq!(
            live_id, static_id,
            "content-addressed identity must survive static→live"
        );

        // 同一条发现管线跑活体：pdata 证据的函数必须在场。
        let functions = kotama_scan::discover_with(
            kotama_scan::ScanView {
                container: kotama_image::Container::Pe64,
                arch: kotama_image::Arch::X86_64,
                image_base: 0,
                entry_rva: image.entry_rva,
                sections: &image.sections,
                symbols: image.empty_symbols(),
                dynamic_symbols: image.empty_symbols(),
                debug_functions: image.empty_symbols(),
            },
            &image,
        );
        assert!(
            functions
                .iter()
                .any(|f| f.evidence.contains(&kotama_scan::Evidence::Pdata)),
            "live discovery should find pdata-backed functions"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    /// P3 活体 e2e：CE 等价闭环（diff 定位 → 冻结 → 目标自己的打印被钉住）。
    ///
    /// 验收链：快照 diff 在 PE 映像范围内找到自增的 `hot_counter` → `Session::with_write`
    /// 冻结它 → spin.exe **自己打印**的计数停在冻结值上（外部可观测的行为改变）。
    /// 同时钉门禁负对照的活体形态：只读会话 freeze 必须被拒。
    #[test]
    #[cfg(target_os = "linux")]
    fn live_e2e_scan_freeze_pins_target_output() {
        if std::env::var_os("KOTAMA_LIVE_E2E").is_none() {
            eprintln!("skip: set KOTAMA_LIVE_E2E=1 to run the live e2e");
            return;
        }
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/spin.exe");
        if !fixture.exists() {
            panic!("fixture missing: run tools/build_fixtures.py first");
        }
        use std::io::BufRead;
        use std::sync::Mutex;

        let mut child = std::process::Command::new("/usr/lib/wine/wine64")
            .arg(&fixture)
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn wine");
        let pid = child.id() as i32;
        let stdout = child.stdout.take().expect("stdout");
        let lines = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = {
            let lines = std::sync::Arc::clone(&lines);
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                {
                    lines.lock().expect("lines lock").push(line);
                }
            })
        };

        // 1) 等 PE 映像。
        let target = loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let Ok(process) = TargetProcess::open(pid) else {
                continue;
            };
            if let Ok(modules) = process.modules() {
                if modules
                    .iter()
                    .any(|m| m.kind == ModuleKind::WinePe && m.path.ends_with("spin.exe"))
                {
                    break process;
                }
            }
            drop(process);
        };
        let modules = target.modules().expect("modules");
        let main = modules
            .iter()
            .find(|m| m.kind == ModuleKind::WinePe && m.path.ends_with("spin.exe"))
            .expect("spin image");

        // 2) 门禁负对照（活体形态）：只读会话必须拒绝冻结。
        {
            let Ok(read_only) = TargetProcess::open(pid) else {
                panic!("reopen");
            };
            let session = control::Session::read_only(read_only);
            assert!(matches!(
                session.freeze(main.base, control_freeze_value(), 20),
                Err(HostError::CapabilityDenied(_))
            ));
        }

        // 3) diff 定位 hot_counter：映像范围内、值小幅度增长的字。
        let before = scanner::Snapshot::capture(&target).expect("snapshot A");
        std::thread::sleep(std::time::Duration::from_millis(1600));
        let after = scanner::Snapshot::capture(&target).expect("snapshot B");
        let image_end = main.base + main.size;
        let candidates: Vec<scanner::Change> = scanner::diff(&before, &after)
            .into_iter()
            .filter(|change| change.address >= main.base && change.address < image_end)
            .filter(|change| change.new > change.old && change.new - change.old < 64)
            .collect();
        assert!(
            !candidates.is_empty(),
            "hot_counter word not found in image range"
        );
        let counter_address = candidates[0].address;

        // 4) 读当前值并冻结。
        let current = target
            .read_absolute(counter_address, 4)
            .expect("read counter");
        let frozen = u32::from_le_bytes([current[0], current[1], current[2], current[3]]);
        let write_session = control::Session::with_write(target).expect("with_write");
        let handle = write_session
            .freeze(counter_address, scanner::Value::U32(frozen), 20)
            .expect("freeze");

        // 5) 目标自己的输出被钉住。
        //
        // 断言性质取「**有界**」而非「恒等」：冻结重写 20ms vs 目标 tick 100ms，最多漏
        // 一个 tick 的增量（i&3 ≤ 3）进打印值——CE 同款竞态。不冻结时 hot_counter 单调
        // 无界增长（每秒 ≈ +10），所以「冻结后所有打印 ≤ frozen + 8」就是钉住的充分证据。
        let before_freeze_count = lines.lock().expect("lines lock").len();
        std::thread::sleep(std::time::Duration::from_millis(4000));
        let all_lines = lines.lock().expect("lines lock").clone();
        drop(handle);
        let _ = child.kill();
        let _ = child.wait();
        let _ = sink.join();
        let printed: Vec<u32> = all_lines
            .iter()
            .filter_map(|line| line.strip_prefix("spin: ").and_then(|v| v.parse().ok()))
            .collect();
        let after_freeze: Vec<u32> = printed[before_freeze_count.min(printed.len())..].to_vec();
        assert!(
            after_freeze.len() >= 3,
            "not enough post-freeze lines: {printed:?}"
        );
        assert!(
            after_freeze.iter().all(|value| *value <= frozen + 8),
            "output not pinned: after_freeze={after_freeze:?} frozen={frozen} all={printed:?}"
        );
        // 冻结前确实在涨（对照组，避免「本来就平」的假阳性）。
        assert!(
            printed.len() >= 2 && printed[1] > printed[0],
            "pre-freeze growth missing: {printed:?}"
        );
    }

    /// 负对照用的冻结值（不真正落到写——门禁应先拒）。
    #[cfg(target_os = "linux")]
    fn control_freeze_value() -> scanner::Value {
        scanner::Value::U32(0x7f7f_7f7f)
    }
}
