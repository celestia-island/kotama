//! 活体会话的 wire 协议：msgpack 帧 + 握手 + 能力位图。
//!
//! 四种调用形态（CLI 会话 / 库 / 服务面 / 远程节点）共用这一套帧——不存在
//! 「CLI 一套、RPC 一套、远程又一套」（设计案 §3 地基三）。
//!
//! P2 第一版只有**只读**方法（模块枚举 + 内存读）；写方法随能力门禁（P3）再入表，
//! 届时 `Request` 加变体、`PROTO_VERSION` 递增，握手不匹配一律拒绝。
//!
//! 帧格式：裸 msgpack 编码的 [`Frame`]；长度前缀帧（4 字节 LE）在传输层（管道 /
//! socket）包一层，本 crate 只管单帧编解码。

use serde::Deserialize;
use serde::Serialize;

/// 协议版本（结构不兼容变更时递增；握手不匹配 = 拒绝，无回退）。
pub const PROTO_VERSION: u16 = 3;

/// 一个会话端点声明的能力。写类能力（写内存 / 冻结 / 注入）在 P3 随门禁引入，
/// 这里先占只读集合，让握手形状稳定下来。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub enum Capability {
    /// 枚举目标进程里的模块。
    ListModules,
    /// 读目标进程内存。
    ReadMemory,
    /// 写目标进程内存（P3 起入表；默认不授）。
    WriteMemory,
    /// 冻结一个值（P3 起入表；默认不授）。
    Freeze,
    /// 自抓当前线程的栈帧（载荷内 `RtlCaptureStackBackTrace`；加法能力，默认只授 Windows 载荷）。
    StackSnapshot,
}

impl Capability {
    /// manifest / CLI 共用的稳定短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListModules => "list-modules",
            Self::ReadMemory => "read-memory",
            Self::WriteMemory => "write-memory",
            Self::Freeze => "freeze",
            Self::StackSnapshot => "stack-snapshot",
        }
    }
}

/// 当前载荷与 manifest 共同声明的只读能力集；写/冻结必须走显式门禁，不在此列。
pub const READ_ONLY_CAPABILITIES: &[Capability] =
    &[Capability::ListModules, Capability::ReadMemory];

/// 握手载荷。
///
/// [`Handshake::supports`] 是宿主侧唯一的「能不能发」判据：能力没声明就不发，
/// 避免把旧载荷（C agent）推给不认识的方法。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Handshake {
    /// 对端协议版本。
    pub proto_version: u16,
    /// 对端链接的载荷 ABI（恒等 [`kotama::ABI_VERSION`]）。
    pub abi_version: u16,
    /// 对端能力集合。
    pub capabilities: Vec<Capability>,
}

impl Handshake {
    /// 能力是否已声明（宿主据此决定「发不发」，而不是先发后猜）。
    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// 载荷内自抓的一帧栈（载荷视角）。
///
/// 模块以**加载基址**标识而不是路径：载荷侧 `GetModuleHandleExW(FROM_ADDRESS)`
/// 只能拿到基址，宿主再用自己的 Toolhelp 模块表把基址映射回路径。确定性比较用
/// `module_base + module_rva`，`address` 只作诊断。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StackFrame {
    /// 帧的绝对地址（载荷视角的 VA）。
    pub address: u64,
    /// 帧所属模块的加载基址；0 = 不属于任何已知模块。
    pub module_base: u64,
    /// 模块内偏移（`address - module_base`；`module_base` 为 0 时也是 0）。
    pub module_rva: u64,
    /// 符号名（空串 = 未符号化；载荷内不初始化 dbghelp，符号化留给宿主）。
    pub symbol: String,
    /// 符号内偏移（未符号化时为 0）。
    pub displacement: u64,
}

/// 一个线程的自抓栈（帧序 = 由内向外）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ThreadStack {
    /// 线程 ID（载荷视角的 `GetCurrentThreadId`）。
    pub thread_id: u32,
    /// 帧列表，由内向外；空 = 抓取失败或线程无帧。
    pub frames: Vec<StackFrame>,
}

/// 一个模块条目（活体）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ModuleInfo {
    /// 映像在目标进程里的绝对基址。
    pub base: u64,
    /// 映像大小（字节）。
    pub size: u64,
    /// 模块种类。
    pub kind: ModuleKind,
    /// 来源路径（ELF 的映射文件；wine PE 可能为空；原生 PE 为 Win32 全路径）。
    pub path: String,
}

/// 模块种类。
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ModuleKind {
    /// Linux ELF 映像。
    Elf,
    /// wine 宿主内的 PE 映像（wine 进程就是 Linux 进程，`/proc/<pid>/mem` 直读）。
    WinePe,
    /// 原生 Windows 进程内的 PE 映像（Toolhelp / Win32 活体车道）。
    NativePe,
}

/// 宿主 → 目标侧的请求。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Request {
    /// 握手（必须是第一帧）。
    Hello(Handshake),
    /// 枚举模块。
    ListModules,
    /// 读一段内存。
    ReadMemory {
        /// 目标进程绝对地址。
        address: u64,
        /// 长度（单帧上限 1 MiB，超出由宿主分片）。
        length: u32,
    },
    /// 写一段内存（需 `WriteMemory` 能力）。
    WriteMemory {
        /// 目标进程绝对地址。
        address: u64,
        /// 内容。
        bytes: Vec<u8>,
    },
    /// 自抓当前（服务）线程的栈（需 `StackSnapshot` 能力）。
    ///
    /// 载荷只抓**它自己**的服务线程：进程内没有「抓别的线程」的授权语义，也不做
    /// `SuspendThread`（那会干扰目标）。没有该能力的载荷（例如 C agent）回
    /// `Response::Error`，宿主不应发送。
    StackSnapshot {
        /// 最多抓取的帧数（载荷按自身实现上限夹取；0 视为默认）。
        max_frames: u32,
    },
}

/// 目标侧 → 宿主的应答。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Response {
    /// 握手确认（回己方版本与能力）。
    HelloAck(Handshake),
    /// 模块列表。
    Modules(Vec<ModuleInfo>),
    /// 内存内容（与请求等长；失败走 [`Response::Error`]）。
    Memory(Vec<u8>),
    /// 写确认（回写长度）。
    Wrote(u32),
    /// 自抓栈快照（每项一个线程，线程按 ID 升序；未声明能力的载荷回 `Error`）。
    Stacks(Vec<ThreadStack>),
    /// 错误。
    Error {
        /// 机器可读错误码（负数）。
        code: i32,
        /// 人读消息。
        message: String,
    },
}

/// 单帧：请求或应答。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Frame {
    /// 请求方向。
    Request(Request),
    /// 应答方向。
    Response(Response),
}

/// 编码一帧（msgpack）。
///
/// # Errors
/// 序列化失败（理论不可达——所有类型都是平凡数据）。
pub fn encode(frame: &Frame) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec(frame)
}

/// 解码一帧（msgpack）。
///
/// # Errors
/// 字节不是合法帧。
pub fn decode(bytes: &[u8]) -> Result<Frame, rmp_serde::decode::Error> {
    rmp_serde::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> Frame {
        Frame::Request(Request::Hello(Handshake {
            proto_version: PROTO_VERSION,
            abi_version: kotama::ABI_VERSION,
            capabilities: READ_ONLY_CAPABILITIES.to_vec(),
        }))
    }

    #[test]
    fn frame_roundtrip() {
        let bytes = encode(&sample_frame()).unwrap();
        assert_eq!(decode(&bytes).unwrap(), sample_frame());
    }

    #[test]
    fn read_only_capability_names_are_stable() {
        let names: Vec<&str> = READ_ONLY_CAPABILITIES
            .iter()
            .map(|capability| capability.as_str())
            .collect();
        assert_eq!(names, ["list-modules", "read-memory"]);
        assert_eq!(Capability::WriteMemory.as_str(), "write-memory");
        assert_eq!(Capability::Freeze.as_str(), "freeze");
        assert_eq!(Capability::StackSnapshot.as_str(), "stack-snapshot");
    }

    #[test]
    fn native_pe_module_roundtrip() {
        let frame = Frame::Response(Response::Modules(vec![ModuleInfo {
            base: 0x140000000,
            size: 0x9000,
            kind: ModuleKind::NativePe,
            path: r"C:\fixtures\spin.exe".into(),
        }]));
        let bytes = encode(&frame).unwrap();
        assert_eq!(decode(&bytes).unwrap(), frame);
    }

    #[test]
    fn stack_snapshot_roundtrip() {
        let request = Frame::Request(Request::StackSnapshot { max_frames: 32 });
        assert_eq!(decode(&encode(&request).unwrap()).unwrap(), request);
        let response = Frame::Response(Response::Stacks(vec![ThreadStack {
            thread_id: 4242,
            frames: vec![
                StackFrame {
                    address: 0x7ff6_1234_5678,
                    module_base: 0x7ff6_1234_0000,
                    module_rva: 0x5678,
                    symbol: String::new(),
                    displacement: 0,
                },
                StackFrame {
                    address: 0x0000_7ffb_0000_1000,
                    module_base: 0,
                    module_rva: 0,
                    symbol: String::new(),
                    displacement: 0,
                },
            ],
        }]));
        assert_eq!(decode(&encode(&response).unwrap()).unwrap(), response);
    }

    #[test]
    fn handshake_supports_reports_declared_capabilities_only() {
        let handshake = Handshake {
            proto_version: PROTO_VERSION,
            abi_version: kotama::ABI_VERSION,
            capabilities: vec![Capability::ListModules, Capability::StackSnapshot],
        };
        assert!(handshake.supports(Capability::ListModules));
        assert!(handshake.supports(Capability::StackSnapshot));
        assert!(!handshake.supports(Capability::ReadMemory));
        assert!(!handshake.supports(Capability::WriteMemory));
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode(b"not msgpack frame").is_err());
    }

    #[test]
    fn memory_request_roundtrip() {
        let frame = Frame::Request(Request::ReadMemory {
            address: 0x140001000,
            length: 4096,
        });
        let bytes = encode(&frame).unwrap();
        assert_eq!(decode(&bytes).unwrap(), frame);
    }
}
