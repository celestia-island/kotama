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
pub const PROTO_VERSION: u16 = 2;

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
}

/// 握手载荷。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Handshake {
    /// 对端协议版本。
    pub proto_version: u16,
    /// 对端链接的载荷 ABI（恒等 [`kotama::ABI_VERSION`]）。
    pub abi_version: u16,
    /// 对端能力集合。
    pub capabilities: Vec<Capability>,
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
    /// 来源路径（ELF 的映射文件；wine 宿主 PE 为 exe 路径或空）。
    pub path: String,
}

/// 模块种类。
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ModuleKind {
    /// Linux ELF 映像。
    Elf,
    /// wine 宿主内的 PE 映像（wine 进程就是 Linux 进程，`/proc/<pid>/mem` 直读）。
    WinePe,
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
            capabilities: vec![Capability::ListModules, Capability::ReadMemory],
        }))
    }

    #[test]
    fn frame_roundtrip() {
        let bytes = encode(&sample_frame()).unwrap();
        assert_eq!(decode(&bytes).unwrap(), sample_frame());
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
