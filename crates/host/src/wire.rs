//! 传输无关的帧编解码与只读会话巡检。
//!
//! 帧格式只有一种（`kotama-proto` 的 msgpack + 4 字节 LE 长度前缀），只读会话步骤也
//! 只有一套（Hello 握手 + ListModules / ReadMemory）。Linux own-launch 的 unix socket、
//! Windows 原生车道的命名管道与 wine 车道的 TCP 都只提供 `Read + Write`，复用本模块。

use std::io::Read;
use std::io::Write;

use kotama_proto::Capability;
use kotama_proto::Frame;
use kotama_proto::Handshake;
use kotama_proto::ModuleInfo;
use kotama_proto::Request;
use kotama_proto::Response;
use kotama_proto::ThreadStack;

use crate::HostError;

/// 一帧的最大长度；peer 给的 u32 不能直接触发无界分配。
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// 发送一帧：4 字节 LE 长度前缀 + msgpack 载荷。
///
/// # Errors
/// 帧编码失败（理论不可达）或流写入失败。
pub fn send_frame<S>(stream: &mut S, frame: &Frame) -> Result<(), HostError>
where
    S: Write,
{
    let bytes =
        kotama_proto::encode(frame).map_err(|error| HostError::Proc(format!("encode: {error}")))?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(HostError::Proc(format!(
            "frame too large: {} bytes (limit {MAX_FRAME_LEN})",
            bytes.len()
        )));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| HostError::Proc(format!("frame too large: {} bytes", bytes.len())))?;
    stream
        .write_all(&length.to_le_bytes())
        .map_err(|error| HostError::Proc(format!("send length: {error}")))?;
    stream
        .write_all(&bytes)
        .map_err(|error| HostError::Proc(format!("send frame: {error}")))
}

/// 接收一帧。
///
/// # Errors
/// 流提前结束、长度前缀读取失败或 msgpack 解码失败。
pub fn recv_frame<S>(stream: &mut S) -> Result<Frame, HostError>
where
    S: Read,
{
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| HostError::Proc(format!("recv length: {error}")))?;
    let length = u32::from_le_bytes(length);
    let length = usize::try_from(length)
        .map_err(|_| HostError::Proc(format!("frame length does not fit usize: {length}")))?;
    if length > MAX_FRAME_LEN {
        return Err(HostError::Proc(format!(
            "frame too large: {length} bytes (limit {MAX_FRAME_LEN})"
        )));
    }
    let mut bytes = vec![0u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| HostError::Proc(format!("recv frame: {error}")))?;
    kotama_proto::decode(&bytes).map_err(|error| HostError::Proc(format!("decode: {error}")))
}

/// 发一个请求并等待一个应答。
///
/// # Errors
/// 发送失败、流关闭或对端回了一个请求帧。
pub fn request<S>(stream: &mut S, request: &Request) -> Result<Response, HostError>
where
    S: Read + Write,
{
    send_frame(stream, &Frame::Request(request.clone()))?;
    match recv_frame(stream)? {
        Frame::Response(response) => Ok(response),
        Frame::Request(_) => Err(HostError::Proc(
            "payload sent a request instead of a response".into(),
        )),
    }
}

/// 只读能力握手：发 Hello → 校验协议版本 → 返回载荷侧握手。
///
/// 版本不匹配 = 拒绝（无回退），与 `kotama_proto::PROTO_VERSION` 的契约一致。
///
/// # Errors
/// 请求失败、对端协议版本不同或对端显式拒绝握手。
pub fn handshake<S>(stream: &mut S) -> Result<Handshake, HostError>
where
    S: Read + Write,
{
    let reply = request(
        stream,
        &Request::Hello(Handshake {
            proto_version: kotama_proto::PROTO_VERSION,
            abi_version: kotama::ABI_VERSION,
            capabilities: kotama_proto::READ_ONLY_CAPABILITIES.to_vec(),
        }),
    )?;
    match reply {
        Response::HelloAck(theirs) => {
            if theirs.proto_version != kotama_proto::PROTO_VERSION {
                return Err(HostError::Proc(format!(
                    "payload proto {} != host proto {}",
                    theirs.proto_version,
                    kotama_proto::PROTO_VERSION
                )));
            }
            Ok(theirs)
        }
        Response::Error { code, message } => Err(HostError::Proc(format!(
            "handshake rejected: {code} {message}"
        ))),
        other => Err(HostError::Proc(format!(
            "unexpected handshake reply: {other:?}"
        ))),
    }
}

/// 枚举载荷所在进程的模块。
///
/// # Errors
/// 请求失败或对端返回错误。
pub fn list_modules<S>(stream: &mut S) -> Result<Vec<ModuleInfo>, HostError>
where
    S: Read + Write,
{
    match request(stream, &Request::ListModules)? {
        Response::Modules(modules) => Ok(modules),
        Response::Error { code, message } => {
            Err(HostError::Proc(format!("list modules: {code} {message}")))
        }
        other => Err(HostError::Proc(format!(
            "unexpected list modules reply: {other:?}"
        ))),
    }
}

/// 经载荷读一段目标进程内存（载荷视角的绝对地址）。
///
/// # Errors
/// 请求失败或对端返回错误。
pub fn read_memory<S>(stream: &mut S, address: u64, length: u32) -> Result<Vec<u8>, HostError>
where
    S: Read + Write,
{
    match request(stream, &Request::ReadMemory { address, length })? {
        Response::Memory(bytes) => Ok(bytes),
        Response::Error { code, message } => {
            Err(HostError::Proc(format!("read memory: {code} {message}")))
        }
        other => Err(HostError::Proc(format!(
            "unexpected read memory reply: {other:?}"
        ))),
    }
}

/// 让载荷自抓**它自己**服务线程的栈（`StackSnapshot` 能力）。
///
/// 能力门禁在宿主侧：载荷没在 `HelloAck` 里声明 `StackSnapshot` 就直接
/// [`HostError::CapabilityDenied`]，**不**把请求发给不认识它的旧载荷（C agent）。
/// 这一步也顺手钉住「加法能力靠握手声明」的语义：能力表是唯一判据。
///
/// 返回帧序由内向外，模块以加载基址标识（`module_base + module_rva`）；符号化是宿主
/// 的事（载荷内不初始化 dbghelp，免得和目标自己的符号处理器抢进程级状态）。
///
/// # Errors
/// 载荷未声明该能力、请求失败或对端返回错误。
pub fn stack_snapshot<S>(
    stream: &mut S,
    handshake: &Handshake,
    max_frames: u32,
) -> Result<Vec<ThreadStack>, HostError>
where
    S: Read + Write,
{
    if !handshake.supports(Capability::StackSnapshot) {
        return Err(HostError::CapabilityDenied(
            "payload did not declare capability stack-snapshot in the handshake; refusing to send a request it cannot serve",
        ));
    }
    match request(stream, &Request::StackSnapshot { max_frames })? {
        Response::Stacks(stacks) => Ok(stacks),
        Response::Error { code, message } => {
            Err(HostError::Proc(format!("stack snapshot: {code} {message}")))
        }
        other => Err(HostError::Proc(format!(
            "unexpected stack snapshot reply: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let length = u32::try_from(MAX_FRAME_LEN + 1).expect("limit fits u32");
        let mut cursor = Cursor::new(length.to_le_bytes().to_vec());
        let error = recv_frame(&mut cursor).expect_err("oversized frame accepted");
        assert!(error.to_string().contains("frame too large"), "{error}");
    }
}
