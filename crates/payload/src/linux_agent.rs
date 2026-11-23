#![allow(unsafe_code)] // C ABI 边界；安全论据见各 SAFETY 注。

//! Linux 载荷注册与传输：`.init_array` + 裸 `pthread_create` + unix socket 回连。
//!
//! 安全论据见各 SAFETY 注；协议层在 crate 根（传输无关）。

use std::os::unix::net::UnixStream;

/// 登记点：`.init_array` 在装载时调用（loader lock 内——只允许 pthread_create 这一件事）。
#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = bootstrap;

pub(crate) extern "C" fn bootstrap() {
    let Ok(socket_path) = std::env::var("KOTAMA_PAYLOAD_SOCKET") else {
        return; // 不是 kotama 拉起的进程：静默不接线。
    };
    // CString（瘦指针）过 pthread 边界；线程收回后释放。
    let bytes = socket_path.as_bytes();
    // SAFETY: malloc(len+1) 装得下路径串 + NUL。
    let arg = unsafe { libc::malloc(bytes.len() + 1) as *mut libc::c_char };
    // SAFETY: 写入 NUL 结尾的路径串。
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const libc::c_char, arg, bytes.len());
        *arg.add(bytes.len()) = 0;
    }
    let mut thread = 0;
    // SAFETY: arg 指向 NUL 结尾路径串；agent_entry 是 C 兼容入口。
    unsafe {
        libc::pthread_create(
            &mut thread,
            std::ptr::null(),
            agent_entry,
            arg as *mut libc::c_void,
        );
        libc::pthread_detach(thread);
    }
}

/// pthread 入口：回到 Rust 世界（工作线程不再持有 loader lock）。
extern "C" fn agent_entry(arg: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: bootstrap malloc 的路径串；收回成 String（此线程独占）。
    let path = unsafe {
        std::ffi::CStr::from_ptr(arg as *const libc::c_char)
            .to_string_lossy()
            .into_owned()
    };
    for _ in 0..200 {
        if let Ok(stream) = UnixStream::connect(path.as_str()) {
            super::serve(stream);
            return std::ptr::null_mut();
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    std::ptr::null_mut()
}
