/* SPDX-License-Identifier: SySL-1.0
 * Copyright (c) 2026 langyo <sysl.contact@celestia.world>
 *
 * kotama windows payload agent (C, cross-built by zig cc).
 *
 * Why C and not the Rust agent: rust's windows-gnu std pulls in
 * synchronization / msvcrt / libpthread.a, which the mingw set bundled with
 * zig predates and ships only as sources. zig cc emits the dll directly and
 * wine loads it (verified). The wire format is byte-compatible with
 * kotama_proto, so the host speaks one protocol on both platforms.
 *
 * Transport is loopback TCP rather than a named pipe: wine maps winsock onto
 * host TCP, so a Linux host can attach natively; named pipes have no
 * host-side entry point under wine.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PROTO_VERSION 3
#define ABI_VERSION 1

// Growable output buffer.
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} Buf;

// Ensure room for `extra` more bytes; returns 1 on success.
static int buf_reserve(Buf *buffer, size_t extra)
{
    if(buffer->len + extra <= buffer->cap) {
        return 1;
    }
    size_t cap = buffer->cap ? buffer->cap * 2 : 256;
    while(cap < buffer->len + extra) {
        cap *= 2;
    }
    unsigned char *next = realloc(buffer->data, cap);
    if(next == NULL) {
        return 0;
    }
    buffer->data = next;
    buffer->cap = cap;
    return 1;
}

// msgpack unsigned integer (fixint through uint64).
static void mp_uint(Buf *buffer, unsigned long long value)
{
    if(value < 128) {
        buf_reserve(buffer, 1);
        buffer->data[buffer->len++] = (unsigned char)value;
        return;
    }
    if(value <= 0xff) {
        buf_reserve(buffer, 2);
        buffer->data[buffer->len++] = 0xcc;
        buffer->data[buffer->len++] = (unsigned char)value;
        return;
    }
    if(value <= 0xffff) {
        buf_reserve(buffer, 3);
        buffer->data[buffer->len++] = 0xcd;
        buffer->data[buffer->len++] = (unsigned char)(value >> 8);
        buffer->data[buffer->len++] = (unsigned char)value;
        return;
    }
    if(value <= 0xffffffffULL) {
        buf_reserve(buffer, 5);
        buffer->data[buffer->len++] = 0xce;
        for(int i = 3;i >= 0;i--) {
            buffer->data[buffer->len++] = (unsigned char)(value >> (8 * i));
        }
        return;
    }
    buf_reserve(buffer, 9);
    buffer->data[buffer->len++] = 0xcf;
    for(int i = 7;i >= 0;i--) {
        buffer->data[buffer->len++] = (unsigned char)(value >> (8 * i));
    }
}

// msgpack array header.
static void mp_array(Buf *buffer, unsigned count)
{
    if(count < 16) {
        buf_reserve(buffer, 1);
        buffer->data[buffer->len++] = (unsigned char)(0x90 | count);
        return;
    }
    buf_reserve(buffer, 3);
    buffer->data[buffer->len++] = 0xdc;
    buffer->data[buffer->len++] = (unsigned char)(count >> 8);
    buffer->data[buffer->len++] = (unsigned char)count;
}

// msgpack string (fixstr / str8).
static void mp_str(Buf *buffer, const char *text)
{
    size_t size = strlen(text);
    if(size < 32) {
        buf_reserve(buffer, 1);
        buffer->data[buffer->len++] = (unsigned char)(0xa0 | size);
    } else {
        buf_reserve(buffer, 2);
        buffer->data[buffer->len++] = 0xd9;
        buffer->data[buffer->len++] = (unsigned char)size;
    }
    buf_reserve(buffer, size);
    memcpy(buffer->data + buffer->len, text, size);
    buffer->len += size;
}

// msgpack binary blob.
static void mp_bin(Buf *buffer, const unsigned char *payload, size_t size)
{
    if(size < 256) {
        buf_reserve(buffer, 2);
        buffer->data[buffer->len++] = 0xc4;
        buffer->data[buffer->len++] = (unsigned char)size;
    } else {
        buf_reserve(buffer, 3);
        buffer->data[buffer->len++] = 0xc5;
        buffer->data[buffer->len++] = (unsigned char)(size >> 8);
        buffer->data[buffer->len++] = (unsigned char)size;
    }
    buf_reserve(buffer, size);
    memcpy(buffer->data + buffer->len, payload, size);
    buffer->len += size;
}

// Reader over one decoded frame.
typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
} Reader;

// Consume one scalar, storing integers in `out`; returns 1 on success.
static int mp_read(Reader *reader, unsigned long long *out)
{
    if(reader->pos >= reader->len) {
        return 0;
    }
    unsigned char tag = reader->data[reader->pos++];
    if(tag <= 0x7f) {
        *out = tag;
        return 1;
    }
    if(tag >= 0xe0) {
        *out = (unsigned long long)(signed char)tag;
        return 1;
    }
    if(tag >= 0xa0 && tag <= 0xbf) {
        size_t size = tag & 0x1f;
        if(reader->pos + size > reader->len) {
            return 0;
        }
        reader->pos += size;
        *out = 0;
        return 1;
    }
    if(tag == 0xcc || tag == 0xcd || tag == 0xce) {
        size_t width = (size_t)1 << (tag - 0xcc);
        if(reader->pos + width > reader->len) {
            return 0;
        }
        unsigned long long value = 0;
        for(size_t i = 0;i < width;i++) {
            value = (value << 8) | reader->data[reader->pos + i];
        }
        reader->pos += width;
        *out = value;
        return 1;
    }
    if(tag == 0xcf) {
        if(reader->pos + 8 > reader->len) {
            return 0;
        }
        unsigned long long value = 0;
        for(int i = 0;i < 8;i++) {
            value = (value << 8) | reader->data[reader->pos + i];
        }
        reader->pos += 8;
        *out = value;
        return 1;
    }
    if(tag == 0xd9) {
        if(reader->pos + 1 > reader->len) {
            return 0;
        }
        size_t size = reader->data[reader->pos++];
        if(reader->pos + size > reader->len) {
            return 0;
        }
        reader->pos += size;
        *out = 0;
        return 1;
    }
    if(tag == 0xdc) {
        if(reader->pos + 2 > reader->len) {
            return 0;
        }
        reader->pos += 2;
        *out = 0;
        return 1;
    }
    if(tag == 0xc4 || tag == 0xc5) {
        size_t width = (tag == 0xc4) ? 1 : 2;
        if(reader->pos + width > reader->len) {
            return 0;
        }
        size_t size = 0;
        for(size_t i = 0;i < width;i++) {
            size = (size << 8) | reader->data[reader->pos + i];
        }
        reader->pos += width;
        if(reader->pos + size > reader->len) {
            return 0;
        }
        reader->pos += size;
        *out = 0;
        return 1;
    }
    *out = 0;
    return 1;
}

// Read a string into `dst` (fixstr / str8 only).
static int mp_read_str(Reader *reader, char *dst, size_t dst_len)
{
    if(reader->pos >= reader->len) {
        return 0;
    }
    unsigned char tag = reader->data[reader->pos++];
    size_t size = 0;
    if(tag >= 0xa0 && tag <= 0xbf) {
        size = tag & 0x1f;
    } else if(tag == 0xd9) {
        if(reader->pos >= reader->len) {
            return 0;
        }
        size = reader->data[reader->pos++];
    } else {
        return 0;
    }
    if(reader->pos + size > reader->len || size >= dst_len) {
        return 0;
    }
    memcpy(dst, reader->data + reader->pos, size);
    dst[size] = 0;
    reader->pos += size;
    return 1;
}

// Write exactly `size` bytes to the socket.
static int send_all(SOCKET sock, const unsigned char *payload, size_t size)
{
    while(size > 0) {
        int sent = send(sock, (const char *)payload, (int)size, 0);
        if(sent <= 0) {
            return 0;
        }
        payload += sent;
        size -= (size_t)sent;
    }
    return 1;
}

// Read exactly `size` bytes from the socket.
static int recv_all(SOCKET sock, unsigned char *payload, size_t size)
{
    while(size > 0) {
        int got = recv(sock, (char *)payload, (int)size, 0);
        if(got <= 0) {
            return 0;
        }
        payload += got;
        size -= (size_t)got;
    }
    return 1;
}

// Emit a frame: 4-byte little-endian length, then the msgpack payload.
static int send_frame(SOCKET sock, Buf *buffer)
{
    unsigned char header[4];
    header[0] = (unsigned char)(buffer->len & 0xff);
    header[1] = (unsigned char)((buffer->len >> 8) & 0xff);
    header[2] = (unsigned char)((buffer->len >> 16) & 0xff);
    header[3] = (unsigned char)((buffer->len >> 24) & 0xff);
    return send_all(sock, header, 4) && send_all(sock, buffer->data, buffer->len);
}

// Start a response: map(1){"Response": map(1){<variant>: ...}}.
static void begin_response(Buf *out, const char *variant)
{
    out->len = 0;
    buf_reserve(out, 2);
    out->data[out->len++] = 0x81;
    mp_str(out, "Response");
    out->data[out->len++] = 0x81;
    mp_str(out, variant);
}

// Emit an error response with a message.
static void respond_error(Buf *out, const char *message)
{
    begin_response(out, "Error");
    mp_array(out, 2);
    mp_uint(out, 0);
    mp_str(out, message);
}

// wine exports wine_get_version from ntdll; native Windows does not. This is
// only for honest ModuleKind reporting, never for capability or detection logic.
static int running_under_wine(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll != NULL && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

// Decode one request and build its response.
static void handle(Reader *reader, Buf *out)
{
    reader->pos = 0;
    unsigned long long ignored = 0;
    char name[64];
    name[0] = 0;

    // Outer map(1) shell, then "Request".
    mp_read(reader, &ignored);
    mp_read_str(reader, name, sizeof(name));

    // Unit variants (ListModules) are bare strings after "Request"; variants
    // with a payload wrap another map(1) (verified against kotama-proto dumps:
    // 81 a7 "Request" ab "ListModules" vs 81 a7 "Request" 81 aa "ReadMemory").
    if(reader->pos < reader->len && reader->data[reader->pos] == 0x81) {
        reader->pos++;
        name[0] = 0;
        mp_read_str(reader, name, sizeof(name));
    } else if(reader->pos < reader->len && reader->data[reader->pos] >= 0xa0 &&
              reader->data[reader->pos] <= 0xbf) {
        name[0] = 0;
        mp_read_str(reader, name, sizeof(name));
    }

    if(strcmp(name, "Hello") == 0) {
        begin_response(out, "HelloAck");
        mp_array(out, 3);
        mp_uint(out, PROTO_VERSION);
        mp_uint(out, ABI_VERSION);
        mp_array(out, 2);
        mp_str(out, "ListModules");
        mp_str(out, "ReadMemory");
        return;
    }

    if(strcmp(name, "ListModules") == 0) {
        unsigned long long base = (unsigned long long)(uintptr_t)GetModuleHandleW(NULL);
        begin_response(out, "Modules");
        mp_array(out, 1);
        mp_array(out, 4);
        mp_uint(out, base);
        mp_uint(out, 0);
        mp_str(out, running_under_wine() ? "WinePe" : "NativePe");
        mp_str(out, "");
        return;
    }

    if(strcmp(name, "ReadMemory") == 0) {
        mp_read(reader, &ignored);
        unsigned long long address = 0;
        unsigned long long length = 0;
        mp_read(reader, &address);
        mp_read(reader, &length);
        if(length > 0x100000) {
            length = 0x100000;
        }
        unsigned char *payload = malloc((size_t)length);
        SIZE_T read = 0;
        int ok = payload != NULL &&
                 ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)address, payload,
                                   (SIZE_T)length, &read) &&
                 read == length;
        if(ok) {
            begin_response(out, "Memory");
            mp_bin(out, payload, (size_t)length);
        } else {
            respond_error(out, "read failed");
        }
        free(payload);
        return;
    }

    if(strcmp(name, "WriteMemory") == 0) {
        respond_error(out, "write lane gated (host capability)");
        return;
    }

    respond_error(out, "unknown method");
}

// Worker thread: winsock, connect, then the protocol loop.
static DWORD WINAPI agent_thread(LPVOID param)
{
    (void)param;
    char port_text[16];
    port_text[0] = 0;
    if(GetEnvironmentVariableA("KOTAMA_PAYLOAD_TCP", port_text, sizeof(port_text)) == 0) {
        return 0;
    }
    int port = atoi(port_text);
    if(port <= 0 || port > 65535) {
        return 0;
    }

    WSADATA wsa;
    if(WSAStartup(0x0202, &wsa) != 0) {
        return 0;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int connected = 0;
    for(int attempt = 0;attempt < 200 && connected == 0;attempt++) {
        if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            connected = 1;
        } else {
            Sleep(25);
        }
    }
    if(connected == 0) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    for(;;) {
        unsigned char header[4];
        if(recv_all(sock, header, 4) == 0) {
            break;
        }
        size_t length = (size_t)header[0] | ((size_t)header[1] << 8) | ((size_t)header[2] << 16) |
                        ((size_t)header[3] << 24);
        if(length == 0 || length > 0x100000) {
            break;
        }
        unsigned char *frame = malloc(length);
        if(frame == NULL) {
            break;
        }
        if(recv_all(sock, frame, length) == 0) {
            free(frame);
            break;
        }
        Reader reader;
        reader.data = frame;
        reader.len = length;
        reader.pos = 0;
        Buf out;
        out.data = NULL;
        out.len = 0;
        out.cap = 0;
        handle(&reader, &out);
        free(frame);
        int ok = send_frame(sock, &out);
        free(out.data);
        if(ok == 0) {
            break;
        }
    }
    closesocket(sock);
    WSACleanup();
    return 0;
}

// Registration point: attach only spawns the thread (loader-lock discipline).
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;
    if(reason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, agent_thread, NULL, 0, NULL);
    }
    return TRUE;
}