/* hookme.c — 活体钩子 e2e 的靶子：一个序言没有 RIP-relative 指令、够放 5 字节跳转的函数。
 * 用法：hookme [秒]。每 100ms 调一次 beat() 并打印它的返回值；beat 的序言是纯栈操作，
 * 前 8 字节正好是三条完整指令（push rbp / mov rbp,rsp / sub rsp,0x20），安装钩子时能整段搬走。 */
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <unistd.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

/* 序言是纯栈操作，前 5 字节正好是三条完整指令（push rbp; push rax; mov rbp,rsp），
 * 没有 RIP-relative，安装钩子时能整段搬走。noinline 挡住内联；它被 main 调用，
 * 不会被当作死代码删掉——所以不需要 MSVC 的 /include（那在 x86 上会去找 _beat）。 */
#if defined(_MSC_VER)
__declspec(noinline) int beat(int i) { volatile int t = i & 3; return t + 1; }
#else
__attribute__((noinline, used)) int beat(int i) { volatile int t = i & 3; return t + 1; }
#endif

int main(int argc, char **argv) {
    int seconds = argc > 1 ? atoi(argv[1]) : 1;
    for (int i = 0; i < seconds * 10; i++) {
        printf("hookme: %d\n", beat(i));
        fflush(stdout);
        SLEEP_MS(100);
    }
    return 0;
}
