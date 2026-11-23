/* spin.c — 长跑靶子：活体注入/分析的默认目标进程。
 * 用法：spin [秒]（默认 1；活体 e2e 用 20+）。每秒打一行心跳带自增计数，
 * 便于 e2e 等待「已进入主循环」再附加。 */
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <unistd.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

static int hot_counter = 0;

/* 活体扫描的锚点函数：计数器在栈外，肉眼/扫描都能看到它在变。 */
__attribute__((used)) static int tick(int i) {
    hot_counter += i & 3;
    return hot_counter;
}

int main(int argc, char **argv) {
    int seconds = argc > 1 ? atoi(argv[1]) : 1;
    for (int i = 0; i < seconds * 10; i++) {
        int value = tick(i);
        if (i % 10 == 0) {
            printf("spin: %d\n", value);
            fflush(stdout);
        }
        SLEEP_MS(100);
    }
    return hot_counter >= 0 ? 0 : 1;
}
