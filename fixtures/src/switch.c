/* switch.c — 稠密 switch（应出**控制流**跳转表）与稀疏 switch（应出比较链/树）。
 *
 * 两个夹具坑（都踩过，别再踩）：
 * 1. 输入必须来自运行时（argc）：传常量会被 -O2 整体常量折叠，switch 整个消失。
 * 2. 每个 case 必须做**不同且体量相当**的事：如果 case 只是返回不同常量字符串，
 *    clang 会把它编译成「指针表查表」（movsxd + add + call），没有控制流跳转，
 *    跳转表恢复自然无从谈起。所以这里每个分支做不同算术，逼出 `jmp [table]`。
 *
 * 自校验：argc==1（正常直跑 / wine 跑）时结果必须是 0。 */
#include <stdio.h>

/* 每个分支做**不同的、无法合并成数据表**的运算：只有这样 clang 才会生成
 * 控制流跳转表（`movslq (base,idx,4),tmp` + `add base` + `jmp *tmp`），
 * 而不是「常量表索引」或 if 链。*/
static int mutate(int op, int x) {
    switch (op) {
        case 0: x = x + 0x11; break;
        case 1: x = x ^ 0x22; break;
        case 2: x = x - 0x33; break;
        case 3: x = x * 0x44; break;
        case 4: x = x | 0x55; break;
        case 5: x = x & 0x66; break;
        case 6: x = x << 1; break;
        case 7: x = x >> 1; break;
        case 8: x = -x; break;
        case 9: x = ~x; break;
        default: x = 0; break;
    }
    return x;
}

static int sparse(int x) {
    switch (x) {
        case 1: return 100;
        case 1000: return 200;
        case 100000: return 300;
        case 77777777: return 400;
        default: return -1;
    }
}

int main(int argc, char **argv) {
    (void)argv;
    // 循环上界与 op 都来自运行时：否则 clang 会展开循环 + 折叠成常量，
    // 跳转表根本不会出现在二进制里。
    int acc = 0;
    for (int i = 0; i < argc + 9; i++) {
        acc += mutate(i & 15, argc + 7);
    }
    int s = sparse(argc == 1 ? 1000 : 42);
    printf("switch: %d %d\n", acc, s);
    return s == 200 ? 0 : 1;
}