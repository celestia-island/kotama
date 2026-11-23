/* strings.c — 字符串字面量与导入函数引用：测字符串 xref 与导入表。
 * ⚠️ 输入必须来自运行时（argc）：传常量会被 -O2 常量折叠，字面量直接被内联成立即数，
 * .rodata 里什么都不会有（switch.c 同型坑，初版实测踩过）。
 * 自校验：拼出的串长度 > 10 则退出码 0。 */
#include <stdio.h>
#include <string.h>

static const char *banner = "kotama fixture: strings";
static char buffer[64];

static const char *choose(int x) {
    if (x > 100) return "large";
    if (x > 10) return "medium";
    return "small";
}

int main(int argc, char **argv) {
    (void)argv;
    strcpy(buffer, banner);
    strcat(buffer, "/");
    strcat(buffer, choose(argc * 40));
    size_t n = strlen(buffer);
    printf("strings: %s (%zu)\n", buffer, n);
    return n > 10 ? 0 : 1;
}