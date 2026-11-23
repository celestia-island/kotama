/* recurs.c — 直接递归与互递归：测调用图深度与栈帧。
 * 自校验：期望值不对则退出码非 0。 */
#include <stdio.h>

static int fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

static int is_even(int n);
static int is_odd(int n);

static int is_even(int n) { return n == 0 ? 1 : is_odd(n - 1); }
static int is_odd(int n) { return n == 0 ? 0 : is_even(n - 1); }

int main(void) {
    int f = fib(20);
    int e = is_even(34);
    printf("recurs: %d %d\n", f, e);
    return (f == 6765) && (e == 1) ? 0 : 1;
}