/* loops.c — 嵌套循环 / 归纳变量 / 取模：测循环复原与归纳变量提升。
 * 自校验：期望和不对则退出码非 0。 */
#include <stdio.h>

static int sum_squares(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if ((i + j) % 3 == 0) {
                total += i * j;
            } else {
                total -= 1;
            }
        }
    }
    return total;
}

static int count_down(int n) {
    int steps = 0;
    while (n > 1) {
        n = (n % 2 == 0) ? n / 2 : 3 * n + 1;
        steps++;
    }
    return steps;
}

int main(void) {
    int a = sum_squares(9);
    int b = count_down(27);
    printf("loops: %d %d\n", a, b);
    return (a == 387) && (b == 111) ? 0 : 1;
}