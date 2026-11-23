/* float.c — 浮点算术与整型混合：测浮点寄存器语义与调用约定。
 * 自校验：容差不满足则退出码非 0。 */
#include <stdio.h>

static double poly(double x) {
    return 2.5 * x * x * x - 3.0 * x + 0.5;
}

static float mix(int a, float b) {
    float acc = 0.0f;
    for (int i = 0; i < a; i++) {
        acc += b * (float)i;
    }
    return acc;
}

int main(void) {
    double p = poly(2.0);
    float m = mix(5, 1.5f);
    printf("float: %.4f %.4f\n", p, m);
    double d = p - 14.5;
    return (d > -0.01 && d < 0.01) && (m > 14.99f && m < 15.01f) ? 0 : 1;
}