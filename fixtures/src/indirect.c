/* indirect.c — 函数指针表 / vtable 形态的间接调用：测间接调用边发现。
 * 自校验：分发表全走一遍，结果不对则退出码非 0。 */
#include <stdio.h>

typedef int (*op_fn)(int, int);

typedef struct {
    const char *name;
    op_fn op;
} vtable_entry;

static int op_add(int a, int b) { return a + b; }
static int op_sub(int a, int b) { return a - b; }
static int op_mul(int a, int b) { return a * b; }
static int op_xor(int a, int b) { return a ^ b; }

static const vtable_entry ops[4] = {
    {"add", op_add},
    {"sub", op_sub},
    {"mul", op_mul},
    {"xor", op_xor},
};

static int dispatch(int idx, int a, int b) {
    return ops[idx].op(a, b);
}

int main(void) {
    int acc = 0;
    for (int i = 0; i < 4; i++) {
        acc += dispatch(i, 10, 4);
    }
    printf("indirect: %d\n", acc);
    return acc == (14 + 6 + 40 + 14) ? 0 : 1;
}