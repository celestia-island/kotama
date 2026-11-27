// Cross-compiled sample for the RISC-V lifter: three calls, one loop, a literal.
__attribute__((noinline)) int helper(int x) { return x * 2 + 1; }
__attribute__((noinline)) int other(int x) { return x - 7; }
int compute(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += (i & 1) ? helper(i) : other(i);
    return s;
}
void _start(void) { (void)compute(6); __builtin_trap(); }
