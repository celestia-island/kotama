int sink;
__attribute__((noinline)) int add3(int a, int b, int c) { return a + b + c + sink; }
__attribute__((noinline)) int mul2(int a, int b) { return a * b - sink; }
__attribute__((noinline)) int loopish(int n) { int s = 0; for (int i = 0; i < n; i++) s += i * (n - i); return s; }
int main(void) { return add3(1, 2, 3) + mul2(4, 5) + loopish(6); }
