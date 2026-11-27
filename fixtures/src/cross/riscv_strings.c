// Cross-compiled sample whose literals exercise auipc/lui + addi address forming.
int sink;
__attribute__((noinline)) int len(const char *s) { int n = 0; while (s[n]) n++; return n; }
int compute_all(void) {
  sink += len("hello_from_riscv");
  sink += len("another_string_here");
  sink += len("third_literal_ok");
  return sink;
}
void _start(void) { (void)compute_all(); __builtin_trap(); }
