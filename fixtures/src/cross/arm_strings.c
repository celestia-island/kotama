// Cross-compiled sample whose literals exercise movw + movt address forming.
int sink;
__attribute__((noinline)) int len(const char *s) { int n = 0; while (s[n]) n++; return n; }
volatile int out;
int main(void) {
  out += len("hello_from_arm");
  out += len("second_literal");
  out += len("third_one_ok");
  return out;
}
