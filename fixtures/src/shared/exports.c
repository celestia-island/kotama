// Shared-library fixture: its exports are what a runtime's C ABI looks like from
// outside (the shape of a Lua or QuickJS .so/.dll). Built with -shared, never run.
__attribute__((visibility("default"))) int exported_add(int a, int b) { return a + b; }
__attribute__((visibility("default"))) int exported_mul(int a, int b) { return a * b; }
__attribute__((visibility("default"))) void exported_void(void) {}
// Deliberately not exported: a static must never appear in the dynamic table.
static int hidden_helper(int x) { return x * 2; }
