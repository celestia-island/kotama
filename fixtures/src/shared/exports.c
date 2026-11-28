// Shared-library fixture: its exports are what a runtime's C ABI looks like from
// outside (the shape of a Lua or QuickJS .so/.dll). Built with -shared, never run.
__attribute__((visibility("default"))) int exported_add(int a, int b) { return a + b; }
__attribute__((visibility("default"))) int exported_mul(int a, int b) { return a * b; }
__attribute__((visibility("default"))) void exported_void(void) {}
// Exported **data**, not code: a shared library's ABI can export a variable, and
// the hook planner must offer it as little as a PE's RTTI vtable. This is the
// ELF shape of what __mingw_module_is_dll is on the PE side.
__attribute__((visibility("default"))) const int exported_rodata = 0x5a5a5a5a;
// Deliberately not exported: a static must never appear in the dynamic table.
static int hidden_helper(int x) { return x * 2; }
