#ifdef _WIN32
#define KOTAMA_EXPORT __declspec(dllexport)
#else
#define KOTAMA_EXPORT __attribute__((visibility("default")))
#endif

KOTAMA_EXPORT int fixture_exported(int value) { return value + 1; }

int main(void) { return fixture_exported(0); }
