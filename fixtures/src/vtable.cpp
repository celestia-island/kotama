/* vtable.cpp — 真实 C++ 虚表：基类 + 两个派生类，经指针数组 + 运行时下标分发。
 *
 * ⚠️ 与 C 夹具同律：下标必须来自运行时（argc），否则整个分发被静态解虚拟化，
 * vtable 照样生成（语言要求），但调用边会被折叠——测扫描器没问题，测 xref 会空。
 *
 * PIE 下 vtable 槽位在文件里是 0，真值在 R_X86_64_RELATIVE 重定位里——
 * 这是 kotama-scan::vtables 必须走重定位表的全部理由。
 * 自校验：acc 为正则退出码 0（argc==1 时 acc = 3 + 6 + 1 + 2 = 12）。 */
#include <cstdio>

struct Device {
    virtual int step(int x) = 0;
    virtual int mode() const = 0;
    virtual ~Device() = default;
};

struct Fan final : Device {
    int state = 3;
    int step(int x) override { state += x; return state; }
    int mode() const override { return 1; }
};

struct Pump final : Device {
    int state = 7;
    int step(int x) override { state -= x; return state; }
    int mode() const override { return 2; }
};

int main(int argc, char **argv) {
    (void)argv;
    Device *devices[2] = {new Fan, new Pump};
    int acc = 0;
    for (int i = 0; i < argc + 1; i++) {
        acc += devices[i % 2]->step(i);
    }
    acc += devices[0]->mode() + devices[1]->mode();
    std::printf("vtable: %d\n", acc);
    delete devices[0];
    delete devices[1];
    return acc > 0 ? 0 : 1;
}