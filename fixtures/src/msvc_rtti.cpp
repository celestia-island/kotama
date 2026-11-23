/* msvc_rtti.cpp — 真实 C++ RTTI 靶子：多重继承 + 虚继承 + 交叉转换。
 *
 * 目的：给 kotama-scan::msvc_rtti 提供真实的 MSVC PE32/PE64 CompleteObjectLocator、
 * TypeDescriptor、BaseClassArray 事实。同一份源码也会被 windows-gnu / linux-gnu 车道
 * 编译成 Itanium ABI 虚表——那是「MSVC RTTI 不得误判」的阴性对照。
 *
 * 设计要点：
 * - Fan : Left, Right 是多重继承，Left 又虚继承 Device：完整对象里因此有多张
 *   vftable（各自带 COL，offset 不同）和虚基类位移事实；
 * - dynamic_cast 交叉转换（Device* -> Right*）与 typeid 比较迫使 RTTI 与继承图落地；
 * - 种子来自 argc/argv、构造走 noinline 函数：阻断静态解虚拟化，避免虚调用被折叠；
 * - 自校验：全部检查通过退出码 0，任一失败退出码 1。
 */
#include <cstdio>
#include <cstring>
#include <typeinfo>

namespace rtti_fixture {

#if defined(_MSC_VER)
#define KOTAMA_NOINLINE __declspec(noinline)
#else
#define KOTAMA_NOINLINE __attribute__((noinline))
#endif

/// 抽象基类：纯虚函数让它的 vftable 出现 __purecall 槽。
struct Device {
    virtual int step(int x) = 0;
    virtual int mode() const = 0;
    virtual ~Device() = default;
};

/// 虚继承 Device：Device 虚基类子对象在完整对象里不与 Left 子对象相邻。
struct Left : virtual Device {
    int left_state = 3;
    int step(int x) override {
        left_state += x;
        return left_state;
    }
    virtual int left_extra() const { return left_state * 2; }
};

/// 第二条多继承分支（普通基类），带自己的 vftable。
struct Right {
    int right_state = 7;
    virtual int right_value() const { return right_state; }
    virtual ~Right() = default;
};

/// 完整对象：多继承 + 虚继承，至少三张 vftable。
struct Fan final : Left, Right {
    int mode() const override { return 1; }
    int right_value() const override { return right_state + 1; }
};

KOTAMA_NOINLINE Device *make_device(int seed) {
    Fan *fan = new Fan;
    fan->left_state = seed;
    fan->right_state = seed + 1;
    return fan;
}

KOTAMA_NOINLINE int probe(int seed) {
    Device *device = make_device(seed);
    int failures = 0;

    // 交叉转换必须沿真实继承图走：Device -> Fan -> Right。
    Right *right = dynamic_cast<Right *>(device);
    if (right == nullptr) {
        failures |= 1;
    } else {
        // 调整后的子对象指针与完整对象指针必然不同（Right 不是主基类）。
        if (static_cast<void *>(right) == static_cast<void *>(device)) {
            failures |= 2;
        }
        if (right->right_value() != seed + 2) {
            failures |= 4;
        }
    }

    // 反向转换与 typeid 比较迫使 TypeDescriptor / 类层次真实可用。
    Fan *fan = dynamic_cast<Fan *>(device);
    if (fan == nullptr) {
        failures |= 8;
    }
    if (typeid(*device) != typeid(Fan)) {
        failures |= 16;
    }
    if (std::strlen(typeid(*device).name()) == 0) {
        failures |= 32;
    }

    Left *left = dynamic_cast<Left *>(device);
    if (left == nullptr) {
        failures |= 64;
    }

    // 顺序求值：left_extra 读 left_state，step 会改它，写成一条表达式会让
    // 编译器在两个优化档之间给出不同结果（fixture 输出应当是确定的）。
    int acc = 0;
    if (fan != nullptr && left != nullptr) {
        acc += left->step(seed);
        acc += fan->right_value();
        acc += fan->mode();
        acc += fan->left_extra();
    }
    delete device;
    if (acc <= 0) {
        failures |= 128;
    }
    std::printf("msvc_rtti: seed=%d acc=%d\n", seed, acc);
    return failures;
}

} // namespace rtti_fixture

int main(int argc, char **argv) {
    // 运行时输入：argv[0] 首字符定种子；argc/argv 参与计算，阻断常量折叠。
    const unsigned char byte = (argc > 0 && argv != nullptr && argv[0] != nullptr)
        ? static_cast<unsigned char>(argv[0][0])
        : 1u;
    const int seed = static_cast<int>(byte % 4u) + 1;
    const int failures = rtti_fixture::probe(seed);
    return failures == 0 ? 0 : 1;
}
