#pragma once
#include "aarch64_asm_stack_buf_guard.h"

// 默认跳过的字节数，足以避开绝大多数函数的金丝雀 (Canary)
constexpr uint32_t DEFAULT_CANARY_BYPASS_SIZE = 0x50;

/***************************************************************************
 * 金丝雀绕过守卫 (CanaryBypassGuard)
 * 作用: 专用于在带有 SSP (Stack Protector) 的函数中，向下开辟绝对安全的内存区，完美避开金丝雀的检测范围。
 ***************************************************************************/
class CanaryBypassGuard : public StackBufGuard {
public:
    /*************************************************************************
     * 构造函数
     * 参数: a         : Assembler 指针
     *       bytes     : 默认跳过 0x50 字节 (足以避开绝大多数函数的金丝雀)
     *************************************************************************/
    explicit CanaryBypassGuard(asmjit::a64::Assembler* a, uint32_t bytes = DEFAULT_CANARY_BYPASS_SIZE) : StackBufGuard(a, bytes, xzr) {}

    // 禁用拷贝与赋值
    CanaryBypassGuard(const CanaryBypassGuard&) = delete;
    CanaryBypassGuard& operator=(const CanaryBypassGuard&) = delete;

    // 允许移动语义 (复用基类的机制)
    CanaryBypassGuard(CanaryBypassGuard&&) = default;
    CanaryBypassGuard& operator=(CanaryBypassGuard&&) = default;
    ~CanaryBypassGuard() = default;
};