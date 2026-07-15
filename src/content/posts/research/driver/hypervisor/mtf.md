---
title: Hypervisor Sparkle 研究日志 - MTF
description: 在这篇文章中将对 MTF 分析研究。探究 EPT Hook 场景 MTF 所起到的重要作用。
published: 2026-07-19
category: 驱动开发
tags: [Hypervisor, Windows内核, Windows, WDM, Sparkle, Vmcs, MTF]
pinned: false
draft: false
---

## 前言

写 EPT hook 的时候会碰到一个棘手问题：**怎么"临时把某条指令原样执行一次"，然后马上拿回控制权？**

比如你 hook 了一个函数入口，`EPT violation` 触发后你想让原始指令（被 patch/重定向前的那几个字节）**真正跑一次**，跑完立刻再 trap 回来继续你的逻辑。

举个例子：一般 `Inline Hook` 的 `jmp` 会破坏函数头，但它又希望执行这个函数头，为了解决这个问题，它会将原始指令复制到 Hook 后的函数。

但是 `EPT Hook` 和它不同，对于一个运行在虚拟化层的 hypervisor 它没法轻松实现这一点。

如果没有一个"单步执行 + 立即通知我"的机制，那么久只能靠软件模拟指令语义，既麻烦又容易出错。

这就是 **MTF（Monitor Trap Flag）** 存在的意义：

它是 VT-x 提供的用于解决这个难题，也就是 `单步执行并在下一条指令边界强制 VM-exit` 的硬件机制。

---

## MTF

### 定义

MTF 是 `VMCS` 里的一个控制位，开启后，**guest 每执行完一条指令，或者说在下一个指令边界，都会强制触发一次 VM-exit**，exit reason 为 `EXIT_REASON_MONITOR_TRAP_FLAG`。

它本质上跟 `EFLAGS.TF`（单步陷阱标志）功能类似，但**完全独立于 guest 自己的 TF 位**。

guest OS 完全感知不到你在用 MTF，不会污染它自己的调试状态，这对 hypervisor 来说非常关键。

### 控制位置

```c
#define CPU_BASED_MONITOR_TRAP_FLAG   (1UL << 27)

UINT32 ProcCtrls = __vmx_vmread(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS);
ProcCtrls |= CPU_BASED_MONITOR_TRAP_FLAG;
__vmx_vmwrite(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, ProcCtrls);
```

> [!NOTE]
> 这个位要先检查 IA32_VMX_PROCBASED_CTLS MSR 里对应 bit 是否 allow-1。

### 和普通 VM-exit 的区别

MTF 是**一次性**机制：

你设置了这个位，guest 执行完当前这条（或者说，从当前 VM-entry 开始的下一条）指令之后就会 VM-exit，**exit 之后这个位不会自动保持**。

如果你想继续单步下一条，你需要在下一次 `VM-entry` 前**重新设置**这个位。

这个"用一次就得手动重挂"的特性，正是它和 debug register / TF 单步的核心差异。

## MTF 与 EPT Hook

### EPT Hook 的痛点

EPT Hook 天然是`页级别`粒度，而不是`指令级别`。

EPT Hook 常见做法是把某一页设成 `execute-only`，guest 尝试读/写那个地址时会触发 `EPT violation`。

但这里有个问题：**一旦我们把控制权还给 guest，它可能会一直在那个页里执行很多条指令，直到离开这一页**——如果你只关心"这一条特定指令执行完之后"要做点什么（比如恢复原始字节，或者记录执行后的寄存器状态），EPT violation 本身给不了你这个粒度。

但是这种情况又是非常普遍的，这该怎么办？

这时候我们就可以在 **EPT violation 触发后，先临时把该页恢复成可读写执行的原始状态，让 CPU 真正执行这条指令，同时开启 MTF，指令执行完毕 MTF 立刻把你 trap 回来，你再把页面权限改回 hook 状态**。

比如下一条指令是 `call PlayerPositionDecrypt` 我们肯定是希望看看这个执行后会怎么样。

~~毕竟说不定坐标就到手了~~

### Hook Step-Over

这里写一下大致的过程：

```c
// VM-exit handler 处理 EPT violation
VOID HandleEptViolationForHook(PVCPU Vcpu, UINT64 GuestPhysicalAddr)
{
    PHOOK_ENTRY Hook = FindHookByPhysAddr(GuestPhysicalAddr);
    if (!Hook)
        return; // 不是我们关心的地址,走正常反射逻辑

    // 临时恢复该页为原始可执行状态
    RestoreOriginalPageMapping(Hook);

    // 开启 MTF, 让guest真正执行这一条指令
    UINT32 ProcCtrls = __vmx_vmread(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS);
    ProcCtrls |= CPU_BASED_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, ProcCtrls);

    // 记录当前正在单步恢复的hook，供MTF exit时查表用
    Vcpu->PendingMtfHook = Hook;
}

// VM-exit handler 处理 MTF
VOID HandleMonitorTrapFlag(PVCPU Vcpu)
{
    PHOOK_ENTRY Hook = Vcpu->PendingMtfHook;
    if (Hook)
    {
        // 指令已经真实执行完毕,把页面权限改回hook状态
        ReapplyHookPageMapping(Hook);
        Vcpu->PendingMtfHook = NULL;
    }

    // 关闭MTF位 (不再需要)
    UINT32 ProcCtrls = __vmx_vmread(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS);
    ProcCtrls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, ProcCtrls);
}
```

### 为什么不能直接用 `EFLAGS.TF` 代替 MTF

- **guest 可感知**：`EFLAGS.TF` 是架构可见状态，guest 里的调试器/反作弊如果读了 `EFLAGS` 或者自己也用单步调试，两边会打架，导致 hypervisor 的存在暴露。
- **状态污染风险**：你需要在设置前保存、之后精确恢复原始 `EFLAGS.TF`，一旦某个中间环节被打断（比如又插入了一次 VM-exit），很容易漏恢复，导致 guest 表现异常。
- **MTF 完全在 VMX root 之外不可见**：guest 无法通过任何指令读到"我现在正在被 MTF 监控"，这对 hypervisor 的隐蔽性和正确性都更友好。

## MTF 的应用

### 精确恢复"注入事件"之后的状态

如果你刚给 guest 注入了一个异常/中断，想知道 guest 的 IDT handler **第一条指令**执行前的状态（比如验证注入是否成功送达、栈是否正确构造），可以在注入的同时开 MTF，下一次 exit 就是 handler 入口执行前的精确断点。

### 单步追踪 / 沙箱分析

恶意代码分析沙箱经常需要"指令级别 trace"，每执行一条指令记录一次寄存器/内存状态。

相比于纯软件模拟执行，MTF + VM-exit handler 记录状态是性能和精度都更好的方案，虽然仍然比原生执行慢得多，但比全软件模拟快。

### 配合 Instruction VM-exit 做部分模拟

有些指如果令你想自己完全模拟（不让它真执行，比如 `RDTSC`/`CPUID` 这类常规做法直接拦截即可），但有些指令你只想在**执行完之后**追加逻辑（比如 `WRMSR` 之后你想知道写入生效后的实际 MSR 值）。

这种场景下，可以先放行指令执行，同时开 MTF，下一次 exit 拿到"执行完毕后"的状态，而不必自己完整实现该指令的语义。

## 注意

### MTF 是下一条指令边界，不是"当前VM-exit立刻返回"

设置 MTF 之后做 VM-entry，CPU 会先**正常执行**当前 guest 该执行的下一条指令，执行完了才 trap。

如果 `VM-entry` 时机不对（比如 guest RIP 还没正确设置成"要执行的那条指令"），MTF 触发的时间点会和预期的不一致。

### 中断/异常可能打断单步窗口

如果在开启 MTF、准备执行那条指令期间，恰好有一个外部中断或者 NMI 需要送达，硬件通常会**优先处理中断**，此时 MTF **可能**会被推迟到中断处理完之后才触发。

### MTF 是一次性的

如上面提过的，MTF 是一次性的。

## 和普通单步 debug 对比

| 特性 | MTF | `EFLAGS.TF` 单步 | 硬件断点 (DR0-3) |
|---|---|---|---|
| Guest 可感知 | 否 | 是 | 是（可通过`DR7`观测） |
| 触发方式 | VMCS 控制位 | 修改架构可见寄存器 | 修改调试寄存器 |
| 一次性/持续 | 一次性，需手动重挂 | 持续（直到清TF） | 持续（直到清DR7对应位） |
| 是否产生guest可见异常 | 否 | 是（触发`#DB`） | 是（触发`#DB`） |
| 典型用途 | Hook单步恢复、精确trace | ring0调试 | 断点调试 |

MTF 相比 `#DB` 单步的最大优势就是**完全绕过 guest 的异常处理路径**，直接从 VMX non-root 陷回 VMX root。

guest 自己的 IDT、`#DB` handler 完全不参与。

因此 MTF 对于实现无痕 Hook 意义重大。

## 参考

- Intel SDM Vol.3C, 25.5.2 "Monitor Trap Flag"
- Intel SDM Vol.3C, 24.6.2 "Processor-Based VM-Execution Controls"
- Intel SDM Vol.3C, Appendix A.3 "VM-Execution Controls"
