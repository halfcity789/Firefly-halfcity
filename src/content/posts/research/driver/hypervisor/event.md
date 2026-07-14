---
title: Hypervisor Sparkle 研究日志 - Event Injection
description: 在这篇文章中将对 hypervisor 的事件注入进行详细的分析研究，探索它的由来以及它所发挥的重要作用。
published: 2026-07-15
category: 驱动开发
tags: [Hypervisor, Windows内核, Windows, WDM, Sparkle, Vmcs, Interrupt, Reflect]
pinned: false
draft: false
---

## 前言

有时我们会遇到这样一个问题：

**guest 触发了一个异常/中断，但这个异常本该由 guest 自己处理，我该怎么"还给它"？** 

或者换句话说 **我作为 VMM，想让 guest 主动感知到一个中断/异常（模拟设备中断、反调试陷阱等），该怎么塞进去？**

答案就是 **事件注入（Event Injection）**

它是由 VT-x 提供的、允许 VMM 在 VM-entry 时刻，让 CPU 硬件自动帮你构造一次"中断/异常发生"场景的机制。

---

## 理论

### 核心矛盾

没有虚拟化的时候，CPU 遇到异常（比如执行了非法指令 `#UD`）会自动走 IDT 查表、切换特权级、压栈、跳转到 handler。

这一整套流程叫 **event delivery**。

引入 VT-x 之后，如果这个异常发生在 guest mode 下，并且在 VMCS 里配置了对应的 exception bitmap 位，CPU 就不会走 guest 自己的 IDT，而是直接 VM-exit 到 VMM。

这时候 guest 的 IDT 就完全被劫持了。

如果 VMM 什么都不做，或者 VMM 不告诉 guest 发生了什么，guest 就永远不知道自己应该进入哪个异常处理流程。

事件注入就是用来解决这个矛盾的：

**VMM 决定，在下一次 VM-entry 时，让硬件替我完成"就像这个异常/中断刚刚在 guest 里发生"的全部动作**，包括查 guest IDT、压栈、跳转、必要时的错误码传递。

这一切都在 VM-entry 这一步由硬件原子完成，VMM 不需要手动模拟 IDT walk。

### VMCS 字段

```c
typedef union _VMENTRY_INTERRUPT_INFO {
    struct {
        UINT32 Vector             : 8;  // [7:0]   中断/异常向量号
        UINT32 InterruptionType   : 3;  // [10:8]  事件类型
        UINT32 DeliverErrorCode   : 1;  // [11]    是否压入错误码
        UINT32 Reserved           : 19; // [30:12]
        UINT32 Valid              : 1;  // [31]    本次entry是否注入事件
    } Fields;
    UINT32 All;
} VMENTRY_INTERRUPT_INFO;
```

### Interruption Type

| 值 | 名称 | 触发场景 | 是否需要 Instruction Length |
|---|---|---|---|
| 0 | External Interrupt | 外部硬件中断（如虚拟 PIC/APIC 定时器） | 否 |
| 2 | NMI | 不可屏蔽中断 | 否 |
| 3 | Hardware Exception | CPU 检测到的异常，如 `#PF`(14)、`#GP`(13)、`#UD`(6) | 否（`#BP`/`#OF` 除外的绝大多数） |
| 4 | Software Interrupt | `INT n` 指令（n≠3） | **是** |
| 5 | Privileged Software Exception | `INT1`（`ICEBP`） | 是 |
| 6 | Software Exception | `INT3`、`INTO` | **是** |
| 7 | Other Event | 保留（部分场景用于 MTF） | - |

> [!NOTE]
> 类型选错，guest 行为会不一致。比如你想反射一个真实发生的 `#PF`，必须用类型 3（Hardware Exception），而不是类型 6，否则 guest 的 IDT descriptor 里 DPL 检查、error code 是否压栈的语义都会不对。

### 哪些异常需要 DeliverErrorCode

参考硬件真实行为，这些异常在 real hardware 上就会压入错误码，注入时也必须同步设置：

#DF(8), #TS(10), #NP(11), #SS(12), #GP(13), #PF(14), #AC(17)

`#PF` 比较特殊：它的错误码内容需要自己填（P/W/U/RSVD/I-D 位），并且还要正确设置 **VM-Entry Exception Error Code** 以及 guest 的 `CR2`（对于 `#PF` 而言，CR2 需要 VMM 手动写入，硬件不会替你算）。

### 优先级

VM-Entry Interruption-Information Field 只有一个 Valid bit，意味着 **一次 VM-entry 最多注入一个事件**。

如果同时有多个 pending 事件（比如一个虚拟中断 + 一个 guest 自己刚触发的异常需要反射），VMM 必须自己维护优先级队列，每次 VM-exit 后重新裁决"这次 entry 该注入谁"。

Intel SDM 给出的**建议优先级顺序**：

- Hardware Exceptions
- NMI（如果没被 NMI window blocking）
- External Interrupt（如果 EFLAGS.IF=1 且没被 interrupt window blocking）
- 自己模拟的软件事件


### Guest Interruptibility State —— 什么时候不能注入

VMCS 里的 **Guest Interruptibility-State** 决定了当前 guest 是否处于"屏蔽窗口"：

```c
typedef union _GUEST_INTERRUPTIBILITY_STATE {
    struct {
        UINT32 BlockingBySti      : 1; // 刚执行完 STI，下一条指令前不能注入可屏蔽中断
        UINT32 BlockingByMovSs    : 1; // 刚执行完 MOV SS / POP SS
        UINT32 BlockingBySmi      : 1;
        UINT32 BlockingByNmi      : 1; // 上一个NMI还没被IRET确认
        UINT32 EnclaveInterruption: 1;
        UINT32 Reserved           : 27;
    } Fields;
    UINT32 All;
} GUEST_INTERRUPTIBILITY_STATE;
```

> [!NOTE]
> 如果在这些 blocking 状态下强行把可屏蔽中断的 Valid bit 置 1 去 VM-entry，会导致 **VM-entry failure**。

### IDT-Vectoring Information Field —— 注入失败后如何恢复现场

如果你刚注入了一个事件，guest 在真正处理它之前（比如 IDT descriptor fetch 阶段）又触发了新的 VM-exit（例如这块内存被你 EPT hook 了），那么这次 VM-exit 时 VMMM 就需要知道刚才那个事件还没送达，这就是 **IDT-Vectoring Information Field** 的作用：

```c
typedef union _IDT_VECTORING_INFO {
    struct {
        UINT32 Vector           : 8;
        UINT32 Type             : 3;
        UINT32 DeliverErrorCode : 1;
        UINT32 Undefined        : 18;
        UINT32 Valid            : 1;
    } Fields;
    UINT32 All;
} IDT_VECTORING_INFO;
```

因此 VMM 就需要每次 VM-exit handler 一开始就检查这个字段，如果 `Valid=1`，说明上次没送达的事件需要在**这次**新的注入里重新排队（通常还是原样注入回去，除非该事件已经过时）。

这是保证 nested exception / double fault 语义正确的关键——硬件会按照真实机器的级联规则处理，VMM 只需要如实转发，不需要手动模拟整个 fault 树。

## 理论作用

| 作用 | 说明 |
|---|---|
| **异常反射（Exception Reflection）** | guest 自己产生的异常（`#PF`/`#GP`/`#UD`等）在 exit-bitmap 拦截后，VMM 判断"这不是我关心的"，原样注入回 guest 自己的 IDT handler |
| **虚拟中断控制器** | 模拟 PIC/APIC/定时器等设备中断，在 interrupt window 打开时注入 External Interrupt |
| **Trap-and-Emulate** | EPT violation / instruction VM-exit 后，如果你想让 guest "感知"到一个异常（而不是静默模拟），用软件异常注入 |
| **反调试 / 完整性检测对抗** | 主动注入 `#BP`(3)、`#GP`(13) 等，干扰调试器或反作弊 anti-tamper 逻辑对硬件断点/单步的假设 |
| **精确控制执行流** | 结合 MTF（Monitor Trap Flag）+ 事件注入，实现单步级别的异常投放 |

## 实战应用

### EPT Hook 中的异常反射

假设你用 EPT 权限位做 hook，当 guest 访问到你 hook 的地址触发 EPT violation，你需要区分两种情况：

1. **确实是你关心的 hook 地址** → 直接在 handler 里改 `Guest RIP`、模拟执行、不注入任何事件，静默返回
2. **误触发或者本该是 guest 自己的合法异常**（比如该页本来就该触发 `#PF` 因为 guest 页表还没建立映射） → 需要把 `#PF` 注入回去

```c
VOID InjectPageFault(PVMCS_GUEST_STATE GuestState, UINT64 FaultAddress, UINT32 ErrorCode)
{
    VMENTRY_INTERRUPT_INFO InjectInfo = { 0 };

    InjectInfo.Fields.Vector           = 14;               // #PF
    InjectInfo.Fields.InterruptionType = 3;                // Hardware Exception
    InjectInfo.Fields.DeliverErrorCode = 1;                // #PF 必须带 error code
    InjectInfo.Fields.Valid            = 1;

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO_FIELD, InjectInfo.All);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);

    __vmx_vmwrite(GUEST_CR2, FaultAddress);
}
```

### 主动注入用于反调试对抗

如果你在做游戏安全 / anti-cheat 相关研究，一个常见思路是：

**当检测到某些可疑访问模式时，主动向被 hook 的进程对应的 vCPU 注入 `#GP` 或 `#BP`**，让调试器/cheat 引擎的异常处理逻辑产生误判，或者触发它自己的完整性校验失败分支。这类技术的核心就是：

注入一个"看起来像guest自己触发"的 #GP

```c
VMENTRY_INTERRUPT_INFO InjectInfo = { 0 };
InjectInfo.Fields.Vector           = 13;  // #GP
InjectInfo.Fields.InterruptionType = 3;
InjectInfo.Fields.DeliverErrorCode = 1;
InjectInfo.Fields.Valid            = 1;

__vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO_FIELD, InjectInfo.All);
__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
```

> 这一类应用的边界在于 hypervisor 层的事件注入本身是中立技术，同样的机制被合法 anti-cheat 厂商用来做完整性检测，也被研究人员用来做对抗测试。

### MTF + 事件注入做精确单步分析

在做恶意代码分析沙箱时，可以打开 `Monitor Trap Flag`（VMCS Proc-Based Controls 一位），配合事件注入实现"每执行一条指令就重新评估要不要注入下一个事件"，常用于：

- 精确复现某条指令执行前后的 CPU 状态
- 单步追踪 guest 对某个虚拟中断的响应路径
- 调试你自己 hypervisor 的注入逻辑是否正确

## 参考

Intel SDM Vol.3C, Chapter 24 (VMX Non-Root Operation) & Chapter 26 (VM Entries)

Intel SDM Vol.3C, 24.8.3 "VM-Entry Controls for Event Injection"

Intel SDM Vol.3C, 24.4.2 "Guest Non-Register State" (Interruptibility State)
