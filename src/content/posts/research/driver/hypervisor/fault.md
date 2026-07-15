---
title: Hypervisor Sparkle 研究日志 - Intel 异常
description: 在这篇文章中将对 Intel 的 Fault / Trap / Abort 与事件注入的对应处理分析研究。同时结合事件注入进行探索。
published: 2026-07-18
category: 驱动开发
tags: [Hypervisor, Windows内核, Windows, WDM, Sparkle, Vmcs, Interrupt, Fault, Abort, Event]
pinned: false
draft: false
---

## 前言

对于事件注入而言，**32 个异常向量里，每一个的"性格"都不一样**——有的可以恢复重试，有的重试了也没用，有的甚至连自己是谁触发的都说不清楚（比如 `#DF`）。

如果不搞清楚这些分类，那么异常反射逻辑迟早会在某个边界情况下让 guest 蓝屏或者陷入无限重入。

这篇文章专门梳理 Intel SDM 里对异常的分类体系，以及每一类在事件注入时该怎么处理。

> [!NOTE]
> 有关事件注入的内容在[这里](/posts/research/driver/hypervisor/event/)可以找到

---

## Fault / Trap / Abort

Intel SDM Vol.3A, 6.3 节把异常按"程序恢复方式"分成三类，这个分类比向量号本身更重要，因为它直接决定了**注入时 guest RIP 应该指向哪里**。

### Fault（故障）—— 重试型

**特征**：CPU 在**执行指令之前**检测到问题，压栈保存的 RIP 指向**触发异常的那条指令本身**。如果异常处理完毕后问题解决了，`IRET` 会重新执行这条指令，就像什么都没发生过。

**典型代表**：
- `#PF`(14) —— 缺页
- `#GP`(13) —— 通用保护
- `#DE`(0) —— 除零
- `#NP`(11) —— 段不存在
- `#SS`(12) —— 栈段错误
- `#TS`(10) —— 任务状态段错误

**对事件注入的意义**：

- 注入 Fault 时，**不需要调整 guest RIP**，也**不需要设置 VM-Entry Instruction Length**（因为硬件异常注入时 CPU 知道该指向当前指令，只需要保证 Guest RIP 本身没被你误改过）。

### Trap（陷阱）—— 事后型

**特征**：CPU 在**指令执行完毕之后**才触发，压栈的 RIP 指向**下一条指令**。

**典型代表**：
- `#BP`(3) —— `INT3` 断点
- `#OF`(4) —— `INTO` 溢出检查（仅当溢出标志置位时触发）
- 调试异常 `#DB`(1) 的部分场景（比如指令断点之后触发时算 Trap，数据断点触发时行为更复杂）

**对事件注入的意义**：

- 如果要**主动构造**一个 Trap 类异常（比如模拟 `INT3`），需要正确设置 **VM-Entry Instruction Length**，让硬件知道"这条指令本来的长度"，以便 IRET 之后能正确恢复到下一条。

- 如果只是**反射**一个 guest 自己已经触发的 Trap（真实执行了 `INT3` 导致 VM-exit），guest RIP 已经被硬件正确处理过，只需要照抄向量号即可。

### Abort（中止）—— 不可恢复型

**特征**：无法精确报告是哪条指令、哪个位置出的问题，通常意味着系统级的严重错误，不支持恢复重试。

**典型代表**：
- `#DF`(8) —— Double Fault
- 部分 Machine-Check `#MC`(18) 场景

**对事件注入的意义**：

- Abort 类异常在实际工程里**几乎不会由 VMM 主动注入**——它们是硬件在处理级联失败时自动产生的产物，VMM 唯一该做的是**正确响应**（比如 `#DF` 发生时通常意味着 guest 环境已经出了大问题，需要考虑是否直接 crash 该 vCPU 或者重置）。

---

## 完整异常向量表

| Vec | 助记符 | 名称 | 分类 | Error Code |
|---|---|---|---|---|
| 0 | #DE | Divide Error | Fault | 否 |
| 1 | #DB | Debug Exception | Fault/Trap| 否 |
| 2 | — | NMI | （不算异常，属中断） | 否 |
| 3 | #BP | Breakpoint | Trap | 否 |
| 4 | #OF | Overflow | Trap | 否 |
| 5 | #BR | BOUND Range Exceeded | Fault | 否 |
| 6 | #UD | Invalid Opcode | Fault | 否 |
| 7 | #NM | Device Not Available | Fault | 否 |
| 8 | #DF | Double Fault | **Abort** | 是（恒为0） |
| 9 | — | (保留，早期Coprocessor段超限) | — | — |
| 10 | #TS | Invalid TSS | Fault | 是 |
| 11 | #NP | Segment Not Present | Fault | 是 |
| 12 | #SS | Stack-Segment Fault | Fault | 是 |
| 13 | #GP | General Protection | Fault | 是 |
| 14 | #PF | Page Fault | Fault | 是 |
| 15 | — | 保留 | — | — |
| 16 | #MF | x87 FPU Error | Fault | 否 |
| 17 | #AC | Alignment Check | Fault | 是（恒为0） |
| 18 | #MC | Machine Check | **Abort** | 否 |
| 19 | #XM | SIMD FP Exception | Fault | 否 |
| 20 | #VE | Virtualization Exception（EPT专用） | Fault | 否 |
| 21 | #CP | Control Protection（CET） | Fault | 是 |

> `#VE`(20) 是 VT-x 引入的专属异常，只有在开启 `EPT-violation #VE` 特性并且 guest 里配置了 VE Information Area 时才会出现。

## `#DB` 的特例

`#DB`（Debug Exception）值得单独拎出来讲，因为它是**唯一一个分类要看触发原因**的异常：

| 触发原因 | 分类 | RIP 指向 |
|---|---|---|
| 指令断点（`DR0-3` 配合 `DR7` 的执行断点） | **Trap** | 下一条指令 |
| 数据断点（读写断点） | **Trap**（但触发时机在导致该访问的指令**之后**） | 下一条指令 |
| 单步执行（`EFLAGS.TF=1`） | **Trap** | 下一条指令 |
| 一般检测条件（如 `DR7.GD` 触发的调试寄存器访问检测） | **Fault** | 触发指令本身 |

在反调试研究里 `#DB` 的语义分裂给了很多"时序错位"的操作空间。

## Double Fault 级联失败

### Contributory vs Benign 分类

Intel 把可能导致 `#DF` 的异常分成两组：

**Contributory exceptions（贡献性异常）**：

#DE(0), #TS(10), #NP(11), #SS(12), #GP(13)

**Benign exceptions（良性异常，不会促成DF）**：

#DB(1), #BP(3), #OF(4), #BR(5), #NM(7), #MF(16), #AC(17), #MC(18), #XM(19)

**`#PF` 单独一类**，规则最特殊。

### 触发 `#DF` 的规则

只有以下两种"级联组合"会导致 `#DF`（第二个异常在处理第一个异常的过程中发生）：

```bash
Contributory  → Contributory   (比如 #GP 处理中又触发 #TS)
Contributory  → #PF            (比如 #GP 处理中又触发 #PF)
#PF           → #PF            (缺页处理中又缺页)
```

**不会**触发 `#DF` 的组合（比如 Benign → 任何东西，或者 `#PF` → Contributory），这种情况下第二个异常会正常递交，不会级联。

### Triple Fault

如果 `#DF` 的处理过程中又发生第三次符合级联条件的异常，CPU 不会再产生新异常，而是直接 **shutdown**（Triple Fault），这在真实硬件上表现为重启。

在 hypervisor 里，这通常意味着 VM-exit reason 会是 `EXIT_REASON_TRIPLE_FAULT`，这时候 guest 状态基本已经不可信，VMM 通常选择：终止该 vCPU、dump 状态用于调试，而不是尝试恢复。

## 硬件异常 vs 软件异常

结合 Interruption Type 表格，这里给一个决策表：

| 场景 | Interruption Type | Vector | Instr Length | Error Code |
|---|---|---|---|---|
| 反射一个 guest 真实触发的 `#PF`/`#GP` 等 Fault | 3 (Hardware Exception) | 对应向量 | 不需要 | 需要（如适用） |
| 反射一个 guest 真实触发的 `#BP`（真的执行了`INT3`） | 6 (Software Exception) | 3 | 需要（=1，跳过INT3的1字节） | 否 |
| 主动模拟一次 `INT n` 软件中断（guest没真正执行这条指令） | 4 (Software Interrupt) | n | 需要（你要自己算） | 视n而定 |
| 模拟外部设备中断（timer/IPI） | 0 (External Interrupt) | IDT向量 | 不需要 | 否 |
| 主动构造 `#GP` 做反调试/完整性对抗 | 3 (Hardware Exception) | 13 | 不需要 | 是（通常填0） |
| NMI 注入 | 2 (NMI) | 2 | 不需要 | 否 |

> **判断准则**：只要这个事件是"CPU 会自己检测触发"的（`#DE`/`#GP`/`#PF`等），一律用类型 3，哪怕是主动构造的也一样——因为 guest 的 IDT descriptor 权限检查、栈切换语义都是按 Hardware Exception 的规则走的。
>
> 只有真正对应某条软件指令执行结果的情况（`INT n`/`INT3`/`INTO`）才用类型 4/5/6。

---

## 多个异常同时待处理

Intel SDM Vol.3A, 6.9 节给出了指令执行过程中异常/中断的优先级顺序（从高到低）：

1. Hardware Reset / Machine Check
2. Trap on Task Switch
3. External Hardware Interventions (FLUSH, STOPCLK, SMI, INIT)
4. Traps from前一条指令 (#DB trap-class)
5. NMI
6. Maskable External Interrupt
7. 取指阶段的Code Break Point Fault
8. 指令译码阶段的Faults (#UD 等)
9. 指令执行阶段的Faults (#GP/#PF/#SS 等，按微架构顺序)

这个优先级是**真实 CPU 执行单条指令时**的裁决顺序，所以**如果 guest 报告了某个异常，理论上不可能同时"还欠着"更高优先级的异常**。

所以如果 IDT-Vectoring 字段和自己维护的 pending 队列出现矛盾，往往是自己的状态机出了 bug，而不是硬件行为异常。

## 参考

- Intel SDM Vol.3A, Chapter 6 "Interrupt and Exception Handling"
  - 6.3 "Sources of Interrupts and Exceptions" (Fault/Trap/Abort)
  - 6.9 "Priority Among Simultaneous Exceptions and Interrupts"
  - 6.15 "Exception and Interrupt Reference" 
- Intel SDM Vol.3C, 24.8.3 "VM-Entry Controls for Event Injection"
- Intel SDM Vol.3C, 6.15, Interrupt 8—Double Fault Exception (#DF)
