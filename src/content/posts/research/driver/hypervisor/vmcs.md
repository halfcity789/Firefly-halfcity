---
title: Hypervisor Sparkle 研究日志 - VMCS
description: 在这篇文章中将对VMCS进行详细的分析研究，探索它的由来以及作用。
published: 2026-07-06
category: 驱动开发
tags: [Hypervisor, Windows内核, Windows, WDM, VMCS, Sparkle, EPT Hook]
pinned: false
draft: false
---

## 简介

VMCS（Virtual Machine Control Structure，虚拟机控制结构）是 Intel VT-x 技术中最核心的数据结构，几乎所有 VMX 操作都围绕它展开。

管理 VMCS 的内存布局、字段分类和生命周期管理，是编写 Hypervisor 的必要前提。

## VMCS 是什么

VMCS 是一块由处理器管理的、位于物理内存中的数据结构，用于保存：

- **Guest（客户机）的完整处理器状态**：包括通用寄存器之外的几乎所有架构状态（CR0/CR3/CR4、段寄存器、RIP、RSP、RFLAGS、调试寄存器、MSR 等）。
- **Host（宿主机/Hypervisor）的处理器状态**：VM-exit 发生时处理器应恢复到的状态。
- **VM 执行控制域**：决定哪些指令/事件会触发 VM-exit（例如 CR3 访问、CPUID、RDMSR/WRMSR、I/O 端口访问、EPT violation 等）。
- **VM-entry / VM-exit 控制域**：控制进入和退出虚拟机时的行为（如是否加载 MSR、是否注入事件等）。
- **只读的 VM-exit 信息域**：记录最近一次 VM-exit 的原因和相关细节（exit reason、exit qualification、guest linear address 等）。

每一个逻辑处理器（不是核心数）可以关联多个 VMCS，但同一时刻只能有一个处于 **active（活动）** 状态。

## VMCS 的内存区域格式

VMCS 本质上是一段 4KB 对齐的物理内存（VMXON region 同理）。它的大小由 `IA32_VMX_BASIC` MSR 报告，通常不超过 4KB，实际有效字节数由处理器实现决定。

内存布局大致分为两部分：

```bash
+----------------------------------+
| VMCS Revision Identifier (4B)    |
| VMX-Abort Indicator (4B)         |
+----------------------------------+
| VMCS Data                        |
| (guest-state / host-state /      |
|  control fields / exit info...)  |
+----------------------------------+
```

这里的 Data 区域是由Intel决定的，我们无需知道每一个字段具体的偏移。

具体来说：

- **Revision Identifier**：每次分配 VMCS 内存后，必须先从 `IA32_VMX_BASIC` MSR 的低 31 位读取当前处理器支持的 revision ID，写入 VMCS 区域的前 4 字节，否则 `VMPTRLD` / `VMLAUNCH` 会失败。
- **数据区格式对软件不透明**：软件不能直接用偏移量读写这块内存,必须通过 `VMREAD` / `VMWRITE` 指令，并通过 **encoding（编码值）** 来访问具体字段,而不是内存偏移。这是 Intel 为了保持向后兼容和跨微架构灵活性而设计的抽象层。

## VMCS 的状态机

一个 VMCS 在其生命周期中会处于以下几种状态之一：

| 状态 | 说明 |
|------|------|
| **Active** | 通过 `VMPTRLD` 加载到某个逻辑处理器上,该处理器上执行的 `VMREAD`/`VMWRITE`/`VMLAUNCH`/`VMRESUME` 会作用于这个 VMCS |
| **Current** | 与 active 含义基本重合,表示"当前生效"的 VMCS,是 VMLAUNCH/VMRESUME 的隐式操作对象 |
| **Clear** | 通过 `VMCLEAR` 显式清除,表示该 VMCS 不再与任何处理器关联,处理器缓存的相关状态被写回内存 |
| **Launched** | 该 VMCS 已经成功执行过一次 `VMLAUNCH`,之后必须使用 `VMRESUME` 而非再次 `VMLAUNCH` |

**重要约束**：

- 一个 VMCS 同一时刻只能在一个逻辑处理器上 active。
- 多核环境下，每个 VMCS 在迁移到另一个逻辑处理器使用前，必须先在原处理器上执行 `VMCLEAR`，否则会因为处理器内部缓存（VMCS cache）不一致导致未定义行为。这也是多核 Hypervisor 中常见的 "VMCS 迁移" 陷阱之一。

## VMCS 字段

VMCS 的数据字段可分为六大类。

Intel SDM Volume 3C Chapter 24 有完整定义。

每个字段有唯一的 encoding，encoding 的位域本身还编码了字段的宽度（16/32/64/natural-width）和类型（control/read-only/guest-state/host-state）。

### Guest-State

保存 VM-entry 时加载、VM-exit 时保存的 guest 处理器状态,包括：

- 控制寄存器：CR0、CR3、CR4（部分位受 CR0/CR4 Guest/Host Mask 与 Read Shadow 影响）
- 调试寄存器 DR7
- 段寄存器（CS/SS/DS/ES/FS/GS/LDTR/TR）及其 selector、base、limit、access rights
- GDTR / IDTR base 和 limit
- RSP、RIP、RFLAGS
- 部分 MSR：`IA32_SYSENTER_CS/ESP/EIP`、`IA32_EFER`、`IA32_PAT` 等（若相应 VM-entry/exit control 开启）
- Guest 非寄存器状态：activity state（active / HLT / shutdown / wait-for-SIPI）、interruptibility state、pending debug exceptions、VMCS link pointer

### Host-State

VM-exit 发生时，处理器会将执行状态切换为该区域中保存的值。

基本对称于 guest-state 中的寄存器项，但不包含段寄存器的 base/limit/access rights（VM-exit 时段寄存器按固定规则重新加载），也不保存 RFLAGS（VM-exit 后 RFLAGS 由处理器按架构定义的固定值设置）。

如果对 `syscall` 熟悉的就会发现，Guest -> Host 的切换就像是 User -> Krnel 一样。

### VM-Execution Control Fields

决定 guest 运行期间哪些操作会触发 VM-exit，是 Hypervisor 拦截逻辑的核心配置，主要包括：

- **Pin-Based VM-Execution Controls**：外部中断、NMI 相关的拦截开关
- **Processor-Based VM-Execution Controls（Primary / Secondary）**：
  - CR3-load/store exiting、CR8 exiting
  - MOV-DR exiting、使用 I/O bitmap
  - RDTSC/RDTSCP exiting
  - `activate secondary controls` 位决定是否解析 Secondary 控制域
  - Secondary 控制域中常用的有：**Enable EPT**、**Enable VPID**、**Unrestricted Guest**、**Enable RDTSCP**、**Enable INVPCID**、**APIC-Access 相关虚拟化**、**Enable XSAVES/XRSTORS** 等
- **Exception Bitmap**：32 位位图，决定哪些异常（#PF/#GP/#UD 等）需要 VM-exit
- **I/O Bitmap A/B、MSR Bitmap**：细粒度控制特定端口/MSR 访问是否 exit
- **CR0/CR4 Guest/Host Mask 与 Read Shadow**：实现"虚拟化"控制寄存器某些位的关键机制,允许 Hypervisor 让 guest 看到与实际硬件不同的 CR0/CR4 值
- **EPT Pointer（EPTP）**：指向 guest 的扩展页表根,是实现内存虚拟化和 EPT Hook 的入口
- **VPID**：为 guest 的 TLB 条目打标签,避免每次 VM-entry/exit 都全局刷新 TLB

### VM-Exit Control Fields

控制 VM-exit 发生时的行为，例如：

- Host address-space size（是否切换到 64 位模式）
- 是否在 VM-exit 时保存/加载特定 MSR（VM-exit MSR-store/load area）
- 是否应答外部中断的 acknowledge interrupt on exit

### VM-Entry Control Fields

控制 VM-entry 时的行为，例如：

- Guest address-space size
- VM-entry 时是否加载 MSR
- **VM-Entry Interruption-Information Field**：用于向 guest 注入中断/异常/软件中断,是实现异常转发、中断注入的关键字段

### VM-Exit Information Fields

VM-exit 发生后由处理器自动填写，Hypervisor 在 VM-exit handler 中读取这些字段来判断发生了什么，典型字段：

- **Exit Reason**：exit 的具体原因（如 EPT violation、CPUID、RDMSR、CR access 等编号）
- **Exit Qualification**：与 exit reason 配套的附加信息（例如 EPT violation 时具体是读/写/执行权限缺失）
- **Guest-Linear/Physical Address**：EPT violation 或分页相关 exit 时的地址信息
- **VM-Exit Interruption Information / Error Code**：exit 由异常/NMI 引起时的具体信息
- **Instruction Length**：触发 exit 的指令长度，常用于 VM-exit handler 中推进 guest RIP

## VMCS 与 EPT 的关系

对于做 EPT Hook / 内存虚拟化的场景，VMCS 中与之直接相关的字段主要是：

- **Secondary Processor-Based Controls 中的 Enable EPT 位**：必须置位才能启用 EPT
- **EPT Pointer (EPTP)**：指向 EPT PML4 表的物理地址，同时编码了 memory type 和 page-walk length
- **INVEPT** 指令用于在修改 EPT 页表后使相关 TLB/paging-structure cache 失效，避免处理器使用陈旧的转换缓存

**EPT-violation 也就是 `EXIT_REASON_EPT_VIOLATION` 会触发 VM-exit**，Exit Qualification 中会标明是读/写/执行访问违规，Guest-Physical Address 字段给出触发违规的 GPA，这是实现 `EPT Hook` 的基础。

```c
VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    DbgPrint("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    DbgPrint("\EXIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason)
    {

    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMLAUNCH:
    {
        break;
    }
    case EXIT_REASON_HLT:
    {
        DbgPrint("[*] Execution of HLT detected... \n");

        AsmVmxoffAndRestoreState();

        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        break;
    }

    case EXIT_REASON_CPUID:
    {
        break;
    }

    case EXIT_REASON_INVD:
    {
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    default:
    {
        // DbgBreakPoint();
        break;
    }
    }
}
```

就像这样。

不过Intel最初设计时应该是没想过EPT Hook这一点的。

## 参考

- Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3C, Chapter 24
- Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3C, Chapter 25-28

[Rayanfam Blog](https://rayanfam.com/topics/hypervisor-from-scratch-part-4/)

::github{repo=DarthTon/HyperBone}

::github{repo=ionescu007/SimpleVisor}

::github{repo=hyperdbg/hyperdbg}
