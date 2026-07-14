---
title: Windbg 全面解析
description: 深入解读 WinDbg 调试器，涵盖内核调试、符号配置、常用命令与驱动开发实战，系统解析其运作机制及内核结构查看技巧。
published: 2026-07-03
category: 驱动开发
tags: [Windbg, Windows内核, 调试, 逆向, Windows]
pinned: false
draft: false
---

## 下载

在微软商店中搜索`Windbg Preview`下载即可

## 简介

### Windbg 是什么

WinDbg（Windows Debugger）是微软官方出品的 Windows 平台调试器，隶属于 **Debugging Tools for Windows** 工具集，是 Windows Driver Kit（WDK）与 Windows SDK 的核心组成部分之一。它既可以调试用户态（User Mode）进程，也可以调试内核态（Kernel Mode）代码，还能离线分析崩溃转储文件（Dump），是 Windows 生态里唯一一款同时覆盖"用户态 + 内核态 + 离线分析"三大场景的官方工具。
 
与 gdb、lldb 这类通用调试器不同，WinDbg 从设计之初就是围绕 Windows 自身的内部机制（PE 格式、PDB 符号系统、WOW64、ETW、内核对象模型等）深度定制的，因此在 Windows 平台的调试深度和还原度上，几乎没有第三方工具能够完全替代。

可以说一旦谈及了Windows内核，Windbg就是必不可少的。

> [!NOTE]
> 在[这里](/posts/build/vm/)你可以找到内核调试环境部署的教程

### Windbg的诞生背景

WinDbg 最早可以追溯到 Windows NT 时代。微软在开发 NT 内核时，需要一个能够跨越用户态和内核态边界、还能理解 NT 内核对象模型的调试器，于是在传统 CDB（Console Debugger）、NTSD（NT Symbolic Debugger）的基础上，逐步演化出图形化的 WinDbg。
 
它的研发目的很明确：
 
- **服务微软自己的操作系统研发团队**：Windows 内核、驱动、子系统的开发都离不开一个能够深入系统底层的调试工具
- **服务第三方驱动开发者**：WHQL 认证、驱动签名之前的调试验证环节，WinDbg 是事实标准
- **服务企业级故障排查**：微软客户支持服务（CSS）大量使用 WinDbg 分析客户提交的蓝屏 Dump（BSOD Minidump / Kernel Dump / Complete Memory Dump）

### Windbg 的历史

- **WinDbg（WinDbg Classic）**：基于 Win32 GUI，界面偏"上世纪工具"风格，但功能最全、社区资料最多，很多老牌反作弊、驱动开发教程默认用的都是这个版本
- **WinDbg Preview**：微软在 2017 年后推出的 UWP 版本，界面重做，支持深色主题、多标签调试会话、TTD 时间旅行调试（Time Travel Debugging）、更好的脚本集成，从 Microsoft Store 分发
- **命令行工具族**：CDB（用户态命令行）、NTSD（用户态，带独立控制台）、KD（内核态命令行）—— 这些是 WinDbg GUI 背后共享的同一套调试引擎（DbgEng.dll）

> [!NOTE]
> WinDbg GUI、KD、CDB 本质上都是 **DbgEng 引擎** 的不同外壳，命令、扩展、符号系统是完全通用的。

现在一般提及 `Windbg` 说的就是 `Windbg preview`。

### Windbg 的地位

| 工具 | 定位 | 用户态 | 内核态 | Dump 分析 | 平台 |
|---|---|---|---|---|---|
| WinDbg | 官方全能调试器 | ✅ | ✅ | ✅ | Windows |
| Visual Studio Debugger | IDE 内置调试器 | ✅ (方便) | ❌ | 有限 | Windows |
| x64dbg | 用户态调试器 | ✅ (强) | ❌ | ❌ | Windows |
| OllyDbg | 老牌逆向调试器 | ✅ (强) | ❌ | ❌ | Windows |
| IDA Pro | 静态反汇编 + 动态调试 | ✅ (强) | 有限 | ❌ | 跨平台 |
 
WinDbg 的不可替代性主要体现在两点：
 
1. **唯一原生支持 Windows 内核调试协议**（KDNET / Serial / 1394 / USB）的调试器，VirtualKD、VMware 的调试通道最终都是对接到 WinDbg/KD 的调试协议上
2. **唯一深度打通微软官方符号服务器（Symbol Server）** 的工具，能够直接下载几乎所有微软官方组件（包括很多没有公开源码的系统 DLL、内核模块）的精确符号信息，这是其他第三方工具无法比拟的，如果你去尝试了就会发现这一点很特别

## 运作机制

### 调试引擎

WinDbg 的核心调试逻辑都在 `DbgEng.dll`（调试引擎）里，GUI/CDB/KD 只是不同的前端外壳。这意味着：
 
- 你在 WinDbg GUI 里学到的命令，在 CDB/KD 命令行下完全通用
- 第三方工具（比如 Python 的 `pykd`、`WinDbg 脚本`）也是通过调用 DbgEng 的 COM 接口来驱动调试会话的

### 符号系统

WinDbg 依赖 **PDB（Program Database）** 文件来还原函数名、变量名、结构体布局等调试信息。这套体系分为：
 
- **公共符号（Public Symbols）**：只有函数入口地址和名字，没有参数、局部变量信息，微软官方符号服务器提供的通常是这一级
- **私有符号（Private Symbols）**：包含完整的类型、局部变量、行号信息，一般只有微软内部工程师或你自己编译的项目才有
Symbol Path 的配置语法：
 
```txt
srv*本地缓存路径*符号服务器地址
```
 
比如：
 
```txt
srv*D:\symbols*https://msdl.microsoft.com/download/symbols
```
 
WinDbg 会先查本地缓存，没有再去符号服务器下载，下载后缓存到本地路径，下次直接复用。

### 用户态调试

WinDbg 附加到用户态进程时，本质上是利用 Windows 的 **调试 API**（`DebugActiveProcess`、`WaitForDebugEvent` 等），操作系统内核会把目标进程标记为"被调试"状态，所有异常（断点、访问违例等）会先转发给调试器处理，这套机制和 gdb 通过 `ptrace` 实现的原理是同一层次的，只是 API 完全不同。

显然WinDbg在用户态调试的能力并不突出，和`x64dbg`对比。

### 内核态调试

内核调试依赖两台机器（或一台 Host + 一台虚拟机）：
 
- **目标机（Target）**：跑着你要调试的系统，内核会在启动时加载一个调试 Stub，暂停等待调试器连接
- **主机（Host）**：跑 WinDbg，通过传输通道（网络 KDNET、串口 Serial、1394、USB 2.0/3.0）与 Target 的调试 Stub 通信

## 应用场景

### 驱动开发与调试

Windows 驱动开发几乎是 WinDbg 的第一大应用场景：
 
1. 在开发机上编译驱动（生成 `.sys` + `.pdb`）
2. 在测试虚拟机上加载驱动
3. Host 端 WinDbg 通过 KDNET 连接，设置断点在 `DriverEntry`、`IRP` 处理函数、`IOCTL` 分发函数等关键位置
4. 单步跟踪，查看 `IRP` 结构体内容、蓝屏时分析 `!analyze -v`

### 对Windows本身的研究

很多研究 Windows 内部原理（类似《Windows Internals》这本书涉及的内容）的人，会直接打开一台带符号的 Windows 虚拟机，用 WinDbg 实时查看：
 
- 进程/线程对象的内部结构（`EPROCESS`、`ETHREAD`）
- 内存管理器的工作方式（PTE、VAD 树）
- 对象管理器、句柄表的实现细节

这也是学习 Windows 内核最直接、最"眼见为实"的方式，比单纯看书更有说服力。

## 使用方式

### 常用命令

#### 基础控制
 
| 命令 | 作用 |
|---|---|
| `g` | 继续执行（Go） |
| `p` | 步过，不进入函数（Step Over） |
| `t` | 步入，进入函数（Step Into） |
| `gu` | 执行到当前函数返回（Go Up） |
| `bp <地址/符号>` | 设置断点 |
| `bp <符号> "命令"` | 设置带自动执行命令的断点 |
| `bl` | 列出所有断点 |
| `bc <编号>` | 清除指定断点 |
| `bd <编号>` / `be <编号>` | 禁用/启用断点 |

#### 符号与模块
 
| 命令 | 作用 |
|---|---|
| `.sympath` | 查看/设置符号路径 |
| `.reload /f` | 强制重新加载符号 |
| `lm` | 列出已加载模块 |
| `!lmi` | 给出完整的模块元数据 |
| `x module!*` | 按通配符搜索符号 |
| `ln <地址>` | 查找地址最接近的符号 |

例如：

```bash
kd> x nt!KiSystemCall64
fffff805`4c411000 nt!KiSystemCall64 (KiSystemCall64)
kd> !lmi fffff805`4c411000
Loaded Module Info: [fffff805`4c411000] 
         Module: ntkrnlmp
   Base Address: fffff8054c000000
     Image Name: ntkrnlmp.exe
   Machine Type: 34404 (X64)
     Time Stamp: 1c62bee3 (This is a reproducible build file hash, not a true timestamp)
           Size: 1046000
       CheckSum: a638ca
Characteristics: 22  
Debug Data Dirs: Type  Size     VA  Pointer
             CODEVIEW    25, 41100,   40900 RSDS - GUID: {F57E740B-088E-5056-E8AF-0772F1CC5BEB}
               Age: 1, Pdb: ntkrnlmp.pdb
                 POGO  1574, 41128,   40928 [Data not mapped]
                REPRO    24, 4271c,   41f1c Reproducible build
     Image Type: MEMORY   - Image read successfully from loaded memory.
    Symbol Type: PDB      - Symbols loaded successfully from symbol server.
                 d:\data\security\reverse\symbols\ntkrnlmp.pdb\F57E740B088E5056E8AF0772F1CC5BEB1\ntkrnlmp.pdb
    Load Report: public symbols , not source indexed 
                 d:\data\security\reverse\symbols\ntkrnlmp.pdb\F57E740B088E5056E8AF0772F1CC5BEB1\ntkrnlmp.pdb
```
 
#### 内核态专用
 
| 命令 | 作用 |
|---|---|
| `!process 0 0` | 列出所有进程 |
| `!process <地址> 7` | 显示指定进程详细信息 |
| `!thread` | 显示当前线程信息 |
| `!pte <地址>` | 查看PTE |
| `!vad` | 查看VADT |
| `!drvobj <驱动名>` | 查看DriverObject |
| `!irp <地址>` | 分析 IRP |
| `!analyze -v` | 分析崩溃/蓝屏根因 |
 
#### 数据结构查看
 
| 命令 | 作用 |
|---|---|
| `dt <类型> <地址>` | 按结构体类型解析内存（Display Type） |
| `dt nt!_EPROCESS` | 查看结构体定义 |
| `dx <表达式>` | 现代化的数据模型查看方式，支持 LINQ 风格表达式 |

例如：

```bash
kd> dt !_EPROCESS
nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : Uint4B
   +0x460 JobNotReallyActive : Pos 0, 1 Bit
   +0x460 AccountingFolded : Pos 1, 1 Bit
   +0x460 NewProcessReported : Pos 2, 1 Bit
   +0x460 ExitProcessReported : Pos 3, 1 Bit
   +0x460 ReportCommitChanges : Pos 4, 1 Bit
   +0x460 LastReportMemory : Pos 5, 1 Bit
   +0x460 ForceWakeCharge  : Pos 6, 1 Bit
   +0x460 CrossSessionCreate : Pos 7, 1 Bit
   +0x460 NeedsHandleRundown : Pos 8, 1 Bit
   +0x460 RefTraceEnabled  : Pos 9, 1 Bit
   +0x460 PicoCreated      : Pos 10, 1 Bit
   +0x460 EmptyJobEvaluated : Pos 11, 1 Bit
   +0x460 DefaultPagePriority : Pos 12, 3 Bits
   +0x460 PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x460 ProcessVerifierTarget : Pos 16, 1 Bit
   +0x460 RestrictSetThreadContext : Pos 17, 1 Bit
   +0x460 AffinityPermanent : Pos 18, 1 Bit
   +0x460 AffinityUpdateEnable : Pos 19, 1 Bit
   +0x460 PropagateNode    : Pos 20, 1 Bit
   +0x460 ExplicitAffinity : Pos 21, 1 Bit
   +0x460 ProcessExecutionState : Pos 22, 2 Bits
   +0x460 EnableReadVmLogging : Pos 24, 1 Bit
   +0x460 EnableWriteVmLogging : Pos 25, 1 Bit
   +0x460 FatalAccessTerminationRequested : Pos 26, 1 Bit
   +0x460 DisableSystemAllowedCpuSet : Pos 27, 1 Bit
   +0x460 ProcessStateChangeRequest : Pos 28, 2 Bits
   +0x460 ProcessStateChangeInProgress : Pos 30, 1 Bit
   +0x460 InPrivate        : Pos 31, 1 Bit
   +0x464 Flags            : Uint4B
   +0x464 CreateReported   : Pos 0, 1 Bit
   +0x464 NoDebugInherit   : Pos 1, 1 Bit
   +0x464 ProcessExiting   : Pos 2, 1 Bit
   +0x464 ProcessDelete    : Pos 3, 1 Bit
   +0x464 ManageExecutableMemoryWrites : Pos 4, 1 Bit
   +0x464 VmDeleted        : Pos 5, 1 Bit
   +0x464 OutswapEnabled   : Pos 6, 1 Bit
   +0x464 Outswapped       : Pos 7, 1 Bit
   +0x464 FailFastOnCommitFail : Pos 8, 1 Bit
   +0x464 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x464 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x464 SetTimerResolution : Pos 12, 1 Bit
   +0x464 BreakOnTermination : Pos 13, 1 Bit
   +0x464 DeprioritizeViews : Pos 14, 1 Bit
   +0x464 WriteWatch       : Pos 15, 1 Bit
   +0x464 ProcessInSession : Pos 16, 1 Bit
   +0x464 OverrideAddressSpace : Pos 17, 1 Bit
   +0x464 HasAddressSpace  : Pos 18, 1 Bit
   +0x464 LaunchPrefetched : Pos 19, 1 Bit
   +0x464 Background       : Pos 20, 1 Bit
   +0x464 VmTopDown        : Pos 21, 1 Bit
   +0x464 ImageNotifyDone  : Pos 22, 1 Bit
   +0x464 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x464 VdmAllowed       : Pos 24, 1 Bit
   +0x464 ProcessRundown   : Pos 25, 1 Bit
   +0x464 ProcessInserted  : Pos 26, 1 Bit
   +0x464 DefaultIoPriority : Pos 27, 3 Bits
   +0x464 ProcessSelfDelete : Pos 30, 1 Bit
   +0x464 SetTimerResolutionLink : Pos 31, 1 Bit
   +0x468 CreateTime       : _LARGE_INTEGER
   +0x470 ProcessQuotaUsage : [2] Uint8B
   +0x480 ProcessQuotaPeak : [2] Uint8B
   +0x490 PeakVirtualSize  : Uint8B
   +0x498 VirtualSize      : Uint8B
   +0x4a0 SessionProcessLinks : _LIST_ENTRY
   +0x4b0 ExceptionPortData : Ptr64 Void
   +0x4b0 ExceptionPortValue : Uint8B
   +0x4b0 ExceptionPortState : Pos 0, 3 Bits
   +0x4b8 Token            : _EX_FAST_REF
   +0x4c0 MmReserved       : Uint8B
   +0x4c8 AddressCreationLock : _EX_PUSH_LOCK
   +0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x4d8 RotateInProgress : Ptr64 _ETHREAD
   +0x4e0 ForkInProgress   : Ptr64 _ETHREAD
   +0x4e8 CommitChargeJob  : Ptr64 _EJOB
   +0x4f0 CloneRoot        : _RTL_AVL_TREE
   +0x4f8 NumberOfPrivatePages : Uint8B
   +0x500 NumberOfLockedPages : Uint8B
   +0x508 Win32Process     : Ptr64 Void
   +0x510 Job              : Ptr64 _EJOB
   +0x518 SectionObject    : Ptr64 Void
   +0x520 SectionBaseAddress : Ptr64 Void
   +0x528 Cookie           : Uint4B
   +0x530 WorkingSetWatch  : Ptr64 _PAGEFAULT_HISTORY
   +0x538 Win32WindowStation : Ptr64 Void
   +0x540 InheritedFromUniqueProcessId : Ptr64 Void
   +0x548 OwnerProcessId   : Uint8B
   +0x550 Peb              : Ptr64 _PEB
   +0x558 Session          : Ptr64 _MM_SESSION_SPACE
   +0x560 Spare1           : Ptr64 Void
   +0x568 QuotaBlock       : Ptr64 _EPROCESS_QUOTA_BLOCK
   +0x570 ObjectTable      : Ptr64 _HANDLE_TABLE
   +0x578 DebugPort        : Ptr64 Void
   +0x580 WoW64Process     : Ptr64 _EWOW64PROCESS
   +0x588 DeviceMap        : Ptr64 Void
   +0x590 EtwDataSource    : Ptr64 Void
   +0x598 PageDirectoryPte : Uint8B
   +0x5a0 ImageFilePointer : Ptr64 _FILE_OBJECT
   +0x5a8 ImageFileName    : [15] UChar
   +0x5b7 PriorityClass    : UChar
   +0x5b8 SecurityPort     : Ptr64 Void
   +0x5c0 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x5c8 JobLinks         : _LIST_ENTRY
   +0x5d8 HighestUserAddress : Ptr64 Void
   +0x5e0 ThreadListHead   : _LIST_ENTRY
   +0x5f0 ActiveThreads    : Uint4B
   +0x5f4 ImagePathHash    : Uint4B
   +0x5f8 DefaultHardErrorProcessing : Uint4B
   +0x5fc LastThreadExitStatus : Int4B
   +0x600 PrefetchTrace    : _EX_FAST_REF
   +0x608 LockedPagesList  : Ptr64 Void
   +0x610 ReadOperationCount : _LARGE_INTEGER
   +0x618 WriteOperationCount : _LARGE_INTEGER
   +0x620 OtherOperationCount : _LARGE_INTEGER
   +0x628 ReadTransferCount : _LARGE_INTEGER
   +0x630 WriteTransferCount : _LARGE_INTEGER
   +0x638 OtherTransferCount : _LARGE_INTEGER
   +0x640 CommitChargeLimit : Uint8B
   +0x648 CommitCharge     : Uint8B
   +0x650 CommitChargePeak : Uint8B
   +0x680 Vm               : _MMSUPPORT_FULL
   +0x7c0 MmProcessLinks   : _LIST_ENTRY
   +0x7d0 ModifiedPageCount : Uint4B
   +0x7d4 ExitStatus       : Int4B
   +0x7d8 VadRoot          : _RTL_AVL_TREE
   +0x7e0 VadHint          : Ptr64 Void
   +0x7e8 VadCount         : Uint8B
   +0x7f0 VadPhysicalPages : Uint8B
   +0x7f8 VadPhysicalPagesLimit : Uint8B
   +0x800 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x820 TimerResolutionLink : _LIST_ENTRY
   +0x830 TimerResolutionStackRecord : Ptr64 _PO_DIAG_STACK_RECORD
   +0x838 RequestedTimerResolution : Uint4B
   +0x83c SmallestTimerResolution : Uint4B
   +0x840 ExitTime         : _LARGE_INTEGER
   +0x848 InvertedFunctionTable : Ptr64 _INVERTED_FUNCTION_TABLE
   +0x850 InvertedFunctionTableLock : _EX_PUSH_LOCK
   +0x858 ActiveThreadsHighWatermark : Uint4B
   +0x85c LargePrivateVadCount : Uint4B
   +0x860 ThreadListLock   : _EX_PUSH_LOCK
   +0x868 WnfContext       : Ptr64 Void
   +0x870 ServerSilo       : Ptr64 _EJOB
   +0x878 SignatureLevel   : UChar
   +0x879 SectionSignatureLevel : UChar
   +0x87a Protection       : _PS_PROTECTION
   +0x87b HangCount        : Pos 0, 3 Bits
   +0x87b GhostCount       : Pos 3, 3 Bits
   +0x87b PrefilterException : Pos 6, 1 Bit
   +0x87c Flags3           : Uint4B
   +0x87c Minimal          : Pos 0, 1 Bit
   +0x87c ReplacingPageRoot : Pos 1, 1 Bit
   +0x87c Crashed          : Pos 2, 1 Bit
   +0x87c JobVadsAreTracked : Pos 3, 1 Bit
   +0x87c VadTrackingDisabled : Pos 4, 1 Bit
   +0x87c AuxiliaryProcess : Pos 5, 1 Bit
   +0x87c SubsystemProcess : Pos 6, 1 Bit
   +0x87c IndirectCpuSets  : Pos 7, 1 Bit
   +0x87c RelinquishedCommit : Pos 8, 1 Bit
   +0x87c HighGraphicsPriority : Pos 9, 1 Bit
   +0x87c CommitFailLogged : Pos 10, 1 Bit
   +0x87c ReserveFailLogged : Pos 11, 1 Bit
   +0x87c SystemProcess    : Pos 12, 1 Bit
   +0x87c HideImageBaseAddresses : Pos 13, 1 Bit
   +0x87c AddressPolicyFrozen : Pos 14, 1 Bit
   +0x87c ProcessFirstResume : Pos 15, 1 Bit
   +0x87c ForegroundExternal : Pos 16, 1 Bit
   +0x87c ForegroundSystem : Pos 17, 1 Bit
   +0x87c HighMemoryPriority : Pos 18, 1 Bit
   +0x87c EnableProcessSuspendResumeLogging : Pos 19, 1 Bit
   +0x87c EnableThreadSuspendResumeLogging : Pos 20, 1 Bit
   +0x87c SecurityDomainChanged : Pos 21, 1 Bit
   +0x87c SecurityFreezeComplete : Pos 22, 1 Bit
   +0x87c VmProcessorHost  : Pos 23, 1 Bit
   +0x87c VmProcessorHostTransition : Pos 24, 1 Bit
   +0x87c AltSyscall       : Pos 25, 1 Bit
   +0x87c TimerResolutionIgnore : Pos 26, 1 Bit
   +0x87c DisallowUserTerminate : Pos 27, 1 Bit
   +0x880 DeviceAsid       : Int4B
   +0x888 SvmData          : Ptr64 Void
   +0x890 SvmProcessLock   : _EX_PUSH_LOCK
   +0x898 SvmLock          : Uint8B
   +0x8a0 SvmProcessDeviceListHead : _LIST_ENTRY
   +0x8b0 LastFreezeInterruptTime : Uint8B
   +0x8b8 DiskCounters     : Ptr64 _PROCESS_DISK_COUNTERS
   +0x8c0 PicoContext      : Ptr64 Void
   +0x8c8 EnclaveTable     : Ptr64 Void
   +0x8d0 EnclaveNumber    : Uint8B
   +0x8d8 EnclaveLock      : _EX_PUSH_LOCK
   +0x8e0 HighPriorityFaultsAllowed : Uint4B
   +0x8e8 EnergyContext    : Ptr64 _PO_PROCESS_ENERGY_CONTEXT
   +0x8f0 VmContext        : Ptr64 Void
   +0x8f8 SequenceNumber   : Uint8B
   +0x900 CreateInterruptTime : Uint8B
   +0x908 CreateUnbiasedInterruptTime : Uint8B
   +0x910 TotalUnbiasedFrozenTime : Uint8B
   +0x918 LastAppStateUpdateTime : Uint8B
   +0x920 LastAppStateUptime : Pos 0, 61 Bits
   +0x920 LastAppState     : Pos 61, 3 Bits
   +0x928 SharedCommitCharge : Uint8B
   +0x930 SharedCommitLock : _EX_PUSH_LOCK
   +0x938 SharedCommitLinks : _LIST_ENTRY
   +0x948 AllowedCpuSets   : Uint8B
   +0x950 DefaultCpuSets   : Uint8B
   +0x948 AllowedCpuSetsIndirect : Ptr64 Uint8B
   +0x950 DefaultCpuSetsIndirect : Ptr64 Uint8B
   +0x958 DiskIoAttribution : Ptr64 Void
   +0x960 DxgProcess       : Ptr64 Void
   +0x968 Win32KFilterSet  : Uint4B
   +0x970 ProcessTimerDelay : _PS_INTERLOCKED_TIMER_DELAY_VALUES
   +0x978 KTimerSets       : Uint4B
   +0x97c KTimer2Sets      : Uint4B
   +0x980 ThreadTimerSets  : Uint4B
   +0x988 VirtualTimerListLock : Uint8B
   +0x990 VirtualTimerListHead : _LIST_ENTRY
   +0x9a0 WakeChannel      : _WNF_STATE_NAME
   +0x9a0 WakeInfo         : _PS_PROCESS_WAKE_INFORMATION
   +0x9d0 MitigationFlags  : Uint4B
   +0x9d0 MitigationFlagsValues : <anonymous-tag>
   +0x9d4 MitigationFlags2 : Uint4B
   +0x9d4 MitigationFlags2Values : <anonymous-tag>
   +0x9d8 PartitionObject  : Ptr64 Void
   +0x9e0 SecurityDomain   : Uint8B
   +0x9e8 ParentSecurityDomain : Uint8B
   +0x9f0 CoverageSamplerContext : Ptr64 Void
   +0x9f8 MmHotPatchContext : Ptr64 Void
   +0xa00 DynamicEHContinuationTargetsTree : _RTL_AVL_TREE
   +0xa08 DynamicEHContinuationTargetsLock : _EX_PUSH_LOCK
   +0xa10 DynamicEnforcedCetCompatibleRanges : _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
   +0xa20 DisabledComponentFlags : Uint4B
   +0xa28 PathRedirectionHashes : Ptr64 Uint4B
   +0xa30 MitigationFlags3 : Uint4B
   +0xa30 MitigationFlags3Values : <anonymous-tag>
```

这里就可以清楚地看到指定字段的偏移，比如`Protection`字段这类敏感字段。

```bash
+0x87a Protection       : _PS_PROTECTION
```

## 脚本

WinDbg 支持多种脚本化方式，适合重复性调试任务或自动化分析：
 
**内置脚本语言（.scr / j 命令）**：适合简单的条件断点、循环判断
 
**JavaScript 调试扩展（WinDbg Preview 起支持）**：
 
```javascript
"use strict";
function invokeScript() {
    host.diagnostics.debugLog("Hello from WinDbg\n");
}
```
 
**pykd（Python 扩展）**：社区维护的 Python 绑定，适合复杂的批量分析、自动化逆向脚本，很多安全研究人员用它写自动化的漏洞分析工具
 
**TTD（Time Travel Debugging）**：WinDbg Preview 独有的"录制回放"调试技术，可以录制一段程序执行轨迹，之后任意前进、后退、跳转到某个时间点重放，对于分析难以复现的 Bug 或者深入理解一段复杂逻辑的执行流程极其有用

## 总结
 
WinDbg 不是一个"好用"的工具，但它是 Windows 平台上**最权威**的调试器。

无论是驱动开发、内核研究、漏洞挖掘还是崩溃分析，只要涉及到 Windows 底层机制，最终都绕不开它。

它的命令行风格虽然显得"复古"，但这种复古背后是三十多年 Windows 内核演进积累下来的深度集成能力——这是任何图形化程度更高的第三方工具短期内都难以追赶的护城河。
 
对于做底层安全研究而言，WinDbg 是可以说是工具链里绕不开的那一环。
