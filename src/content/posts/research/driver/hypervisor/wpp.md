---
title: Hypervisor Sparkle 研究日志 - VWPP Tracing
description: 在这篇文章中将对 WPP 进行详细的分析研究，探索它的由来以及作用。
published: 2026-07-17
category: 驱动开发
tags: [Hypervisor, Windows内核, Windows, WDM, Sparkle, WPP, ETW, 日志]
pinned: false
draft: true
---

## 引言

在 Windows 内核驱动开发中，几乎每个人第一次想要"打印点东西看看发生了什么"时，都会写下一行 `DbgPrint` 或者 `KdPrint`。这在开发早期调试阶段确实好用，但当驱动进入压力测试、性能分析、甚至生产环境诊断阶段时，`DbgPrint` 这类朴素手段的局限性就会迅速暴露——没有过滤、没有等级控制、性能开销不可控、而且必须挂着调试器才能看到输出。

这正是 **WPP（Windows software trace Preprocessor）Tracing** 存在的意义。对于写驱动、写 hypervisor 这类需要长时间在无调试器环境下运行、又需要高保真诊断信息的项目来说，WPP 是 WDK 里被低估但极其实用的一套基础设施。

本文会从架构、与 ETW 的关系、与 DbgPrintEx 的区别、到实际工程落地几个角度，把 WPP Tracing 讲透。

## 一、WPP Tracing 是什么

WPP 本质上不是一个"新的日志系统"，而是**一套围绕 ETW（Event Tracing for Windows）的代码生成与封装工具链**。它由三部分组成：

1. **预处理器 `tracewpp.exe`**：在编译前扫描你的源代码，识别形如 `DoTraceMessage(...)` 的宏调用，为每个调用生成对应的元数据，并输出一个 `.tmh`（Trace Message Header）文件，供源文件 `#include`。
2. **运行时 API**：`WPP_INIT_TRACING` / `WPP_CLEANUP` 以及被 `tracewpp` 展开后的 `DoTraceMessage` 宏，最终落地为对 ETW 内核 API（如 `EtwWrite` / `IoWMIWriteEvent` 家族）的调用。
3. **后处理 / 解码工具**：`tracefmt.exe`、`traceview.exe`、以及新一点的 `wpp` 相关 PowerShell 封装，用来读取 ETL 文件并结合 **PDB 符号**把二进制事件还原成可读的格式化字符串。

关键点在于：**WPP 记录下来的 trace 消息在磁盘/ETL 文件里是二进制的、不含格式字符串本体的**。格式字符串（比如 `"EPT violation at GPA=%p"`）是在编译期被编码进 PDB 里的，解码时工具会拿着 PDB 去反查，把二进制参数填回格式串。这就是为什么你会经常看到"trace 消息没有对应符号就显示成乱码"的情况——本质上这是一种**基于符号的延迟格式化机制**。

一个典型的 WPP 调用长这样：

```c
// 头文件顶部
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(SparkleTraceGuid, (a1b2c3d4,e5f6,7890,abcd,ef1234567890), \
        WPP_DEFINE_BIT(TRACE_VMX) \
        WPP_DEFINE_BIT(TRACE_EPT) \
        WPP_DEFINE_BIT(TRACE_GENERAL))

#include "sparkle.tmh"  // 由 tracewpp.exe 生成

VOID VmxInitializeCpu(ULONG CpuIndex)
{
    DoTraceMessage(TRACE_VMX,
        "Initializing VMX on CPU %lu, VMXON region PA=0x%llx",
        CpuIndex, VmxonPhysAddr);
    ...
}
```

编译时，构建系统（无论是老式 `sources` 文件还是新的 WDK Visual Studio 项目）会调用 `tracewpp.exe` 扫描这个文件，生成 `sparkle.tmh`，里面包含把 `DoTraceMessage` 展开为实际 ETW 调用所需的宏和结构体。

## 二、WPP 与 ETW 的关系

**一句话总结：WPP 是 ETW 之上的一层"语法糖 + 编译期代码生成"，本身不是独立的传输或存储机制。**

ETW 提供的是底层能力：
- **Provider（提供程序）**：以 GUID 标识的事件来源。
- **Session（会话）**：由消费者（如 `logman`、`xperf`、`traceview`）创建，决定事件写到 ETL 文件还是实时消费。
- **Channel/Level/Keyword 过滤**：控制哪些事件被记录。

WPP 在这套体系上做的事情是：

1. 把你写的 `DoTraceMessage(FLAG, "format", args...)` 这种"看起来像 printf"的调用，编译期转换成合法的 ETW 事件写入调用；
2. 用 **控制 GUID（Control GUID）** 把一组 trace flag（如 `TRACE_VMX`、`TRACE_EPT`）关联起来，允许你用工具按位掩码启用/禁用某一类日志，而不需要重新编译；
3. 把格式化字符串的解析工作从"运行时"推迟到"离线解码时"，从而让运行时开销降到极低——**没有被启用的 trace 调用，运行时成本基本只是一次分支判断**。

对比现代 ETW 用户态的写法（manifest-based 或 `TraceLoggingProvider`），WPP 走的是**PDB-based** 路线而不是 **manifest-based** 路线：

| | WPP | Manifest-based ETW / TraceLogging |
|---|---|---|
| 格式字符串存放位置 | 编译期编码进 PDB | XML manifest 编译进资源，或 TraceLogging 元数据内嵌在事件里 |
| 适用场景 | 内核驱动、传统 WDM/KMDF 驱动 | 用户态服务、现代自诊断组件 |
| 解码依赖 | 必须有匹配的 PDB | 不需要外部符号，自解码 |
| 工具链 | tracewpp.exe + tracefmt.exe | mc.exe(manifest) 或 TraceLoggingProvider 宏 |

所以可以理解为：**ETW 是"运输管道"，WPP 是内核驱动最常用的"往管道里塞数据的一种打包方式"**。你完全可以不用 WPP 而直接调用底层 ETW API，但那样你要自己处理 GUID 注册、事件描述符、过滤逻辑，工程量大很多。

## 三、WPP 与 DbgPrintEx 的区别

这是很多刚接触驱动开发的人容易混淆的地方，二者定位完全不同：

### DbgPrintEx / KdPrint 的特点

- 直接写入**内核调试打印缓冲区**，本质上是给内核调试器（WinDbg）或 DbgView 这类工具消费的字符串流。
- **必须有调试器附加，或者启用了内核调试打印过滤器**（`DbgPrintEx` 受 `Debug Print Filter` 注册表项和组件级掩码控制，见 `IHVDRIVER` 之类的默认组件 ID）才能看到输出；否则字符串直接被丢弃。
- 无内建的结构化数据模型，纯字符串，无法做后续的机器分析、聚合、时间线关联。
- 性能开销显著：哪怕过滤级别不匹配导致最终丢弃，格式化字符串的过程本身在部分实现路径下仍有一定成本，且频繁调用容易触发死锁风险（尤其是在高 IRQL 或者持锁状态下调用不当）。
- Release 驱动通常会把大量 `DbgPrint` 编译期剔除（用 `#if DBG` 包裹），导致生产环境完全没有可观测性。

### WPP Tracing 的特点

- 基于 ETW，**不需要挂调试器**，可以在生产机器上通过 `logman start` 或 `tracelog.exe` 动态开启一个 trace session，实时收集或写入 ETL 文件。
- 天然支持 **flag（关注点）+ level（严重程度）** 两个维度的过滤，可以做到"只看 EPT 相关的高优先级日志"这种细粒度控制，且**无需重新编译驱动**，直接改 session 配置即可。
- 未被任何 session 消费时，`DoTraceMessage` 的运行时成本近似于一次原子读 + 分支判断，开销极小，因此可以放心地在 release 驱动里保留大量埋点，不必像 `DbgPrint` 那样成组剔除。
- 输出是结构化的二进制事件（时间戳、CPU、线程、事件参数都被结构化记录），配合 `tracefmt` / `WPA (Windows Performance Analyzer)` 可以做时间线关联分析、跨组件因果链追踪，这是 `DbgPrint` 完全做不到的。
- 需要额外的编译期工具链支持（`tracewpp.exe`），以及**必须保留匹配的 PDB** 才能正确解码，一旦符号丢失或版本不匹配，历史 ETL 文件可能变得难以解读。

### 一句话对比

> `DbgPrintEx` 是"开发阶段临时观察窗口"，WPP 是"生产级、可控粒度、低开销的结构化诊断基础设施"。前者是给人临时看的，后者是给系统长期用的。

两者也可以共存——很多驱动在开发阶段用 `KdPrint` 快速验证逻辑，进入稳定阶段后逐步替换为 WPP 埋点，最终把 `DbgPrint` 完全清理掉。

## 四、典型工程落地流程

以一个 Windows 内核驱动项目（比如你在做的 hypervisor 类项目）为例，落地 WPP 大致是这几步：

**1. 定义控制 GUID 和 trace flag**

```c
// trace.h
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(SparkleTraceGuid, (11112222-3333-4444-5555-666677778888), \
        WPP_DEFINE_BIT(TRACE_VMX)      \
        WPP_DEFINE_BIT(TRACE_EPT)      \
        WPP_DEFINE_BIT(TRACE_VMEXIT)   \
        WPP_DEFINE_BIT(TRACE_MTRR))
```

**2. 在驱动入口初始化/清理**

```c
DriverEntry(...)
{
    WPP_INIT_TRACING(DeviceObject, RegistryPath);
    ...
}

DriverUnload(...)
{
    WPP_CLEANUP(DeviceObject);
}
```

**3. 在项目文件里配置 tracewpp（Visual Studio WDK 项目一般已经内建支持，只需要在 vcxproj 里启用 Run Wpp Tracing）**，构建时会自动生成 `.tmh` 文件。

**4. 埋点**

```c
DoTraceMessage(TRACE_VMEXIT,
    "VM-Exit reason=%lu, GuestRIP=0x%llx, ExitQualification=0x%llx",
    ExitReason, GuestRip, ExitQualification);
```

**5. 采集与解码**

在目标机器上（可以是没有调试器的真机）：

```powershell
# 开启一个 WPP session，收集到 ETL
logman start SparkleTrace -p "SparkleTraceGuid" 0xffffffff 0xff -o C:\logs\sparkle.etl -ets

# ... 触发驱动行为 ...

logman stop SparkleTrace -ets

# 用带符号的 PDB 解码
tracefmt.exe C:\logs\sparkle.etl -p . -o C:\logs\sparkle_decoded.txt
```

只要 `sparkle.pdb` 版本和当时驱动版本一致，`tracefmt` 就能把二进制事件还原成完整的格式化字符串输出，包括时间戳、CPU 编号、进程/线程 ID。

## 五、适合什么场景使用

结合上面的对比，WPP 比较适合下面几类场景：

- **长期运行、需要持续可观测性的内核组件**：比如 hypervisor、防护类驱动、minifilter，这类组件往往不能频繁挂调试器，WPP 可以在不停机、不重启的情况下动态开关诊断。
- **性能敏感路径的诊断**：VM-Exit handler、EPT violation handler 这种高频路径，用 `DbgPrint` 基本会拖垮性能，而 WPP 在未启用时开销可以忽略不计，适合"埋点常驻，需要时才打开"。
- **需要事后回溯分析的问题**：客户现场问题复现困难时，让客户开一个 WPP session 采集一段时间的 ETL，寄回来后离线用 PDB 解码分析，比让客户远程挂 WinDbg 现实得多。
- **需要按子系统精细过滤日志的大型驱动**：比如你的 Aurora/Sparkle 项目里 VMX 初始化、EPT hook、Minifilter 交互本身就是几个相对独立的子系统，用不同的 trace flag 拆开后，排查问题时只开需要的那部分 flag，噪音会小很多。

不太适合 WPP 的场景，反而还是老老实实用 `DbgPrint`/断点：

- 早期原型阶段，逻辑还在剧烈变动，加 WPP 埋点的工具链成本（写 GUID、维护 flag、保留 PDB）显得不划算；
- 需要交互式单步调试、查看复杂数据结构内容的场景，这时候 WinDbg 断点 + `dt`/`dx` 命令比任何形式的 trace 都直接。

## 六、小结

WPP Tracing 的核心心智模型可以浓缩成一句话：**编译期把"看起来像 printf 的宏"转换成对 ETW 的结构化事件写入调用，解码时再借助 PDB 把二进制事件还原成人类可读的字符串**。它与 ETW 的关系是"封装与被封装"，与 `DbgPrintEx` 的关系是"生产级替代方案与开发期临时手段"的关系——二者服务的阶段和目标完全不同，并不冲突,通常在一个成熟的驱动项目里是共存并逐步过渡的。

对于像 hypervisor、minifilter 这类需要长期在客户机器上无调试器运行、又对诊断信息有强烈需求的项目，把关键路径（VMX 初始化、EPT hook 命中、VM-Exit 分发）用 WPP 重新埋点，会比纯粹依赖 `DbgPrint` 更适合工程化落地。