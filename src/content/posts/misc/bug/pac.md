---
title: Windbg 在 Windows 运行时断点失效解决
description: 记录一次由第三方内核驱动影响 Windows Kernel Debug Runtime 行为的问题排查过程
published: 2026-08-05
category: 问题解决
tags: [Windows, WinDbg, AntiCheat, Windows内核, PAC]
pinned: false
draft: false
image: https://img.halfcity.top/2026/08/05/841c5951c433f064cdac8e1ec1ff043b.avif
---

> [!NOTE]
> 想先看结论的可以直接跳转到问题 `解决部分`

## 背景

在使用 WinDbg 通过 调试驱动时，遇到了一个非常奇怪的问题。

现象如下：

- WinDbg 可以正常连接目标机
- 系统启动早期可以正常断下
- Kernel Debug 状态显示正常
- 进入 Windows Runtime 后，点击 Break 无响应
- 使用 `DbgBreakPoint()` 触发断点时直接蓝屏

环境：

- Windows 10 22H2
- VMware 虚拟机
- KDNET Kernel Debug
- WDM 驱动开发环境

## 现象

连接 KDNET：

```txt
Using NET for debugging
Opened WinSock 2.0

Waiting to reconnect...

Connected to target 192.168.183.129 on port 50000

Kernel Debugger connection established.
```

进入 WinDbg 检查 Kernel Debug 状态：

```bash
kd> dd nt!KdDebuggerEnabled L1
fffff801`21a4310b 00000001
kd> dd nt!KdDebuggerNotPresent L1
fffff801`21a4310c 00000000
```

结果：

```bash
KdDebuggerEnabled = 1
KdDebuggerNotPresent = 0
```

说明：

- Kernel Debug 已启用
- Debugger 当前连接正常

因此可以排除：

- debug 没打开
- KDNET key 错误
- 网络连接问题

## 探究

经过测试发现：

### 在 Windows启动早期

WinDbg 点击 `Break` -> 正常断下

### 出现 KDTARGET Refresh

看到：

```txt
KDTARGET: Refreshing KD connection
```

之后 `Break` 仍然可以正常进入。


### 进入完整Windows Runtime

等待一段时间 `Break` 无响应。


因此问题基本确认为 `Kernel Debug Runtime` 阶段异常

## 排查

说实话，这个问题很无厘头，他就像是突然出现的一样，并且有很多种原因可能会导致 Runtime 阶段连接异常。

我因此绕了很大的一个弯。

### 基础测试

由于问题发生前平台一直进不去，就先把 Debug 暂时关闭了一会，就想这样 `bcdedit /debug off`。

因此首先怀疑 Debug 状态没有完全恢复。

检查：

```bash
> bcdedit /set {current} debug on
> bcdedit /set {current} testsigning on
> bcdedit /enum {current}
...
debug Yes
testsigning Yes
```

重新设置后重启无效。

说明 BCD 中的基础 Debug 配置大概率不是问题。

### KDNET 配置

这里尝试重新配置 KDNET:

```bash
bcdedit /dbgsettings net hostip:192.168.183.1 port:50000 key:1.2.3.4
```

重新连接测试。

结果问题依旧。

因此排除：

- KDNET Key
- dbgsettings 异常
- 网络传输问题

### Hypervisor / VBS

由于 `systeminfo` 显示 `已检测到虚拟机监控程序`

因此怀疑：

- Hyper-V
- VBS
- HVCI
- VMware Nested Virtualization

这里其实有一点死马当作活马医的感觉了，因为我其实比较清楚这里大概率不会是问题的根源。

因为我绝对没有对这里进行过修改，除非微软又做什么神秘隐藏操作。

检查基于虚拟化的安全性，结果未启用。

尝试

```bash
bcdedit /set hypervisorlaunchtype off
```

重启后问题仍然存在。

因此 `VBS/CG` 应该不是根因。

### 断点测试

虽然调试驱动时自动蓝屏重启所以基本肯定 windbg 已经完全失去了运行时 debugger 的功能。

但是这里我还是想测试一下：

我将 `DbgBreakPoint()` 加入到 `DriverEntry` 并尝试运行，理想状态下 windbg 会捕获这个断点。

但是实际上 Windows 直接蓝屏了，并提示 `NOT_HANDLED` 也就是没有可以用于异常派遣处理的调试器，所以蓝屏。

所以问题位置大致缩小到 `Runtime Kernel Exception Handling`

### 小结

我们总结一下现有的信息：

- KDNET 传输层正常，在 Windows 启动时可以连接到 Windbg
- Windbg 本身大概率正常
- Windbg 的控制大致是在 Windows 从 boot 切换到 runtime 后一小段时间失效
- 在最后有效的断点使用 `lm` 可以看到只有 `nt` 模块被加载
- 除了无法调试 Windows 本身运行正常

## 问题发现

现在我们可以大致描述一下问题是由什么导致的：

> 很可能有一个东西，它会在 Windows 运行时初始化的时候被加载，同时它很可能在主动阻碍 Windows 内核调试的功能，它可鞥反感调试环境，同时它具有高权限，可以对 Windows 内核进行控制。

重新回忆时间线：

最初：

执行 `bcdedit /debug off` 同时 `testsigning` 关闭。

之后安装了 `CS2` 和 `完美对战平台`。

这时候可以发现有一个东西极其符合现在发现的现象，就是 `AC`，准确的说是完美的 `PAC`。

作为反作弊系统，现在的绝大多数驱动都会在开机后预加载，并且它不希望被调试器分析，同时具有 r0 的操作权限。

就时间线来看，这个猜想也完全合理。

## 问题解决

卸载完美对战平台后，重启，再次测试 WinDbg Break：

Windbg 断下，恢复正常。

![](https://img.halfcity.top/2026/08/05/841c5951c433f064cdac8e1ec1ff043b.avif)

抽象来说，卸载可疑的驱动程序是解决的办法。

## 详细分析

完美对战平台可能做了什么？

虽然最终没有对该驱动进行逆向，但是根据这类游戏平台的常见设计，可以推测其可能包含：

检查 `KdDebuggerEnabled` 或者 `KdDebuggerNotPresent`

例如：

```c
if (KdDebuggerEnabled)
{
    DrvUnattachDebugger();
}
```

`DrvUnattachDebugger` 中它可以有多种方式让 Windows 误以为没有 debugger 附加，所以出现异常直接蓝屏。

## 总结

1. 有些时候某个东西正常连接不代表它的状态一定正常

即使：

KdDebuggerEnabled = 1

KdDebuggerNotPresent = 0

也只能说明 Debugger 基础设施存在。

任何Ring0组件都有可能影响。

2. 时间线很重要

如果不是这里强烈地指向了驱动加载的时间线，我大概率是不会怀疑到 PAC 头上的。

## 附

虽然问题解决，但是其实也没有那么实锤，只能说调试环境还是要注意一下这些乱七八糟的东西。

指不定就被坑了。

但是话又说回来 `VAC` 就没有在 Windows 里乱搞，这该说好还是不好...
