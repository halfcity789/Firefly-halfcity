---
title: OmniARK 开发日志 - PPL
description: 介绍 Windows PPL（Protected Process Light）机制，以及在 OmniARK 中如何通过内核驱动设置进程保护级别
published: 2026-07-27
updated: 2026-07-27
category: 驱动开发
tags: [PPL, Windows内核, Windows, WDM, OmniARK, 进程保护]
pinned: false
draft: false
---

## PPL 出现的原因

### 早期进程保护

在 Windows 8 之前，Protected Process（PP）是一种"全有或全无"的保护机制。只有带有特定微软签名的系统进程才能被保护，且保护强度固定。这带来了几个问题：

- **安全软件之间的互斥**：传统安全软件需要注入或终止其他进程来完成工作，但 PP 进程完全不可触碰，导致第三方安全软件无法与系统组件协作。
- **粒度太粗**：要么完全保护（连调试器都连不上），要么完全不保护，没有中间状态。
- **生态封闭**：只有微软自己能发布 PP 进程，第三方开发者无法利用这套机制保护自己的关键进程。

### PPL 的设计思路

Protected Process Light（PPL）是 Windows 8.1 引入的一种进程保护机制，作为早期 PP 的轻量级版本。它允许非系统签名的进程也能获得分级保护，同时保留了比 PP 更灵活的保护级别控制。

PPL 引入了**分级保护**的概念。不同 signer 级别的进程之间存在层级关系，高等级可以访问低等级，但反之不行。这使得微软可以在开放保护能力给第三方的同时，维持系统核心组件的最高优先级。

## PPL 简介

### PPL 的结构

PPL 的保护级别由 `_PS_PROTECTION` 结构定义，包含三个字段：

| 字段 | 含义 |
|---|---|
| **Type** | 保护类型：`0` = 无保护，`1` = PPL，`2` = PP |
| **Audit** | 审计标志，用于记录访问尝试 |
| **Signer** | 签名者级别，决定保护强度 |

Signer 级别从弱到强如下：

| Signer | 级别值 | 说明 |
|---|---|---|
| PsProtectedSignerNone | 0 | 无保护 |
| PsProtectedSignerAuthenticode | 1 | Authenticode 签名 |
| PsProtectedSignerCodeGen | 2 | 代码生成 |
| PsProtectedSignerAntimalware | 3 | 反恶意软件 |
| PsProtectedSignerLsa | 4 | LSA 相关 |
| PsProtectedSignerWindows | 5 | Windows 系统组件 |
| PsProtectedSignerWinTcb | 6 | WinTCB |
| PsProtectedSignerWinSystem | 7 | WinSystem |

除了 `_PS_PROTECTION` 结构外，PPL 还涉及两个关键的签名级别字段：

- **SignatureLevel**：进程镜像的签名级别
- **SectionSignatureLevel**：内存区块的签名级别

这两个字段与 Protection 结构共同构成了 PPL 的完整保护状态。如果仅修改 Protection 而不调整 SignatureLevel，某些系统检查仍然会失败。

### PPL 的保护效果

当一个进程被设置为 PPL 后，Windows 内核会在多个关键路径上检查访问者的 Protection 级别：

1. **进程终止**：`NtTerminateProcess` 会检查调用方是否有足够的 signer 级别来终止目标进程
2. **内存读写**：`NtReadVirtualMemory` / `NtWriteVirtualMemory` 会拒绝低级别进程对高级别进程的访问
3. **句柄操作**：打开进程时请求的权限会被裁剪，通常无法获得 `PROCESS_TERMINATE` 或 `PROCESS_VM_WRITE`
4. **调试器附加**：调试器通常无法附加到 PPL 进程

这意味着，一旦一个普通进程被提升到 `Antimalware` 或更高级别，即使是管理员权限的标准工具（如任务管理器）也无法终止它。

## PPL 实战

### 内核态

驱动层通过直接修改 `EPROCESS` 结构中的保护字段来实现 PPL 设置。

Windows 并未提供公开的 API 来修改其他进程的 PPL 状态，因此需要直接操作。

我将 `EPROCESS` 的内容另外声明了一个 `EPROCESS_INTERNAL` 用于方便后续的操作，由于过大这里就不贴了。

```c
NTSTATUS SetTargetProcessPPL(
    IN ULONG pid,
    IN UCHAR level
)
{
    NTSTATUS status = STATUS_SUCCESS;

    PEPROCESS_INTERNAL ProcessInternal = NULL;
    PEPROCESS Process = { 0 };
    
    status = PsLookupProcessByProcessId(ULongToHandle(pid), &Process);
    if (!NT_SUCCESS(status))
    {
        LogError("Failed to found process %d\n", pid);
        return STATUS_UNSUCCESSFUL;
    }

    ProcessInternal = (PEPROCESS_INTERNAL)Process;

    // Increase CI level
    ProcessInternal->SignatureLevel = 0x38;
    ProcessInternal->SectionSignatureLevel = 0x08;

    ProcessInternal->Protection.Type = 1; // Set PPL
    ProcessInternal->Protection.Audit = 0;
    ProcessInternal->Protection.Signer = level; // Set PPL Level

    LogInfo("Protection set to %d\n", level);
    return STATUS_SUCCESS;
}
```

这里实现了三点：

- 通过 `PsLookupProcessByProcessId` 获取目标进程的 EPROCESS。
- SignatureLevel = 0x38 和 SectionSignatureLevel = 0x08 对应 Windows 10/11 上反恶意软件组件的签名级别。
- Protection.Type = 1 表示启用 PPL。

IOCTL 处理函数负责从用户层接收请求并调用上述函数：

```c
NTSTATUS HandleSetProcessPPL(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpStack,
    _Out_ PULONG_PTR BytesReturned
)
{
    UNREFERENCED_PARAMETER(IrpStack);
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    *BytesReturned = 0;

    PPROTECTION_REQUEST request = (PPROTECTION_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    status = SetTargetProcessPPL(request->Pid, request->ProtectionLevel);

    PCOMMON_RESPONSE response = (PCOMMON_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    response->status = status;

    *BytesReturned = sizeof(COMMON_RESPONSE);

    return STATUS_SUCCESS;
}
```

后面将这个 Handler 注册到 Handler Table 中，在对应的 IOCTL 传入后 Dispatcher 会查表并将请求传递给对应的 Handler。

就像这样：

```c
NTSTATUS DriverIoctlDispatcher(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PIRP Irp
) {
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR bytesReturned = 0;

	ULONG ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    // 校验参数
	status = ValidateIoctlBuffers(Irp, IrpStack, ioctl);
	if (!NT_SUCCESS(status)) {
		goto Complete;
	}

    // 处理请求
	PIOCTL_HANDLER handler = FindIoctlHandler(ioctl);
	if (handler) {
        status = handler(Irp, IrpStack, &bytesReturned);
	}
	else {
		LogError("Unsupported request - IOCTL: 0x%X\n", ioctl);
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

    // 返回
Complete:
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}
```

### 用户态

这里可以通过 `DeviceIoControl` 这个 API 来和驱动设备通信，我将他简单封装成了一个 `SparkleDriverClient` 对象，然后这样调用它：

```csharp
public bool TrySetPpl(int pid, PplSigner level, out string message)
{
    var request = new ProtectionRequest
    {
        Pid = (uint)pid,
        ProtectionLevel = (byte)level
    };

    bool ok = _driverClient.SendIoctl((uint)SparkleIoctl.SetProcessPpl, request, out CommonResponse response);

    if (ok && response.Status == 0)  // STATUS_SUCCESS
    {
        message = $"已设置进程 PID={pid} PPL={level}";
        return true;
    }

    message = ok
        ? $"设置 PPL 失败，驱动返回错误码 0x{response.Status:X}"
        : "设置 PPL 失败，请确认驱动已连接";

    return ok;
}
```

用户层同时提供了 PPL 查询功能，用于在进程列表中实时显示当前保护状态：

```csharp
private PplSigner? ResolvePpl(int pid)
{
    // 用户态 API 直接查询
    return _processService.QueryPplSigner(pid);
}
```

### 实战效果

![](https://img.halfcity.top/2026/07/27/acf83ae16513b02a56f925312993369e.avif)

这是一个普通的 `notepad.exe`，它没有被设置 PPL，Windows 不愿意保护它。

所以他可以轻松被任务管理器结束。

我们将 notepad.exe 的 PPL 级别设置为 Antimalware 后，OmniARK 的进程列表可以正确识别并显示其保护状态：

![](https://img.halfcity.top/2026/07/27/0274e73cb4433ea6e31c35fe7133448d.avif)

可以看到，notepad.exe 的 PPL 列已经从 N/A 变成了 Antimalware，说明驱动层的修改已经生效。

此时尝试通过系统自带的任务管理器终止该进程：

![](https://img.halfcity.top/2026/07/27/d6d595fafc650767f72e585917e6592c.avif)

系统弹出`拒绝访问。`的提示框，证明 PPL 保护已经生效。

即使是管理员权限的任务管理器，也无法终止一个被标记为 `Antimalware` 级别的 PPL 进程。

## PPL 的攻防

### 防御侧

- 保护关键进程：安全软件可以将自己的核心进程设为 PPL，防止被恶意软件终止或注入
- 反调试/反内存读取：PPL 进程对普通进程在内存访问层面是受限的，增加了逆向分析的难度

### 攻击侧

- 权限维持：恶意软件也可以利用 PPL 保护自己，使常规的安全工具无法清除
- EDR 逃逸：某些 EDR 产品依赖用户态代理进程，如果这些进程不是 PPL，攻击者可以先终止它们
- Rootkit 辅助：内核级恶意软件可以直接修改 EPROCESS 结构，给自己或同伴进程加上 PPL 保护

## 总结

PPL 是 Windows 内核安全体系中的重要一环。

## 附

你可以在这里找到 `OmniARK` 的完整源码：

::github{repo=halfcity789/OmniARK}
