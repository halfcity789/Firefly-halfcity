---
title: Hypervisor Sparkle 研究日志 - VMX
description: 在这篇文章中将对VMX进行详细的分析研究，探索它的由来以及作用。
published: 2026-07-04
category: 驱动开发
tags: [Hypervisor, Windows内核, Windows, WDM, VMX, Sparkle]
pinned: false
draft: false
---

## VMX 出现的原因

### 早期VM的权限冲突

在没有硬件虚拟化支持的年代，guest OS 运行在 ring 0 会直接和 host OS 的 ring 0 打架——毕竟 x86 只有一套特权级，guest 内核和真实内核不可能同时"真的"跑在 ring 0。
 
解决方案要么是:
 
- **Ring compression**:把 guest 内核降级到 ring 1（Xen 早期的半虚拟化思路，需要修改 guest 内核代码，不透明）。
- **二进制翻译**:动态扫描并重写 guest 的特权指令流，把敏感指令替换成安全的等价代码(VMware 早期方案，复杂且有性能开销)。

## VMX 简介

VT-x 引入了两个新的 CPU 运行模式:**root 模式**(VMM 所在)和 **non-root 模式**(guest 所在)。

核心机制便是是 **VMCS**(Virtual Machine Control Structure)
 
- Guest 在 non-root 模式下可以"真的"以 ring 0 身份运行，不需要降级也不需要指令重写。
- VMCS 里配置了一系列 **VM-exit 触发条件**——guest 执行到某些敏感指令(如 `CPUID`、`RDMSR`、访问某些控制寄存器)或者发生某些事件时，CPU 自动切换回 root 模式，把控制权交还给 VMM，VMM 处理完之后再 `VMRESUME` 回 non-root。

所以 VMX 的意义是:**让 guest 内核可以"名义上"独占 ring 0，同时 VMM 在硬件层面拿到一个可控的陷入机制**，不需要修改 guest 代码，也不需要软件翻译的开销。
 
这一层解决的是"执行"层面的隔离——**谁在什么时候能做什么**。

VMX和[EPT](/posts/research/driver/hypervisor/ept)是硬件虚拟化至关重要的两个部分。

## VMX 初始化

```c
BOOLEAN VmxInitializeCpu()
{
	if (!UtilsCheckVmxSupport()) {
		ErrorLog("VMX is not supported on this processor %d\n"， KeGetCurrentProcessorNumber());
		return FALSE;
	}

	ULONG cpuNumber = KeGetCurrentProcessorNumber();
	PVCPU CurrentVCpu = &g_vcpu[cpuNumber];

	CurrentVCpu->ProcessorIndex = cpuNumber;

	PHYSICAL_ADDRESS vmxon = {0};
	PHYSICAL_ADDRESS vmcs = { 0 };
	vmxon.QuadPart = 0xFFFFFFFF; // intel specifies that the region must be below 4GB
	vmcs.QuadPart = 0xFFFFFFFF;
	PVMX_VMCS pVmxonRegion = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS)， vmxon);
	PVMX_VMCS pVmcsRegion = (PVMX_VMCS)MmAllocateContiguousMemory(sizeof(VMX_VMCS)， vmcs);
	if (pVmxonRegion == NULL) {
		ErrorLog("Failed to allocate memory for VMXON regions on processor %d\n"， cpuNumber);
		MmFreeContiguousMemory(pVmxonRegion);
		return FALSE;
	}
	if (pVmcsRegion == NULL) {
		ErrorLog("Failed to allocate memory for VMCS regions on processor %d\n"， cpuNumber);
		MmFreeContiguousMemory(pVmcsRegion);
		return FALSE;
	}
	RtlSecureZeroMemory(pVmxonRegion， sizeof(VMX_VMCS));
	RtlSecureZeroMemory(pVmcsRegion， sizeof(VMX_VMCS));

	IA32_VMX_BASIC_MSR vmxBasic = {0};
	vmxBasic.All = __readmsr(MSR_IA32_VMX_BASIC);
	pVmxonRegion->RevisionIdentifier = (ULONG)vmxBasic.Fields.RevisionIdentifier;
	pVmcsRegion->RevisionIdentifier = (ULONG)vmxBasic.Fields.RevisionIdentifier;

	CurrentVCpu->VmxonRegion = pVmxonRegion;
	CurrentVCpu->VmcsRegion = pVmcsRegion;

	VmxAdjustControlRegisters();

	PHYSICAL_ADDRESS physVmxonAddr = MmGetPhysicalAddress(pVmxonRegion);
	PHYSICAL_ADDRESS physVmcsAddr = MmGetPhysicalAddress(pVmcsRegion);
	ULONG64 vmxonPhysAddr = (ULONG64)physVmxonAddr.QuadPart;
	
	CurrentVCpu->VmxEnabled = TRUE;

	ULONG64 vmcsPhysAddr = (ULONG64)physVmcsAddr.QuadPart;

	if (__vmx_on(&vmxonPhysAddr) || __vmx_vmclear(&vmcsPhysAddr) || __vmx_vmptrld(&vmcsPhysAddr)) {
		ErrorLog("Failed to execute VMXON on processor %d\n"， cpuNumber);
		MmFreeContiguousMemory(pVmxonRegion);
		MmFreeContiguousMemory(pVmcsRegion);

		CurrentVCpu->VmxEnabled = FALSE;

		CurrentVCpu->VmxonRegion = NULL;
		CurrentVCpu->VmcsRegion = NULL;

		return FALSE;
	}

	VmxLaunchCpu(CurrentVCpu);

	InfoLog("VMX enabled on CPU %u， RevisionId=0x%X\n"， cpuNumber， pVmxonRegion->RevisionIdentifier);

	return TRUE;
}

static VOID VmxTerminateCpu() {
	USHORT cpuNumber = KeGetCurrentNodeNumber();
	InfoLog("Terminating CPU %d\n"， cpuNumber);

	__vmx_off();
	MmFreeContiguousMemory((PVOID)PhysicalToVirtualAddress((ULONG_PTR)g_vcpu[cpuNumber].VmxonRegion));
	MmFreeContiguousMemory((PVOID)PhysicalToVirtualAddress((ULONG_PTR)g_vcpu[cpuNumber].VmcsRegion));
}
```

这里便是Vmx初始化的过程


## 参考

[Rayanfam Blog](https://rayanfam.com/topics/hypervisor-from-scratch-part-2/)

::github{repo=DarthTon/HyperBone}

::github{repo=ionescu007/SimpleVisor}

::github{repo=hyperdbg/hyperdbg}
