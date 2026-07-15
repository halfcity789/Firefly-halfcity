---
title: Hypervisor Sparkle 研究日志 - Meltdown & Spectre
description: 在这篇文章中将对幽灵和熔断这两个著名的侧信道漏洞进行详细的分析研究，探索它的由来以及作用，并说说影响与缓解机制。
published: 2026-07-17
category: 驱动开发
tags: [Hypervisor, Windows内核, Windows, WDM, Sparkle, Meltdown, Spectre]
pinned: false
draft: true
---

## 前言

Spectre/Meltdown 系列漏洞是基于 **微架构层面推测执行（Speculative Execution）留下的侧信道** 实现的。

对于 hypervisor 来说，这类问题特别棘手，因为它们绕过了我们精心设计的 EPT 隔离、VMCS 权限检查，直接从 CPU 缓存的时序差异里泄露数据。

---

## 漏洞起因

现代 CPU 为了提高性能，会在**分支方向还未确定**、**权限检查还未完成**之前，就推测性地执行后续指令，把结果暂存在流水线中。

如果推测被证明是错的，CPU 会把架构状态（寄存器）回滚，**但缓存状态不会回滚**——被推测执行路径访问过的内存地址，已经被加载进了 L1/L2 缓存。

攻击者只要能：

1. 诱导 CPU 推测执行一段本不该执行的代码（读取本无权限访问的数据，或者读取到某个受害者的机密数据）
2. 用这段数据做一次编码访问（比如把秘密字节值当作数组下标去访问另一块内存）
3. 之后测量哪个缓存行被加载了（**Flush+Reload** 或 **Prime+Probe** 计时攻击）

就能把本该 `architecturally invisible` 的数据，通过缓存命中时间的微小差异**side-channel 出来**。

这是所有这一系列漏洞的共同骨架，区别只在于怎么诱导 CPU 越权推测执行。

## Meltdown —— CVE-2017-5754

### 原理

Meltdown 利用的是**乱序执行下权限检查的延迟**：

CPU 在真正提交（retire）一条访问内核地址的加载指令之前，会先推测性地把数据取出来并用于后续指令，权限检查然最终会导致该指令被标记为 fault，但**太晚了**——数据已经通过后续的编码访问进了缓存。

### 对 hypervisor 的影响

Meltdown 本身主要针对**用户态读内核态**，但在虚拟化环境下这个边界被复制了一层：

**guest 用户态是否能读到 host/hypervisor 的内存？** 由于 hypervisor 的地址空间通常与 host 内核共享，未打补丁的系统上，恶意 guest 里的用户态代码理论上可以通过类似手法侧信道读取 **host 物理内存的一部分**（如果 TLB/缓存状态被跨特权级共享）。

### 缓解 - KPTI / KVA Shadow

> 如果分析过 `ntoskrnl.exe` 应该会发现一个奇怪的现象：那就是有一些函数比如 `KiSystemCall` 会有一个奇怪的同名函数 `KiSystemCallShadow`，而这种带有 `Shadow` 后缀的函数就是 Windows 对熔断漏洞的缓解方式。

**核心思路**：把内核地址空间和用户地址空间的页表彻底分离（而不是像传统那样共享同一份页表、只靠 U/S 位区分权限），这样用户态代码即使推测执行，也**无法在页表里找到内核地址的映射**，从源头掐断。

Windows 上对应的是 **KVA Shadow**（KSR，Kernel Virtual Address Shadowing），Linux 上是 **KPTI**（Kernel Page Table Isolation）。

**对 hypervisor 开发的启示**：如果你在 Sparkle 里管理 guest 的页表/EPT，要意识到 **KPTI 类缓解措施在每次用户态/内核态切换时都要多做一次 CR3 reload**，这个开销在 nested virtualization 场景下会被放大（guest 内部切换一次，可能触发额外的 VM-exit 或 TLB flush 语义变化），做性能分析时不能忽略这部分。

## Spectre

Meltdown 相对好修（页表隔离一刀切），Spectre 系列则是滥用**分支预测器**本身，修复代价高得多，因为分支预测器是性能的核心，CPU 乱序执行对于现代 CPU 意义巨大，如果直接禁止这个功能会导致严重的性能下降，很难简单关掉。

### Spectre v1 —— CVE-2017-5753

**原理**：诱导 CPU 推测执行一段 `数组越界访问` 的代码，比如：

```c
if (index < array1_size)  // 分支预测器认为大概率为true，提前推测执行
    result = array2[array1[index] * 256];  // 用越界读到的值做编码访问
```

攻击者反复用合法的 `index` 训练分支预测器，让它"预期"这个 if 恒为真，然后突然传入一个越界的 `index`，CPU 会在分支判断结果出来之前就推测执行内层的越界读取。

#### 对 hypervisor 的影响

任何 hypervisor 里**处理 guest 可控输入、并且有边界检查的代码路径** 都可能是潜在目标。

如果 guest 能通过某种方式训练 host 里的分支预测器，就可能诱导 hypervisor 自己的代码发生越界推测读取。

#### 缓解

编译器插入 `lfence`（Load Fence）作为"推测执行屏障"，强制 CPU 在真正确认分支条件之前不进行后续推测。

MSVC 的 `/Qspectre`、Clang/GCC 的 `-mspeculative-load-hardening` 都是做这件事。

### Spectre v2 —— CVE-2017-5715

**原理**：攻击者污染**间接分支预测器**（Branch Target Buffer, BTB），让受害者进程/VM 执行间接跳转（比如虚函数调用、`call rax`）时，CPU 推测性地跳到攻击者精心挑选的目标地址执行一段"gadget"，这段 gadget 本身会做编码访问把数据泄露出去。

**这是对 hypervisor 影响最大的变种，因为它天然是跨特权级、跨 VM 的**——BTB 在早期实现中是**按物理核心共享**的，不区分当前跑的是 host 还是 guest，也不区分是哪个 VM。这意味着：

**恶意 guest A 可以训练 BTB，等 host/hypervisor 或另一个 guest B 执行间接跳转时，被诱导跳到 A 预先布置好的推测执行路径，泄露 host 或 guest B 的数据。**

**缓解机制**：

- **IBRS（Indirect Branch Restricted Speculation）**：写 `MSR_IA32_SPEC_CTRL`（0x48）的 bit 0，限制间接分支预测跨特权级复用。VMM 在每次 VM-exit（guest→host）时需要设置该位，VM-entry（host→guest）前视情况恢复 guest 自己的值。
- **IBPB（Indirect Branch Predictor Barrier）**：写 `MSR_IA32_PRED_CMD`（0x49）的 bit 0，是一次性"清空"指令，典型用在**vCPU 切换的时候**——一个物理核心上如果要切换运行不同的 VM（或者从 host 切到 guest 且怀疑其信任边界变化），必须发一次 IBPB，防止上一个"住户"训练的 BTB 状态被下一个"住户"读取。
- **STIBP（Single Thread Indirect Branch Predictors）**：在开启超线程（SMT）的情况下，防止同一物理核心上**两个逻辑线程之间**互相污染 BTB。这对同时把两个不同信任级别的 vCPU 调度到同一物理核心的两个超线程上的场景（多租户云环境）尤其重要。

如果 hypervisor 要考虑多 vCPU 调度到同一物理核心的场景，VM-exit handler 里需要有一段：

```c
// VM-exit 后，从guest态回到host态时
UINT64 SpecCtrl = __readmsr(MSR_IA32_SPEC_CTRL);
SpecCtrl |= SPEC_CTRL_IBRS;
__writemsr(MSR_IA32_SPEC_CTRL, SpecCtrl);

// 如果即将调度到不同的vCPU/信任域，额外发一次屏障
__writemsr(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
```

反过来 VM-entry 前，需要把 `SPEC_CTRL` 恢复成 guest 自己配置的值（guest OS 内部也会写这个 MSR 做自己的缓解，VMM 不能覆盖 guest 的选择，需要 per-VM 保存/恢复）。

### Spectre v3a — CVE-2018-3640

推测性读取系统寄存器（如 MSR），泄露本该受权限保护的配置信息。缓解主要靠微码更新。

### Spectre v4 — CVE-2018-3639

CPU 推测性地让一条 load 越过前面还未完成的 store 执行（乱序执行的正常优化），如果 load 读到了"过时"的值并被用于编码访问，同样能侧信道。

缓解涉及 `MSR_IA32_SPEC_CTRL` 的 **SSBD（Speculative Store Bypass Disable）** 位。

## L1TF（L1 Terminal Fault, CVE-2018-3615/3620/3646

这个变种**几乎是为虚拟化场景量身定做的**。

### 原理

当页表项的 **Present 位（P bit）= 0** 时，正常来说这应该直接触发 `#PF`，但在受影响的 CPU 上，如果该 PTE 里**物理地址部分恰好指向一个合法的 L1 缓存行**，CPU 会在处理 `#PF` 之前，先推测性地把这个`本应无效`的地址所对应的 L1 缓存内容读出来用于后续推测执行——即使这个 PTE 根本没有 Present。

### 对 hypervisor

guest 的页表虽然由 guest OS 自己管理，但**最终的物理地址转换要经过 EPT**。

如果 guest 恶意构造一个 Present=0、但 PFN 字段指向**host 物理内存里某个敏感位置**（比如另一个 guest 的内存、或者 hypervisor 自己的内存）的 PTE，在受影响 CPU 上，这个无效 PTE 依然可能触发对该 L1 缓存行内容的推测读取——**相当于 guest 可以越过 EPT 的隔离边界，读取任意 host 物理内存在 L1 缓存里的残留内容**。

这直接打破了 hypervisor 最基本的安全承诺：

**EPT 应该是 guest 无法绕过的隔离层**。

L1TF 证明了在推测执行的世界里，"页表项无效"这个条件本身也可能被绕过。

### 缓解措施

- **EPT 层面加固**：Intel 建议 VMM 把所有**尚未使用的 EPT PTE**（比如没映射的 guest 物理页）的 PFN 字段填充为**超出实际物理内存范围的值**，这样即使推测执行读取，也读不到任何有意义的真实缓存内容。这是 VMM 开发者需要**主动做**的加固。
- **L1D Flush**：在每次 VM-entry（host→guest）之前，主动 flush 整个 L1 数据缓存，防止 guest 能读到上一个执行上下文（可能是 host 或另一个 guest）残留在 L1 里的数据。对应 `MSR_IA32_FLUSH_CMD`（0x10B）的 bit 0，以及 VMCS 里 **VM-Execution Control** 的 `EPT-violation #VE` 与相关新增控制位配合使用。

```c
// VM-entry前的L1D flush（简化示意）
UINT64 FlushCmd = FLUSH_CMD_L1D;
__writemsr(MSR_IA32_FLUSH_CMD, FlushCmd);
```

- **禁用超线程（SMT）**：如果 hypervisor 场景对安全性要求极高，最彻底的做法是**直接关闭 SMT**，因为很多变种在两个逻辑线程共享同一物理核心 L1 缓存的情况下危害被放大。这是`性能 vs 安全` 权衡里最直接粗暴但最有效的一招。

## MDS 系列（Microarchitectural Data Sampling，2019）—— 从缓存扩展到微架构缓冲区

MDS 是一组相关漏洞的统称，包括：

| 名称 | CVE | 泄露来源 |
|---|---|---|
| RIDL (Rogue In-Flight Data Load) | CVE-2018-12130 | Line Fill Buffer / Load Port |
| Fallout | CVE-2018-12126 | Store Buffer |
| ZombieLoad | CVE-2018-12127 / 2019-11091 | Line Fill Buffer |

**核心思路和 Meltdown/L1TF 一脉相承**：这些微架构里的临时缓冲区（用于处理 cache miss、store 转发等）在推测执行过程中会短暂持有"不属于当前执行上下文"的数据，通过侧信道手法依然可以泄露。

**对 hypervisor 的影响**：跟 L1TF 类似，MDS 也能跨越 VM 边界。**缓解手段主要是 `VERW` 指令**（原本用于加载段选择子，微码更新后被赋予了"清空微架构缓冲区"的副作用）：

```c
// VM-entry前执行VERW清空缓冲区（配合微码更新）
UINT16 Selector = 0;
__asm { verw word ptr [Selector] }
```

VMM 需要在每次 **VM-entry 之前**、以及 **vCPU 从一个物理核心迁移/上下文切换时**执行这条指令。

## 写在最后

Spectre/Meltdown 系列从 2018 年披露至今，一直在持续发现新变种（L1TF、MDS、TAA、CacheOut、Downfall...本质上都是同一个推测执行留下痕迹的问题在不同微架构组件上的具体化）。

对 hypervisor 来说：

> 性能优化（推测执行、缓存、乱序执行）天然会留下可观测的副作用，而虚拟化的隔离承诺建立在 `guest 不能观测到 EPT 边界之外的任何东西` 这个假设上——这两者存在结构性张力，短期内不会被一次性修复。

理解了这套防护体系才更深刻地理解了**为什么 VT-x 要给 VMCS 里设置那么多的控制位**。

## 参考

- Intel, "Q3 2018 Speculative Execution Side Channel Update"
- Intel SDM Vol.3D, Chapter 9 "Managing Speculative Execution Side Channel Hardware Support"
- Intel, "Deep Dive: Intel Analysis of Microarchitectural Data Sampling"
- Kocher et al., "Spectre Attacks: Exploiting Speculative Execution"
- Lipp et al., "Meltdown: Reading Kernel Memory from User Space" 
