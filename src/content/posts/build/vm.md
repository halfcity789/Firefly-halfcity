---
title: 搭建vmm驱动调试环境 - Windows虚拟机
description: 手工搭建一个WIndows 22H2的调试虚拟机，用于方便后续驱动和Implant的调试。
published: 2026-07-03
category: 其他
tags: [部署, 虚拟机, 环境搭建, WinDbg, HyperDbg]
pinned: false
draft: false
image: https://img.halfcity.top/2026/07/03/3b99e6a3a75d8415649aad33386fd27b.avif
---

> [!NOTE]
> 被某鱼倒X坑死了，虚拟机虽然是去虚拟化了，但是又老又难用，白费我一块大洋了。
> 这里决定自己搭建一个去虚拟化的调试Windows虚拟机。

## 获取Windows 22H2镜像

在这里[HelloWindows.cn - 只收录官方原版Windows系统](https://hellowindows.cn/)可以获取到镜像文件。

![](https://img.halfcity.top/2026/07/03/272406c7059fb7a7d5a1ea205ecb0170.avif)

这里可以看到有很多的版本，下载包含Pro的版本即可。

## 安装Windows虚拟机

### 配置VMWare

来到VMWare，选择典型安装。

![](https://img.halfcity.top/2026/07/03/664b2de3391031cf2e15e0834197dfb2.avif)

选择稍后安装操作系统，然后选择Windows 10 x64。

![](https://img.halfcity.top/2026/07/03/5768f26de35570bb5cc30da20d69164a.avif)

这里命好名称然后选择好位置，点击下一步。

然后这里会要求选择磁盘的大小，注意这里的典型安装默认是按需占用磁盘空间的，也就是说这里设置的是可用的最大大小，并不是立即分配的大小。另外这里选择保存为单一文件可能性能更优，但是当数据损害时可能更难恢复，这里我选择了单一文件。

在这里选择128G，按需调整，然后下一步，完成。

![](https://img.halfcity.top/2026/07/03/7d31965030a0a496837a15ffbd946041.avif)

在虚拟机设置这里编辑内存、处理器等信息，并且一定要启用这里的`虚拟化 Interl VT-x/EPT`。然后在`显示`这里配置一下显存，一般设置成分配内存的一半即可。

最后在CD / DVD这里配置Windows的ISO文件。

启动虚拟机。

### Windows安装

![](https://img.halfcity.top/2026/07/03/cf57429bf55bf0d87c48d242e0dde88e.avif)

来到这里，点击下一页。

> [!NOTE]
> 这里Windows可能会很卡，窗口还很小，这是因为还没有安装`VMTools`，这里后面会安装

选择现在安装，并选中Windows 10 专业版。然后选择仅安装Windows，并点击下一步。

![Windows安装中](https://img.halfcity.top/2026/07/03/e2e46d46773b38250bc8b33f05a083d5.avif)

安装过程会比较慢，等安装好重启后，Windows会出现一些设置，按照提示填写即可。

填写好后，等待进入桌面。

进入桌面后，点击左上角的虚拟机，选择安装VMTools。

此时Windows会弹出一个通知，点击后选择运行`setup.exe`。安装好的重启。

![Windows](https://img.halfcity.top/2026/07/03/d4d035e1377104a9207a735c4ca4dc75.avif)

这是就可以去关闭Defender之类的设置了。

## 清理Windows虚拟机

### Win11Debloat

::github{repo=Raphire/Win11Debloat}

这里先清理一下Windows自带的垃圾。

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
.\Get.ps1
```

![主界面](https://img.halfcity.top/2026/07/03/45c189f229d98be055fae9cdc149e105.avif)

![删除中](https://img.halfcity.top/2026/07/03/d0454adcfd6d67e55b432ce11d129d73.avif)

## 配置Windows设置

### Windows虚拟化

这里使用一下CPU-V这个工具检测一下Vt的支持状态，像这样就没问题了。

![](https://img.halfcity.top/2026/07/03/38ecd9894fc0e61e3f5d7de3c7c1c690.avif)

一般来讲Win10是不会报错的，但是以防万一，如果报错了这里可以解决。

<iframe width="100%" height="468" src="//player.bilibili.com/player.html?bvid=BV1BouDzUE3L&p=1&autoplay=0" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true" &autoplay=0> </iframe>

### 防火墙

`Ctrl + R`打开运行，输入`control`来到防火墙，点击高级设置添加入站规则。

> [!WARNING]
> 一定要保证Host和VM可以互ping

![像这样](https://img.halfcity.top/2026/07/03/33d0b067392207826f51a0d68a4dddb4.avif)

## Windows内核调试

### Kdnet

确保SecureBoot关闭。

```powershell
PS C:\users\halfcity\Desktop> Confirm-SecureBootUEFI
False
```

启用kdnet调试。

这里不使用串口调试，为什么呢，单纯是因为它真的很慢很慢！

```cmd
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.183.1 port:50000
Key=xxx
```

### Windbg

Key复制出来输入到`Windbg`里面。

记得先到Windbg的设置中配置好符号文件的路径，然后启动调试。

![](https://img.halfcity.top/2026/07/03/3b99e6a3a75d8415649aad33386fd27b.avif)

```bash
Response                         Time (ms)     Location
Deferred                                       srv*D:\data\security\reverse\symbols*https://msdl.microsoft.com/download/symbols
Error                                          D:\data\code\projects\Sparkle\x64\Debug
WARNING: Path element is empty
Symbol search path is: srv*D:\data\security\reverse\symbols*https://msdl.microsoft.com/download/symbols;;D:\data\code\projects\Sparkle\x64\Debug
Executable search path is: 
WARNING: Path element is empty
Windows 10 Kernel Version 19041 MP (1 procs) Free x64
Edition build lab: 19041.1.amd64fre.vb_release.191206-1406
Kernel base = 0xfffff805`4c000000 PsLoadedModuleList = 0xfffff805`4cc2a420
System Uptime: 0 days 0:00:01.721
nt!DebugService2+0x5:
fffff805`4c406fd5 cc              int     3
```

看到这个提示就是Windbg接收到Windows的调试请求了，这个时候Windows会保持黑屏状态，因为这里有一个断点。

> [!NOTE]
> 如果你对Windbg不熟悉的话，在这里可以看到关于它的详细教程[Windbg](/posts/misc/usage/windbg/)

输入`lm`查看缺失的符号，然后这里也可以输入`.reload /f`强制下载并加载符号文件。

```bash
kd> lm
start             end                 module name
fffff805`48a30000 fffff805`48cbf000   mcupdate_GenuineIntel   (deferred)             
fffff805`48cc0000 fffff805`48cc6000   hal        (deferred)             
fffff805`48cd0000 fffff805`48d2c000   kd_02_8086   (deferred)             
fffff805`48d30000 fffff805`48d79000   kdcom      (deferred)             
fffff805`48d80000 fffff805`48da9000   tm         (deferred)             
fffff805`48db0000 fffff805`48e1e000   CLFS       (deferred)             
fffff805`48e20000 fffff805`48e2b000   BOOTVID    (deferred)             
fffff805`4c000000 fffff805`4d046000   nt         (pdb symbols)          d:\data\security\reverse\symbols\ntkrnlmp.pdb\F57E740B088E5056E8AF0772F1CC5BEB1\ntkrnlmp.pdb
fffff805`4e400000 fffff805`4e41a000   PSHED      (deferred)             
fffff805`4e420000 fffff805`4e537000   clipsp     (deferred)             
fffff805`4e540000 fffff805`4e5ad000   FLTMGR     (deferred)             
fffff805`4e5b0000 fffff805`4e5dc000   ksecdd     (deferred)             
fffff805`4e5e0000 fffff805`4e642000   msrpc      (deferred)             
fffff805`4e650000 fffff805`4e660000   cmimcext   (deferred)             
fffff805`4e670000 fffff805`4e681000   werkernel   (deferred)             
fffff805`4e690000 fffff805`4e69c000   ntosext    (deferred)             
fffff805`4e6a0000 fffff805`4e78c000   CI         (deferred)             
fffff805`4e790000 fffff805`4e84b000   cng        (deferred)             
fffff805`4e850000 fffff805`4e921000   Wdf01000   (deferred)             
fffff805`4e930000 fffff805`4e943000   WDFLDR     (deferred)             
fffff805`4e950000 fffff805`4e95f000   SleepStudyHelper   (deferred)             
fffff805`4e960000 fffff805`4e971000   WppRecorder   (deferred)             
fffff805`4e980000 fffff805`4e9a6000   acpiex     (deferred)             
fffff805`4e9b0000 fffff805`4e9be000   msseccore   (deferred)             
fffff805`4e9c0000 fffff805`4ea8c000   ACPI       (deferred)             
fffff805`4ea90000 fffff805`4ea9c000   WMILIB     (deferred)             
fffff805`4eaa0000 fffff805`4eab0000   WdBoot     (deferred)             
fffff805`4eac0000 fffff805`4eb2b000   intelpep   (deferred)             
fffff805`4eb30000 fffff805`4eb48000   WindowsTrustedRT   (deferred)             
fffff805`4eb50000 fffff805`4eb5b000   IntelTA    (deferred)             
fffff805`4eb60000 fffff805`4eb6b000   WindowsTrustedRTProxy   (deferred)             
fffff805`4eb70000 fffff805`4eb84000   pcw        (deferred)             
fffff805`4eb90000 fffff805`4eb9b000   msisadrv   (deferred)             
fffff805`4eba0000 fffff805`4ebb5000   vdrvroot   (deferred)             
fffff805`4ebc0000 fffff805`4ebf0000   pdc        (deferred)             
fffff805`4ec00000 fffff805`4ec77000   pci        (deferred)             
fffff805`4ec80000 fffff805`4ec99000   CEA        (deferred)             
fffff805`4eca0000 fffff805`4ecd1000   partmgr    (deferred)             
fffff805`4ece0000 fffff805`4ed8b000   spaceport   (deferred)             
fffff805`4ed90000 fffff805`4ed9b000   intelide   (deferred)             
fffff805`4eda0000 fffff805`4edb3000   PCIIDEX    (deferred)             
fffff805`4edc0000 fffff805`4edd9000   volmgr     (deferred)             
fffff805`4ede0000 fffff805`4ee43000   volmgrx    (deferred)             
fffff805`4ee50000 fffff805`4ee68000   vsock      (deferred)             
fffff805`4ee70000 fffff805`4ee8d000   vmci       (deferred)             
fffff805`4ee90000 fffff805`4eeae000   mountmgr   (deferred)             
fffff805`4eeb0000 fffff805`4eebd000   atapi      (deferred)             
fffff805`4eec0000 fffff805`4eefc000   ataport    (deferred)             
fffff805`4ef00000 fffff805`4ef32000   storahci   (deferred)             
fffff805`4ef40000 fffff805`4eff5000   storport   (deferred)             
fffff805`4f000000 fffff805`4f02f000   stornvme   (deferred)             
fffff805`4f030000 fffff805`4f04c000   EhStorClass   (deferred)             
fffff805`4f050000 fffff805`4f06a000   fileinfo   (deferred)             
fffff805`4f070000 fffff805`4f0b0000   Wof        (deferred)             
fffff805`4f0c0000 fffff805`4f11a000   WdFilter   (deferred)             
fffff805`4f120000 fffff805`4f3f7000   Ntfs       (deferred)             
fffff805`4f400000 fffff805`4f40d000   Fs_Rec     (deferred)             
fffff805`4f410000 fffff805`4f580000   ndis       (deferred)             
fffff805`4f590000 fffff805`4f62c000   NETIO      (deferred)             
fffff805`4f630000 fffff805`4f664000   ksecpkg    (deferred)             
fffff805`4f670000 fffff805`4f95c000   tcpip      (deferred)             
fffff805`4f960000 fffff805`4f9df000   fwpkclnt   (deferred)             
fffff805`4f9e0000 fffff805`4fa10000   wfplwfs    (deferred)             
fffff805`4fa20000 fffff805`4faeb000   fvevol     (deferred)             
fffff805`4faf0000 fffff805`4fafb000   volume     (deferred)             
fffff805`4fb00000 fffff805`4fb6d000   volsnap    (deferred)             
fffff805`4fb70000 fffff805`4fbc0000   rdyboost   (deferred)             
fffff805`4fbd0000 fffff805`4fbf6000   mup        (deferred)             
fffff805`4fc00000 fffff805`4fc12000   iorate     (deferred)             
fffff805`4fc20000 fffff805`4fc30000   hwpolicy   (deferred)             
fffff805`4fc40000 fffff805`4fc5d000   disk       (deferred)             
fffff805`4fc60000 fffff805`4fcd2000   CLASSPNP   (deferred)      

kd> .reload /f

```

输入`g`继续运行

## 拍摄快照

### 快照是什么

快照是VMWare保持虚拟机状态的一种机制，通过快照可以很快将虚拟机还原到指定状态

### 如何拍摄快照

左上角选择虚拟机快照，点击`拍摄快照`

### 快照是如何运行的

快照的核心是“**写时复制 (Copy-On-Write)**”或“**写时重定向 (Redirect-on-Write)**”技术，流程如下：

1. **“冻结”原始磁盘**  
   创建快照时，系统会立刻将你的原始虚拟磁盘文件（如 `.vmdk` 或 `.vhdx`）“冻结”为**只读**状态。这意味着之后所有的数据修改都不会再写入这个原始文件。

2. **创建“差异文件”**  
   系统会同时生成一个新的、很小的**差异磁盘文件**（也叫增量文件，如 `-delta.vmdk` 或 `.avhd`）。

3. **记录所有变更**  
   从此刻起，虚拟机的一切新操作（安装软件、修改文件等）产生的数据变更，**全部都会被写入到这个新的差异文件里**。

所以，快照本身的机制是只保存**从创建那一刻起，到当前时间点为止，所有发生变化的“差异”数据**，而非整个磁盘的全部内容。

### 注

> [!WARNING]
> - **快照不是备份**：快照依赖于原始磁盘，如果原始磁盘损坏或被删除，快照也无法恢复数据。可靠的备份应是完全独立的副本。
> - **避免长期使用**：长期保留大量快照会显著占用存储空间并拖慢虚拟机性能。建议在完成测试或确认系统稳定后，及时清理（合并）不再需要的快照。

## 总结

到此，这台Windows虚拟机就部署完成了，后续可以用于vmm开发研究。

后面可能会加上去虚拟化的内容...

## 附

如果有兴趣可以看看这个项目

::github{repo=hyperdbg/hyperdbg}