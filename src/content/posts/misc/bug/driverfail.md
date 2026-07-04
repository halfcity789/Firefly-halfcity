---
title: Visual Studio 2026 无法正确识别驱动项目
description: Visual Studio 2026 无法正确识别驱动项目，具体表现为项目属性中的有关驱动的选项全部消失，但是项目属性的的确设置的是Driver，这里来讲讲如何解决。同时讲讲微软最新引入的C的包管理工具NuGet。
published: 2026-07-03
category: 问题解决
tags: [包管理, WDM, WDK, SDK, NuGet, VIsual Studio 2026]
pinned: false
draft: true
image: https://img.halfcity.top/2026/07/03/df6e72e72a6eae681eb36bd7c4b018fc.avif
---

## 问题

![](https://img.halfcity.top/2026/07/03/df6e72e72a6eae681eb36bd7c4b018fc.avif)

可以看到作为一个驱动项目，但是没有任何驱动项目该有的东西。

## 解决办法

右键项目，找到 `管理 NuGet 包`。

点击去，然后搜索最新版的`Microsoft.Windows.WDK.x64`，下载安装后，重启VS即可。

## 问题探究

### NuGet 的发展

从 Visual Studio 2026 开始，微软进一步推进了 **NuGet-based（基于 NuGet 包）** 的开发模式，不再推荐依赖传统 MSI Installer、VSIX 或独立 SDK 安装的方式来集成开发组件，而是将越来越多的开发工具链拆分为可独立版本管理的 NuGet 包。

如果对 .NET 比较熟悉的，比如搞WPF的应该对NuGet比较熟悉。

但这一变化不仅影响普通的 .NET 开发，也逐渐覆盖了 C++、Windows SDK、WDK 等原生开发领域。

传统情况下，一个 Visual Studio 项目依赖的 SDK 通常来自于：

- Visual Studio Installer
- Windows SDK Installer
- WDK Installer
- 独立 MSI 安装包

安装后，所有项目共享同一套全局环境，例如：

```
C:\Program Files (x86)\Windows Kits\10\
```

项目本身并不知道自己依赖哪个版本，只能依赖开发机上的环境。

说实话C的依赖真的很需要一个包管理工具，每次用过`go`或者`cargo`后都有点无法接受C几乎毫无包管理的生态，感觉十分混乱。

而 NuGet-based 的思想则是：

> **项目声明依赖，而不是机器声明依赖。**

例如：

```xml
<ItemGroup>
    <PackageReference Include="Microsoft.Windows.WDK" Version="10.0.28000.1839" />
</ItemGroup>
```

当项目 Restore 时：

- 自动下载对应 SDK
- 自动配置 Include Path
- 自动配置 Lib Path
- 自动配置 Build Targets
- 自动配置编译参数

整个过程无需手动安装 WDK。

---

### WDK 也开始支持 NuGet 化

这是 VS2026 中最值得关注的一项变化之一。

以前开发 WDM / KMDF / UMDF 驱动需要手动安装 WDK

项目模板也来自 WDK Installer。

现在则逐渐变成：

```
Visual Studio
        │
        ▼
Restore NuGet Packages
        │
        ▼
获得完整 WDK 开发环境
```

项目自身声明需要哪个版本的 WDK，而不是依赖开发机器已经安装什么。

这意味着：

- 不同项目可以使用不同版本 WDK。
- CI/CD 环境无需提前安装完整 WDK。
- 新成员 Clone 项目后 Restore 即可开始编译。
- 降低了环境配置成本。

---

### 与传统方式相比的优势

#### 项目环境可复现

我不知道有多少人可以做到Github上面的项目一下载到本地就可以直接过编译。

反正我基本上是从来没有直接编译成功过，打开项目一编译就是一大堆的报错。

这通常都是 Windows SDK 或 WDK 版本不同或者包依赖缺失、包版本不同等问题导致。

但是反观rust或者go，由于有完善的包管理工具。他们可以基本做到每一个项目都可以直接在本地编译，而不需要恐惧下一秒编译器会丢出一大堆的错误。


NuGet 后：

```
Project
    ↓
Package Version
    ↓
完全一致的 Build Environment
```

每个人使用完全一致的工具链和包，版本同步。

---

#### 更容易做版本管理

例如：

项目 A：

```
WDK 10.0.26100
```

项目 B：

```
WDK 10.0.22621
```

两者可以共存，不需要不断切换全局安装版本。

---

#### 更适合 CI/CD

例如 GitHub Actions：

过去需要：

```
Install VS
Install SDK
Install WDK
Install Integration
```

现在很多情况下只需要：

```
git clone
dotnet restore
msbuild
```

构建环境更加轻量，也更容易自动化。

#### 项目保持一致

近年来微软不断推动 C++ 工程向包管理发展，例如：

- NuGet
- vcpkg
- CMake Package
- MSBuild PackageReference

WDK 的 NuGet 化也是这一趋势的一部分。

说白了也就是微软也看不下去了，决定自己搞一个包管理了。

---

### 对现有项目的影响

对于旧版驱动项目：

- 仍然可以继续使用传统 WDK。
- Visual Studio 保留兼容性。
- 不会强制迁移。

但微软推荐新项目逐步采用 PackageReference 的方式管理依赖。

未来更多 Windows 开发组件预计都会提供 NuGet 包，而不是依赖全局安装。

---

## 总结

Visual Studio 2026 标志着微软进一步推进 **NuGet-first** 的开发理念。无论是 Windows SDK、WDK，还是 C++ 原生工具链，都在逐步从"机器安装依赖"转向"项目声明依赖"。

对于驱动开发者而言，最大的变化在于 WDK 不再只是一个需要全局安装的开发套件，而开始成为项目可管理、可版本化、可自动恢复的一部分。这种模式不仅提升了团队协作和 CI/CD 的效率，也使驱动开发逐步融入现代软件工程的依赖管理体系，为未来更加模块化、可复现的 Windows 原生开发奠定了基础。

## 吐槽

包管理不错是真的，期待它能够做到类似`cargo`的效果，但是就目前而言项目模版创建的项目都能出问题...前路堪忧啊。
