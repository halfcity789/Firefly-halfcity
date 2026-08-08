---
title: CS2 Cheats From Scratch!
description: 本文仅用于游戏安全技术科普、逆向工程原理学习以及反作弊研究交流，目的在于技术分享与安全意识提升，绝不鼓励、支持或教唆任何形式的游戏作弊行为。纯学术性质研究探讨，无危害，无恶意！纯学术性质研究探讨，无危害，无恶意！纯学术性质研究探讨，无危害，无恶意！
published: 2026-08-08
updated: 2026-08-08
category: 游戏安全
tags: [CS2, FPS, Windows, WDM, CE, WinDbg, Windows内核, PPL, 窗口, EPT Hook, Windows驱动, 游戏引擎, 射影几何, Tauri, React, 外挂, rust, IRQL, IDA, 页表, Spectre]
pinned: false
draft: false
password: cs2{Th3_tru3_0ff5et_@f_3ntry_1s_0x70}
passwordHint: "由于文章内容较为敏感，为避免不必要的麻烦，感兴趣或者希望交流下的可以通过邮箱来找我要密码"
slug: encrypted-cs2-study
---

> [!WARNING]
> 请确保阅读本文前你已完整阅读下列声明，下文内容将默认视为你同意声明中的内容

## 声明 / Disclaimer

本文仅用于游戏安全技术科普、逆向工程原理学习以及反作弊研究交流，旨在帮助读者理解 FPS 作弊的技术实现机制，从而更好地认识游戏安全防护的必要性。

作者本人为游戏安全相关学习者，撰写本文的目的在于技术分享与安全意识提升，**绝不鼓励、支持或教唆任何形式的游戏作弊行为**。

读者应明确以下内容：

1. 本文内容仅为技术原理说明和代码展示，不提供任何可直接使用的偏移或者基址。

2. 使用本文所述技术制作、传播或使用游戏作弊程序，可能违反《Counter-Strike 2》及相关平台的用户协议，导致账号永久封禁等处罚。

3. 在部分国家和地区，制作、销售或使用游戏外挂软件可能涉嫌违法，读者需自行了解并遵守所在地相关法律法规。

4. 因读者将本文内容用于任何不正当目的而产生的一切后果（包括但不限于账号封禁、法律纠纷、经济损失等），均由读者本人承担，与作者无关。

请尊重游戏公平环境，支持官方反作弊机制，共同维护健康的游戏生态。如对游戏安全技术感兴趣，建议通过正规渠道学习逆向工程、内存安全、反作弊系统设计等相关知识。

**本文发布后，作者保留文章版权以及随时修改或删除内容的权利。**

---

## 前言

本文将讲述的是 FPS 游戏的一般外挂的开发流程，这里以 CS2 作为例子。

希望读者不要带着的复现心态阅读，我绝对不支持任何编写类似程序的行为，**再次强调这篇文章是用于反作弊交流的学术文章**。

在 CS2 这类 FPS 竞技游戏中，`外挂` 是一个长期存在的话题。

作为游戏安全学习者，理解外挂的实现原理，有助于我们更清晰地看到反作弊系统需要防护的攻击面。

本文不会提供任何可直接运行的外挂本体、相关的偏移或基址，而是从技术原理角度，梳理内存挂从内存读取到屏幕绘制的完整链路。

接下来我会先补充一些背景知识，然后详细地从最基础的内容讲到如何制作一个合格的 CS2 外挂，这里取名参考了一个很厉害的文章 `Hypervisor From Scratch`。

然后...让我们开始吧，CS2 Cheats From Scratch!

## 外挂的类型

在 FPS 游戏中的外挂是最多的，因为 FPS 有即时性的特性，这导致服务器难以完全掌控权威，这是极其利好外挂的。

随着技术的发展，外挂已经明显分化为两大流派：

**传统的内存挂** 和 **新兴的AI挂**。

两者各有利弊，下面将详细谈谈他们。

### 内存挂

顾名思义就是基于内存操作的外挂。

内存挂的核心逻辑是：**读取或篡改游戏进程的运行时内存数据**。

因为对于一个运行的游戏，玩家的 `血量`、`坐标`、`朝向` 等状态，全部都会由 Server 传递并保存在内存中的某一个地方。

而某些数据又会同步给 Server ，比如 `朝向` 等，这就是 FPS 外挂的基础。

#### 历史

内存挂的历史非常悠久，可以追溯到很久以前。

大致发展的过程是：

1. DOS 至 Win95 时代，这个时候 CE 和 WPE 还没有出现，相关法律也很少，属于是野蛮生长的阶段，各种野路子工具盛行，AC 的身影很少出现。
2. 网络游戏兴起，同时 CE 和 WPE 出现，外挂制作流程和工具有了大致的标准，外挂快速发展，与此同时就出现了很多的 AC （比如 CS:Source 的 VAC），一些著名的 AC 经过发展维护留存到现在，成为了现代外挂对抗的基石。
3. 到现在 AC 和 外挂的竞争越来越激烈，从 r3 斗到 r0 再到 r-1，外挂开发的门槛明显提高了很多，相关法律也完善了，就成了现在的样子。

#### 外部读写

这里以常见的用户态外部内存绘制距离

| 步骤 | 核心动作 | 技术手段 |
| :--- | :--- | :--- |
| **1. 定位进程** | 获取游戏进程句柄 | `OpenProcess` |
| **2. 寻找基址** | 找到模块基址（如 `client.dll` / `GameAssembly.dll`） | `EnumProcessModules` / 手动解析PE结构 |
| **3. 偏移量扫描** | 通过签名扫描内存并根据 Pattern 提取 Offset | 这里使用 `ReadProcessMemory` 来暴力获取内容并根据签名提取偏移 |
| **4. 读取/写入** | 跨进程读写内存 | `ReadProcessMemory` / `WriteProcessMemory` |
| **5. 绘制** | 将数据绘制到屏幕 | 常见的做法是创建一个 `imgui` 的 overlay window |

> **核心痛点**：外部读写由于与游戏独立，所以可能效果不太好容易脱框或者锁歪，这个问题很难解决，一般来讲只能依赖性能优化提高绘制帧率

当然本文最后不会使用这种用户态的方式，因为他们已经烂大街了。

#### 内部读写

这个比较特殊，和外部不同，它依赖将 DLL 注入进目标进程，直接操作目标的内存

| 步骤 | 核心动作 | 技术手段 |
| :--- | :--- | :--- |
| **1. 定位进程** | 获取游戏进程句柄 | N/A |
| **2. 寻找基址** | 找到模块基址（如 `client.dll` / `GameAssembly.dll`） | 可以通过 PEB 枚举也可以通过 API 获取 |
| **3. 偏移量扫描** | 通过签名扫描内存并根据 Pattern 提取 Offset | 同上 |
| **4. 读取/写入** | 跨进程读写内存 | 同上 |
| **5. 绘制** | 将数据绘制到屏幕 | Hook D3D/OpenGL渲染函数（如 `Present`/`EndScene`）在绘制结尾加上自己的内容 |

> **核心痛点**：内部读写虽然效果极其的好，因为它是和游戏本身同步进行的，但是 `注入 + Hook 渲染函数` 这个行为极其惹眼，隐蔽性很差劲

本文同样不会采用这种方式，它确实好用，但我决定放弃它寻找更好的ta...

### AI挂

AI挂是近几年因为深度学习成熟而迅速崛起的新流派。它的核心逻辑是：**完全不触碰游戏内存，仅依赖屏幕像素输入，模拟人眼识别与手部操作**。

它不需要 Hook 任何函数，也不需要自己寻找任何数，因此对传统的反作弊几乎完全免疫。

#### 历史

原谅我对 AI 挂的了解不是很深，但是就我的记忆来说 AI 挂第一次广泛出现大致是在 2022 年末一个叫《永劫无间》的游戏中。

怎么一个作弊法呢？先让我简单介绍一下这个游戏：

《永劫无间》这个游戏中玩家对抗大致可以理解为石头剪刀布的游戏，具体来说是振刀、蓄力和普攻。

在每一个动作触发之前都会出现一个醒目的颜色，比如振刀是红色、蓄力是蓝色。

就像这样：

![](https://img.halfcity.top/2026/08/08/03ef0d8c3446224a4a0c2d35e0cbcd81.avif)

在真正做出这个动作之前，你可以任意变招，而 AI 挂就是通过识别敌人的动作以及颜色并调用键盘按下指定按键实现博弈全胜。

而在这个时期其实 FPS 中似乎 AI 挂并没有十分兴盛，因为 AI 挂的功能很烂，唯一可以做到的就是锁头，远远不如内存挂强大。

但随着 AC 的发展，AI 挂可移植性强、开发较为简单、反 AC 能力较强的优势逐渐被认可，同时被应用到许多 FPS 游戏中，比如 《无畏契约》或者《三角洲行动》这类 AC 较强的游戏。

### 原理

大致如下：

1. 先捕获游戏画面 (采集卡 / OBS截屏 / DXGI截图)
2. 输入检测神经网络 (YOLO)
3. 输出敌人边界框 BBox [x, y, w, h] + 置信度
4. 逻辑决策
5. 鼠标控制输出，使用贝塞尔曲线模拟人手运行的轨迹
6. 游戏收到鼠标输入 → 准星锁定敌人

大致识别出来长这样：

![](https://img.halfcity.top/2026/08/08/da6613606b1ffbae1c6a5a5fcab2d0c1.avif)

AI 挂的数学核心在**神经网络的前向推理**：

- **卷积层**：提取画面中的边缘、纹理、形状特征（低层特征如“人的轮廓”）。
- **全连接层**：将特征图映射为 **边界框回归值**。损失函数通常使用 **CIoU Loss**（Complete Intersection over Union），它不仅计算框的重叠面积，还计算中心点距离和长宽比。
- **非极大值抑制（NMS）**：屏幕上可能出现多个重叠的预测框，NMS通过计算交并比（IoU）筛选出最优的那个框，这是一个纯粹的几何排序算法。

另外由于使用鼠标模拟会触发反作弊的输入行为分析，很多AI挂采用**物理层模拟**的方式逃避检测：

- **Arduino/STM32 USB HID**：计算完偏移量后，通过串口发给单片机，单片机模拟出真实的USB鼠标信号移动。
- 因为反作弊软件检查的是硬件驱动层的鼠标报文，这种物理信号与人工操作无法区分，极难被封禁。

### DMA

准确来说 DMA 应该属于内存挂的范围，但是我觉得它值得单独来说

为了绕过内核级反作弊（如EAC、BE、ACE等）对内存的检测，一些内存挂采用**DMA**：

- 利用PCIE设备（如FPGA开发板）直接读取物理内存总线上的数据，**完全不调用任何系统API**。
- 外挂程序运行在第二台电脑上，通过DMA板卡读取第一台电脑的RAM，游戏进程完全无感知，实现了物理级别的内存读取。

但是定制的 DMA 三件套往往价格高昂，而 AC 的目的本身就是提高作弊成本而不是 Ban 掉所有的作弊者，所以 AC 的任务也算是变相达成了？。

总之 DMA 的地位非常特殊，一般我们说的双机就是说的使用 DMA 读取一台机器的内存并在另一台机器分析数据。但本文在这里不会详细讲解它。

### AI挂与内存挂对比

| 对比维度 | 内存挂 | AI 挂 |
| :--- | :--- | :--- |
| **数据来源** | 进程内存 | 屏幕像素矩阵（RGB图像） |
| **核心算法/数学** | 指针运算、矩阵代数、欧几里得向量计算 | 深度学习、统计学 |
| **依赖对象** | 技术，强大的技术(确信) | 游戏画面（若换皮肤/地图，模型可能泛化失效） |
| **延迟** | 极低 | 较高（20~50ms） |
| **反作弊检测难度** | 看你实力 | **难**（完全不读写游戏内存，行为近似于人） |
| **硬件成本** | 无 | 高（需要独立GPU推理） |
| **信息维度** | 应有尽有| 仅二维像素和目标二维坐标信息 |

### 网络挂

这种类型的外挂比较特殊，也很少见。它通常是通过截获游戏的通信包来获取信息或者通过修改封包来实现网游的修改。

比如我记得不错，以前就有一件事故，一名职业选手购买了一个雷达挂，这个挂通过 `OpenWRT` 让路由器截获游戏同步坐标的数据的包，然后通过解析协议获取里面的坐标信息，实现了在不操作内存的前提下获取坐标信息的能力。

## 外挂的功能种类

世界之大无奇不有，不同的游戏通常来讲都会有一些独特的外挂。

不过细分一下还是能分出几个种类来，我将分类说说。

1. 对于 MMO 游戏：

这种游戏由于通常是强 Server 权威的，理论上作弊是极难的。

但是这类游戏老旧的技术弥补了这一点。如果 Server 校验不完全可能会有瞬移/加速挂。

不过这类游戏其实最多的还是各种图色脚本。

2. 对于 RPG 游戏：

一般到了现在我们说的就是那种大世界养成类的游戏啦，这类游戏的挂无非也是利用 Server 不会较真某些数据，导致外挂可以修改速度等属性实现快速获取养成资源，这里就不多说了。

3. 对于 FPS 游戏：

这里才是真正的外挂大区，实力不详，只有你想不到没有他做不到。

我将讲讲常见的几种

- 透视 - ESP：几种实现，要么是画框画骨骼，要么是调用游戏本身的某种发光透视类的操作，比如 CS2 死后敌人会发光，这个就可以利用上让他一直发光

- 自瞄 - Aimbot：修改玩家的 Angle 平滑地将中心移动到目标指定位置

- 静默自瞄/子弹追踪 - SilentAim：Hook 发包函数或者填充发包数据的函数，参考 Aimbot 将数据修改为指向目标的指定位置

- 魔法子弹 - MagicBullet：由于 Server 不够权威，可以 Hook 子弹生成函数，将子弹直接生成在目标的头里面

- 自动扳机 - Triggerbot：通过人物 flag 或者射线检测函数判断前方是否是玩家，如果是则控制开火

- 快速射击 - RapidFire：由于 Server 不够权威，可以修改枪械射击冷却实现连续射击

- 大陀螺 - Spinbot：Hook 发包函数或者填充发包数据的函数，参考 SilentAim 将 Angle 数据快速修改实现在敌人视角中快速旋转但本地视角不变的效果

- 雷达 - Radar：将实体投影到二维平面并绘制到表盘上

- 加速 - Speed：由于 Server 不够权威，可以修改人物移速

有一些变态的功能不好归类，这个就是发挥想象力的地方了，比如让舰艇上岸创人、坦克飞天、自动重新部署、强制敌人开枪就切换匕首、强制敌人开枪就换弹、自动振刀、寻宝鼠、暴风吸入神瞳等等，这些都是游戏特色的功能。

类似的奇怪的挂应该还有一些，这里就不一一列举了。

接下来我们准备步入正题了。

> [!NOTE]
> 看这里！这里有一些小 Tip
>
> 如果你看到了这里感觉一头雾水，没关系下面的内容会更清晰一点，但是如果你对里面大多数词都极其陌生，我其实并不推荐你往下阅读，因为你可能缺少了基本 Win32 API 的了解或者是游戏安全相关的经验
>
> 限于篇幅，我不可能将每一个字词都解释一遍，并且接下来的内容会不断深入，如果没有相关的认知可能会感觉越来越难，但是不必担心我会尽力说明白的。不过当你看到某一个部分感觉很晦涩时我其实更建议你去补充一下相关的知识，因为这样体验也许会更好些...
>
> 出于观感考虑，这个建议不会在下文再出现，你可以自行体会内容是否适合你 @w@
>
> 如果是大佬就当没看见吧

## ESP 基础理论

想要画框？总是感觉很难？但是其实画一个 Box 只需要三个东西就好了：

1. 视角矩阵基址
2. 实体列表基址
3. 人物坐标偏移

我将详细解释这三个概念。

### 基址与偏移

> 无论是做游戏修改、逆向工程，还是调试程序崩溃，**基址（Base Address）** 与 **偏移量（Offset）** 都是绕不开的核心概念。
>
> 如果把计算机内存比作一座巨大的城市，那么**基址就是“街道名”**，而**偏移量就是“门牌号”**。两者结合，才能精确定位到我们想要访问的数据。

这里我们在外挂领域说的基址和一般而言的基址的含义不太一样，让我来解释一下。

#### 基址的定义 - Base

**基址**是指一个模块（如 `.exe` 可执行文件或 `.dll` 动态链接库）被操作系统加载到进程内存空间时的**起始地址**。

为什么需要基址？

程序编译后，代码和全局变量通常被安排在一个固定的**建议地址**。但在现代操作系统中，由于 **ASLR** 的存在，系统每次启动程序时，都会随机分配一个加载基址，以防止恶意代码的攻击。

- **静态地址（绝对地址）**：如 `0x00A1B2C3`。
- **基址（动态起点）**：如 `game.exe + 0x1000`。

> 我们一般说的基址就是这个全局变量相对于一个模块基址的偏移，我们将他称为这个全局变量的基址

**关键点**：基址是运行时确定的。程序每次重启，基址都会变。

#### 偏移的定义 - Offset

**偏移**是指**目标数据**相对于某个**基址**的**距离**（字节数）。

偏移量的特点：

- 在程序本身不变的前提下，偏移量是**固定的**。
- 无论程序重启多少次，基址如何变化，从基址到目标数据的距离（偏移）永远不会改变（除非程序版本更新导致结构变化）。

而我们一般说的偏移是指一个结构体成员相对于结构体头部的偏移量，这对于定位该成员的位置很重要！

#### 一般用法

目标数据的内存地址 = 模块基址（Module Base） + 偏移量（Offset）

举个例子：

假设我们想读取当前人物的血量：

模块基址：`Naraka.exe` 被系统加载到了 `0x7FF612340000`。

全局基址偏移：`Naraka.exe + 0x05C8A910` 这个地址里，存放着“人物对象管理器”的指针。

嵌套偏移：管理器地址 + 0x20 -> 指向玩家对象；玩家对象 + 0x02C -> 指向血量数值。


很多时候，我们看到的写法并不是简单的 基址 + 1个偏移，而是多层嵌套，例如：

```txt
[[Base + 0x10] + 0x04] + 0x08 = Value
```

这是因为这个结构体较为复杂所以有一个很长的指针链。

通俗理解：

基址是 “藏宝图”上的起点。

第一层偏移找到了 “埋着箱子的具体地点”。

第二层偏移找到了 “箱子里夹层的密码”。

但准确来说，每一个偏移处的指针可能都有很多作用，因为他们可能都是一些重要的组件。

#### 怎么找到基址和偏移？

这里使用 CE 为例：

寻找基址：

首次扫描数值（如血量 100）。

改变血量（受伤/吃药），再次扫描。

找到内存地址后，点击`查找什么访问了这个地址`。

CE 会记录下访问的指令，显示类似的指令：

```asm
mov eax, [esi + 0x2C]
```

这里其实就可以看出来，`0x2C` 就是 `m_iHealth` 偏移量，而 esi 中存放的其实就是我们熟悉的 `this`，也就是当前实例的地址。

向上追溯 esi 寄存器的来源，最终找到类似 `[[game.exe + 0x5C8A910] + 0x20] + 0x2C` 的结构。

使用 CPP 来举一个例子：

```cpp
// 获取模块基址
DWORD64 moduleBase = (DWORD64)GetModuleHandleA("client.dll");

// 读取一级指针
DWORD64 ptrAddress = moduleBase + 0x1000;
DWORD64 objAddress = 0;
ReadProcessMemory(hProcess, (LPCVOID)ptrAddress, &objAddress, sizeof(DWORD64), NULL);

// 读取第二级偏移
DWORD64 targetAddress = objAddress + 0x200;
int health = 0;
ReadProcessMemory(hProcess, (LPCVOID)targetAddress, &health, sizeof(int), NULL);

std::cout << "当前血量: " << health << std::endl;
return 0;
```

不过需要注意的是，注意后面用户态实际的代码我将使用 `rust` 编写。

#### 小结

基址和偏移量是通往内存世界的经纬度。

基址是根基（动态的起点），由操作系统分配。

偏移量是路径（固定的距离），由编译器/开发者结构决定。

#### 注

可能你会疑惑

> 要是开发者很变态，什么东西都不放全局，那么是不是就没招了？

首先就不太可能会出现这个极端的情况，其实即便是真的出现了，我们也有很好的解决方案。

比如我之前遇到过一个 Unity 游戏叫逃离鸭科夫，它就是这种特别的类型，它不维护一个实体列表，而是维护一个生成器，根据场景生成不同的 AI 小队，并且这个生成器也不是 `static` 的。

如果每次都动态去查找生成器实例，解析怪物组，再解析小队，最后遍历添加实体，这看着就不是一个很好的主意。

那么我的解决办法是什么？

虽然实例散布各处，但是他们都是继承于一个基类，而调用非 static 的方法都需要传入自己的 `this`，而 `this` 不正是我们想要的东西吗？

> 通过 Hook 目标类虚表中的函数，我们可以通过 `this` 手动维护一个实体列表。在实例初始化函数处将他加入我们的列表，并在目标实例的 Destory() 方法被调用时将他从我们的列表中移除

我通过这个方式优雅地实现了一个人造的实体列表。

![](https://img.halfcity.top/2026/08/08/663a4a1e3df49ceee5bef1ace8ed573d.avif)

看起来不错对吧？

同样的，假如视角矩阵不是全局的怎么办？视角矩阵总是要被调用的，而且他的地址不可能持续变化，最次也是动态在堆中，所以通过 Hook 相关函数，提取参数，一样可以获取视角矩阵当前的地址。

可以说这种开发层面试图给外挂使绊子的行为，往往都是没什么实际作用的 @w@

反外挂就应该依赖专业的 AC 才对。

在后面我会详细地讲解现在提到的几个概念。

### 视角矩阵 - dwViewMatrix

> [!NOTE]
> 如果你对这里具体的数学原理不太感兴趣，那么你可以直接跳过，这不会对后面的开发有什么大的影响哒，只要你记住这个是做什么的就行

#### 简介

矩阵是一个很重要的东西，它会被游戏引擎使用用于向量的变换，通常在一般的游戏引擎中比如 Unity 中会存在这样一个函数 `WorldToScreenPoint`。

在游戏中，`WorldToScreenPoint` 它的任务非常简单直观：**将游戏世界中的任意三维坐标（X, Y, Z）转换为屏幕上的二维像素坐标（X, Y）**，同时通常还会返回一个深度值（Z）。

而它依赖的就是我们说的这个矩阵。

对于我们而言，其实就是需要用到它将人物三维的向量投影为窗口中的二维向量。

接下来让我们看看它的原理。

#### 变换

整体流程如下：

在标准的图形渲染管线中，一个三维顶点要精准地显示在屏幕上，必须依次经历以下**五个坐标空间**的变换：

| 空间名称 | 坐标形式 | 核心意义 |
| :--- | :--- | :--- |
| **世界空间** (World Space) | 齐次坐标 $ (x, y, z, 1) $ | 游戏逻辑中的绝对位置 |
| **视图空间** (View Space) | 齐次坐标 $ (x, y, z, 1) $ | 以摄像机为原点、视线为轴向的观察坐标 |
| **裁剪空间** (Clip Space) | 齐次坐标 $ (x_c, y_c, z_c, w_c) $ | 应用投影矩阵后的齐次坐标，$ w_c \neq 1 $ |
| **NDC空间** (Normalized Device Coordinates) | 三维向量 $ (x_{ndc}, y_{ndc}, z_{ndc}) $ | 范围在 $ [-1, 1] $ 的抽象立方体 |
| **屏幕空间** (Screen Space) | 二维像素 $ (u, v) $ + 深度 $ d $ | 实际显示器上的像素位置 |

`WorldToScreenPoint` 的本质就是一次性走完这条流水线。

#### 数学推导

设世界坐标为齐次向量 $ P_{world} = (x_w, y_w, z_w, 1)^T $。整个变换链可以浓缩为以下公式：

$$
P_{screen\_hom} = M_{viewport} \cdot M_{proj} \cdot M_{view} \cdot P_{world}
$$

为了深刻理解，我们将其拆解为四步，并展开每一个矩阵的内部构造。

1. 世界空间 $ \rightarrow $ 视图空间（View Matrix）

摄像机的本质是定义了新的坐标系原点 $ \mathbf{eye} $ 和三个正交轴（右轴 $ \mathbf{r} $、上轴 $ \mathbf{u} $、视轴 $ \mathbf{f} $）。观察矩阵 $ M_{view} $ 的作用是将世界坐标系“搬到”摄像机坐标系下。它是一个**刚体变换的逆矩阵**：

$$
M_{view} = \begin{bmatrix}
r_x & r_y & r_z & -\mathbf{r} \cdot \mathbf{eye} \\
u_x & u_y & u_z & -\mathbf{u} \cdot \mathbf{eye} \\
f_x & f_y & f_z & -\mathbf{f} \cdot \mathbf{eye} \\
0 & 0 & 0 & 1
\end{bmatrix}
$$

经过该矩阵后，我们得到视图坐标 $ P_{view} = (x_v, y_v, z_v, 1)^T $，其中 $ z_v $ 表示物体距离摄像机的深度（在右手系中，物体在摄像机前方时 $ z_v < 0 $）。

2. 视图空间 $ \rightarrow $ 裁剪空间（Projection Matrix）

这是最关键的一步。我们需要将视锥体（Frustum）映射到齐次裁剪立方体。我们采用**透视投影矩阵**（我们要找的也是这个），其标准形式为（假设对称视锥体，使用OpenGL风格NDC，且摄像机看向 $ -Z $ 轴）：

设：

- $ fov $：垂直视场角（Field of View）
- $ aspect $：屏幕宽高比 $ \frac{width}{height} $
- $ n $：近裁剪面距离（> 0）
- $ f $：远裁剪面距离（> 0）

构造透视投影矩阵 $ M_{proj} $：

$$
M_{proj} = \begin{bmatrix}
\frac{1}{\tan(fov/2) \cdot aspect} & 0 & 0 & 0 \\
0 & \frac{1}{\tan(fov/2)} & 0 & 0 \\
0 & 0 & \frac{-(f+n)}{f-n} & \frac{-2fn}{f-n} \\
0 & 0 & -1 & 0
\end{bmatrix}
$$

将视图坐标代入，得到裁剪空间坐标 $ P_{clip} = (x_c, y_c, z_c, w_c)^T $：

$$
\begin{cases}
x_c = \frac{1}{\tan(fov/2) \cdot aspect} \cdot x_v \\
y_c = \frac{1}{\tan(fov/2)} \cdot y_v \\
z_c = \frac{-(f+n)}{f-n} \cdot z_v + \frac{-2fn}{f-n} \cdot 1 \\
w_c = - z_v
\end{cases}
$$

> **注意此处**：$ w_c $ 不再恒等于 1，而是等于 $ -z_v $（观察空间下的深度）。这正是**射影变换**的精髓——将深度信息编码进齐次坐标的缩放因子中，为下一步的透视除法做准备。

3. 裁剪空间 $ \rightarrow $ NDC

GPU 在光栅化之前，会自动对每个顶点执行一步**透视除法**，将齐次坐标归一化：

$$
P_{ndc} = \begin{pmatrix}
x_{ndc} \\
y_{ndc} \\
z_{ndc}
\end{pmatrix} =
\begin{pmatrix}
\frac{x_c}{w_c} \\
\frac{y_c}{w_c} \\
\frac{z_c}{w_c}
\end{pmatrix}
$$

展开来看，真正的 `近大远小` 效果在此刻发生：

$$
x_{ndc} = \frac{x_c}{-z_v} = \frac{x_v}{-z_v \cdot \tan(fov/2) \cdot aspect}
$$

由于远处物体的 $ -z_v $ 较大，其 $ x_{ndc} $ 和 $ y_{ndc} $ 就会被压缩得更小，完美模拟了人眼的透视效果。

此时，坐标被映射到了 $ [-1, 1] $ 的立方体内。若任意分量的绝对值大于 1，则该点在视锥体外，将被裁剪掉。

4. NDC $ \rightarrow $ 屏幕空间

最后一步是将 $ [-1, 1] $ 的抽象坐标映射到具体的像素矩阵上。设屏幕宽为 $ W $，高为 $ H $：

$$
\begin{aligned}
u &= \frac{(x_{ndc} + 1) \cdot W}{2} \\
v &= \frac{(1 - y_{ndc}) \cdot H}{2} \quad (\text{注意：屏幕坐标系 } y \text{ 轴向下，故取反}) \\
d &= z_{ndc} \quad (\text{或映射到 } [0, 1] \text{ 区间，用于深度缓冲})
\end{aligned}
$$

将上述公式整合为视口变换矩阵 $M_{viewport} $（齐次形式）：

$$
M_{viewport} = \begin{bmatrix}
\frac{W}{2} & 0 & 0 & \frac{W}{2} \\
0 & -\frac{H}{2} & 0 & \frac{H}{2} \\
0 & 0 & \frac{1}{2} & \frac{1}{2} \\
0 & 0 & 0 & 1
\end{bmatrix}
$$

#### 代数表达

将上述所有步骤合并，`WorldToScreenPoint` 的完整数学本质是：

$$
\boxed{
\begin{pmatrix}
u \\
v \\
d \\
1
\end{pmatrix}
=
\begin{bmatrix}
\frac{W}{2} & 0 & 0 & \frac{W}{2} \\
0 & -\frac{H}{2} & 0 & \frac{H}{2} \\
0 & 0 & \frac{1}{2} & \frac{1}{2} \\
0 & 0 & 0 & 1
\end{bmatrix}
\cdot
\begin{bmatrix}
\frac{1}{\tan(fov/2) \cdot aspect} & 0 & 0 & 0 \\
0 & \frac{1}{\tan(fov/2)} & 0 & 0 \\
0 & 0 & \frac{-(f+n)}{f-n} & \frac{-2fn}{f-n} \\
0 & 0 & -1 & 0
\end{bmatrix}
\cdot
M_{view}
\cdot
\begin{pmatrix}
x_w \\
y_w \\
z_w \\
1
\end{pmatrix}
}
$$

其中，透视除法隐含在从裁剪空间到 NDC 的过程中，必须发生在视口矩阵应用**之前**。

#### 代码实现

投影：

```rust
fn project_column(&self, world: Vector3, screen_w: f32, screen_h: f32) -> Option<Vector2> {
    if !world.is_valid() {
        return None;
    }

    let x = world.x;
    let y = world.y;
    let z = world.z;

    // clip = VP * world（列优先）
    let clip_x = self.m[0][0]*x + self.m[1][0]*y + self.m[2][0]*z + self.m[3][0];
    let clip_y = self.m[0][1]*x + self.m[1][1]*y + self.m[2][1]*z + self.m[3][1];
    let clip_w = self.m[0][3]*x + self.m[1][3]*y + self.m[2][3]*z + self.m[3][3];

    // 背面剔除
    if clip_w <= 0.0 { return None; }

    // NDC
    let ndc_x =  clip_x / clip_w;
    let ndc_y = -clip_y / clip_w;

    // 屏幕坐标
    Some(Vector2 {
        x: (ndc_x + 1.0) * 0.5 * screen_w,
        y: (ndc_y + 1.0) * 0.5 * screen_h,
    })
}

fn project_row(&self, world: Vector3, screen_w: f32, screen_h: f32) -> Option<Vector2> {
    if !world.is_valid() {
        return None;
    }

    let x = world.x;
    let y = world.y;
    let z = world.z;

    // clip = M * world（行优先：m[row][col]）
    let clip_x = self.m[0][0]*x + self.m[0][1]*y + self.m[0][2]*z + self.m[0][3];
    let clip_y = self.m[1][0]*x + self.m[1][1]*y + self.m[1][2]*z + self.m[1][3];
    let clip_w = self.m[3][0]*x + self.m[3][1]*y + self.m[3][2]*z + self.m[3][3];

    if clip_w <= 0.0 { return None; }

    let ndc_x =  clip_x / clip_w;
    let ndc_y =  clip_y / clip_w; // Source 矩阵 Y 已是屏幕方向，不需要取负

    Some(Vector2 {
        x: (1.0 + ndc_x) * 0.5 * screen_w,
        y: (1.0 - ndc_y) * 0.5 * screen_h, // NDC Y 向上 → 屏幕 Y 向下
    })
}
```

WorldToScreenPoint 实现：

```rust
pub fn world_to_screen(&self, world: Vector3, screen_w: f32, screen_h: f32) -> Option<Vector2> {
    if !self.is_valid() { return None; }

    let matrix = self.matrix.read::<Matrix4x4>(0).unwrap();

    matrix.project_row(world, screen_w, screen_h)
}
```

#### 内存表现

可能有人会想问：

> 道理我都懂，但是这个东西实际长什么样子呢？

实际上它的特征非常明显！就长这个样子：

![](https://img.halfcity.top/2026/08/08/d8f08d3fe9b6eaf9a63d3aa682ffd8cc.avif)

可能有点糊，这是我从我之前录的视频里截的，CE 当时调的比较小，将就看。

但依旧可以看见它明显的坐标分量之类的特征。

一般来讲这个是 VP 矩阵，所以 V 矩阵和 P 矩阵会在它上面，这也是一个明显的特征。

> 我要是就是不认识这个矩阵怎么办？

这个确实没办法，就好像你一定要把钻石当玻璃一样，只能说多见几次肯定就认识了。

### 坐标偏移 - m_vecAbsOrigin

这个现在就很好解释了，就是为了获取人物的世界坐标。

然后通过矩阵将这个世界坐标转换为平面的坐标。

由于上面的内容基本已经将这个概念彻底解释了，所以我在这里不对这个东西本身做什么解释。

> 但这里强调一下，坐标很重要，它描述了一个物体在空间中的位置，同样的血量描述了一个物体在空间中的存活状态，也很重要。所以在一些游戏中这些字段的值会被加密，只有在需要时才会调用解密函数解密

### 实体列表 - dwEntityList

在人物本身之外，另一个更加基础且关键的概念就是**实体列表**。

无论是游戏引擎的渲染循环、物理碰撞检测，还是外挂的各种功能，一切的起点都是**找到场景中所有的对象**。

所以实体列表很重要。

下面让我简单介绍一下相关概念。

#### 实体

在不同的游戏引擎中，`实体` 有不同的术语，但本质相同：

| 引擎/术语 | 官方名称 | 定义 |
| :--- | :--- | :--- |
| **Unreal Engine** | `AActor` | 所有可以放置在世界场景中的对象的基类（玩家、敌人、子弹、触发器） |
| **Unity** | `GameObject` | 场景中所有实例的基类，通过挂载 `Component` 来扩展功能 |
| **自定义引擎** | `Entity` | 通常指代带有唯一 ID 和位置/旋转/缩放的游戏对象 |

如在 `CS2` 玩家实体类叫 `C_CSPlayerPawn` 玩家实体 Controller 类叫 `C_CSPlayerController`

> **核心定义**：实体是游戏世界中**动态或静态交互对象**的抽象封装。它通常包含：
> - **变换组件**：位置 `(X,Y,Z)`、旋转、缩放。
> - **状态属性**：血量、阵营、是否存活、速度。
> - **逻辑组件**：AI控制器、物理刚体、渲染网格（Mesh）。

#### 实体列表的类型

游戏引擎需要在每一帧高效地遍历、查找、增删这些实体。

因此，**数据结构的选择直接影响游戏性能**。

1. 传统 OOP 架构：动态数组

在 UE4/UE5 和传统的 Unity 项目中，实体列表通常以 **动态数组** 的形式存储在内存中。

- **Unreal Engine**：`UWorld` 对象内包含 `TArray<AActor*> LevelActors`。
- **Unity**：通过 `FindObjectsOfType()` 返回一个缓存数组。

优点：缓存友好，遍历速度快。

缺点：中间插入/删除成本高（O(n) 移动内存），但游戏通常采用 `标记删除`（将无效指针置空，后续统一清理）来规避此问题。

2. 现代 ECS 架构：结构体数组

为了追求极致性能，现代引擎开始采用 ECS（Entity-Component-System）架构。

在 ECS 中，`实体` 本身只是一个 64 位的整数 ID，数据与逻辑完全分离。

所有实体的位置、旋转等属性被拆开，存入独立的连续数组中。

对于传统架构，遍历时，CPU 缓存同时加载位置和血量，若只需位置则浪费带宽。

对于现代架构，遍历时仅加载位置数组，完美命中 CPU Cache。

> ECS 使得外挂开发更难，因为不再有一个集中的 Actor* 数组。

不过 ECS 的应用目前真的很少...

3. 链表与哈希集

链表：早期游戏（如CSGO）使用双向链表管理实体，便于动态增删，但遍历时产生大量Cache Miss，现代引擎已抛弃。

哈希集：用于快速通过 EntityID 查询实体，但不会作为主遍历列表使用。

#### 实体列表定位

绝大多数引擎会在全局静态区或模块的 `.data` 段中存储一个单例指针。

如：

```
UE4/UE5：GWorld -> PersistentLevel -> Actors。
```

Unity（Mono/IL2CPP）：虽然没有全局 GWorld，但通过 Object.FindObjectsOfType 的底层实现，可以定位到 UnityEngine.Object 的全局对象缓存表。

#### 可见性剔除与网格划分

仅仅拿到实体列表还不够，游戏不能每帧渲染几百公里外的敌人。实体列表常常与空间加速结构结合：

- 视锥体剔除（Frustum Culling）：利用 WorldToScreenPoint 返回的深度值，先计算实体是否在摄像机的平截头棱椎体（Frustum）内。若 NDC.x 或 NDC.y 超出 [-1.1, 1.1]，则跳过后续绘制逻辑，节省GPU开销。
- 网格划分（Spatial Hashing / Octree）：大型开放世界不会遍历整个世界的所有实体，而是将地图划分为 Cell（网格单元）。实体列表被分散到各个网格中，玩家只需遍历自己所在网格及相邻网格的实体。

> 这里针对具体场景补充一下，对于大型开放世界的游戏（如创造与魔法、英灵神殿、原神），通常而言实体列表中只会有少量的实体，在足够远处的可能实体引擎不会实际加载他们，因为加载他们没有任何实际作用

> [!NOTE]
> 这里再提一嘴，对于一些在线游戏比如一些 FPS 游戏，实体的数据是 Server 同步而来的，所以有时 Server 会拒绝给你同步一些实体的数据。
>
> 比如 CS2 中当某个实体的位置不在你人物的视野角内时，Server 就不会将这个实体的信息同步给你。
>
> CSGO 中也有类似的逻辑，不过有点不一样，它会同步视野角外的实体，但它只会持续同步本地人物周围的实体，远处的实体不会同步

所以实体列表这个东西没有那么固定的做法，不同的游戏需要不同地分析。

至此，理论部分结束。

## ESP 编写规划

> 太好了！现在我们有了充足的理论知识，现在让我们开始实际地操作吧！

首先我们需要先规划一下我们的架构，这决定了我们后续的开发方向。

### 读写方案

我在这类选择了外部内存读写的方式，即使它缺点再多，也抵不住它的隐蔽性确实极具实战意义，不是吗？

### 架构

这里我准备的是三段进行协同：

- Sparkle：作为驱动，在内核提供底层的 Hook 和内存访问方式
- Aurora：一个 GUI，用于创建 overlay 并负责后续的绘制工作
- OmniARK： 一个 ARK 工具，负责将 Aurora 保护好

话不多说，开始吧！

首先我们需要先完成我们的 GUI，这个是基本。

## GUI

我准备使用 `Tauri + React` 来完成这个 GUI，这里不会贴大量的

### Overlay

Overlay 是绘制的基础，这里要感谢这个项目[1]，帮助我实现了 Overlay 的创建。

接下来我将分别给出相关的代码并说说他们的作用，这里给出我的 Overlay 的实现。

#### d3d

```rs
pub struct D3d11Render {
    pub p_swap_chain: IDXGISwapChain,
    pub pd3d_device: ID3D11Device,
    pub pd3d_device_context: ID3D11DeviceContext,
    pub p_main_render_target_view: Option<ID3D11RenderTargetView>,
}

impl D3d11Render {
    /// 绑定到窗口
    pub fn bind(hwnd: HWND) -> Result<D3d11Render> {
        let sd = DXGI_SWAP_CHAIN_DESC {
            BufferCount: 2,
            BufferDesc: DXGI_MODE_DESC {
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                RefreshRate: DXGI_RATIONAL {
                    Numerator: 60,
                    Denominator: 1,
                },
                ..DXGI_MODE_DESC::default()
            },
            Flags: DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH.0 as _,
            BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            OutputWindow: hwnd,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Windowed: TRUE,
            SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
            ..DXGI_SWAP_CHAIN_DESC::default()
        };
        let mut feature_level = D3D_FEATURE_LEVEL::default();
        let feature_level_array = [D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0];
        let (p_swap_chain, pd3d_device, pd3d_device_context) = unsafe {
            let mut p_swap_chain = MaybeUninit::uninit();
            let mut pd3d_device = MaybeUninit::uninit();
            let mut pd3d_device_context = MaybeUninit::uninit();
            if D3D11CreateDeviceAndSwapChain(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE(0 as _),
                D3D11_CREATE_DEVICE_FLAG(0),
                Some(&feature_level_array),
                D3D11_SDK_VERSION,
                Some(&sd),
                Some(p_swap_chain.as_mut_ptr()),
                Some(pd3d_device.as_mut_ptr()),
                Some(&mut feature_level),
                Some(pd3d_device_context.as_mut_ptr()),
            )
                .is_err()
            {
                D3D11CreateDeviceAndSwapChain(
                    None,
                    D3D_DRIVER_TYPE_WARP,
                    HMODULE(0 as _),
                    D3D11_CREATE_DEVICE_FLAG(0),
                    Some(&feature_level_array),
                    D3D11_SDK_VERSION,
                    Some(&sd),
                    Some(p_swap_chain.as_mut_ptr()),
                    Some(pd3d_device.as_mut_ptr()),
                    Some(&mut feature_level),
                    Some(pd3d_device_context.as_mut_ptr()),
                )?
            }
            (
                p_swap_chain.assume_init().unwrap(),
                pd3d_device.assume_init().unwrap(),
                pd3d_device_context.assume_init().unwrap(),
            )
        };
        let p_main_render_target_view = unsafe {
            let result: ID3D11Resource = p_swap_chain.GetBuffer(0)?;
            let mut p_main_render_target_view = MaybeUninit::uninit();
            pd3d_device.CreateRenderTargetView(
                &result,
                None,
                Some(p_main_render_target_view.as_mut_ptr()),
            )?;
            p_main_render_target_view.assume_init().unwrap()
        };
        Ok(D3d11Render {
            p_swap_chain,
            pd3d_device,
            pd3d_device_context,
            p_main_render_target_view: Some(p_main_render_target_view),
        })
    }

    pub fn create_render_target(&mut self) -> Result<()> {
        unsafe {
            let result: ID3D11Resource = self.p_swap_chain.GetBuffer(0)?;
            let mut p_main_render_target_view = MaybeUninit::uninit();
            self.pd3d_device.CreateRenderTargetView(
                &result,
                None,
                Some(p_main_render_target_view.as_mut_ptr()),
            )?;
            self.p_main_render_target_view = Some(p_main_render_target_view.assume_init().unwrap());
            Ok(())
        }
    }

    /// 清理渲染目标
    pub fn cleanup_render_target(&mut self) {
        if self.p_main_render_target_view.is_some() {
            self.p_main_render_target_view = None;
        }
    }
}

```

这里的逻辑很简单，就是**初始化 DirectX 11 渲染设备，并准备好用于绘制的后台缓冲区。**

这个文件暴露了一个 `D3d11Render` 结构体，保存以下内容：

- **`ID3D11Device`**：资源创建工厂（用来生成纹理、缓冲等）。
- **`ID3D11DeviceContext`**：执行命令的上下文（下发 Draw Call 的地方）。
- **`IDXGISwapChain`**：交换链（负责把画好的后台缓冲区翻转到屏幕上）。

`bind()` 函数：

1.  **构造交换链描述**：设置双缓冲和 32 位颜色格式。
2.  **创建设备**：调用 `D3D11CreateDeviceAndSwapChain`。如果硬件渲染（`D3D_DRIVER_TYPE_HARDWARE`）初始化失败，它会自动降级为 WARP（软件模拟渲染）。
3.  **获取渲染目标**：从交换链后台缓冲区中创建 `RenderTargetView`。

当游戏窗口拉伸时，覆盖层也必须跟着变。`create_render_target` 和 `cleanup_render_target` 这对函数专门负责在窗口尺寸变化（`WM_SIZE`）时，无痛重建渲染目标，避免绘制撕裂或黑屏。

#### tracker

```rs
pub static mut WINDOWS_RECT: Rect = Rect { width: 0, high: 0 };

pub struct Rect {
    pub width: i32,
    pub high: i32,
}

#[allow(dead_code)]
pub enum OverlayTarget {
    Window(HWND),
    WindowTitle(String),
    WindowOfProcess(u32),
}

impl OverlayTarget {
    pub(crate) fn resolve_target_window(&self) -> Result<HWND> {
        Ok(match self {
            Self::Window(hwnd) => *hwnd,
            Self::WindowTitle(title) => unsafe {
                FindWindowW(
                    PCWSTR::null(),
                    PCWSTR::from_raw(HSTRING::from(title).as_ptr()),
                )
                    .expect(format!("窗口({})句柄获取失败", title).as_str())
            },
            Self::WindowOfProcess(process_id) => {
                const MAX_ITERATIONS: usize = 1_000_000;
                let mut iterations = 0;
                let mut current_hwnd = HWND::default();
                while iterations < MAX_ITERATIONS {
                    iterations += 1;
                    current_hwnd =
                        unsafe { FindWindowExA(None, Some(current_hwnd), None, None)? };
                    if current_hwnd.0 as i32 == 0 {
                        break;
                    }
                    let mut window_process_id = 0;
                    let success = unsafe {
                        GetWindowThreadProcessId(current_hwnd, Some(&mut window_process_id)) != 0
                    };
                    if !success || window_process_id != *process_id {
                        continue;
                    }

                    let mut window_rect = RECT::default();
                    let success = unsafe { GetWindowRect(current_hwnd, &mut window_rect) };
                    if !success.is_ok() {
                        continue;
                    }

                    if window_rect.left == 0
                        && window_rect.bottom == 0
                        && window_rect.right == 0
                        && window_rect.top == 0
                    {
                        continue;
                    }

                    return Ok(current_hwnd);
                }

                Default::default()
            }
        })
    }
}

pub struct WindowTracker {
    pub hwnd: HWND,
    pub current_bounds: RECT,
}

impl WindowTracker {
    /// 跟踪窗口
    #[allow(dead_code)]
    pub fn update(&mut self, hwnd: HWND) -> bool {
        let mut rect: RECT = Default::default();
        let success = unsafe { GetClientRect(self.hwnd, &mut rect) };
        if success.is_err() {
            let error = unsafe { GetLastError() };
            if error == ERROR_INVALID_WINDOW_HANDLE {
                return false;
            }
            return true;
        }

        unsafe {
            let _ = ClientToScreen(self.hwnd, &mut rect.left as *mut _ as *mut POINT);
            let _ = ClientToScreen(self.hwnd, &mut rect.right as *mut _ as *mut POINT);
        }

        if unsafe { GetFocus() } != self.hwnd {
            rect.bottom -= 1;
        }

        if rect == self.current_bounds {
            return true;
        }

        self.current_bounds = rect;
        let width = rect.right - rect.left;
        let high = rect.bottom - rect.top + 1;
        unsafe {
            WINDOWS_RECT.width = width;
            WINDOWS_RECT.high = high;
        }
        unsafe {
            let _ = MoveWindow(
                hwnd, rect.left, rect.top, width, high,
                false, // Don't do a complete repaint (may flicker)
            );
            // Request repaint, so we acknoledge the new bounds
            SendMessageA(hwnd, WM_PAINT, WPARAM::default(), LPARAM::default());
        }
        true
    }

    /// 跟踪窗口，每调用一次会对目标窗口进行跟踪
    #[allow(dead_code)]
    pub fn tracking(&mut self, hwnd: HWND) -> bool {
        let mut rect = RECT::default();
        unsafe {
            let _ = GetClientRect(self.hwnd, &mut rect);
            let _ = ClientToScreen(self.hwnd, &mut rect.left as *mut _ as *mut POINT);
        }
        if !unsafe { IsWindow(Some(self.hwnd)).as_bool() } {
            return false;
        }
        if self.current_bounds == rect {
            return true;
        }
        self.current_bounds = rect;
        unsafe {
            let _ = SetWindowPos(
                hwnd,
                None,
                rect.left,
                rect.top,
                rect.right,
                rect.bottom,
                windows::Win32::UI::WindowsAndMessaging::SWP_SHOWWINDOW,
            );
        }
        true
    }
}
```

画如果覆盖层窗口不动，而游戏窗口移动了，那画面就错位了，所以需要一个东西来定位，`tracker` 就是负责**动态追踪目标窗口位置**的定位仪。

`WindowTracker` 结构体持有的 `tracking()` 函数会在每一帧被调用：

- 它通过 `GetClientRect` 拿到游戏窗口的客户区（去除边框的纯净绘制区域）。
- 利用 `ClientToScreen` 将客户区坐标转换为屏幕绝对坐标。
- 一旦发现当前边界（`RECT`）与上一帧记录的不一致，立即调用 `MoveWindow` 或 `SetWindowPos` 强制把 Overlay 窗口挪过去。

#### imgui

```rs
lazy_static! {
    static ref GLOBAL_DATA: Mutex<Option<D3d11Render>> = Mutex::new(None);
}

#[macro_export]
macro_rules! loword {
    ($uint:expr) => {
        $uint & 0xFFFF
    };
}

#[macro_export]
macro_rules! hiword {
    ($uint:expr) => {
        ($uint >> 16) & 0xFFFF
    };
}
#[macro_export]
macro_rules! rgb {
    ($r:expr,$g:expr,$b:expr) => {
        (($b as u32) << 16) | (($g as u32) << 8) | ($r as u32)
    };
}

extern "C" {
    /// imgui初始化win32
    fn ImGui_ImplWin32_Init(hwnd: *const c_void) -> bool;
    /// 初始化dx11
    fn ImGui_ImplDX11_Init(device: *mut ID3D11Device, ctx: *mut ID3D11DeviceContext) -> bool;
    /// imgui循环事件处理
    fn ImGui_ImplWin32_WndProcHandler(
        hwnd: *const c_void,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT;

    fn ImGui_ImplDX11_NewFrame();
    fn ImGui_ImplWin32_NewFrame();

    fn ImGui_ImplDX11_RenderDrawData(draw_data: *const DrawData);

    fn ImGui_ImplDX11_Shutdown();
    fn ImGui_ImplWin32_Shutdown();
    fn ImGui_ImplWin32_EnableDpiAwareness();
    /// 隐藏边框
    fn ImGui_ImplWin32_EnableAlphaCompositing(hwnd: *const c_void);
    fn ImGui_ImplWin32_GetDpiScaleForMonitor(monitor: *const c_void) -> f32;
}

pub struct FrameRate(u32);

#[allow(dead_code)]
impl FrameRate {
    /// 屏幕同步
    pub const SYNC_SCREEN: FrameRate = FrameRate(1);
    /// 无限制
    pub const UN_LIMITED: FrameRate = FrameRate(0);
}

pub struct WindowsOptions {
    /// imgui绘制窗口
    pub title: String,
    /// 需要覆盖的目标窗口
    pub overlay_target: OverlayTarget,
    /// 帧率
    pub frame_rate: FrameRate,
    pub dll_hinstance: usize,
    /// 初始化样式
    pub style_init: Option<Box<dyn Fn(&mut Context) -> ()>>,
}

impl Default for WindowsOptions {
    fn default() -> WindowsOptions {
        let result = fs::read(r"C:\Windows\Fonts\simhei.ttf");
        let style_init: Option<Box<dyn Fn(&mut Context) -> ()>> = if result.is_err() {
            // log::warn!("simhei read fail");
            None
        } else {
            let vec = result.unwrap();
            Some(Box::new(move |imgui| {
                // 设置主题
                imgui.style_mut().use_classic_colors();
                // 设置圆角
                imgui.style_mut().window_rounding = 12.0;
                // 设置字体
                imgui.fonts().add_font(&[FontSource::TtfData {
                    data: &*vec,
                    size_pixels: 12.0,
                    // config:None
                    config: Some(FontConfig {
                        glyph_ranges: FontGlyphRanges::chinese_simplified_common(),
                        rasterizer_multiply: 2f32,
                        oversample_h: 4,
                        ..FontConfig::default()
                    }),
                }]);
            }))
        };
        WindowsOptions {
            title: String::from("Aurora"),
            overlay_target: OverlayTarget::Window(unsafe { GetDesktopWindow() }),
            frame_rate: FrameRate(1),
            style_init,
            dll_hinstance: 0,
        }
    }
}

impl WindowsOptions {
    /// 通过窗口创建
    pub fn new(target: OverlayTarget) -> WindowsOptions {
        WindowsOptions {
            overlay_target: target,
            ..WindowsOptions::default()
        }
    }
}

pub struct Windows {
    pub hwnd: HWND,
    window_tracker: WindowTracker,
    wc: WNDCLASSEXW,
    imgui: Context,
    window_is_active: bool,
    sync_interval: u32,
    #[allow(unused)]
    hinstance: HINSTANCE,
}

impl Windows {
    /// 创建窗口与D3D渲染
    pub fn new(options: &WindowsOptions) -> Result<Windows> {
        let target_hwnd = options.overlay_target.resolve_target_window()?;
        unsafe {
            ImGui_ImplWin32_EnableDpiAwareness();
            let hmonitor = MonitorFromPoint(
                POINT { x: 0, y: 0 },
                windows::Win32::Graphics::Gdi::MONITOR_FROM_FLAGS(0x1),
            );
            let scale = ImGui_ImplWin32_GetDpiScaleForMonitor(hmonitor.0);
            let vec = PCWSTR(HSTRING::from(&options.title).as_ptr());
            let window_class = PCWSTR::from_raw(vec.as_ptr());
            let hinstance = if options.dll_hinstance > 0 {
                HMODULE(options.dll_hinstance as _)
            } else {
                GetModuleHandleA(None)?
            };
            let wc = WNDCLASSEXW {
                cbSize: size_of::<WNDCLASSEXW>() as u32,
                hCursor: LoadCursorW(None, IDC_ARROW)?,
                hInstance: HINSTANCE(hinstance.0),
                lpszClassName: window_class,
                style: CS_VREDRAW | CS_HREDRAW,
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hIcon: HICON::default(),
                hbrBackground: CreateSolidBrush(COLORREF(rgb!(0, 0, 0))),
                lpszMenuName: PCWSTR::null(),
                hIconSm: Default::default(),
            };
            RegisterClassExW(&wc);
            let hwnd = CreateWindowExW(
                WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
                window_class,
                window_class,
                WS_POPUP | WS_CLIPSIBLINGS,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                (300f32 * scale) as _,
                (200f32 * scale) as _,
                None,
                None,
                Some(wc.hInstance),
                None,
            )?;

            let result = D3d11Render::bind(hwnd);
            if result.is_err() {
                UnregisterClassW(wc.lpszClassName, Some(wc.hInstance))?;
                return Err(result.err().unwrap());
            }
            ImGui_ImplWin32_EnableAlphaCompositing(hwnd.0);
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = UpdateWindow(hwnd);
            let renderer = result?;
            let mut imgui_context = Context::create();
            imgui_context.style_mut().use_classic_colors();
            imgui_context.style_mut().colors[2] = [0.1, 0.1, 0.1, 1.];
            imgui_context.style_mut().window_rounding = 5.0;
            imgui_context.style_mut().scale_all_sizes(scale);
            imgui_context.io_mut().config_flags |= ConfigFlags::NAV_ENABLE_KEYBOARD;
            imgui_context.io_mut().config_flags |= ConfigFlags::NAV_ENABLE_GAMEPAD;
            imgui_context.io_mut().config_flags |= ConfigFlags::NAV_ENABLE_SET_MOUSE_POS;
            imgui_context.set_ini_filename(None);
            if let Some(func) = &options.style_init {
                func(&mut imgui_context)
            }
            ImGui_ImplWin32_Init(hwnd.0);
            let (pd3d_device, ctx) = {
                let device = renderer.pd3d_device.as_raw();
                let ctx = renderer.pd3d_device_context.as_raw();
                (device, ctx)
            };
            ImGui_ImplDX11_Init(pd3d_device as _, ctx as _);
            *GLOBAL_DATA.lock().unwrap() = Some(renderer);
            Ok(Windows {
                hwnd,
                window_tracker: WindowTracker {
                    hwnd: target_hwnd,
                    current_bounds: Default::default(),
                },
                wc,
                imgui: imgui_context,
                window_is_active: true,
                sync_interval: options.frame_rate.0,
                hinstance: HINSTANCE(options.dll_hinstance as _),
            })
        }
    }

    /// 进入循环
    /// [render] 渲染函数
    pub fn run<R>(&mut self, mut render: R) -> Result<()>
    where
        R: FnMut(&mut Ui, &mut Style) -> bool + 'static,
    {
        let mut exit = false;
        let style = unsafe { &mut *(self.imgui.style_mut() as *mut Style) };
        loop {
            let mut message = MSG::default();
            while unsafe { PeekMessageA(&mut message, None, 0, 0, PM_REMOVE) } == TRUE {
                unsafe {
                    let _ = TranslateMessage(&message);
                    let _ = DispatchMessageA(&message);
                    if message.message == WM_QUIT {
                        exit = true;
                        break;
                    }
                };
            }
            if !self.window_tracker.tracking(self.hwnd) {
                exit = true;
            }
            if exit {
                break;
            }

            unsafe {
                ImGui_ImplDX11_NewFrame();
                ImGui_ImplWin32_NewFrame();
            }
            {
                self.imgui_active_check()?;
            }
            {
                let frame = self.imgui.new_frame();
                exit = !render(frame, style)
            }
            let mut guard = GLOBAL_DATA.lock().unwrap();
            if let Some(ref mut renderer) = *guard {
                unsafe {
                    let view = renderer.p_main_render_target_view.take().unwrap();
                    renderer
                        .pd3d_device_context
                        .OMSetRenderTargets(Some(&[Some(view.clone())]), None);
                    renderer
                        .pd3d_device_context
                        .ClearRenderTargetView(&view, &[0f32; 4]);
                    ImGui_ImplDX11_RenderDrawData(self.imgui.render());
                    let _ = renderer
                        .p_swap_chain
                        .Present(self.sync_interval, DXGI_PRESENT(0));
                    renderer.p_main_render_target_view = Some(view);
                }
            }
        }
        unsafe {
            ImGui_ImplDX11_Shutdown();
            ImGui_ImplWin32_Shutdown();
        }
        {
            let mut guard = GLOBAL_DATA.lock().unwrap();
            if let Some(ref mut r) = *guard {
                r.cleanup_render_target();
            }
        }
        unsafe {
            let _ = UnregisterClassW(self.wc.lpszClassName, Some(self.wc.hInstance));
        }
        self.free();
        Ok(())
    }

    /// imgui窗口检查
    #[inline]
    fn imgui_active_check(&mut self) -> Result<()> {
        {
            let io = self.imgui.io_mut();
            // 活动检查 1.鼠标输入事件 2.鼠标按键事件
            {
                let mut point = POINT::default();
                unsafe {
                    let _ = GetCursorPos(&mut point)?;
                    let _ = ScreenToClient(self.hwnd, &mut point);
                };
                io.add_mouse_pos_event([point.x as _, point.y as _]);
            }
            let imgui_active = io.want_capture_mouse;
            if imgui_active != self.window_is_active {
                self.window_is_active = imgui_active;
                if imgui_active {
                    unsafe {
                        let _ = SetWindowLongA(
                            self.hwnd,
                            GWL_EXSTYLE,
                            (WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW).0 as _,
                        );
                    }
                } else {
                    unsafe {
                        let _ = SetWindowLongA(
                            self.hwnd,
                            GWL_EXSTYLE,
                            (WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW).0
                                as _,
                        );
                    }
                }
                if imgui_active {
                    unsafe {
                        let _ = SetActiveWindow(self.hwnd);
                    };
                }
            }
            Ok(())
        }
    }

    /// 释放
    fn free(&self) {}
}

extern "system" fn wndproc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        let handler = ImGui_ImplWin32_WndProcHandler(window.0, message, wparam, lparam);
        if handler.0 > 0 {
            return handler;
        }
        match message {
            WM_PAINT => {
                let _ = ValidateRect(Some(window), None);
                LRESULT(0)
            }
            WM_SIZE => {
                if wparam.0 as u32 != SIZE_MINIMIZED {
                    let mut guard = GLOBAL_DATA.lock().unwrap();
                    if let Some(ref mut renderer) = *guard {
                        renderer.cleanup_render_target();
                        let _ = renderer.p_swap_chain.ResizeBuffers(
                            0,
                            loword!(lparam.0 as u32),
                            hiword!(lparam.0 as u32),
                            DXGI_FORMAT_B8G8R8A8_UNORM,
                            DXGI_SWAP_CHAIN_FLAG(0),
                        );
                        let _ = renderer.create_render_target();
                        return LRESULT(0);
                    }
                }
                LRESULT(0)
            }
            WM_SYSCOMMAND => {
                if ((wparam.0 & 0xfff0) as u32) == SC_KEYMENU {
                    LRESULT(0)
                } else {
                    DefWindowProcW(window, message, wparam, lparam)
                }
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(window, message, wparam, lparam),
        }
    }
}
```

这是整个框架的核心。它不仅负责创建 Overlay 窗口，还负责驱动 ImGui 的每一帧渲染，并处理 Windows 消息。

在 `Windows::new()` 中，我们注册了一个自定义窗口类，并在创建窗口时传递了三个极其关键的扩展样式：

- `WS_EX_TOPMOST`：置顶，保证永远画在游戏窗口上面。
- `WS_EX_TRANSPARENT`：透明，**鼠标点击直接穿透**。这意味着玩家操作游戏时，理论上完全感觉不到覆盖层的存在。
- `WS_EX_NOACTIVATE`：不激活，防止覆盖层抢走游戏窗口的焦点。

#### mod

这里出于方便，我就直接将成品的 `start_overlay_render_loop` 贴在这里了：

```rs
#[tauri::command]
pub async fn start_overlay_render_loop() -> Result<(), String> {

    aurora_log!(trace, "RenderLoopStarter", "Starting overlay render loop");
    let class_name: Vec<u16> = "SDL_app".encode_utf16().chain(std::iter::once(0)).collect();
    let caption: Vec<u16> = "Counter-Strike 2".encode_utf16().chain(std::iter::once(0)).collect();
    aurora_log!(trace, "RenderLoopStarter", "target window class name: {:?}", class_name);
    aurora_log!(trace, "RenderLoopStarter", "target window caption: {:?}", caption);

    let hwnd = unsafe {
        FindWindowW(
            PCWSTR(class_name.as_ptr()),
            PCWSTR(caption.as_ptr()),
        ).map_err(|e| format!("Failed to find Window: {}", e))?
    };
    aurora_log!(info, "RenderLoopStarter", "hwnd: {:?}", hwnd);

    let mut pid: u32 = u32::default();
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    aurora_log!(info, "RenderLoopStarter", "Target process PID: {}", pid);

    set_target_pid(pid);

    // =================== init
    init_hypervisor_service();

    init_memory_controller();

    init_scene();
    // ==================== init end

    let options = WindowsOptions::new(OverlayTarget::Window(hwnd));

    let mut app = Windows::new(&options).map_err(|err| err.to_string())?;

    let mut render = AuroraRender::new();

    aurora_log!(trace, "RenderLoopStarter", "entering render loop");
    render.initialize();

    aurora_log!(trace, "RenderLoopStarter", "Starting overlay render loop");
    app.run(move |ui, _style| {
        let display_size = ui.io().display_size;

        ui.window("Aurora")
            .position([0.0, 0.0], Condition::Always)
            .size(display_size, Condition::Always)
            .flags(
                imgui::WindowFlags::NO_TITLE_BAR
                    | imgui::WindowFlags::NO_RESIZE
                    | imgui::WindowFlags::NO_MOVE
                    | imgui::WindowFlags::NO_SCROLLBAR
                    | imgui::WindowFlags::NO_BACKGROUND
                    | imgui::WindowFlags::NO_BRING_TO_FRONT_ON_FOCUS
                    | imgui::WindowFlags::NO_INPUTS
            )
            .build(|| {
                render.render(&ui.get_window_draw_list(), ui.io());
            });

        true // loop
    }).map_err(|err| err.to_string())?;
    aurora_log!(info, "RenderLoopStarter", "overlay render loop end");

    Ok(())
}

```

这里的逻辑其实也很简单：

1. 通过窗口名和窗口类锁定目标窗口，获取需要的hwnd
2. 通过 hwnd 获取 pid
3. 初始化服务
4. 初始化场景数据
5. 启动 Render Loop

### Config

接下来我们需要为这个 GUI 准备一些 config，因为程序中会有大量的 `启用/不启用` 的配置，所以这里我打算使用 bitflag 来适配现在的场景。

就像这样：

```rs
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FeatureFlags: u64 {
        const NONE         = 0;

        const AIMBOT       = 1 << 0;
        const ESP          = 1 << 1;
        const TRIGGERBOT   = 1 << 2;
        const SPINBOT      = 1 << 3;
        const GODMODE      = 1 << 4;
        const NO_RECOIL    = 1 << 5;

        const BHOP              = 1 << 6;
        const SILENT_AIM        = 1 << 7;

        const DEFAULT = Self::ESP.bits()
            | Self::AIMBOT.bits()
            | Self::SILENT_AIM.bits()
            | Self::TRIGGERBOT.bits()
            | Self::GODMODE.bits();

        const FULL = Self::AIMBOT.bits()
                   | Self::ESP.bits()
                   | Self::TRIGGERBOT.bits()
                   | Self::GODMODE.bits()
                   | Self::NO_RECOIL.bits();
    }
}
```

你可以自由向里面添加不同的 flag 配置，这里交给你自由发挥。

这里的 config 是十分重要的，这里的 config 将会决定后面很多系统的行为，因为这里会被后续的很多概念引用，所以这里优先说说。

### 数据黑板

#### 概念

思考一下，对于某一帧中的数据比如坐标，会同时被 ESP 使用也会被 AimBot 等多个模块使用，但是你觉得我们应该重复在每一个需要的地方都去获取一次吗？

显然不应该，我们最好应该做到 `一次获取、到处使用`。

> 这里我就要引入数据黑板的概念，这是我之前从游戏开发了解到的概念，但是放在这里同样极其合适。

打个比方，在现实世界的作战指挥中心，墙上挂着一块巨大的黑板。

侦察兵把敌情坐标写上去，后勤部把弹药库存写上去，指挥官看着黑板下达指令。

**重点在于：写信息的人不需要知道谁会去看，看信息的人也不需要知道是谁写的。**

一般游戏中的数据黑板是一个集中的、基于键值对（Key-Value）或结构化数据的**共享内存区域**。

任何游戏系统（AI逻辑、动画系统、任务系统、UI）都可以随时往上面读写数据，而完全不需要知道数据来自哪里、去向何方。

> 我们在这里也可以这么做，我们在每一帧根据 config 推断需要获取或者计算哪些数据，然后我们将他写在黑板上，后续所有模块可以自由引用上面的数据，同时也可以补充上自己特殊的数据，而需要这个数据的模块同样不需要知道这个数据来自哪里

#### 实现

我暂时这样定义黑板：

```rs
static BLACKBOARD: OnceLock<Mutex<Blackboard>> = OnceLock::new();

pub fn blackboard() -> MutexGuard<'static, Blackboard> {
    BLACKBOARD.get_or_init(|| Mutex::new(Blackboard::new())).lock().unwrap()
}

impl Blackboard {
    pub fn new() -> Self {
        Self { entities: HashMap::new() }
    }

    pub fn update_all(
        &mut self,
        characters: &[Player],
        local_pos: Vector3,
        camera: &Camera,
        screen_w: f32,
        screen_h: f32,
        requirements: DataRequirements,
    ) {
        let mut seen = HashMap::with_capacity(characters.len());

        for ch in characters {
            if !ch.is_valid() { continue; }
            let addr = ch.addr();
            seen.insert(addr, ());

            self.entities
                .entry(addr)
                .or_insert_with(|| EntityBoard::new(*ch))
                .update(ch, local_pos, camera, screen_w, screen_h, requirements);
        }

        for (addr, board) in self.entities.iter_mut() {
            if !seen.contains_key(addr) {
                board.is_valid = false;
            }
        }
    }
}
```

然后我们可以定义一个 `DataRequirements`，这个将基于 config 来指挥数据获取模块：

```rs
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DataRequirements: u32 {
        const POSITION   = 1 << 0;
        const SCREEN     = 1 << 1;
        const BONES      = 1 << 2;
        const DISTANCE   = 1 << 3;
    }
}

impl Default for DataRequirements {
    fn default() -> Self {
        Self::POSITION | Self::DISTANCE | Self::BONES | Self::SCREEN
    }
}

pub fn compute_data_requirements(cfg: &AuroraConfig) -> DataRequirements {
    let mut req = DataRequirements::empty();

    if cfg.feature_flags.contains(FeatureFlags::ESP) {
        req |= DataRequirements::SCREEN | DataRequirements::DISTANCE;
        req |= DataRequirements::POSITION;
    }

    if cfg.vision_flags.contains(VisionFlags::SHOW_RADAR) {
        req |= DataRequirements::POSITION | DataRequirements::DISTANCE;
    }

    if cfg.vision_flags.intersects(
        VisionFlags::SHOW_SKELETON
            | VisionFlags::BONE_HEAD_CIRCLE
            | VisionFlags::BONE_SPINE
            | VisionFlags::BONE_ARMS
            | VisionFlags::BONE_LEGS
            | VisionFlags::BONE_HANDS
            | VisionFlags::BONE_FEET,
    ) {
        req |= DataRequirements::BONES;
        req |= DataRequirements::SCREEN;
    }

    let screen_dependent_flags = VisionFlags::SHOW_BOX
        | VisionFlags::SHOW_SNAPLINE
        | VisionFlags::SHOW_HEALTH
        | VisionFlags::SHOW_ARMOR
        | VisionFlags::SHOW_NAME
        | VisionFlags::SHOW_HP_TEXT
        | VisionFlags::SHOW_LABELS
        | VisionFlags::SHOW_DISTANCE
        | VisionFlags::SHOW_SPEED
        | VisionFlags::SHOW_TEAM_TAG
        | VisionFlags::SHOW_WEAPON
        | VisionFlags::SHOW_STATE
        | VisionFlags::SHOW_HEAD_CIRCLE
        | VisionFlags::SHOW_STAGGER_BAR
        | VisionFlags::SHOW_STAMINA_BAR
        | VisionFlags::SHOW_ENERGY_BAR
        | VisionFlags::SHOW_LEVEL
        | VisionFlags::SHOW_POSITION
        | VisionFlags::SHOW_AMMO;

    if cfg.vision_flags.intersects(screen_dependent_flags) {
        req |= DataRequirements::SCREEN | DataRequirements::POSITION;
    }

    let distance_dependent_flags = VisionFlags::SHOW_DISTANCE
        | VisionFlags::SHOW_LABELS
        | VisionFlags::SHOW_BOX
        | VisionFlags::SHOW_SKELETON
        | VisionFlags::SHOW_HEAD_CIRCLE
        | VisionFlags::SHOW_SPEED;

    if cfg.vision_flags.intersects(distance_dependent_flags) {
        req |= DataRequirements::DISTANCE;
    }

    if cfg.feature_flags.contains(FeatureFlags::AIMBOT) {
        req |= DataRequirements::POSITION;
        req |= DataRequirements::BONES;
        req |= DataRequirements::DISTANCE;
        req |= DataRequirements::SCREEN;
    }

    if cfg.feature_flags.contains(FeatureFlags::TRIGGERBOT) {
        req |= DataRequirements::POSITION | DataRequirements::DISTANCE;
    }

    req
}

```

接下来我们就可以在 `update()` 中使用它了！

就像这样：

```rs
if need_position {
    let foot = ch.foot_position();
    let head = ch.head_position();
    aurora_log!(trace, "Entity", "foot={:?},head={:?}", foot, head);

    if requirements.contains(DataRequirements::DISTANCE) && foot.is_valid() {
        self.distance = Some(local_pos.distance_to(foot));
    }

    if requirements.contains(DataRequirements::POSITION) {
        self.foot_world = foot.is_valid().then_some(foot);
        self.head_world = head.is_valid().then_some(head);
    }

    if requirements.contains(DataRequirements::SCREEN) {
        self.foot_screen = foot.is_valid()
            .then(|| camera.world_to_screen(foot, screen_w, screen_h))
            .flatten();

        self.head_screen = head.is_valid()
            .then(|| camera.world_to_screen(head, screen_w, screen_h))
            .flatten();
        aurora_log!(trace, "Entity", "foot_s={:?},head_s={:?}", self.foot_screen, self.head_screen);
    }
}
```

接下来我们就只需要在需要数据的地方调用黑板 `blackboard()` 就好啦。

### 前端

```tsx
export type Page = 'home' | 'service' | 'protection' | 'modules' | 'log' | 'settings'

const variants: Variants = {
    initial: { opacity: 0, x: 10 },
    animate: { opacity: 1, x: 0, transition: { duration: 0.16, ease: 'easeOut' } },
    exit:    { opacity: 0, x: -10, transition: { duration: 0.1 } },
}

export default function App() {
    const [page, setPage] = useState<Page>('home')

    return (
        <div style={{
            display: 'flex', flexDirection: 'column',
            height: '100vh',
            background: 'var(--bg-window)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            overflow: 'hidden',
        }}>
            <TitleBar />

            <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
                <Sidebar current={page} onNavigate={setPage} />

                <main style={{
                    flex: 1,
                    overflow: 'hidden auto',
                    padding: '32px 36px',
                    position: 'relative',
                }}>
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={page}
                            variants={variants}
                            initial="initial"
                            animate="animate"
                            exit="exit"
                            style={{ height: '100%' }}
                        >
                            {page === 'home'       && <Home />}
                            {page === 'service'    && <Service />}
                            {page === 'protection' && <Protection />}
                            {page === 'modules'    && <Modules />}
                            {page === 'log'        && <Log />}
                            {page === 'settings'   && <Settings />}
                        </motion.div>
                    </AnimatePresence>
                </main>
            </div>

            <Toaster
                position="top-right"
                visibleToasts={5}
                gap={8}
                offset={{ top: 48, right: 16 }}
                toastOptions={{
                    unstyled: true,
                    classNames: { toast: '' },
                }}
            />
        </div>
    )
}
```

由于这不是本文的重点，所以这里简单给一下。

```tsx
export default function Home() {
    return (
        <div>
            <h1 style={{ fontSize: 22, fontWeight: 600, margin: '0 0 4px', color: 'var(--t1)' }}>Dashboard</h1>
            <p style={{ fontSize: 13, color: 'var(--t3)', margin: '0 0 28px' }}>System overview</p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
                <StatCard Icon={Activity} label="Status"     value="Active"  accent />
                <StatCard Icon={Cpu}      label="Driver"     value="Loaded"  />
                <StatCard Icon={Shield}   label="Protection" value="On"      />
                <StatCard Icon={Zap}      label="Mode"       value="Normal"  />
            </div>

            <GameCard />

            <Card style={{ padding: '20px 24px' }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--t2)', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Activity Log
                </div>
                {LOGS.map((log, i) => (
                    <div key={i} style={{
                        display: 'flex', alignItems: 'center', gap: 12,
                        padding: '9px 0',
                        borderBottom: i < LOGS.length - 1 ? '1px solid var(--border)' : 'none',
                    }}>
                        <span style={{ fontSize: 11, color: 'var(--t3)', fontFamily: 'monospace', minWidth: 68 }}>{log.time}</span>
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: log.ok ? 'var(--accent)' : '#f87171', flexShrink: 0 }} />
                        <span style={{ fontSize: 12, color: 'var(--t2)' }}>{log.msg}</span>
                    </div>
                ))}
            </Card>
        </div>
    )
}
```

我的 `Home` 页有很多占位的东西，搞得不太好。

你完全可以自由发挥制作一个比我更加好看精美的 GUI 界面。

![](https://img.halfcity.top/2026/08/08/1e7a081c514745c97370b37da5288c5c.avif)

你可以现在就完成前端，也可以先进入下一个模块，但是前端部分我不会再提及了。

## 驱动

> [!NOTE]
> 接下来我们要进入 Windows 驱动开发的部分了，这也是本文的重点，可能刚开始接触会有点懵，但是深入了解后你会觉得轻松的！让我们开始吧

### 简介

如何理解驱动？

实际上的 Windows 驱动是一个标准的 PE 文件，

> 你可以将内核简单理解为一个超级大的进程，而驱动就类似于加载进这个大进程的 DLL，可以获取和操作系统几乎相同的控制能力

在 Windows 的世界中，一般来讲驱动承担着连接操作系统与硬件之间的桥梁作用，比如和键盘、鼠标、磁盘之类的交互。

但抽象来说从网络设备、虚拟设备到安全软件，几乎所有需要高权限访问系统资源的组件，都离不开驱动。

### WDM

在 Windows 驱动发展历史中，**Windows Driver Model（WDM）** 是一个非常重要的里程碑。它定义了一套统一的驱动框架，使驱动能够运行于不同版本的 Windows 系统之上，同时提供设备管理、电源管理、即插即用等完整能力。

简单来说 `WDM` 就是一个微软官方的驱动开发框架，他让我们可以较为方便地开发一个轻量的驱动。

接下来我将简单介绍一下 WDM。

#### WDM 的历史背景

在 WDM 出现之前，Windows 驱动开发经历了几个阶段。

1. Windows 9x 驱动模型

早期 Windows 9x（Windows 95/98/ME）中的驱动模型非常混乱。

不同类型设备拥有不同的驱动接口：

- VxD（Virtual Device Driver）
- 专用设备驱动接口
- 各厂商自定义接口

这种设计导致：

- 驱动开发复杂
- 代码难以复用
- 系统稳定性较差

尤其是 Windows 9x 本身内核结构并不完善，一个错误的驱动很容易导致整个系统崩溃。

2. Windows NT 驱动模型

Windows NT 系列采用了更加现代化的内核架构。

它引入：

- 内核模式
- 用户模式
- I/O Manager
- Object Manager
- Executive

驱动程序成为内核对象的一部分。

但是早期 NT 驱动仍然存在问题：

- 不同 Windows 版本之间兼容性有限
- 设备管理逻辑需要驱动自己实现
- 即插即用支持不足

3. WDM 的诞生

1996 年，微软推出 Windows Driver Model。

WDM 的目标：

> 让 Windows 98 和 Windows NT 系列能够共享同一套驱动模型。

因此 WDM 引入了：

- 统一设备模型
- 即插即用（PnP）
- 电源管理（Power Management）
- 分层驱动架构
- IRP 请求机制

从此 Windows 驱动开发进入现代阶段。

> 你可能会有疑问，WDM 看起来依旧是一个老古董啊，为什么现在还要用它？

确实，现在有比他更加新的框架出现 `KMDF`，他是在 `WDM` 之上进一步封装的新框架。但是这样也意味着它会丧失一部分底层的控制能力。

所以实际上 `WDM` 依旧是极其贴近 Windows 内核的框架，它几乎让你可以做任何事，就安全研究来看它是十分不错的选择。

#### WDM 的整体架构

WDM 的核心思想是：

> 驱动不直接控制设备，而是通过 Windows 内核提供的框架与设备交互。

例如一个 USB 鼠标：

应用程序 -> Win32 Input API -> Windows Input Stack -> Mouse Class Driver -> USB HID Driver -> USB Bus Driver -> USB Controller -> 鼠标硬件

每一层驱动负责不同职责，相应的每一层驱动都能拿到自己想要的信息。

#### WDM 的核心对象

WDM 开发中最重要的几个对象：

- Driver Object
- Device Object
- IRP
- Device Extension

1. Driver Object

`DriverObject` 是驱动加载后的核心对象。

当驱动加载时：

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
```

系统会创建对应的 DRIVER_OBJECT，它代表一个已经加载到内核中的驱动实例。

其中包含这两个字段字段：

DriverObject->DriverUnload

DriverObject->MajorFunction[]

`DriverUnload` 指定了驱动卸载时的回调函数，`MajorFunction` 则是指定 IRP 请求对应的派遣函数。

2. Device Object

驱动本身不能直接被用户访问。

因此驱动需要创建设备对象：

例如：

```c
IoCreateDevice(
    DriverObject,
    sizeof(DEVICE_EXTENSION),
    &DeviceName,
    FILE_DEVICE_UNKNOWN,
    0,
    FALSE,
    &DeviceObject
);
```

3. Device Extension

Device Extension 是驱动自己的私有数据区域。

例如：

typedef struct _DEVICE_EXTENSION
{
    PDEVICE_OBJECT DeviceObject;

    BOOLEAN Initialized;

    HANDLE ProcessId;

} DEVICE_EXTENSION;

创建设备时：

```c
sizeof(DEVICE_EXTENSION)
```

系统会自动分配。

访问：

```c
PDEVICE_EXTENSION ext;

ext = DeviceObject->DeviceExtension;
```

它类似用户态中 C++ 的成员变量。


#### IRP

如果说 WDM 有一个最核心的概念，那么一定是：

IRP（I/O Request Packet）

IRP 是 Windows 内核中的 I/O 请求描述结构。

用户调用 `DeviceIoControl()`后最终会进入指定的派遣函数中：

`DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` 这个指定的就是这个函数。

在后面我会使用具体举例的。



假设我们在DriverEntry 中这样注册了派遣函数：

```c
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctlDispatcher;
```

这是派遣函数的实现：

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

#### IRQL

这里补充一个概念：

IRQL (Interrupt Request Level)，它决定了当前正在执行的代码能被打断的级别。

IRQL的核心机制是屏蔽。每个CPU核心都维护着自己的当前IRQL。当一个中断请求发生时，系统会比较其IRQL与CPU当前的IRQL：

- 如果新的中断IRQL更高，它会立即抢占当前执行的低IRQL代码。

- 如果新的中断IRQL小于或等于当前IRQL，它会被屏蔽，直到CPU的IRQL降下来才会被处理。

这是一种通过优先级来确保高实时性任务优先执行的机制。

### 编写雏形

我们可以这样初始化我们的驱动

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	LogInfo("Driver loading.");

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL;

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(SPARKLE_DEVICE_NAME);
	UNICODE_STRING SymbolicLinkName = RTL_CONSTANT_STRING(SPARKLE_SYMBOLIC_LINK);

	status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject
	);

	if (!NT_SUCCESS(status)) {
		LogError("Failed to create device object, status: 0x%X", status);
		return status;
	}

	DeviceObject->Flags |= IO_TYPE_DEVICE;
	DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DriverUnsupported;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = DriverRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DriverWrite;

	DriverObject->DriverUnload = DriverUnload;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctlDispatcher;
	
	LogSuccess("Device registered");

	return status;
}
```

这里指定了我们的派遣函数：

```
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctlDispatcher;
```

我放弃了相对常见的 switch 方式而是使用了这种查表的方式完成了这个函数：

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

他的任务很简单，根据请求的 `IOCTL Code` 校验请求是否符合要求，然后查表提取对应的 handler 执行返回结果。

这样将 `handler` 与派遣函数本身解耦了，我认为付出一点点查表的时间是完全值得的。

### 内存读写

#### 代码实现

这里我们简单地在 r0 进行实现。

由于我们分离的架构，我们可以轻松地定义一个 handler。

还是废话不多说，直接先给完整实现，然后逐步分析：

```c
typedef struct _RW_PROCESS_MEMORY_REQUEST {
    ULONG   ProcessId;          // 目标进程 PID
    UINT64  Address;            // 目标虚拟地址
    ULONG   Size;               // 要读写的大小
} RW_PROCESS_MEMORY_REQUEST, * PRW_PROCESS_MEMORY_REQUEST;

typedef struct _RW_PROCESS_MEMORY_RESPONSE {
    NTSTATUS Status;
    ULONG    BytesTransferred;
    // Data follows...
} RW_PROCESS_MEMORY_RESPONSE, * PRW_PROCESS_MEMORY_RESPONSE;
```

```c
NTSTATUS DrvHandleReadProcessMemory(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpStack,
    _Out_ PULONG_PTR BytesReturned
)
{
    NTSTATUS status = STATUS_SUCCESS;
    *BytesReturned = 0;

    PRW_PROCESS_MEMORY_REQUEST request = (PRW_PROCESS_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	ULONG requestedPid = request->ProcessId;
	UINT64 requestedAddress = request->Address;
    ULONG requiredSize = request->Size;

    if (inputLen < sizeof(RW_PROCESS_MEMORY_REQUEST) ||
        requiredSize == 0 ||
        requiredSize >(1 * 1024 * 1024))
    {
        LogError("ReadProcessMemory: Invalid parameter (InputLen=%u Size=0x%X)", inputLen, requiredSize);
        return STATUS_INVALID_PARAMETER;
    }

    if (outputLen < sizeof(RW_PROCESS_MEMORY_RESPONSE) + requiredSize)
    {
        LogError("ReadProcessMemory: Output buffer too small (need %u, got %u)",
            (ULONG)(sizeof(RW_PROCESS_MEMORY_RESPONSE) + requiredSize), outputLen);
        return STATUS_BUFFER_TOO_SMALL;
    }

    PRW_PROCESS_MEMORY_RESPONSE response = (PRW_PROCESS_MEMORY_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    PEPROCESS Process = NULL;
    status = PsLookupProcessByProcessId(ULongToHandle(requestedPid), &Process);
    if (!NT_SUCCESS(status))
    {
        LogError("ReadProcessMemory: PsLookupProcessByProcessId failed pid=%u status=0x%X", requestedPid, status);
        response->Status = status;
        response->BytesTransferred = 0;
        *BytesReturned = sizeof(RW_PROCESS_MEMORY_RESPONSE);
        return STATUS_SUCCESS;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(Process, &apc);

    __try
    {
        ProbeForRead((PVOID)requestedAddress, requiredSize, 1);

        RtlCopyMemory(
            (PUCHAR)response + sizeof(RW_PROCESS_MEMORY_RESPONSE),
            (PVOID)requestedAddress,
            requiredSize
        );

        response->Status = STATUS_SUCCESS;
        response->BytesTransferred = requiredSize;
        *BytesReturned = sizeof(RW_PROCESS_MEMORY_RESPONSE) + requiredSize;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LogError("ReadProcessMemory: exception 0x%X (pid=%u addr=0x%llX size=0x%X)",
            GetExceptionCode(), requestedPid, requestedAddress, requiredSize);
        response->Status = GetExceptionCode();
        response->BytesTransferred = 0;
        *BytesReturned = sizeof(RW_PROCESS_MEMORY_RESPONSE);
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}
```

#### 解析

> [!NOTE]
> 首先我们进来的第一件事永远是将请求传入的参数保留在栈上，也就是保存为一个局部变量，如果你不想看到电脑反复蓝屏的话，相信我，这一步真的非常重要

```c
if (inputLen < sizeof(RW_PROCESS_MEMORY_REQUEST) ||
    requiredSize == 0 ||
    requiredSize >(1 * 1024 * 1024))
{
    LogError("ReadProcessMemory: Invalid parameter (InputLen=%u Size=0x%X)", inputLen, requiredSize);
    return STATUS_INVALID_PARAMETER;
}

if (outputLen < sizeof(RW_PROCESS_MEMORY_RESPONSE) + requiredSize)
{
    LogError("ReadProcessMemory: Output buffer too small (need %u, got %u)",
        (ULONG)(sizeof(RW_PROCESS_MEMORY_RESPONSE) + requiredSize), outputLen);
    return STATUS_BUFFER_TOO_SMALL;
}
```

然后我们会对传入的参数做一些合理性校验。

随后我们会根据传入的 Pid 调用 `PsLoopUpProcessByProcessId()` 来获取目标 `EPROCESS` 的指针 `PEPROCESS`。

随后我们会附加到目标进程，使用 `ProbeForRead` 判断目标内存是否符合读的条件，然后尝试使用 `RtlCopyMemory()` 读取并返回。

#### 探究

整体的实现很简单，但有的人可能会疑惑为什么要调用 `KeStackAttachProcess()` 呢？

让我来补充一些东西。

#### 页表

在 x86-64 架构中，虚拟地址到物理地址的转换是现代操作系统内存管理的核心。

这一过程依赖两个关键概念：**CR3 寄存器**和**四级页表**。

CR3 是 x86 架构中一个至关重要的**控制寄存器**，专门用于存储当前进程**页目录表的物理基地址**。在分页机制中，它是 CPU 进行地址转换的起点。

- **别称**：CR3 也被称为**页目录基地址寄存器 (PDBR, Page-Directory Base address Register)**。
- **核心功能**：保存当前活动进程的页表的根物理地址。

CR3 的功能随 CPU 工作模式而变化：

| 模式 | 指向的目标 | 备注 |
| :--- | :--- | :--- |
| **32位保护模式** | 页目录表 (Page Directory) | 采用两级页表 (10-10-12) |
| **64位长模式 (Long Mode)** | **PML4 表 (Page Map Level 4)** | 采用四级页表 (9-9-9-9-12)，地址宽度扩展至 **52位** |

在 64 位模式下，CR3 寄存器中的值指向四级页表的顶部——PML4 表。

CR3 寄存器的低几位不仅用于存储地址，还包含控制缓存行为的标志位：

- **PCD (Page Cache Disable)**：控制页目录是否允许被 CPU 缓存。
- **PWT (Page Write-Through)**：控制页目录的缓存策略（直写或回写）。

每个进程都拥有自己独立的页表。当操作系统进行**进程切换**时，内核会将新进程的页表顶级目录（PML4）的**物理地址**加载到 CR3 寄存器中。这相当于切换了整个地址空间，使得 CPU 后续的地址翻译都基于新进程的页表。

> **注意**：在 Linux 内核中，`task_struct->mm->pgd` 存储的是进程页全局目录的**虚拟地址**，而 CR3 寄存器需要的是**物理地址**。

x86-64 的四级页表是一个树形结构，每一级都是一张 **4KB 大小的表**，包含 **512 个 64位（8字节）的表项**。各级名称如下：

| 层级 (Level) | 硬件名称 | Linux 内核中的名称 | 描述 |
| :--- | :--- | :--- | :--- |
| **第1级 (顶级)** | **PML4** (Page Map Level 4) | `PGD` (Page Global Directory) | 页映射四级表，根节点 |
| **第2级** | **PDPT** (Page Directory Pointer Table) | `PUD` (Page Upper Directory) | 页目录指针表 |
| **第3级** | **PD** (Page Directory) | `PMD` (Page Middle Directory) | 页目录表 |
| **第4级 (叶级)** | **PT** (Page Table) | `PTE` (Page Table Entry) | 页表，包含最终的物理页地址 |

> **注意**：Linux 内核中第一级页表被称为 `PGD`，这是历史原因造成的。在 64 位模式下，Linux 的 `PGD` 实际上对应硬件上的 PML4。

在 x86-64 的 4KB 分页模式下，一个 48 位的虚拟地址被划分为 5 个部分：

- **低 12 位 (位 0-11)**：**页内偏移 (Page Offset)**，用于在 4KB 物理页内寻址。
- **位 12-20 (9位)**：**PT 索引**，在页表 (PT) 中定位表项。
- **位 21-29 (9位)**：**PD 索引**，在页目录 (PD) 中定位表项。
- **位 30-38 (9位)**：**PDPT 索引**，在页目录指针表 (PDPT) 中定位表项。
- **位 39-47 (9位)**：**PML4 索引**，在 PML4 表中定位表项[reference:33]。

地址转换是一个从 CR3 开始，逐级查表的过程：

1.  **从 CR3 开始**：CPU 读取 CR3 寄存器中的物理地址，找到 **PML4 表**。
2.  **一级索引 (PML4)**：从虚拟地址中提取 **PML4 索引**，在 PML4 表中找到对应的 **PML4 表项 (PML4E)**。该表项存储了 **PDPT 表**的物理地址。
3.  **二级索引 (PDPT)**：从虚拟地址中提取 **PDPT 索引**，在 PDPT 表中找到对应的 **PDPT 表项 (PDPTE)**。该表项存储了 **PD 表**的物理地址。
4.  **三级索引 (PD)**：从虚拟地址中提取 **PD 索引**，在 PD 表中找到对应的 **PD 表项 (PDE)**。该表项存储了 **PT 表**的物理地址。
5.  **四级索引 (PT)**：从虚拟地址中提取 **PT 索引**，在 PT 表中找到对应的 **PT 表项 (PTE)**。该表项存储了最终**物理页**的基地址。
6.  **计算物理地址**：将找到的物理页基地址与虚拟地址的**低 12 位页内偏移**相加，得到最终的物理地址。

每个页表项（PML4E, PDPTE, PDE, PTE）都是一个 64 位的数据结构。其核心字段包括：

- **Present (存在位)**：表示该表项指向的下一级表或物理页是否在内存中。
- **物理地址字段**：存储下一级表或物理页的基地址（在 64 位模式下为 52 位）。
- **其他标志位**：包括读写权限、用户/管理员模式、缓存禁用、访问过、脏位等。

所以就目前的场景来说，驱动的 CR3 指向的是内核的页表，这个时候你直接将目标进程的虚拟地址给驱动让他读，它实际上是根本没法直接读取的，因为内核的页表无法解析这个虚拟地址。

而 `KeStackAttachProcess()` 有一个非常重要的作用就是切换当前上下文的 CR3 寄存器的值，让他指向目标进程。

但是口说无凭，所以让我们直接来分析一下 `ntoskrnl.exe` 来看看 Windows 内核实际上做了什么吧。

#### 分析 KeStackAttachProcess

> [!NOTE]
> 同上，如果你对这部分内容不感兴趣的话，你可以直接跳过哒

让我们看看 IDA 反编译的结果：

```c
void __stdcall KeStackAttachProcess(PRKPROCESS PROCESS, PRKAPC_STATE ApcState)
{
  struct _KTHREAD *CurrentThread; // rdi
  int PROCESS_1; // ebx
  unsigned __int8 CurrentIrql; // r14
  struct _KPRCB *CurrentPrcb; // rbp
  _DWORD *SchedulerAssist_1; // rcx
  _DWORD *SchedulerAssist_2; // rcx
  _DWORD *SchedulerAssist_3; // rcx
  _DWORD *SchedulerAssist; // r9
  int v11; // eax
  int v12; // eax
  int v13; // eax
  int v14; // [rsp+60h] [rbp+18h] BYREF

  CurrentThread = KeGetCurrentThread();
  PROCESS_1 = (int)PROCESS;
  if ( (KeGetPcr()->Prcb.DpcRequestSummary & 0x10001) != 0 || (*(_DWORD *)&PROCESS->__s0 & 0x400) != 0 )
    KeBugCheckEx(
      BugCheckCode: 5u,
      BugCheckParameter1: (ULONG_PTR)PROCESS,
      BugCheckParameter2: (ULONG_PTR)CurrentThread->ApcState.Process,
      BugCheckParameter3: CurrentThread->ApcStateIndex,
      BugCheckParameter4: KeGetPcr()->Prcb.DpcRequestSummary & 0x10001);
  if ( CurrentThread->ApcState.Process == PROCESS )
  {
    ApcState->Process = (_KPROCESS *)1;
  }
  else
  {
    CurrentIrql = KeGetCurrentIrql();
    __writecr8(2u);
    if ( KiIrqlFlags && (KiIrqlFlags & 1) != 0 && CurrentIrql <= 0xFu )
    {
      SchedulerAssist = KeGetCurrentPrcb()->SchedulerAssist;
      SchedulerAssist[5] |= (-1 << (CurrentIrql + 1)) & 4;
    }
    CurrentPrcb = KeGetCurrentPrcb();
    v14 = 0;
    SchedulerAssist_1 = CurrentPrcb->SchedulerAssist;
    if ( SchedulerAssist_1 )
    {
      if ( CurrentPrcb->NestingLevel <= 1u )
      {
        v11 = SchedulerAssist_1[6];
        SchedulerAssist_1[6] = v11 + 1;
        if ( v11 == -1 )
LABEL_20:
          KiRemoveSystemWorkPriorityKick(CurrentPrcb);
      }
    }
    while ( _interlockedbittestandset64((volatile signed __int32 *)&CurrentThread->ThreadLock, 0) )
    {
      SchedulerAssist_2 = CurrentPrcb->SchedulerAssist;
      if ( SchedulerAssist_2 )
      {
        if ( CurrentPrcb->NestingLevel <= 1u )
        {
          v12 = SchedulerAssist_2[6] - 1;
          SchedulerAssist_2[6] = v12;
          if ( !v12 )
            KiRemoveSystemWorkPriorityKick(CurrentPrcb);
        }
      }
      do
        KeYieldProcessorEx(&v14);
      while ( CurrentThread->ThreadLock );
      SchedulerAssist_3 = CurrentPrcb->SchedulerAssist;
      if ( SchedulerAssist_3 )
      {
        if ( CurrentPrcb->NestingLevel <= 1u )
        {
          v13 = SchedulerAssist_3[6];
          SchedulerAssist_3[6] = v13 + 1;
          if ( v13 == -1 )
            goto LABEL_20;
        }
      }
    }
    if ( CurrentThread->ApcStateIndex )
    {
      KiAttachProcess(CurrentThread: CurrentThread, PROCESS: PROCESS_1, CurrentIrql: CurrentIrql, 0, ApcState: ApcState);
    }
    else
    {
      KiAttachProcess(CurrentThread: CurrentThread, PROCESS: PROCESS_1, CurrentIrql: CurrentIrql, 0, ApcState: &CurrentThread->SavedApcState);
      ApcState->Process = 0;
    }
  }
}
```

可以看到在完成许多调度操作后内核调用了 `KiAttachProcess()` 这个函数。

让我们看看 `KiAttachProcess()` 它做了什么：

```asm
.text:0000000140207443 048 80 3D F6 A3 BF                 cmp     cs:KiKvaShadow, 0
.text:0000000140207443 048 00 00
.text:000000014020744A 048 48 8B 7E 28                    mov     rdi, [rsi+28h]
.text:000000014020744E 048 74 32                          jz      short loc_140207482
.text:0000000140207450 048 48 8B C7                       mov     rax, rdi
.text:0000000140207453 048 40 F6 C7 02                    test    dil, 2
.text:0000000140207457 048 74 0D                          jz      short loc_140207466
.text:0000000140207459 048 48 B9 00 00 00                 mov     rcx, 8000000000000000h
.text:0000000140207459 048 00 00 00 00 80
.text:0000000140207463 048 48 0B C1                       or      rax, rcx
.text:0000000140207466
.text:0000000140207466                    loc_140207466:                          ; CODE XREF: KiAttachProcess+157↑j
.text:0000000140207466 048 65 48 89 04 25                 mov     gs:9000h, rax
.text:0000000140207466 048 00 90 00 00
.text:000000014020746F 048 0F B6 8E 90 03                 movzx   ecx, byte ptr [rsi+390h]
.text:000000014020746F 048 00 00
.text:0000000140207476 048 E8 15 05 00 00                 call    KiSetAddressPolicy
.text:000000014020747B 048 49 C7 C2 FF FF                 mov     r10, 0FFFFFFFFFFFFFFFFh
.text:000000014020747B 048 FF FF
.text:0000000140207482
.text:0000000140207482                    loc_140207482:                          ; CODE XREF: KiAttachProcess+14E↑j
.text:0000000140207482 048 8B 05 94 4F AF                 mov     eax, cs:HvlEnlightenments
.text:0000000140207482 048 00
.text:0000000140207488 048 A8 01                          test    al, 1
.text:000000014020748A 048 0F 85 5C 59 21                 jnz     loc_14041CDEC
.text:000000014020748A 048 00
.text:0000000140207490 048 0F 22 DF                       mov     cr3, rdi
```

可以观察到它将 `rdi` 中的值赋值给了 `cr3`，那么 `rdi` 的值是哪来的呢？

```asm
mov     rdi, [rsi+28h]
```

rdi 的值来自于 rsi 偏移 0x28 处。

此时你应该很敏锐地意识到了 rsi 是一个和进程相关的结构体。

实际上我们根据 `KeStackAttachProcess` 可以看的出来 rsi 里放的应该是就是目标进程 EPROCESS 的地址。

但是 0x28 偏移处的字段是什么呢？

这里是我之前根据 windbg 输出制作的结构体定义：

```c

typedef struct _EPROCESS {
    KPROCESS           Pcb;                                // 0x000
    // ...
} EPROCESS, * PEPROCESS;

typedef struct _KPROCESS {
    DISPATCHER_HEADER           Header;                             // 0x000
    LIST_ENTRY                  ProfileListHead;                    // 0x018
    ULONG64                     DirectoryTableBase;                 // 0x028
    // ...
} KPROCESS, * PKPROCESS;
```

可以看到，0x28 偏移处的字段就是 `DirectoryTableBase` 而这个值就是目标进程内核态 cr3 的值。

> 你可能会对"目标进程内核态 cr3"这句话有点疑惑，但是这里真的不能再说了，再说就没完了。你如果感兴趣可以去了解一下 Meltdown 和 Spectre 这两个漏洞，尤其是 Spectre，Windows 和 Linux 都因此引入了很多特殊的机制，等你看完了就明白了

至此简单的驱动就写好了。

## 功能实现

好的，现在来到了激动人心的部分，让我们来完整的实现具体的功能吧。

> 既然已经到这一步了我就不解释太多了。我想说希望进一步交流的或者愿意勘误的欢迎联系我

### 绘制代码展示

首先我们需要定义一下 CS2 的玩家类：

```rs
impl Player {
    pub fn is_valid(&self) -> bool {
        self.addr != 0
    }

    pub fn new(addr: Address) -> Player {
        Player { addr }
    }

    pub fn addr(&self) -> Address { self.addr }

    pub fn game_scene_node(&self) -> Address {
        self.addr.read(C_BaseEntity::m_pGameSceneNode).unwrap_or(0)
    }

    pub fn team(&self) -> Team {
        Team::from(self.addr.read::<i32>(C_BaseEntity::m_iTeamNum).unwrap_or(-1))
    }

    pub fn health(&self) -> i32 {
        self.addr.read(C_BaseEntity::m_iHealth).unwrap_or(0)
    }

    pub fn is_dormant(&self) -> bool {
        self.game_scene_node().read(CGameSceneNode::m_bDormant).unwrap_or(true)
    }

    pub fn foot_position(&self) -> Vector3 {
        self.game_scene_node().read(CGameSceneNode::m_vecAbsOrigin).unwrap_or_default()
    }
}
```

这里将基于偏移获取需要的值。

然后我们需要实现便捷的内存访问：

```rs
pub trait PointerChain {
    fn read_ptr(&self, offset: Offset) -> HyperResult<Address>;
    fn read<T: Copy>(&self, offset: Offset) -> HyperResult<T>;
    fn write_value<T: Copy>(&self, offset: Offset, value: T) -> HyperResult<()>;
    fn deref(&self) -> HyperResult<Address>;
    fn offset(&self, offset: Offset) -> Address;
}

impl PointerChain for Address {
    fn read_ptr(&self, offset: Offset) -> HyperResult<Address> {
        let pid = target_pid();
        if pid == 0 {
            return Err(HyperError::NotInitialized);
        }
        let hv = hypervisor().ok_or(HyperError::NotInitialized)?;
        hv.read::<Address>(pid, self.wrapping_add(offset))
    }

    fn read<T: Copy>(&self, offset: Offset) -> HyperResult<T> {
        let pid = target_pid();
        if pid == 0 {
            return Err(HyperError::NotInitialized);
        }
        let hv = hypervisor().ok_or(HyperError::NotInitialized)?;
        hv.read::<T>(pid, self.wrapping_add(offset))
    }

    fn write_value<T: Copy>(&self, offset: Offset, value: T) -> HyperResult<()> {
        let pid = target_pid();
        if pid == 0 {
            return Err(HyperError::NotInitialized);
        }
        let hv = hypervisor().ok_or(HyperError::NotInitialized)?;
        hv.write(pid, self.wrapping_add(offset), value)
    }

    #[inline]
    fn deref(&self) -> HyperResult<Address> {
        self.read_ptr(0)
    }

    #[inline]
    fn offset(&self, offset: Offset) -> Address {
        self.wrapping_add(offset)
    }
}

```

至于实体列表，可以这样实现

```rs
const MAX_CHUNK_SIZE: i32 = 64;
const CHUNK_PTR_OFFSET: i32 = 0x10;
const ENTITY_SIZE: i32 = 0x78;
const CHUNK_SIZE: i32 = 0x8;

pub unsafe fn get_all_players() -> Option<Vec<Player>> {
    let entity_list_base = get_entity_list_base();
    let list_entry = entity_list_base.read_ptr(CHUNK_PTR_OFFSET as usize).ok()?;

    let mut players = Vec::new();

    for index in 0..MAX_CHUNK_SIZE {
        if list_entry == 0 { continue; }

        let Some(controller) = list_entry.read_ptr((index * ENTITY_SIZE) as Offset).ok() else { continue };
        if controller == 0 { continue; }

        let Some(pawn_handle) = controller.read::<i32>(m_hPlayerPawn).ok() else { continue };
        if pawn_handle == 0 { continue; }

        let Some(pawn_list_entry) = entity_list_base.read_ptr((CHUNK_SIZE * ((pawn_handle & 0x7FFF) >> 9) + CHUNK_PTR_OFFSET) as Offset).ok() else { continue };
        let Some(pawn) = pawn_list_entry.read_ptr((ENTITY_SIZE * (pawn_handle & 0x1FF)) as Offset).ok() else { continue };

        if pawn == get_local_player_address() { continue; }

        let player = Player::new(pawn);

        if player.is_dormant() || player.health() <= 0 { continue; }

        players.push(Player::new(pawn));
    }

    Some(players)
}
```

根据起源引擎自己的遍历方式，我们可以仿照他进行遍历

```rs
pub struct AuroraRender;

impl AuroraRender {
    pub fn new() -> impl RenderLoop + Send + Sync {
        Self {}
    }
}

impl RenderLoop for AuroraRender {
    fn initialize(&mut self) {
        aurora_log!(trace, "RenderLoopInitializer", "initializing render loop");

        aurora_log!(info, "RenderLoopInitializer", "render loop initialized");
    }

    fn render(&mut self, draw_list: &DrawListMut, io: &Io) {
        aurora_log!(trace, "RenderLoop", "try get runtime");
        let [screen_w, screen_h] = io.display_size;
        aurora_log!(trace, "RenderLoop", "screen is: {:?}", io.display_size);

        let runtime = runtime();
        
        runtime.tick_blackboard(screen_w, screen_h);

        runtime.render_esp(draw_list, screen_w, screen_h);
    }
}
```

我们定义一个 Render 结构体，用于负责在 `start_overlay_render_loop()` 启动 RenderLoop。

然后我们可以给 Runtime 定义具体的 render 方法

```rs
impl AuroraRuntime {
    pub fn render_esp(&self, draw: &DrawListMut, screen_w: f32, screen_h: f32) {
        if !self.config.feature_flags.contains(FeatureFlags::ESP) {
            return;
        }

        let scene = scene();
        if !scene.is_renderable() {
            aurora_log!(trace, "ESP", "scene not renderable");
            return;
        }

        aurora_log!(trace, "ESP", "entering esp area...");

        let camera = scene.camera;
        if !camera.is_valid() {
            return;
        }

        let local = scene.local_player;

        let blackboard = blackboard();
        for board in blackboard.entities() {
            if !board.is_valid {
                continue;
            }

            let entity = board.entity;
            if !self.should_show_character(&entity) {
                continue;
            }

            let Some(dist) = board.distance else { continue };
            let Some(foot_screen) = board.foot_screen else { continue };
            let Some(head_screen) = board.head_screen else { continue };

            let color = if entity.team() == local.team() {
                [0.0, 1.0, 0.0, 1.0]
            } else {
                [1.0, 0.0, 0.0, 1.0]
            };

            // 只有脚部在屏幕内才进行后续绘制
            if foot_screen.x < 0.0 || foot_screen.x > screen_w
                || foot_screen.y < 0.0 || foot_screen.y > screen_h
            {
                continue;
            }

            let height = (foot_screen.y - head_screen.y).abs();
            let width = height * 0.4;

            self.render_box(draw, foot_screen, head_screen, color, width);
        }
    }

    fn render_box(
        &self,
        draw: &DrawListMut,
        foot_screen: Vector2,
        head_screen: Vector2,
        color: [f32; 4],
        width: f32,
    ) {
        if !self.config.vision_flags.contains(VisionFlags::SHOW_BOX) {
            return;
        }


        draw.add_rect(
            [foot_screen.x - width * 0.5, head_screen.y],
            [foot_screen.x + width * 0.5, foot_screen.y],
            color,
        )
            .thickness(1.5)
            .rounding(2.0)
            .build();
    }
}
```

在 `render_box()` 中由于我们准备工作极其充分，所以我们只需要简单地将将坐标传给他就好了。

那么最后的效果是...

### 离线

![](https://img.halfcity.top/2026/08/08/a4d54fcd46d0acaa152f0467a771e5c2.avif)

![](https://img.halfcity.top/2026/08/08/72ffefeb1b095f0880b879b7f468fb20.avif)

### 在线

![](https://img.halfcity.top/2026/08/08/ad6c28504d0b7c3de4e8418eae8b6933.avif)

![](https://img.halfcity.top/2026/08/08/2994681410c965fcf2a633aaefffa371.avif)

有时不禁感叹为了几个框至于吗...

## 附

> 你可能发现了，我这在线的图为啥和离线的图不太一样？

那肯定是因为我添加了一些有趣的新功能啊。不过，都是一些锦上添花的东西啦。

限于篇幅，再讲述有关 ARK 或者 Hypervisor 部分的实现就显得过于长了。

所以这里就先不讲有关 rage 功能的内容了，比如 aimbot、spinbot、slientaim、triggerbot 之类的东西。

目前 ESP 的实现已经基本满足本文的目的了。给一段路画一个句号吧。

这里我依旧要强调一下本文学术的目的，即使我确信你明白 `声明` 中的内容。

至此本文完，感谢你的阅读。

## 引用

[1] Ingex. imgui-rs-overlay. https://github.com/lngex/imgui-rs-overlay
