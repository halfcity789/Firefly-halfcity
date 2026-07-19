---
title: DriverVer set to a date in the future - Solution
description: 解决报错 DriverVer set to a date in the future
published: 2026-07-17
category: 问题解决
tags: [Visual Studio 2026, WDM, Inf2Cat, StampInf]
pinned: false
draft: false
image: https://img.halfcity.top/2026/07/17/93e776af9790ec5b04f7f68ea67df525.avif
---

## 问题

```txt
1>  正在生成代码...
1>  Sparkle.vcxproj -> D:\data\code\projects\Sparkle\x64\Debug\Sparkle.sys
1>  Done Adding Additional Store
1>  Successfully signed: D:\data\code\projects\Sparkle\x64\Debug\Sparkle.sys
1>
1>  ........................
1>  Signability test failed.
1>
1>  Errors:
1>  22.9.7: DriverVer set to a date in the future (postdated DriverVer not allowed) in Sparkle\sparkle.inf.
1>
1>  Warnings:
1>  None
1>x64\Debug\inf2catOutput.log : Inf2Cat error -2: "Inf2Cat, signability test failed." Double click to see the tool output.
```

莫名其妙出现的问题，`DriverVer` 填过去、现在、未来都不行，气笑了。

## Inf2Cat

默认使用的是 `UTC +00:00` 也就是世界协调时作为基准。

但是如果你不是英国人，比如你在 `UTC +08:00` 时区，它就会认为你将时间设置在了未来的八小时...

也就是说如果你是在 `UTC +08:00` 时区的凌晨 0 点到早上 8 点之间编译的，此时你的本地时间是 7月17日，但 UTC 时间还是 7月16日。

StampInf 写入的是未来的 17号，而 Inf2Cat 默认参考 UTC 认为今天是 16号，于是判定 17号是 `未来的日期` ，立即报错。

我之前恰好没有在这个时间段编译，反而没事。

## 解决

点击项目属性，将 `Inf2Cat` 中 `Use Local Time` 选择 `是 / Yes`

![](https://img.halfcity.top/2026/07/17/93e776af9790ec5b04f7f68ea67df525.avif)

```txt
1>  Sparkle.vcxproj -> D:\data\code\projects\Sparkle\x64\Debug\Sparkle.sys
1>  Done Adding Additional Store
1>  Successfully signed: D:\data\code\projects\Sparkle\x64\Debug\Sparkle.sys
1>
1>  .........................
1>  Signability test complete.
1>
1>  Errors:
1>  None
1>
1>  Warnings:
1>  None
1>
1>  Catalog generation complete.
1>  D:\data\code\projects\Sparkle\x64\Debug\Sparkle\sparkle.cat
1>  Done Adding Additional Store
1>  Successfully signed: D:\data\code\projects\Sparkle\x64\Debug\Sparkle\sparkle.cat
```

## 附

偶然有兴致，结果熬夜还要被微软制裁。

我看了一下，这个问题似乎还是古董级的？

真不不得不再说一句，微软自己项目的模版给的默认配置都能出问题，这真是没话说了...
