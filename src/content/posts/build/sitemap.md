---
title: 通过Sitemap将博客接入搜索引擎
description: 新站建好后一般都无法通过搜索引擎搜到自己的网站，此时就需要通过一些方式让搜索引擎知道这个站的存在
published: 2026-06-29
updated: 2026-06-29
category: 其他
tags: [部署, 演示]
pinned: false
draft: false
---

## 检查搜索引擎

新站建好我，我们肯定是要到搜索引擎看看自己的站，这里来谷歌搜一下

![Google搜索](https://img.halfcity.top/2026/06/84eb890a5e8d8acdc6a18777849f3729.avif)

什么！这里可以看看谷歌完全不认识我们的网站，这是怎么回事？

> Google 的搜索机器人，也就是大家常说的爬虫，工作内容其实很简单：持续在网上巡逻，通过页面之间的超链接，从一个页面跳到下一个，把发现的新内容记录下来、加入 Google 的索引数据库。你在 Google 搜索到的每一条结果，背后都是爬虫先爬过、Google 再判断排名的成果。

> 但它有个盲点：它只会沿着链接走。没有链接指向的地方，它不会主动去找。

> 所以如果你是刚上线的新站，网上还没有任何人链接到你，爬虫根本不知道你的存在，更不知道你有几个页面。要等谷歌自然搜索到一个新站，可能要几天，但更可能是好几个月。

所以这个时候我们最好主动提交Sitemap，让自己的网站加入索引

## 什么是Sitemap

> **Sitemap（站点地图）**是一个包含网站上所有重要页面 URL 的文件（通常为 XML 格式）。它就像是一份专门给搜索引擎爬虫（如 Googlebot、Bingbot）阅读的**“网站导游路线图”**，清晰地告诉搜索引擎你的网站有哪些页面、这些页面什么时候更新过，以及它们之间的重要性排序。

### Sitemap 对新站的核心作用

对于一个没有任何外部链接、处于“孤岛”状态的新网站来说，Sitemap 具有至关重要的加速和优化作用：

* **加速收录：** 搜索引擎通常是顺着其他网站的链接来发现新站的。新站往往缺乏外部链接（外链），爬虫很难主动找到你（这也是友链的作用之一，提高网站权重）。直接向搜索引擎提交 Sitemap，等于直接把网址交到搜索引擎手里，**主动邀请它来抓取**。
* **确保深层页面被发现：** 新站的权重较低，爬虫在其上停留的时间和抓取深度非常有限。如果你的网站结构较深（例如：首页 $\rightarrow$ 分类 $\rightarrow$ 子分类 $\rightarrow$ 文章），爬虫可能还没走到深层页面就离开了。Sitemap 可以让爬虫**直达所有深层 URL**，避免留下抓取死角。
* **提高抓取与更新效率：** 建立新站时，你可能会频繁修改或发布新内容。Sitemap 中的 `<lastmod>`（最后修改时间）标签会提示爬虫哪些页面是新产生的或刚刚被修改过的，引导爬虫**优先、高效地抓取变动内容**，而不是盲目重爬旧页面。

Sitemap文件通常叫 `sitemap.xml` 或者索引文件 `sitemap-index.xml` 位于网站根目录下

这个就是一个Sitemap文件，它包含了下一个索引的路径

```xml
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <sitemap>
        <loc>https://blog.halfcity.top/sitemap-0.xml</loc>
    </sitemap>
</sitemapindex>
```

## 提交Sitemap到谷歌

我们到这里[Google Search Console](https://search.google.com/search-console/welcome)来进行提交验证

![Welcome](https://img.halfcity.top/2026/06/8ef05a3cec95ada18945990e72a4b4d7.avif)

输入自己的域名

![Domain](https://img.halfcity.top/2026/06/176e6424709c5d6797ffe0834b4ff436.avif)

到自己的DNS处添加一个TXT记录，名称根据谷歌的提示写

![Verify](https://img.halfcity.top/2026/06/f8e8f170a6433e36de97b6ab7f60f98b.avif)

这里我使用的是Cloudflare

![DNS](https://img.halfcity.top/2026/06/d656e470a8937b3b9d7ecf2288cc8d9b.avif)

等待一会点击 `VERIFY` 即可

![OK](https://img.halfcity.top/2026/06/cf8ed03c282a781ba5677c019c0ca7f0.avif)

在这里可以添加自己的Sitemap

![Console](https://img.halfcity.top/2026/06/0a637a8805986cfeea9d6b46bd3ffea5.avif)

![Submit](https://img.halfcity.top/2026/06/48eca2de3b9405921b67e1f71064e578.avif)

## 提交Sitemap到必应

前往这里[Bing Master Tool](https://www.bing.com/webmasters)添加自己的域

![Bing Console](https://img.halfcity.top/2026/06/77a9fb731af89dd22b0079d88b4d5efe.avif)

添加一个CNAME到DNS点击验证即可

![OK](https://img.halfcity.top/2026/06/267bcd075aa775d15c01032187f8ebd9.avif)

![Submit](https://img.halfcity.top/2026/06/08c9e5140b4dd36f562e6a8fa850ce78.avif)

这里就添加好了自己的Sitemap了
