---
title: 博客搭建过程
description: 论一个博客是如何建成的
published: 2026-06-27
updated: 2026-06-28
category: 其他
tags: [部署, 演示]
pinned: false
draft: false
---

> 感觉别人搭的博客都很好看啊...我也来搞一个吧。可惜我之前手搓的博客了，还没用多久就要再也不见天日了

这里直接我也来基于Firefly和CloudFare来搭建一个美观的博客页面

# Fork库Firefly并构建

![Project](/assets/images/blog/build/blog/image-1.png)

```bash
pnpm install
pnpm dev
```

在 **http://localhost:4321/** 就可以看到网站的效果

![Home](/assets/images/blog/build/blog/image-2.png)

可以看到，这个效果还是非常不错的。

`src/config`下面是一些Firefly的配置文件，里面可以修改一些网站的配置。

比如在 `siteConfig.ts` 这个文件中，可以修改一些基本的配置

```typescript
    // 站点标题
    title: "Halfcity Blog",

    // 站点副标题
    subtitle: "Explore • Memory • Reserve",

    // 站点 URL
    site_url: "https://firefly.cuteleaf.cn",

    // 站点描述
    description:
        "记录自己",

    // 站点关键词
    keywords: [
        "逆向",
        "AD域渗透",
        "Hypervisor",
        "游戏安全",
        "开发",
        "爬虫",
        "安全工具"
    ],
```

一些杂项的配置都可以一个个看一下改一下

# 通过Cloudflare Pages部署博客

> 忘记截图了o(╥﹏╥)o

1.首先先注册一下Cloudflare的账号，直接Github登录即可，登录后如果名字是邮箱的话，可以先修改一下账户的名字

2.登录后点击Workers & Pages，链接到Github账号并使用Firefly库的源，创建一个新的Worker，等待构建...

3.构建完成后，在上面的域选项中就可以看到Worker的URL

# 配置域名

在Cloudflare的域选项中点击连接域，连接到自己的域名

然后替换一下名称服务器，按照提示操作后稍作等待即可

# 配置SSL

在安全选项中选择SSL，概览中选中强制使用HTTPS，然后将访问策略设置成Full(strict)

最后就可以通过自己配置的域名访问网站了在`src/content/posts`下就可以写自己的文章啦
