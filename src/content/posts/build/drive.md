---
title: 基于Cloudflare搭建自己的云盘
description: 这里将会详细讲讲如何搭建自己的个人云盘，空间有限但也足够。
published: 2026-07-08
category: 部署
tags: [CLoudflare, 云盘]
pinned: false
draft: false
---

## 准备

- 需要已经开通过了R2服务，如果没有开通的就需要先绑个卡
- 准备一个域名，可以托管到Cloudflare即可

## 配置CList

### 获取CList

到这里将库clone到本地：

::github{repo=ooyyh/Cloudflare-Clist}

### 创建D1数据库

点击 `数据与存储` 然后选择 `D1数据库`。

点击创建，选择亚太地区，取一个名字即可。

![](https://img.halfcity.top/2026/07/08/faf81ce67af1ed39b3c8c7983d454ed2.avif)

### 初始化D1数据库

到这里找到 `schema.sql` 这个文件：

![](https://img.halfcity.top/2026/07/08/d17ff2d379cc05e7e275dd6c2dfb478a.avif)

将里面的内容粘出来贴到D1的Console里面执行：

![](https://img.halfcity.top/2026/07/08/3290c81055b2b27b67f6c029851e7740.avif)

![执行后](https://img.halfcity.top/2026/07/08/0fb850e4212ee197ab1569abf97c51ac.avif)

### 修改本地配置

```json
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "clist",
  "main": "./workers/app.ts",
  "compatibility_date": "2025-04-04",
  "vars": {
    "VALUE_FROM_CLOUDFLARE": "Hello from Cloudflare",
    "ADMIN_USERNAME": "admin",
    "ADMIN_PASSWORD": "changeme",
    "SITE_TITLE": "CList",
    "SITE_ANNOUNCEMENT": "Welcome to CList storage service!",
    "CHUNK_SIZE_MB": "10",
    "WEBDAV_ENABLED": "false",
    "WEBDAV_USERNAME": "webdav",
    "WEBDAV_PASSWORD": "changeme"
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "clist",
      "database_id": "00000000-0000-0000-0000-000000000000",
      "migrations_dir": "./migrations"
    }
  ]
}
```

这里创建一个 `wrangler.jsonc` 文件，将这里的内容中的内容复制进去，然后将D1的UUID改成自己的。

### 部署

```bash
pnpm install
pnpm wrangler login
pnpm run build
```

> [!NOTE]
> 这里的 `pnpm wrangler login` 需要浏览器中授权。

执行部署即可：

```bash
pnpm wrangler deploy
```

> [!WARNING]
> 部署完一定到记得到Cloudflare修改 `clist` 这个worker的环境变量
> 将里面的admin用户的用户名、密码修改一下

这里登出：

```bash
> pnpm wrangler logout

 ⛅️ wrangler 4.107.0 (update available 4.108.0)
───────────────────────────────────────────────
Successfully logged out.
```

## 连接R2

### 新建Bucket

在Cloudflare中创建一个新的存储桶 `drive`

### 连接Bucket

登录CList页面，点击左上角的 `+` 号

![](https://img.halfcity.top/2026/07/08/90adc19ee4e265519165c7bd3b7abe5d.avif)

创建一个新的R2 Token，将里面的Endpoint/AccessKey/SecretKey记下来。

连接自己的Bucket即可。

![](https://img.halfcity.top/2026/07/08/b3276a802714f400d0ccef6e60711c9b.avif)
