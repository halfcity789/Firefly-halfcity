---
title: RFC 1179 - Line Printer Daemon Protocol 
description: 在这篇文章中将简单介绍一下 LPD 协议 - 行式打印机后台程序协议
published: 2026-07-13
category: 网络
tags: [Protocol, LPD]
pinned: false
draft: false
---

## 概述

LPD 是 BSD Unix 系统在 1990 年定义的远程打印协议，

用于客户端向打印服务器提交打印任务。

标准监听端口为 TCP/515。

> The Line Printer Daemon protocol/Line Printer Remote protocol (or LPD, LPR) is a network printing protocol for submitting print jobs to a remote printer. The original implementation of LPD was in the Berkeley printing system in the BSD UNIX operating system; the LPRng project also supports that protocol. CUPS, which is more common on modern Linux distributions and also found on macOS, supports LPD as well as the Internet Printing Protocol (IPP). Commercial solutions are available that also use Berkeley printing protocol components, where more robust functionality and performance is necessary than is available from LPR/LPD (or CUPS) alone (such as might be required in large corporate environments). The LPD Protocol Specification is documented in RFC 1179.[1]

## 核心命令

Request ID，即数据首字节

| 命令码 | 名称                          | 作用                     |
|--------|-------------------------------|--------------------------|
| 01     | Print any waiting jobs        | 触发队列打印              |
| 02     | Receive a printer job         | 接收一个打印任务（核心）   |
| 03     | Send queue state (short)      | 查询队列状态（简要）      |
| 04     | Send queue state (long)       | 查询队列状态（详细）      |
| 05     | Remove jobs                   | 删除任务                 |

## 子协议

一旦客户端发送 `\x02<queue_name>\n`，会话进入子命令循环。

每个子命令同样以首字节区分：

| 子命令码 | 名称                  | 说明                              |
|----------|-----------------------|-----------------------------------|
| 01       | Abort job              | 终止当前任务                     |
| 02       | Receive control file   | 接收控制文件（cfA...），包含任务元数据，如 'J' = job name,'P' = 用户名, 'N' = 原始文件名 |
| 03       | Receive data file      | 接收实际打印数据（dfA...）        |

每次子命令后服务端要回一个 1 字节 ACK（0x00 = 成功）。

控制文件里以字母开头的每一行代表一个字段，例如：

-  `J<job name>`
-  `P<user name>`
-  `H<host name>`

## 安全历史

LPD 因为完全没有认证机制（只信任源 IP/hostname）。

且历史实现（如 LPRng, cups-lpd）中控制文件解析出过多个已知 CVE（命令注入、路径穿越、缓冲区问题）。

是经典的老协议高风险面之一。

## 参考

[1] Line Printer Daemon protocol. Wiki. https://en.wikipedia.org/wiki/Line_Printer_Daemon_protocol
