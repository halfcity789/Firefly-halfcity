---
title: 深入讨论现代邮件服务如何防范邮件钓鱼攻击
description: 本文会从协议设计缺陷讲起，梳理邮件格式本身的一些机制如何被滥用，再谈现代邮件服务商用 SPF、DKIM、DMARC 打的这套补丁，最后聊聊其他相关协议(IMAP/POP3)、常见攻击手段，以及目前比较完整的缓解方案。
published: 2026-07-02
category: 红队
tags: [邮件钓鱼, 邮件, SMTP, IMAP, POP3, 实战]
pinned: false
draft: false
image: https://img.halfcity.top/2026/07/02/24c7e56e682560a6c7523d00a770f380.avif
---

> 邮件钓鱼是一个老生常谈的话题了，但是邮件钓鱼究竟能够做到什么程度呢？

## 钓鱼邮件

如图，这是我以前改造的钓鱼文件，发送到自己的邮箱用于测试

![](https://img.halfcity.top/2026/07/02/24c7e56e682560a6c7523d00a770f380.avif)

![](https://img.halfcity.top/2026/07/02/380abd508d179b4064c96101b8e29fed.avif)

可以看到，这里的邮件看起来就像是崩铁官方发的，但是点击点击链接后就会跳转到钓鱼网站了

实际上这里通过这两个工具实现的，它利用了STMP设计上的缺陷，进而实现的伪装

::github{repo=xiecat/goblin}
::github{repo=gophish/gophish}

## SMTP 协议

### SMTP 协议是什么？

电子邮件是互联网上少数几个"活化石"级别的服务之一。今天我们收发邮件所依赖的核心协议 SMTP(Simple Mail Transfer Protocol)，其最初的规范 [RFC 821](https://www.rfc-editor.org/rfc/rfc821) 诞生于 1982 年——那是一个互联网还只是少数科研机构互相信任的封闭网络的年代。

这个"设计于信任年代"的协议，至今仍是全球邮件系统的骨架。而它身上大部分安全问题的根源，几乎都可以归结为一句话:**SMTP 从设计之初就没有考虑过"发件人可能在撒谎"这件事**。

### SMTP 协议本身的设计缺陷

#### 缺乏合理的身份认证

SMTP 的核心交互非常简单，一个典型的会话大概长这样:

```txt
HELO mail.attacker.com
MAIL FROM:<ceo@bigcompany.com>
RCPT TO:<victim@target.com>
DATA
From: "CEO" <ceo@bigcompany.com>
To: victim@target.com
Subject: 紧急转账

...正文...
.
QUIT
```

注意到问题了吗?**`MAIL FROM` 这个字段完全是发送方自己声明的，协议本身没有任何机制去验证它。** 这就好比寄一封信，信封上写谁的地址都行，邮局不会去核实寄信人身份——SMTP 服务器默认信任对端说的每一句话。

这是 SMTP 最根本的原罪:它诞生于一个"参与者都是可信节点"的封闭网络假设下，压根没有为身份伪造这种情况设计防御机制。

简单来讲，STMP的报文中维护了两套发件人，一个是给服务器看的，而另一个是给人看的，而这个给人看的部分是可以随便修改的，这里后面会谈到。

#### 明文传输

原始的 SMTP 是纯明文协议。用户名、密码(如果用了 AUTH)、邮件正文，理论上都可以在传输链路上被中间人截获。后来通过 [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207) 引入了 `STARTTLS` 机制，让明文连接"升级"为加密连接——但这是一个**机会性加密(opportunistic encryption)**，而不是强制的。

这意味着:

- 中间人攻击者可以简单地拦截 `STARTTLS` 命令并将其剥离(俗称 **STRIPTLS 攻击**)，迫使双方退回明文通信，而通信双方往往察觉不到。
- 即便双方都支持 TLS，也不代表证书会被严格校验——很多 MTA(Mail Transfer Agent 负责在 SMTP 协议层面接收、路由、转发邮件的服务端程序,是整个邮件系统的核心节点) 出于兼容性考虑，对 STARTTLS 的证书验证是宽松的甚至不验证的。

#### 开放中继与信任传递模型

早期互联网上大量邮件服务器都是"开放中继"(Open Relay)——任何人都可以借助这台服务器转发邮件到任意目的地。这在协议设计上是被允许的，因为 SMTP 的设计初衷就是"节点之间互相转发、逐跳传递"(Store-and-Forward)。

这套信任传递模型的问题在于:**邮件每经过一跳，接收方只能验证上一跳给它的信息，而无法验证最初的发件人身份。** 攻击者只需要找到一台配置不当的开放中继或者自己搭建 MTA，就可以伪造任意发件人身份群发邮件。

#### 没有完整性校验

SMTP 协议本身不保证邮件内容在传输过程中未被篡改。哪怕通过了 TLS 加密的链路，那也只是保证了"点对点"这一跳的机密性，一旦经过多跳转发(邮件经常会被多个 MTA 转发)，内容的完整性和真实性在协议层面完全没有保障。

---

### 邮件格式与语言层面的特殊性

除了传输层的问题，邮件消息本身的格式设计(RFC 5322 + MIME)也留下了不少可被利用的空间。

#### Envelope 与 Header 的分裂

这是理解邮件伪造攻击的关键点，也是很多人容易忽略的细节。**一封邮件其实有两个"发件人地址"**:

| 层面 | 字段 | 定义于 | 用户是否可见 |
|---|---|---|---|
| Envelope(信封) | `MAIL FROM` | RFC 5321 | 不可见，仅用于 SMTP 会话与退信(bounce) |
| Header(信头) | `From:` | RFC 5322 | 客户端展示给用户看的发件人 |

这两者**完全可以不一致**，而且协议并不强制要求它们一致。SPF 验证的是 Envelope From，普通用户在邮件客户端里看到的却是 Header From——这个"验证的字段"和"用户看到的字段"不一致，正是很多钓鱼邮件能够"通过 SPF 检查但发件人显示依然是伪造的"这种诡异现象的根源。DMARC 后面要做的核心事情之一，就是把这两者对齐起来。

#### MIME 编码带来的混淆空间

邮件正文和头部字段支持多种编码(Base64、Quoted-Printable、各种字符集)，这本是为了兼容非 ASCII 语言设计的([RFC 2047](https://www.rfc-editor.org/rfc/rfc2047))，但也带来了:

- **同形异义字攻击(Homograph Attack)**:利用 Unicode 中形近字符(比如西里尔字母的 "а" 和拉丁字母的 "a")伪造域名或显示名，让 `pаypal.com`(其中 а 是西里尔字母)在视觉上与 `paypal.com` 几乎无法区分。
- **头部注入(Header Injection)**:如果应用程序在拼接邮件头时没有正确过滤换行符(`\r\n`)，攻击者可以在看似普通的输入字段(比如网页表单里的"你的邮箱")中注入额外的邮件头，插入抄送、修改主题，甚至注入完整的新邮件体。
- **显示名欺骗**:`From: "PayPal Support" <random123@evil-domain.com>` 这种写法完全合法，大部分邮件客户端默认只展示显示名而隐藏真实地址，极大增加了钓鱼的迷惑性。

#### SMTP Smuggling

值得一提的是，2023 年安全研究者披露的 **SMTP Smuggling** 攻击，利用了不同 MTA 实现对"邮件结束符"(`<CR><LF>.<CR><LF>`)解析的细微差异——类似 HTTP Request Smuggling 的思路。攻击者可以构造特殊的数据序列，让接收端的 MTA 把一条数据流"走私"解析成两封独立的邮件，从而绕过 SPF 校验伪造发件域。这说明即便是运行了几十年的老协议，解析层面的实现差异依然能带来新的攻击面。

---

## SMTP 协议的补丁 - SPF/DKIM/DMARC

针对上面这些问题，业界逐步建立了一套"三件套"式的邮件认证体系。三者各自解决不同的问题，组合起来才形成完整闭环。

### SPF(Sender Policy Framework)—— 验证"谁有权发信"

SPF([RFC 7208](https://www.rfc-editor.org/rfc/rfc7208))的思路很直接:域名所有者在 DNS 里发布一条 TXT 记录，声明"哪些 IP 地址有权代表本域名发送邮件"。

```
example.com.  TXT  "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all"
```

接收方 MTA 在收到邮件时，拿 **Envelope From(`MAIL FROM`)对应的域名**去查 SPF 记录，再比对当前连接的源 IP 是否在授权列表内。`-all` 表示严格拒绝未授权 IP，`~all` 表示软失败(标记但不拒绝)，也就是建议放垃圾箱。

**SPF 的局限性:**

- 只验证 Envelope From，不管 Header From，所以前面提到的"两个发件人"问题依然存在——邮件可以在 Envelope 层用一个授权域名通过 SPF，而在用户看到的 Header From 里显示成完全不同的伪造域名。
- 邮件被转发(Forwarding)时会破坏 SPF，因为转发后的源 IP 变成了转发服务器的 IP，而不是原始授权 IP。
- DNS 查询次数有上限(10 次)，复杂的 `include` 链容易超限失效。

### DKIM(DomainKeys Identified Mail)—— 验证"内容有没有被篡改"

DKIM([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376))走的是密码学签名的路子。发送方用私钥对邮件的部分头部和正文做签名，并把公钥发布在 DNS 里:

```
selector1._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIGfMA0GCSq..."
```

邮件头里会带上类似这样的签名字段:

```
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
  h=from:to:subject:date; bh=...; b=...
```

接收方用 DNS 里公开的公钥验证签名，只要邮件在传输过程中被篡改，签名校验就会失败。

**DKIM 的意义:** 它解决的是**完整性和来源真实性**问题，而且天然对转发友好——因为签名跟着邮件内容走，不依赖源 IP，转发后依然有效(前提是转发过程没有修改被签名的字段)。

**DKIM 的局限性:** 同样，它验证的是签名里 `d=` 声明的域名，这个域名**不一定**等于用户看到的 Header From 域名——攻击者完全可以用自己合法注册的域名(比如 `d=evil-but-legit.com`)正确签名一封邮件，而把 Header From 伪装成别的域名。

### DMARC(Domain-based Message Authentication, Reporting & Conformance)—— 把SPF和DKIM结合在一起

DMARC([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489))它本身不做新的验证，而是一层**策略与对齐(Alignment)机制**，建立在 SPF 和 DKIM 之上:

```
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; adkim=s; aspf=s"
```

DMARC 做两件核心的事:

1. **对齐检查(Alignment)**:强制要求 SPF 或 DKIM 验证通过所对应的域名，必须与用户实际看到的 **Header From 域名**一致(严格模式 `s` 要求完全一致，宽松模式 `r` 允许子域名匹配)。这一步直接堵上了前面提到的"Envelope 和 Header 分裂"漏洞。
2. **策略声明**:域名所有者可以声明当验证失败时接收方应该怎么处理——`p=none`(仅监控不处理)、`p=quarantine`(打入垃圾邮件)、`p=reject`(直接拒收)。
3. **聚合报告(Aggregate Reports)**:通过 `rua` 字段，域名所有者能定期收到全球各大邮件服务商发来的 XML 报告，了解自己域名被冒用的情况——这也是很多企业发现自己域名被拿去钓鱼的主要途径。

**关键点:只要 SPF 或 DKIM 中有一个通过验证并且与 Header From 对齐，DMARC 就算通过**，这也是为什么 DKIM 对转发场景特别重要——转发经常会破坏 SPF，但只要 DKIM 签名还有效，DMARC 依然能过。

---

## IMAP/POP3 协议

既然聊到邮件安全，不能不提用户实际收信用的协议——IMAP 和 POP3，它们和 SMTP 出自同一个时代，有着相似的问题。

- **明文认证问题**:早期的 IMAP(端口 143)/POP3(端口 110)同样是明文协议，`LOGIN` 命令直接明文传输用户名密码。解决方式和 SMTP 类似，要么用 STARTTLS 升级(同样存在被剥离的风险)，要么直接用隐式 TLS 端口(IMAPS 993 / POP3S 995，连接建立时就强制走 TLS，不给降级机会，这也是目前推荐的做法)。
- **缺乏消息来源验证**:IMAP/POP3 是用户"拉取"邮件的协议，它们本身不涉及邮件真实性的判断——这部分工作已经在邮件到达邮箱之前，由 MTA 通过 SPF/DKIM/DMARC 完成了。也就是说 IMAP/POP3 层面能做的更多是"传输安全"，而不是"内容真实性"。
- **认证方式的演进**:早年 IMAP 常用明文密码或者 CRAM-MD5，现在主流服务商(Gmail、Outlook)已经强制迁移到 OAuth2 授权，不再允许"应用密码"级别的明文认证方式，这也是应对撞库/爆破攻击的重要一环。

---

## 常见攻击手段与对应缓解措施

结合以上原理，梳理几种典型攻击及现实中的应对手段:

### 邮件伪造 / 域名仿冒(Email Spoofing)

**手法**:伪造 Header From，冒充可信域名发信，常见于钓鱼和商业邮件诈骗(BEC，Business Email Compromise)。

**缓解**:
- 域名侧部署完整的 SPF + DKIM + DMARC(`p=reject`)，而不是只配置其中一项。
- 收件侧的邮件网关严格执行 DMARC 策略校验，而不仅仅是记录日志。

### 相似域名钓鱼(Lookalike Domain / Typosquatting)

**手法**:注册形近域名(`paypa1.com`、`micros0ft.com`，或利用 IDN 同形字如 `xn--` 编码的国际化域名)冒充品牌方。

**缓解**:
- DMARC 只能保护自己拥有的域名，防不住别人注册的相似域名——这类攻击需要额外的品牌监控服务(Brand Protection)和 IDN 同形字检测。
- 部署 **BIMI**(Brand Indicators for Message Identification)，在邮件客户端展示经过验证的品牌 Logo，增加用户对真实邮件的辨识度(前提是 BIMI 要求域名已经有严格执行的 DMARC 策略，间接推动了 DMARC 的落地)。

值得一提的是这个手法一般是最普遍的，因为它直接对用户进行攻击，对于相似域名其本身没有错误，所以对于可能的攻击最多也只能警告而不能阻止。而一些Unicode字符是真的特别像，基本可以说一模一样，比如a这个字符，是绝对的重灾区。

### 中间人降级攻击(STARTTLS Stripping)

**手法**:攻击者在网络链路上拦截并剥离 STARTTLS 协商，迫使双方退化为明文通信。

**缓解**:
- **MTA-STS**([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)):域名可以发布策略，强制声明"我的邮件服务器必须支持 TLS，如果协商失败就拒绝投递"，避免被动降级为明文。
- **TLS-RPT**:配合 MTA-STS 使用，收集 TLS 连接失败的报告，帮助域名管理者发现潜在的降级攻击。

### SMTP Smuggling / 协议解析差异攻击

**手法**:利用不同 MTA 实现对消息边界解析的不一致，走私伪造邮件绕过验证。

**缓解**:
- 及时更新 MTA 软件版本(Postfix、Exim、Sendmail 等主流实现在披露后均发布了补丁)。
- 邮件网关侧严格规范化处理消息结束符，不依赖单一实现的"宽容解析"行为。

### 邮箱账户层面的攻击(撞库、爆破、会话劫持)

**手法**:针对邮箱账户本身的凭证攻击，而非协议层攻击。

**缓解**:
- 强制 MFA(多因素认证)。
- 强制使用 OAuth2 替代明文密码认证 IMAP/POP3/SMTP AUTH。
- 异常登录行为检测(异地登录、异常客户端指纹等)。

---

## 实战：崩铁验证码邮件
 
这是一封崩铁发到我找的一个临时邮箱的验证码邮件。

```html
Received: from b224-57.smtp-out.eu-central-1.amazonses.com ([69.169.224.57]) by temporary-mail.net
  for <pbagh_80@linshiyouxiang.net>; Fri, 03 May 2024 19:06:21 +0800 (CST)
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple;
	s=z2mre34myvrrloskpe2opf2lrm5wzf5v; d=email.hoyoverse.com;
	t=1714734379;
	h=From:To:Subject:MIME-Version:Content-Type:Content-Transfer-Encoding:Message-ID:Date;
	bh=sIIm+qQLfBuP3fC7zFlcQCNqseDzqxsNOwom2Iqwyeo=;
	b=KQhK63XadBdsJdC17H1nsdW5WZoHrplXFX8n5bW9JZpuXS2TNqSquKYJX7xPgTfR
	Hi/k2C0yqJFu9timIJ9n2o31wsaugrXm0fuQNjbPFdCq/yCMhw9yFEFoIESjBUhPKAd
	C3Wn2BnJgSmi+SqLJfE6tGg7c0pVpNtyPOKpAPifEGSzgy2YBCr+fjW7RIUQbaQxyuL
	Qec4gP5YsOAovOSPr5cZ5KkFePsh2IE5mpumMxsnQUtIuMRMr3NjcJW6Lv7HAov/U1a
	jdsXYJ28Vjg2e1RvH14Yvbx8Uw+Wqxc8vTKOmpM+ht/DiX0CQAwJaSCfU4vlY6X0IlH
	z/ON9SxRSg==
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple;
	s=qftdzk2dqsatjnlrq4r5brjbihpfcrsh; d=amazonses.com; t=1714734379;
	h=From:To:Subject:MIME-Version:Content-Type:Content-Transfer-Encoding:Message-ID:Date:Feedback-ID;
	bh=sIIm+qQLfBuP3fC7zFlcQCNqseDzqxsNOwom2Iqwyeo=;
	b=GqDuT35C3BXc57PQNuIfiee6cj5EvEq/qxsZwABKDamDf56mBa+fpHfBG7Dhp4s+
	9Cm7YGwRsnQMoVOmMy7+IhGMMOjlH7xH4Vcqu03EfWgLk7r8FOtKUfj4OzgJMFc4sAo
	gtFbIw9wfTig/qea9R/LCsK1ijgjdVtgP2AsXWgw=
From: noreply@email.hoyoverse.com
To: pbagh_80@linshiyouxiang.net
Subject: =?UTF-8?Q?163438_=E6=98=AF=E4=BD=A0=E7=9A=84_H?=
 =?UTF-8?Q?oYoverse_=E9=AA=8C=E8=AF=81=E7=A0=81?=
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable
Message-ID: <0107018f3e2230e3-ef6df90c-6ca7-4c2d-8169-e6f79c36923e-000000@eu-central-1.amazonses.com>
Date: Fri, 3 May 2024 11:06:19 +0000
Feedback-ID: 1.eu-central-1.UWouZqoBaiztqjED148NZ8ZPd8bqYYeH8NDBxUps/7k=:AmazonSES
X-SES-Outgoing: 2024.05.03-69.169.224.57

<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dutf-8"></=
meta>


<title>HoYoverse Passport</title>
<style>
  .co_org {
    color: #e99b00;
  }

  .mess {
    width: 690px;
    overflow: hidden;
    padding: 30px;
    background: #fcfbfb;
    border: 1px solid #eaeaea;
  }

  .mess a {
    width: 200px;
    color: #0000ff;
    text-decoration: underline;
    line-height: 16px;
    word-warp: break-warp;
    word-break: break-all;
  }

  .mess a:hover {
    text-decoration: none;
  }

  .mess h3 {
    margin: 30px 0px 20px 0px;
    font-size: 16px;
  }

  .mess h4 {
    color: #b6b6b6;
  }

  .mess p {
    color: #333;
    line-height: 25px;
  }

  .mess_bot {
    margin-top: 50px;
  }

  .mess_bot h5 {
    color: #777;
    border-top: 1px solid #666;
    margin-top: 5px;
    margin-bottom: 10px;
    padding-top: 5px;
  }
</style>


<div class=3D"mess">
  <img width=3D"150px" src=3D"https://webstatic-sea.hoyoverse.com/upload/st=
atic-resource/2022/01/11/747ab8eb3a68ca50fbff6f74e1269d62_16984850334921014=
80.png" />
  <h3><span style=3D"color: rgb(0, 0, 0); font-size: 15px;">Hi=EF=BC=8C=E4=
=BA=B2=E7=88=B1=E7=9A=84=E7=8E=A9=E5=AE=B6</span></h3>
  <span style=3D"color: rgb(0, 0, 0); font-size: 15px;"> </span>
  <p><span style=3D"color: rgb(0, 0, 0); font-size: 15px;">=E6=82=A8=E6=AD=
=A3=E5=9C=A8 =E6=B3=A8=E5=86=8CHoYoverse=E9=80=9A=E8=A1=8C=E8=AF=81=E8=B4=
=A6=E5=8F=B7=EF=BC=8C=E9=AA=8C=E8=AF=81=E7=A0=81=E4=B8=BA=EF=BC=9A</span><s=
pan style=3D"color: rgb(0, 0, 0);"><strong><span style=3D"color: rgb(78, 16=
4, 220); font-size: 15px;">163438</span></strong><span style=3D"font-size: =
15px;">=E3=80=82</span> </span>
  </p>
  <span style=3D"color: rgb(0, 0, 0); font-size: 15px;"> </span>
  <p class=3D"m_top50"><span style=3D"color: rgb(0, 0, 0); font-size: 15px;=
">=E8=AF=B7=E5=9C=A830=E5=88=86=E9=92=9F=E5=86=85=E5=AE=8C=E6=88=90=E9=AA=
=8C=E8=AF=81=E3=80=82</span></p>
  <span style=3D"color: rgb(0, 0, 0); font-size: 15px;"> </span>
  <div class=3D"mess_bot">
    <span style=3D"color: rgb(0, 0, 0); font-size: 15px;"> </span>
    <p><span style=3D"color: rgb(0, 0, 0); font-size: 15px;">HoYoverse</spa=
n></p>
    <span style=3D"color: rgb(0, 0, 0);"> </span>
    <h5><span style=3D"color: rgb(119, 119, 119); font-size: 13px;">=E6=AD=
=A4=E4=B8=BA=E7=B3=BB=E7=BB=9F=E9=82=AE=E4=BB=B6=EF=BC=8C=E8=AF=B7=E5=8B=BF=
=E5=9B=9E=E5=A4=8D=E3=80=82</span></h5>
  </div>
</div><img alt=3D"" src=3D"https://kr77p6wi.r.eu-central-1.awstrack.me/I0/0=
107018f3e2230e3-ef6df90c-6ca7-4c2d-8169-e6f79c36923e-000000/JRNCwzj9X0kuS4H=
nD-T4hkhIgH0=3D153" style=3D"display: none; width: 1px; height: 1px;">
```

接下来来对它进行分析。
 
### Received 头 - 一次转发链路的快照
 
```
Received: from b224-57.smtp-out.eu-central-1.amazonses.com ([69.169.224.57]) by temporary-mail.net
  for <pbagh_80@linshiyouxiang.net>; Fri， 03 May 2024 19:06:21 +0800 (CST)
```
 
这条 `Received` 头是接收方 MTA(`temporary-mail.net`，就是我临时邮件网站的网址)自己写入的，记录了"我是从哪个 IP、哪台服务器收到这封信的"。这里能看到源头是 Amazon SES 位于法兰克福区域(`eu-central-1`)的出口节点。值得注意的是，`Received` 头是**逐跳累加**的——每经过一台 MTA 就会在最上面插入新的一条，后续 MTA 只能验证"上一跳给了我什么"，你能看到的只是最近一跳的信息，没法直接验证最初的发件源头，必须依赖 SPF/DKIM 这类密码学或 DNS 层面的机制来补足。
 
### DKIM 签名
 
这封邮件里出现了两条 `DKIM-Signature`，这是通过邮件服务商(Email Service Provider，这里是 Amazon SES)群发邮件时的典型模式:
 
```
DKIM-Signature: ... s=z2mre34myvrrloskpe2opf2lrm5wzf5v; d=email.hoyoverse.com; ...
DKIM-Signature: ... s=qftdzk2dqsatjnlrq4r5brjbihpfcrsh; d=amazonses.com; ...
```
 
- 第一条 `d=email.hoyoverse.com`，是米哈游自己申请的 DKIM 密钥对邮件签的名，`selector`(`s=`)是 `z2mre34myvrrloskpe2opf2lrm5wzf5v`，对应 DNS 上的 `z2mre34myvrrloskpe2opf2lrm5wzf5v._domainkey.email.hoyoverse.com` TXT 记录。
- 第二条 `d=amazonses.com`，是 Amazon SES 基础设施自己加的签名，用来维护 SES 自身发信基础设施的信誉，和客户域名的签名相互独立。
两条签名的 `bh=`(body hash)完全一致，说明签的是同一份正文，只是分别证明"这封信确实是 email.hoyoverse.com 授权发出的"和"这封信确实经过了 Amazon SES 的正规出口"。**从 DMARC 的角度看，真正起对齐作用的是第一条**——因为 `From: noreply@email.hoyoverse.com` 里的域名和 `d=email.hoyoverse.com` 完全一致，属于严格对齐(strict alignment)，DMARC 会通过 DKIM 这一路径判定通过，不需要依赖 SPF。
 
### 用子域名收发邮件
 
细心看会发现，`From` 用的不是 `noreply@hoyoverse.com`，而是 `noreply@email.hoyoverse.com`——多了一个 `email.` 子域名前缀。这是大型互联网公司做批量邮件(验证码、营销邮件)时的常见做法，原因有二:
 
1. **信誉隔离**:批量发信(尤其是营销类)容易被反垃圾邮件系统打上较低的信誉分，如果和公司主域名共用一个发信身份，一旦触发风控，连带影响主域名下的所有邮件(比如员工的公司邮箱)。用独立子域名可以把"风险面"限制在子域名范围内。
2. **策略隔离**:主域名 `hoyoverse.com` 和子域名 `email.hoyoverse.com` 可以配置完全不同的 SPF/DKIM/DMARC 策略——主域名甚至可以直接发布一条 `v=spf1 -all` 表示"我从不发信，收到任何自称来自 hoyoverse.com 的邮件都应该拒绝"，从根源上防止主域名被拿去做 Envelope/Header 伪造，而实际发信全部收敛到专门的 `email.hoyoverse.com` 子域名下统一管理。

### 邮件头编码 (RFC 2047)
 
`Subject` 字段是这样的:
 
```txt
Subject: =?UTF-8?Q?163438_=E6=98=AF=E4=BD=A0=E7=9A=84_H?=
 =?UTF-8?Q?oYoverse_=E9=AA=8C=E8=AF=81=E7=A0=81?=
```

可以看到这里的编码咋一看直接就是Base64脱口而出，但是仔细一看会发现完全不是，那么这是什么？
 
这其实是[RFC 2047](https://www.rfc-editor.org/rfc/rfc2047) **encoded-word** 语法:`=?字符集?编码方式?内容?=`。这里字符集是 `UTF-8`，编码方式是 `Q`(Quoted-Printable 的变体，专用于头部字段，空格用下划线 `_` 表示而不是 `%20`)，把非 ASCII 字符转成 `=XX` 十六进制转义序列。因为单个头部字段行按 RFC 5322 建议不超过 78 字符，过长的主题会被拆成多个 encoded-word 片段并用折行(前导空格续行)拼接——这也是为什么 `H` 和 `oYoverse` 被硬生生断开成两段。

解码还原后其实就是一句很平常的话:
 
```txt
163438 是你的 HoYoverse 验证码
```
 
正文部分同理，`Content-Transfer-Encoding: quoted-printable` 声明了正文也用同样的转义方式编码，比如 `=E6=82=A8=E6=AD=A3=E5=9C=A8` 解码后就是"您正在"三个汉字的 UTF-8 字节被逐字节转成的十六进制转义.

这套编码本身是为了让邮件在只支持 7-bit ASCII 传输的老旧链路上也能正确传递多字节字符，是一个纯粹的兼容性设计，但也提醒我们:**邮件头和正文里出现的可读文本，很多时候并不是"所见即所得"的原始字节流**，分析可疑邮件时不能只看肉眼渲染结果，必要时要还原编码再判断，尤其是排查显示名/主题里藏有同形字或零宽字符这类花招时。
 
### Feedback-ID 与投递追踪
 
```txt
Feedback-ID: 1.eu-central-1.UWouZqoBaiztqjED148NZ8ZPd8bqYYeH8NDBxUps/7k=:AmazonSES
X-SES-Outgoing: 2024.05.03-69.169.224.57
```
 
`Feedback-ID` 是 Amazon SES 特有的头部，用于关联"投诉反馈回路"(Feedback Loop， FBL)——如果收件人点了"举报垃圾邮件"，这个 ID 能帮 SES 和发信方定位到具体是哪个发信配置/campaign 触发的投诉，是发信方管理自身发件信誉的内部工具。

`X-SES-Outgoing` 则记录了具体的出口 IP 和日期，方便排查问题时对照 SPF 记录里授权的 IP 段。这类头部不属于任何公开 RFC 标准，是各家 ESP(SendGrid、Mailgun、SES 等)自行附加的私有扩展头，分析邮件真实性时如果看到眼熟的 ESP 私有头部，也能作为一个侧面印证发信基础设施合法性的线索。
 
### 藏在正文里的追踪像素
 
正文末尾有一个不起眼的标签:
 
```html
<img alt="" src="https://kr77p6wi.r.eu-central-1.awstrack.me/I0/0107018f3e2230e3-.../JRNCwzj9X0kuS4HnD-T4hkhIgH0=153" style="display: none; width: 1px; height: 1px;">
```
 
这是经典的 **1x1 透明追踪像素**:一个尺寸为 1 像素、`display: none` 隐藏的图片请求，域名 `awstrack.me` 是 Amazon SES 打开追踪(Open Tracking)功能生成的专属跟踪域。

只要邮件客户端加载了远程图片(大部分客户端默认会自动加载)，这次请求就会告诉发信方"这封邮件在什么时间被打开了、来自什么 IP"。

这不算恶意行为，是正规 ESP 提供的营销/通知类邮件统计功能，但技术原理和钓鱼邮件里常用的"探测型追踪像素"完全一样——区别只在于用途正当与否。

这也提示了一个实用的邮件客户端安全习惯:**对不信任发件人的邮件，默认阻止自动加载远程图片**，是防止自己的"已读状态"被反向探测的一个简单有效的手段。
 
### 一点个人看法
 
如果你对Anthropic比较关注的话应该就会注意到它最近的一些新闻:

[在邮件里塞追踪器！在Claude Code中埋“暗门”！Anthropic，狗得没边了……](https://www.163.com/dy/article/L0PKSN6305568W0A.html)

[Reddit 上爆出大猛料，Claude 为何封号中国用户又快又准？](https://finance.sina.cn/tech/2026-07-01/detail-inifiaeq0909122.d.html)

<iframe width="100%" height="468" src="//player.bilibili.com/player.html?bvid=BV1VDTv6rEtM&p=1&autoplay=0" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true" &autoplay=0> </iframe>

这里不过多评价，只能说这种事谁能想到其实基本都是公司的标配呢，甚至还有专门的服务......

---

## 总结

回顾整条演进路线，可以看到一个很清晰的模式:**SMTP 的原始设计基于"参与者互相信任"的假设，而后续几十年的补丁，本质上都是在一个不做身份验证的协议上，一层层叠加身份验证机制。**

- SPF 解决了"这个 IP 有没有权限用这个域名发信"。
- DKIM 解决了"这封信的内容有没有被篡改，签名的域名是不是真的"。
- DMARC 解决了"SPF/DKIM 验证的域名，和用户实际看到的域名是不是同一个"，并给了域名所有者一个"出了问题该怎么处理"的策略声明权。
- MTA-STS/TLS-RPT 进一步解决了传输链路本身可能被降级的问题。

## 附

但即便把这一整套都部署齐全，邮件生态依然存在结构性的软肋:**这套体系是"保护发送域名"的体系，而不是"保护收件人不被欺骗"的体系。** 相似域名钓鱼、显示名伪装、社会工程学攻击，依然可以在完全遵守 SPF/DKIM/DMARC 规则的前提下发生——因为攻击者用的是自己合法拥有的域名。这也是为什么邮件安全从来不是一个纯技术问题，用户教育和品牌监控依然是整条链路里不可替代的一环。

某种意义上，SMTP 这套"打补丁"的演化史，也是互联网上很多老协议共同的宿命——设计于信任年代，却不得不在一个充满恶意的世界里继续服役。

但是众所周知计算机的世界永远是缝缝补补，现有的基础设施和企业应用包袱，无法支持一个新的现代协议取代老旧的协议，类似于SMTP协议缺陷的协议或者应用还有很多，也许今天创建的一些协议或者应用在几十年后也会被认为是不安全的，但是谁又能想到呢？

就好像几十年前的人从来没想过几十年后他们的设计依旧是现在互联网重要的基础。而过时的设计往往会导致一些意料之外又清理之中的问题(千年虫？)