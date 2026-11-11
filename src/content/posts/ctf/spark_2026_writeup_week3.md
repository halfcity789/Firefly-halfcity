---
title: Spark CTF 2026 Writeup (3/5)
description: 这是比赛的 Week 3 部分。
published: 2026-11-11
category: CTF
tags: [Spark CTF 2026, GoDot, 手工脱壳, 控制流平坦化, JNI, SM4]
pinned: false
draft: false
image: https://img.halfcity.top/2026/11/11/44929c2f59dbfa428a2bc7d24bbdd26c.avif
---

## Reverse

### 十重奇迹

下完附件看到程序挺大的，猜测应该是一个 GUI 程序。

双击看看：

![](https://img.halfcity.top/2026/11/11/e1197e09064f26869daffc3943ff561d.avif)

看起来是一个游戏吗？左上角 godot 的图标很明显，那么我们直接尝试解包即可，这里的交互就不看了。

我们使用[这个](https://github.com/GDRETools/gdsdecomp/releases)工具来解包：

![](https://img.halfcity.top/2026/11/11/a74958edfbe554e7414ba3e56af7dca0.avif)

在游戏脚本文件中可以找 flag 的加密逻辑：

![](https://img.halfcity.top/2026/11/11/86d137119cf4d09b895d774f77ef0bc4.avif)

```gdscript
extends RefCounted
class_name AstralCipher

# Standard SM4 substitution table, modified 24-round data transformation.
const SBOX_HEX := (
    "d690e9fecce13db716b614c228fb2c05"
    + "2b679a762abe04c3aa44132649860699"
    + "9c4250f491ef987a33540b43edcfac62"
    + "e4b31ca9c908e89580df94fa758f3fa6"
    + "4707a7fcf37317ba83593c19e6854fa8"
    + "686b81b27164da8bf8eb0f4b70569d35"
    + "1e240e5e6358d1a225227c3b01217887"
    + "d40046579fd327524c3602e7a0c4c89e"
    + "eabf8ad240c738b5a3f7f2cef96115a1"
    + "e0ae5da49b341a55ad933230f58cb1e3"
    + "1df6e22e8266ca60c02923ab0d534e6f"
    + "d5db3745defd8e2f03ff6a726d6c5b51"
    + "8d1baf92bbddbc7f11d95c411f105ad8"
    + "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    + "8969974a0c96777e65b9f109c56ec684"
    + "18f07dec3adc4d2079ee5f3ed7cb3948"
)
const FK := [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
const MASK := 0xffffffff
static var _box: PackedByteArray = PackedByteArray()

static func _sha256(data: PackedByteArray) -> PackedByteArray:
    var h := HashingContext.new()
    if h.start(HashingContext.HASH_SHA256) != OK:
        return PackedByteArray()
    h.update(data)
    return h.finish()

static func golden_seal(slot: int) -> PackedByteArray:
    var phrase := "CHALDEA/SEAL/v1|%d|LUMEN-2731" % slot
    return _sha256(phrase.to_utf8_buffer()).slice(4, 12)

static func _derive_key(seals: Array[PackedByteArray]) -> PackedByteArray:
    var buf := "CHALDEA/TENFOLD/MNEMOSYNE|".to_utf8_buffer()
    for i in range(10):
        buf.append(i)
        buf.append_array(seals[i])
    buf.append_array("|STARS-ARE-WITNESSES".to_utf8_buffer())
    return _sha256(buf).slice(0, 16)

static func _rol(x: int, n: int) -> int:
    x &= MASK
    return ((x << n) | (x >> (32 - n))) & MASK

static func _load_u32(b: PackedByteArray, at: int) -> int:
    return (int(b[at]) << 24) | (int(b[at + 1]) << 16) | (int(b[at + 2]) << 8) | int(b[at + 3])

static func _put_u32(out: PackedByteArray, value: int) -> void:
    value &= MASK
    out.append((value >> 24) & 255)
    out.append((value >> 16) & 255)
    out.append((value >> 8) & 255)
    out.append(value & 255)

static func _tau(w: int) -> int:
    if _box.is_empty():
        _box = SBOX_HEX.hex_decode()
    var y := 0
    for j in range(4):
        var shift := 24 - 8 * j
        y |= int(_box[(w >> shift) & 255]) << shift
    return y & MASK

static func _l(w: int) -> int:
    return (w ^ _rol(w, 3) ^ _rol(w, 9) ^ _rol(w, 17) ^ _rol(w, 25)) & MASK

static func _key_l(w: int) -> int:
    return (w ^ _rol(w, 13) ^ _rol(w, 23)) & MASK

static func _round_keys(key: PackedByteArray) -> Array[int]:
    var k: Array[int] = []
    var keys: Array[int] = []
    for i in range(4):
        k.append(_load_u32(key, i * 4) ^ int(FK[i]))
    for rnd in range(24):
        var ck := 0
        for j in range(4):
            ck = (ck << 8) | (((rnd * 4 + j) * 7) & 255)
        var mix := k[rnd + 1] ^ k[rnd + 2] ^ k[rnd + 3] ^ ck
        var rk := (k[rnd] ^ _key_l(_tau(mix))) & MASK
        k.append(rk)
        keys.append(rk)
    return keys

static func _block(block: PackedByteArray, key: PackedByteArray) -> PackedByteArray:
    var x: Array[int] = []
    for i in range(4):
        x.append(_load_u32(block, i * 4))
    for rk in _round_keys(key):
        var v := x[x.size() - 3] ^ x[x.size() - 2] ^ x[x.size() - 1] ^ rk
        var next := (x[x.size() - 4] ^ _l(_tau(v))) & MASK
        x.append(next)
    var result := PackedByteArray()
    for j in range(4):
        _put_u32(result, x[x.size() - 1 - j])
    return result

static func _ctr(cipher: PackedByteArray, key: PackedByteArray, nonce: PackedByteArray) -> PackedByteArray:
    var plain := PackedByteArray()
    for start in range(0, cipher.size(), 16):
        var iv := nonce.duplicate()
        _put_u32(iv, (start / 16) + 1)
        var stream := _block(iv, key)
        for i in range(mini(16, cipher.size() - start)):
            plain.append(cipher[start + i] ^ stream[i])
    return plain

static func open_record(seals: Array[PackedByteArray]) -> String:
    if seals.size() != 10:
        return ""
    for i in range(10):
        if seals[i] != golden_seal(i):
            return ""
    var data := FileAccess.get_file_as_bytes("res://assets/record.dat")
    if data.size() < 30:
        return ""
    if data.slice(0, 4) != "CLD1".to_ascii_buffer():
        return ""
    var count := (int(data[16]) << 8) | int(data[17])
    if data.size() != 18 + count + 8:
        return ""
    var nonce := data.slice(4, 16)
    var encrypted := data.slice(18, 18 + count)
    var output := _ctr(encrypted, _derive_key(seals), nonce)
    if _sha256(output).slice(0, 8) != data.slice(18 + count, data.size()):
        return ""
    var text := output.get_string_from_utf8()
    if not text.begins_with("flag{") or not text.ends_with("}"):
        return ""
    return text
```

`open_record` 函数读取了一个资源文件 `res://assets/record.dat` 然后自己实现了解密的流程。

所以理论上来说这个游戏通关了应该就会显示 flag？

![](https://img.halfcity.top/2026/11/11/46c997a2b5e2668fbf563a431e391ef4.avif)

检查一下发现这个类根本就没有被引用过，所以无论怎么游玩都不可能得到 flag。如果有 godot 环境的话理论上将他挂载到随便一个节点就可以运行得到  flag 了。

但是下载一个 godot 环境太麻烦了，改包也是，这里我们可以参考它解密的逻辑自己实现一遍解密并获取 flag。

首先对 `slot = 0..9` 分别计算 SHA256，派生 16 字节密钥。

随后调用 CTR 解密。

解密脚本如下：

```py
import hashlib
from typing import List

SBOX_HEX = (
    "d690e9fecce13db716b614c228fb2c05"
    "2b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8"
    "686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887"
    "d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6f"
    "d5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad8"
    "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)
SBOX = bytes.fromhex(SBOX_HEX)
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
MASK = 0xffffffff


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def golden_seal(slot: int) -> bytes:
    phrase = f"CHALDEA/SEAL/v1|{slot}|LUMEN-2731".encode()
    return sha256(phrase)[4:12]


def derive_key(seals: List[bytes]) -> bytes:
    buf = b"CHALDEA/TENFOLD/MNEMOSYNE|"
    for i in range(10):
        buf += bytes([i]) + seals[i]
    buf += b"|STARS-ARE-WITNESSES"
    return sha256(buf)[:16]


def rol(x: int, n: int) -> int:
    x &= MASK
    return ((x << n) | (x >> (32 - n))) & MASK


def load_u32(b: bytes, at: int) -> int:
    return (b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]


def put_u32(value: int) -> bytes:
    value &= MASK
    return bytes([
        (value >> 24) & 255,
        (value >> 16) & 255,
        (value >> 8) & 255,
        value & 255,
    ])


def tau(w: int) -> int:
    y = 0
    for j in range(4):
        shift = 24 - 8 * j
        y |= SBOX[(w >> shift) & 255] << shift
    return y & MASK


def L(w: int) -> int:
    return (w ^ rol(w, 3) ^ rol(w, 9) ^ rol(w, 17) ^ rol(w, 25)) & MASK


def key_L(w: int) -> int:
    return (w ^ rol(w, 13) ^ rol(w, 23)) & MASK


def round_keys(key: bytes) -> List[int]:
    k = [load_u32(key, i * 4) ^ FK[i] for i in range(4)]
    keys = []
    for rnd in range(24):
        ck = 0
        for j in range(4):
            ck = (ck << 8) | (((rnd * 4 + j) * 7) & 255)
        mix = k[rnd + 1] ^ k[rnd + 2] ^ k[rnd + 3] ^ ck
        rk = (k[rnd] ^ key_L(tau(mix))) & MASK
        k.append(rk)
        keys.append(rk)
    return keys


def sm4_block(block: bytes, key: bytes) -> bytes:
    x = [load_u32(block, i * 4) for i in range(4)]
    for rk in round_keys(key):
        v = x[-3] ^ x[-2] ^ x[-1] ^ rk
        nxt = (x[-4] ^ L(tau(v))) & MASK
        x.append(nxt)
    return b"".join(put_u32(x[-1 - j]) for j in range(4))


def ctr_decrypt(cipher: bytes, key: bytes, nonce: bytes) -> bytes:
    plain = bytearray()
    for start in range(0, len(cipher), 16):
        iv = nonce + put_u32((start // 16) + 1)  # 12-byte nonce + 4-byte counter
        stream = sm4_block(iv, key)
        for i in range(min(16, len(cipher) - start)):
            plain.append(cipher[start + i] ^ stream[i])
    return bytes(plain)


def open_record(path: str) -> str:
    seals = [golden_seal(i) for i in range(10)]
    key = derive_key(seals)

    data = open(path, "rb").read()
    if len(data) < 30 or data[:4] != b"CLD1":
        return ""

    count = (data[16] << 8) | data[17]
    if len(data) != 18 + count + 8:
        return ""

    nonce = data[4:16]
    encrypted = data[18 : 18 + count]
    tag = data[18 + count :]

    plain = ctr_decrypt(encrypted, key, nonce)
    if sha256(plain)[:8] != tag:
        return ""

    text = plain.decode("utf-8")
    if not (text.startswith("flag{") and text.endswith("}")):
        return ""
    return text


if __name__ == "__main__":
    flag = open_record("record.dat")
    print(flag)
```

```txt
flag{t3n_g0ld3n_summ0ns_unl0ck_th3_ch4ld34_4rch1v3}
```

### 阿萨拉下班指南·三：你架着，我拆个包

```txt
撤离前，队友又发现一份封好的机密包。“最后一个，真最后一个。”，这次的结构异常奇怪，看来只能靠你手动拆掉了
```

看这描述，应该要手脱 UPX 吧。

![](https://img.halfcity.top/2026/11/11/995e115a0d8926584a778463184e62c5.avif)

UPX 壳的特征码没有匹配，但是启发式检测还是发现了是 UPX。

UPX 是压缩壳，我们使用压缩壳最常用的 ESP 大法脱壳即可。

#### 脱壳

打开 x64dbg 断在系统断点，运行来到入口断点：

![](https://img.halfcity.top/2026/11/11/9a6947e5bb6972234c0b32f852565374.avif)

![](https://img.halfcity.top/2026/11/11/d1365367781d8d7a0e849742d14ef412.avif)

在 x86 程序中开头应该是 `pushad` ，x64 程序是 `push rbx push rsi push rdi push rbp` ，不过都一样。

利用栈平衡我们可以断在壳最后的尾声部分。

在栈顶设置硬件写入断点：

![](https://img.halfcity.top/2026/11/11/1333c06e4c96dad84287423b3f8703d3.avif)

F9 运行来到尾声：

![](https://img.halfcity.top/2026/11/11/770392ac670a01650e53507eef7708ee.avif)

```txt
00007FF79CB7019F | E9 810FFEFF                 | jmp <challenge (1).sub_7FF79CB51125>                      |
```

这一条指令就是大跳了。

F4 运行到 jmp 指令，然后 F7 来到 OEP：

![](https://img.halfcity.top/2026/11/11/5f36658bde67121e7a446e709e0d6727.avif)

随后使用 Scylla 来 dump 脱壳后的程序即可。

先 dump 程序，然后解析 IAT，随后点 `Fix Dump` 修复 dump 程序的 IAT：

![](https://img.halfcity.top/2026/11/11/e1d8e54e6a652f4dda9bfad7e7edfba3.avif)

解析失败的条目先不管修复的时候直接删掉，有问题再说。

接下来就可以到 IDA 里分析了。

#### 静态分析

来到 start 并分析 mainCRTStartup() 找到 main 并重命名：

![](https://img.halfcity.top/2026/11/11/c4e1cb3ef8d78db460b9dc909d08a194.avif)

简单重命名一下：

![](https://img.halfcity.top/2026/11/11/c6b756a68cc7d179a70d328719b7d6f4.avif)

`sub_7FF7B80E17A1` 是前面题目见了很多次的 flag 内容提取函数。

`sub_7FF7B80E1A43` 就是要的加密逻辑了。

![](https://img.halfcity.top/2026/11/11/7c1731ee9fe9925aae4296d34b9b9350.avif)

这里先逐字节从 `qword_7FF7B80F4060` 填充了 3 个 QWORD 到 v4 后移交给 buf1，并从 `qword_7FF7B80F4080` 读取了四个 DWORD 给到 v2 并异或，这里的 v2 可能就是加密的 key 了。

![](https://img.halfcity.top/2026/11/11/cf4e0ded8784d3bbced788bed6603f12.avif)

```c
__int64 __fastcall sub_7FF7B80E1892(unsigned int i, unsigned int a2, int a3, _QWORD *key, char j, int a6)
{
  return (((4 * a2) ^ (i >> 5)) + ((a2 >> 3) ^ (16 * i))) ^ ((a2 ^ a3) + (i ^ *((_DWORD *)key + (a6 ^ j & 3u))));
}
```

由此我们得到如下结论：

1. sub_7FF7B80E1892 是 TEA 系列混合函数，结构与 XXTEA 的 MX 混合表达式高度相似。

2. sub_7FF7B80E18F4 并不是标准 XXTEA 的直接实现：它使用了 6 个 32 位字、14 轮、每轮 5 次内层迭代，并且密钥索引、轮常量初始化方式都需要按反编译结果还原。
    外层 sub_7FF7B80E1A43 则是校验入口：先根据 qword_7FF7B80F4060 指定的偏移，从 a1 指向的内存中提取 24 字节，再进行变换，最后与 Buf2 的 24 字节常量比较。

  因此这里应该：

- 还原 128 位密钥：qword_7FF7B80F4080 的 16 字节数据，每个 DWORD 再与 0xA5A5A5A5 异或。
- 按照实际循环顺序逆向恢复变换，而不是直接套用标准 XXTEA 解密函数。


代码中的 `v7 -= 0x61C88647`

它是标准 XXTEA 常用常量 0x9E3779B9 的 32 位负数表示。

因此每轮的 sum 按照以下方式更新：

sum_ = (sum_ - 0x61C88647) & 0xFFFFFFFF

初始 sum 为 0，共执行 14 轮。

从 qword_7FF7B80F4080 读取 16 字节原始数据，并将每个 DWORD 与 0xA5A5A5A5 异或。

解密脚本如下：

```py

import struct

MASK = 0xFFFFFFFF
DELTA_NEG = 0x61C88647
KEY_XOR = 0xA5A5A5A5

RAW_KEY = bytes.fromhex(
    "B2 99 FF C8 A2 11 47 34 "
    "99 88 BB AA 7D 62 13 00"
)

# 每个 DWORD 与 0xA5A5A5A5 异或
KEY = [
    x ^ KEY_XOR
    for x in struct.unpack("<4I", RAW_KEY)
]

TARGET = bytes.fromhex(
    "30 9E 9E 82 32 03 BE DA "
    "AF 24 30 0B DA 97 C8 81 "
    "62 84 AA 46 EA E3 C6 FB"
)

OFFSETS = [
    1, 6, 11, 16, 21,
    2, 7, 12, 17, 22,
    3, 8, 13, 18, 23,
    4, 9, 14, 19, 0,
    5, 10, 15, 20,
]


def mx(z, y, sum_, p, e):
    """还原 sub_7FF7B80E1892，所有运算按 uint32 处理。"""
    left = (
        (((y << 2) & MASK) ^ (z >> 5))
        + ((y >> 3) ^ ((z << 4) & MASK))
    ) & MASK

    right = (
        ((y ^ sum_) + (z ^ KEY[e ^ (p & 3)])
    )) & MASK

    return left ^ right


def decrypt_block(ciphertext):
    """逆向 sub_7FF7B80E18F4。"""
    v = list(struct.unpack("<6I", ciphertext))

    # 正向执行 14 轮后的 sum
    sum_ = 0
    for _ in range(14):
        sum_ = (sum_ - DELTA_NEG) & MASK

    # 逆序执行每轮
    for _ in range(14):
        e = (sum_ >> 2) & 3

        # 正向最后更新 word[5]，因此逆向先撤销它
        v[5] = (
            v[5] - mx(v[4], v[0], sum_, 5, e)
        ) & MASK

        # 逆向撤销 word[4] 到 word[0] 的更新
        for p in range(4, -1, -1):
            z = v[p - 1] if p > 0 else v[5]

            v[p] = (
                v[p] - mx(z, v[p + 1], sum_, p, e)
            ) & MASK

        # 回到上一轮的 sum
        sum_ = (sum_ + DELTA_NEG) & MASK

    return struct.pack("<6I", *v)


def restore_original(extracted):
    """逆转外层的偏移提取操作。"""
    result = bytearray(24)

    for i, offset in enumerate(OFFSETS):
        result[offset] = extracted[i]

    return bytes(result)


def main():
    print("[+] Key:")
    print("    " + " ".join(f"{x:08X}" for x in KEY))

    extracted = decrypt_block(TARGET)

    print("\n[+] Decrypted 24 bytes:")
    print("    " + extracted.hex(" "))

    original = restore_original(extracted)

    print("\n[+] Original bytes:")
    print("    " + original.hex(" "))

    print("\n[+] ASCII:")
    print("    " + original.decode("ascii"))


if __name__ == "__main__":
    main()
```

```txt
flag{unp4ck_while_team_covers}
```

### 提瓦特委托局·三：构造与混沌

跟着 mainCRTStartup 来到 main 函数：

```c
__int64 __fastcall sub_14000196F(__int64 a1)
{
  int v1; // ebx
  unsigned int v2; // eax
  __int64 result; // rax
  unsigned int v4; // [rsp+2Ch] [rbp-74h]
  _WORD v5[38]; // [rsp+30h] [rbp-70h]
  int m; // [rsp+7Ch] [rbp-24h]
  unsigned int v7; // [rsp+80h] [rbp-20h]
  int k; // [rsp+84h] [rbp-1Ch]
  int j; // [rsp+88h] [rbp-18h]
  unsigned int i; // [rsp+8Ch] [rbp-14h]
  int v11; // [rsp+90h] [rbp-10h]
  unsigned int v12; // [rsp+94h] [rbp-Ch]
  int v13; // [rsp+98h] [rbp-8h]
  unsigned int n5; // [rsp+9Ch] [rbp-4h]

  n5 = 0;
  v13 = 0;
  v12 = 0;
  v11 = 0;
  for ( i = 0; i <= 0xB; ++i )
  {
    v1 = rand() << 16;
    dword_1400190A0[i] = (0x9E3779B9 * i) ^ rand() ^ v1;
  }
  v4 = dword_1400190A0[0];
  while ( 2 )
  {
    switch ( sub_1400018AB(a1: v4) )
    {
      case 0LL:
        for ( j = 0; j <= 23; ++j )
          *((_BYTE *)&v5[24] + j) = *(_BYTE *)(byte_140014070[j] + a1);
        n5 = 0;
        v4 = sub_1400018F3(0, 0);
        continue;
      case 1LL:
        v4 = sub_1400018F3(1, n5 <= 5);
        continue;
      case 2LL:
        for ( k = 0; k <= 3; ++k )
        {
          v7 = word_1400140C0[4 * n5 + k];
          for ( m = 0; m <= 3; ++m )
            v7 += word_1400140A0[4 * k + m] * *((unsigned __int8 *)&v5[2 * n5 + 24] + m);
          v5[4 * n5 + k] = v7 % 0x101;
        }
        v4 = sub_1400018F3(2, 0);
        continue;
      case 3LL:
        v11 ^= (unsigned __int16)v5[4 * n5] ^ (157 * n5);
        v4 = sub_1400018F3(3, v11 & 1);
        continue;
      case 4LL:
        ++n5;
        v4 = sub_1400018F3(4, 0);
        continue;
      case 5LL:
        v13 = 0;
        v4 = sub_1400018F3(5, 0);
        continue;
      case 6LL:
        if ( v5[v13] == aYmGec1[v13] )
          v2 = sub_1400018F3(6, 1);
        else
          v2 = sub_1400018F3(6, 0);
        v4 = v2;
        continue;
      case 7LL:
        if ( (unsigned int)++v13 > 0x17 )
          v4 = sub_1400018F3(7, 1);
        else
          v4 = sub_1400018F3(7, 0);
        continue;
      case 8LL:
        v12 = 1;
        v4 = sub_1400018F3(8, 0);
        continue;
      case 9LL:
        v12 = 0;
        v4 = sub_1400018F3(9, 0);
        continue;
      case 10LL:
        result = v12;
        break;
      case 11LL:
        v11 ^= 0x13579BDFu;
        v4 = sub_1400018F3(11, v11 & 1);
        continue;
      default:
        result = 0;
        break;
    }
    return result;
  }
}
```

这里可以看出来有点像 ollvm 的控制流平坦化，不过理论上来说 ollvm 不会这么简单，所以这里应该是一个自定义的控制流。

这里只有一个主 handler，12个分发块编号由 `sub_140018AB()` 来生成。可以看到每个块结束后都会调用 `sub_1400018F3` 迭代块编号。

```c
__int64 __fastcall sub_1400018AB(int a1)
{
  unsigned int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 0xB; ++i )
  {
    if ( a1 == dword_1400190A0[i] )
      return i;
  }
  return 11;
}
```

结合前面的内容可以确定这里固定了初始块是 0 号。

我们先简单将主程序的逻辑重命名还原一下：

![](https://img.halfcity.top/2026/11/11/409a731a7f462fdd2cb0bf1f691f8b2d.avif)

```c
__int64 __fastcall pick_next_block(int a1, unsigned int a2)
{
  dword_1400190D0 ^= rand();
  return (unsigned int)dword_1400190A0[byte_140014140[3 * a1 + a2 % 3]];
}
```

这里的 `byte_140014140` 这个数组保存了块的索引，那么 `sub_1400018F3` 就是根据编号反查索引了，到这里可能 ai 已经可以直接看出控制流了，但是这里我们还是按正常逻辑搞一个模拟执行的脚本来反混淆。

模拟脚本如下：

```py
import re

SRC = r"""
__int64 __fastcall encrypt(__int64 a1)
{
  n5 = 0; v23 = 0; v22 = 0; v21 = 0;
  state = select_index(dword_1400190A0[0]);
  while ( 2 )
  {
    switch ( state )
    {
      case 0LL:
        for ( j = 0; j <= 23; ++j )
          *((_BYTE *)&v15[24] + j) = *(_BYTE *)(byte_140014070[j] + a1);
        n5 = 0;
        block = pick_next_block(a1: 0, a2: 0);
        state = select_index(block);
        continue;
      case 1LL:
        block_1 = pick_next_block(a1: 1, a2: n5 <= 5);
        state = select_index(block_1);
        continue;
      case 2LL:
        for ( k = 0; k <= 3; ++k )
        {
          v17 = word_1400140C0[4 * n5 + k];
          for ( m = 0; m <= 3; ++m )
            v17 += word_1400140A0[4 * k + m] * *((unsigned __int8 *)&v15[2 * n5 + 24] + m);
          v15[4 * n5 + k] = v17 % 0x101;
        }
        block_2 = pick_next_block(a1: 2, a2: 0);
        state = select_index(block_2);
        continue;
      case 3LL:
        v21 ^= (unsigned __int16)v15[4 * n5] ^ (157 * n5);
        block_3 = pick_next_block(a1: 3, a2: v21 & 1);
        state = select_index(block_3);
        continue;
      case 4LL:
        ++n5;
        block_4 = pick_next_block(a1: 4, a2: 0);
        state = select_index(block_4);
        continue;
      case 5LL:
        v23 = 0;
        block_5 = pick_next_block(a1: 5, a2: 0);
        state = select_index(block_5);
        continue;
      case 6LL:
        if ( v15[v23] == aYmGec1[v23] )
          block_6 = pick_next_block(a1: 6, a2: 1u);
        else
          block_6 = pick_next_block(a1: 6, a2: 0u);
        state = select_index(block_6);
        continue;
      case 7LL:
        if ( (unsigned int)++v23 > 0x17 )
          block_7 = pick_next_block(a1: 7, a2: 1u);
        else
          block_7 = pick_next_block(a1: 7, a2: 0u);
        state = select_index(block_7);
        continue;
      case 8LL:
        v22 = 1;
        block_8 = pick_next_block(a1: 8, a2: 0);
        state = select_index(block_8);
        continue;
      case 9LL:
        v22 = 0;
        block_9 = pick_next_block(a1: 9, a2: 0);
        state = select_index(block_9);
        continue;
      case 10LL:
        result = v22;
        break;
      case 11LL:
        v21 ^= 0x13579BDFu;
        block_10 = pick_next_block(a1: 11, a2: v21 & 1);
        state = select_index(block_10);
        continue;
      default:
        result = 0;
        break;
    }
    return result;
  }
}
unsigned char byte_140014140[36] = {
    0x01,0x01,0x01, 0x05,0x02,0x02, 0x03,0x03,0x03, 0x04,0x04,0x04,
    0x01,0x01,0x01, 0x06,0x06,0x06, 0x09,0x07,0x07, 0x06,0x08,0x08,
    0x0A,0x0A,0x0A, 0x0A,0x0A,0x0A, 0x0A,0x0A,0x0A, 0x0A,0x0A,0x0A
};
"""

# ---------- 1. 取出 36 字节转移表 ----------
arr = re.search(r'byte_140014140\[36\]\s*=\s*\{(.*?)\}', SRC, re.S).group(1)
TBL = [int(x, 0) for x in re.findall(r'0x[0-9A-Fa-f]+|\d+', arr)]
assert len(TBL) == 36

# ---------- 2. 模拟 pick_next_block + select_index ----------
STATE = [(i + 1) * 0x1111 for i in range(12)]

def select_index(block):
    for i in range(12):
        if block == STATE[i]:
            return i
    return 11

def pick_next_block(a1, a2):
    return STATE[TBL[3 * a1 + (a2 % 3)]]

TRANS = {(c, a2): select_index(pick_next_block(c, a2))
         for c in range(12) for a2 in (0, 1)}

print("[*] 转移表 (case, a2) -> next")
for c in range(12):
    print(f"    case {c:2d}: a2=0 -> {TRANS[(c,0)]:2d}   a2=1 -> {TRANS[(c,1)]:2d}")

# ---------- 3. 把每个 case 的 body 切出来 ----------
fstart = SRC.index('__int64 __fastcall encrypt')
fend   = SRC.index('unsigned char byte_140014140')
fbody  = SRC[fstart:fend]

case_re = re.compile(r'case\s+(\d+)LL\s*:')
hits    = list(case_re.finditer(fbody))
spans   = {}
for i, m in enumerate(hits):
    cid = int(m.group(1))
    end = hits[i + 1].start() if i + 1 < len(hits) else fbody.find('default:', m.end())
    spans[cid] = fbody[m.end():end]

# ---------- 4. 抽取块的条件与语句 ----------
IF_RE  = re.compile(
    r'if\s*\((.+?)\)\s*\n'
    r'\s*\w+\s*=\s*pick_next_block\(a1:\s*(\d+),\s*a2:\s*1u\);'
    r'\s*\n\s*else\s*\n'
    r'\s*\w+\s*=\s*pick_next_block\(a1:\s*(\d+),\s*a2:\s*0u\);',
    re.S)
PNB_RE = re.compile(r'pick_next_block\(a1:\s*(\d+),\s*a2:\s*([^);]+?)\s*\)')

def strip_dispatch(text, has_if):
    lines = text.split('\n')
    nonempty = [l for l in lines if l.strip()]
    base = min(len(l) - len(l.lstrip()) for l in nonempty) if nonempty else 0
    out = []
    for raw in lines:
        if not raw.strip():
            continue
        s = re.sub(r'//.*$', '', raw[base:]).rstrip()
        if not s.strip():
            continue
        t = s.strip()
        if 'pick_next_block' in s: continue
        if 'select_index' in s: continue
        if t in ('continue;', 'break;', 'else'): continue
        if t.startswith(('state =', 'block_', 'result =')): continue
        if has_if and t.startswith('if'): continue
        out.append(s)
    return out

class Block:
    def __init__(self):
        self.stmts = []
        self.cond  = None
        self.t     = None
        self.f     = None
        self.ret   = False

def parse_case(cid, text):
    b = Block()
    ifm = IF_RE.search(text)
    if ifm:
        b.cond = ifm.group(1).strip()
        b.t = TRANS[(cid, 1)]
        b.f = TRANS[(cid, 0)]
        b.stmts = strip_dispatch(text, has_if=True)
    else:
        p = PNB_RE.search(text)
        if p:
            a2 = p.group(2).strip()
            if a2 in ('0', '0u', '1', '1u'):
                v = int(a2.rstrip('u'))
                b.t = b.f = TRANS[(cid, v)]
            else:
                b.cond = a2
                b.t = TRANS[(cid, 1)]
                b.f = TRANS[(cid, 0)]
        b.stmts = strip_dispatch(text, has_if=False)
    if cid == 10:
        b.ret = True
    return b

BLOCKS = {cid: parse_case(cid, txt) for cid, txt in spans.items()}

# ---------- 5. 输出纯 goto 形式 ----------
def emit_goto():
    L = []
    A = L.append
    print()
    A("__int64 __fastcall encrypt(__int64 a1)")
    A("{")
    A("    n5 = 0; v23 = 0; v22 = 0; v21 = 0;")
    A("")
    for cid in sorted(BLOCKS):
        b = BLOCKS[cid]
        A(f"B{cid}:")
        for s in b.stmts:
            A("    " + s)
        if b.ret:
            A("    return v22;")
        elif b.cond is not None and b.t != b.f:
            A(f"    if ({b.cond}) goto B{b.t}; else goto B{b.f};")
        else:
            tgt = b.t if b.t is not None else b.f
            A(f"    goto B{tgt};")
        A("")
    A("}")
    return "\n".join(L)

print(emit_goto())
```

输出如下：

```txt
> python recover.py
[*] 转移表 (case, a2) -> next
    case  0: a2=0 ->  1   a2=1 ->  1
    case  1: a2=0 ->  5   a2=1 ->  2
    case  2: a2=0 ->  3   a2=1 ->  3
    case  3: a2=0 ->  4   a2=1 ->  4
    case  4: a2=0 ->  1   a2=1 ->  1
    case  5: a2=0 ->  6   a2=1 ->  6
    case  6: a2=0 ->  9   a2=1 ->  7
    case  7: a2=0 ->  6   a2=1 ->  8
    case  8: a2=0 -> 10   a2=1 -> 10
    case  9: a2=0 -> 10   a2=1 -> 10
    case 10: a2=0 -> 10   a2=1 -> 10
    case 11: a2=0 -> 10   a2=1 -> 10

__int64 __fastcall encrypt(__int64 a1)
{
    n5 = 0; v23 = 0; v22 = 0; v21 = 0;

B0:
    for ( j = 0; j <= 23; ++j )
      *((_BYTE *)&v15[24] + j) = *(_BYTE *)(byte_140014070[j] + a1);
    n5 = 0;
    goto B1;

B1:
    if (n5 <= 5) goto B2; else goto B5;

B2:
    for ( k = 0; k <= 3; ++k )
    {
      v17 = word_1400140C0[4 * n5 + k];
      for ( m = 0; m <= 3; ++m )
        v17 += word_1400140A0[4 * k + m] * *((unsigned __int8 *)&v15[2 * n5 + 24] + m);
      v15[4 * n5 + k] = v17 % 0x101;
    }
    goto B3;

B3:
    v21 ^= (unsigned __int16)v15[4 * n5] ^ (157 * n5);
    goto B4;

B4:
    ++n5;
    goto B1;

B5:
    v23 = 0;
    goto B6;

B6:
    if (v15[v23] == aYmGec1[v23]) goto B7; else goto B9;

B7:
    if ((unsigned int)++v23 > 0x17) goto B8; else goto B6;

B8:
    v22 = 1;
    goto B10;

B9:
    v22 = 0;
    goto B10;

B10:
    return v22;

B11:
    v21 ^= 0x13579BDFu;
    goto B10;

}
```

虽然恢复了 handler 但是原有的逻辑不是线性的，还是需要自己识别一下 goto 的语意并恢复成正确逻辑。

这也没办法，也许重新编译一下让 ida 看会好点，但这里还是直接还原吧。

还原的逻辑如下：

```c
__int64 __fastcall encrypt(__int64 a1)
{
    uint16_t v15[38] = {0};
    int v21 = 0, v22 = 0, v23 = 0, n5 = 0;
    int j, k, m;
    unsigned int v17;

    // B0：按 byte_140014070 索引取 24 字节输入，写入 v15[24] 起始处
    for (j = 0; j <= 23; ++j)
        *((_BYTE *)&v15[24] + j) = *(_BYTE *)(byte_140014070[j] + a1);
    n5 = 0;

    // 循环 1（头 B1，条件 n5 <= 5）
    while (n5 <= 5) {
        // B2：4x4 矩阵乘 + 模 0x101
        for (k = 0; k <= 3; ++k) {
            v17 = word_1400140C0[4 * n5 + k];
            for (m = 0; m <= 3; ++m)
                v17 += word_1400140A0[4 * k + m] *
                       *((unsigned __int8 *)&v15[2 * n5 + 24] + m);
            v15[4 * n5 + k] = v17 % 0x101;
        }
        // B3：v21 是死变量，两条出边相同，保留原样
        v21 ^= (unsigned __int16)v15[4 * n5] ^ (157 * n5);
        // B4
        ++n5;
    }

    // B5
    v23 = 0;

    // 循环 2（头 B6/B7）
    while (1) {
        if (!(v15[v23] == aYmGec1[v23])) {   // B6 -> B9
            v22 = 0;
            break;
        }
        if (++v23 > 0x17) {                  // B7 -> B8
            v22 = 1;
            break;
        }
    }

    // B10
    return v22;
}
```

接下来就可以正常解密了。

从目标 UTF-16LE 字符串 aYmGec1 出发，按 6 组、每组 4 个 16 位值，减去对应常量，再乘以 4×4 矩阵的逆（模 257），得到 24 个明文字节。

最后按 byte_140014070 的逆置换把这些字节填回 a1 的对应偏移处。

```py
# 置换表
perm = [
    0x07, 0x0C, 0x11, 0x16, 0x03, 0x08, 0x0D, 0x12,
    0x17, 0x04, 0x09, 0x0E, 0x13, 0x00, 0x05, 0x0A,
    0x0F, 0x14, 0x01, 0x06, 0x0B, 0x10, 0x15, 0x02
]

# 矩阵 M
M = [
    [2, 1, 0, 0],
    [1, 1, 1, 0],
    [0, 1, 1, 1],
    [0, 0, 1, 2]
]

# 常量向量
C = [
    [1,  4,  7, 10],
    [12, 15, 18, 21],
    [23, 26, 29, 32],
    [34, 37, 40, 43],
    [45, 48, 51, 54],
    [56, 59, 62, 65]
]

aYmGec1 = [0x59, 0x4D, 0x3E, 0x2F, 0x47, 0x45, 0x43, 0x31, 0x26, 0x1A, 0x1B, 0x5C, 0x55, 0x64, 0x7A, 0x7F, 0x55, 0x27, 0x24, 0x27, 0x66, 0x71, 0x7D, 0x89]

MOD = 257

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def mod_inv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"模逆不存在: {a} mod {m}")
    return x % m

def mat_inv_mod(M, mod):
    """求 4x4 矩阵在模 mod 下的逆矩阵"""
    n = len(M)
    # 构造增广矩阵 [M | I]
    A = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(M)]
    
    for i in range(n):
        # 寻找主元
        pivot = None
        for r in range(i, n):
            if A[r][i] % mod != 0:
                pivot = r
                break
        if pivot is None:
            raise ValueError("矩阵不可逆")
        A[i], A[pivot] = A[pivot], A[i]
        
        # 归一化主元行
        inv_pivot = mod_inv(A[i][i], mod)
        for c in range(i, 2 * n):
            A[i][c] = (A[i][c] * inv_pivot) % mod
        
        # 消去其他行
        for r in range(n):
            if r != i and A[r][i] != 0:
                factor = A[r][i]
                for c in range(i, 2 * n):
                    A[r][c] = (A[r][c] - factor * A[i][c]) % mod
    
    # 提取逆矩阵
    inv = [row[n:] for row in A]
    return inv

def mat_vec_mul(M, v, mod):
    return [sum(M[i][j] * v[j] for j in range(len(v))) % mod for i in range(len(M))]

# 计算 M 的逆矩阵
M_inv = mat_inv_mod(M, MOD)
print("M_inv =", M_inv)

buf = [0] * 24

for n5 in range(6):
    # 取目标 Y（4 个 16 位值）
    Y = aYmGec1[4 * n5 : 4 * n5 + 4]
    # 减去常量
    D = [(Y[k] - C[n5][k]) % MOD for k in range(4)]
    # 左乘逆矩阵
    X = mat_vec_mul(M_inv, D, MOD)
    
    for k in range(4):
        if X[k] > 255:
            print(f"警告: 组 {n5} 元素 {k} 结果 {X[k]} > 255，可能目标值有误")
        buf[4 * n5 + k] = X[k] & 0xFF

# 逆置换
a1 = [0] * 24
for j in range(24):
    a1[perm[j]] = buf[j]

print("\n解密得到的 24 字节 (hex):")
print(' '.join(f'{b:02X}' for b in a1))

print("\n尝试按 ASCII 解码:")
print(bytes(a1).decode('ascii'))
```

输出如下：

```txt
> python cfg.py
M_inv = [[86, 86, 85, 86], [86, 85, 87, 85], [85, 87, 85, 86], [86, 85, 86, 86]]

解密得到的 24 字节 (hex):
72 34 6E 64 30 6D 5F 73 74 61 74 65 73 5F 6E 65 65 64 5F 61 5F 6D 61 70

尝试按 ASCII 解码:
r4nd0m_states_need_a_map
```

```txt
flag{r4nd0m_states_need_a_map}
```

### 银河售后中心·三：银狼把客服名字改了

![](https://img.halfcity.top/2026/11/11/e4f801a6d055a7ae4686a79facabc165.avif)

`MainActivity` 中依旧调用了 `TicketVerifier.check` 来检查 flag。

![](https://img.halfcity.top/2026/11/11/75555ee4713948f601018290dabadb32.avif)

```java
package org.galactic.aftercare.wolf;

import java.nio.charset.StandardCharsets;

public final class TicketVerifier {
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
                arr_b1[v] = arr_b[(v + 5) % 24];
            }

            return NativeDesk.verifyTicket(arr_b1);
        }

        return false;
    }
}
```

这里是一个简单的有效性检验和数组循环左移。

主要的校验逻辑还是在 native 层：

![](https://img.halfcity.top/2026/11/11/8239bdfe16557fa45ec2824db0c0ac58.avif)将 so 导出并放到 IDA 中分析一下：

![](https://img.halfcity.top/2026/11/11/603cdf68ceb1fcd4a6788452fc10a83b.avif)

第一眼没看到校验函数，猜测是在 `JNI_OnLoad` 里面动态注册的。

![](https://img.halfcity.top/2026/11/11/4586cae2d18373cf7cbbc3a2ab620828.avif)

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
  __int64 v3; // [xsp+10h] [xbp-30h]
  jint n65542; // [xsp+2Ch] [xbp-14h]
  _QWORD v5[2]; // [xsp+30h] [xbp-10h] BYREF

  v5[1] = *(_QWORD *)(_ReadStatusReg(TPIDR_EL0) + 40);
  if ( (*vm)->GetEnv(vm, (void **)v5, 65542) )
  {
    n65542 = -1;
  }
  else
  {
    v3 = (*(__int64 (__fastcall **)(_QWORD, const char *))(*(_QWORD *)v5[0] + 48LL))(
           v5[0],
           "org/galactic/aftercare/wolf/NativeDesk");
    if ( v3
      && !(*(unsigned int (__fastcall **)(_QWORD, __int64, char **, __int64))(*(_QWORD *)v5[0] + 1720LL))(
            v5[0],
            v3,
            off_34A0,                           // "verifyTicket"
            1) )
    {
      n65542 = 65542;
    }
    else
    {
      n65542 = -1;
    }
  }
  _ReadStatusReg(TPIDR_EL0);
  return n65542;
}
```

可以看到这里动态注册了一个函数，这里其实可以直接去看校验逻辑，但我还是简单修复一下吧。

这里应该先通过 vm 获取了 env 然后调用了注册函数：

![](https://img.halfcity.top/2026/11/11/150bae8cab96c9f8aacfaba67a84fab4.avif)

这样看起来舒服多了，我们接下来去看具体注册的 entry：

![](https://img.halfcity.top/2026/11/11/73126d61cbd2593b6ff117eed7081bc6.avif)

标准的 entry 有三个字段，分别是函数名、函数签名和函数 VA。

我们来到 `verifyTicket` 函数中，可以看到 env 没有被识别出来，我们需要稍微修复一下。

![](https://img.halfcity.top/2026/11/11/b193633b95b550de72ffc02c437e0c8a.avif)简单修复如下：

![](https://img.halfcity.top/2026/11/11/d704dbbbdec669c6af630f74db01b24f.avif)

这里的 IDA 总是会错误识别 `GetByteArrayRegion` 这个函数的参数。

![](https://img.halfcity.top/2026/11/11/ef74bbe26ad0a621aa9b49272e31897c.avif)

这里应该是先复制 ticket 到 buf ，然后构造加密块。

加密的逻辑应该在 `sub_DB8` 中：

![](https://img.halfcity.top/2026/11/11/28576a5a22ff55a9861320facf7db95a.avif)

AI 识别一下算法：

![](https://img.halfcity.top/2026/11/11/19dd2ba939e03a4872831c1fb74336cf.avif)

原来是 SM4，回到前面：

```c
__memcpy_chk(v11, &unk_5F2, 16, 16);   // 初始向量 IV = unk_5F2
for ( k = 0; k <= 1; ++k )             // 处理两个 16 字节块
{
    for ( m = 0; m <= 15; ++m )
        buf[16 * k + m] = buf[16 * k + 32 + m] ^ v11[m];   // 异或 IV
    sm4_encrypt(&buf[16 * k], &buf[16 * k], &unk_602);     // SM4 加密，密钥 = unk_602
    __memcpy_chk(v11, &buf[16 * k], 16, 16);               // 加密结果作为下一块的 IV
}
```

- **初始向量 IV**：16 字节常量 `unk_5F2`。
- **密钥**：SM4 密钥 `unk_602`。
- 加密流程为 **CBC 模式**：
  - 第 1 块：`buf[32..47]` 与 IV 异或 → SM4 加密 → 结果存入 `buf[0..15]`，并作为第 2 块的 IV。
  - 第 2 块：`buf[48..63]` 与上一块密文异或 → SM4 加密 → 结果存入 `buf[16..31]`。
- 最终 `buf[0..31]` 为加密后的 32 字节密文。

解密脚本如下：

```py
from gmssl.sm4 import CryptSM4, SM4_DECRYPT

# s2_ ，32 字节 SM4-CBC 密文
cipher = bytes([
    0xCB, 0xC1, 0x00, 0x92, 0x2B, 0x6F, 0x1F, 0xD7,
    0xED, 0x48, 0x7D, 0x44, 0x57, 0x4F, 0x1B, 0x35,
    0xFF, 0x27, 0x24, 0x06, 0x12, 0x50, 0x9A, 0xBC,
    0x10, 0x19, 0x20, 0x5F, 0x61, 0x66, 0x84, 0x7A,
])

# unk_5F2，16 字节 IV
iv = bytes([
    0x27, 0xA1, 0x0E, 0x8C, 0x54, 0x93, 0xF6, 0xB0,
    0xD1, 0x2E, 0x7A, 0x48, 0x65, 0xC0, 0x39, 0xBF,
])

# unk_602，16 字节 SM4 Key
key = bytes([
    0x51, 0x82, 0xD4, 0xA6, 0xC8, 0x39, 0xE0, 0x7B,
    0x12, 0x65, 0xF3, 0xA9, 0xBC, 0x40, 0xDE, 0x78,
])

sm4 = CryptSM4()
sm4.set_key(key, SM4_DECRYPT)
arr_b1 = sm4.crypt_cbc(iv, cipher)

# 逆向 Java 的循环左移 5 位
arr_b = arr_b1[-5:] + arr_b1[:-5]

s1 = arr_b.decode('ascii')
print('flag{' + s1 + '}')
```

```txt
> python center.py
flag{s1lverw0lf_regs_natives!}
```

```txt
flag{s1lverw0lf_regs_natives!}
```

