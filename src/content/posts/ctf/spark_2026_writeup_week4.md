---
title: Spark CTF 2026 Writeup (4/5)
description: 这是比赛的 Week 4 部分。
published: 2026-11-11
category: CTF
tags: [Spark CTF 2026, pyd 逆向, Frida, WebAssembly, SEH, Python Frozen 模块, Rust 逆向, 微信小程序逆向, VM, Nuitka 逆向, Python 解释器魔改]
pinned: false
draft: false
image: https://img.halfcity.top/2026/11/11/44929c2f59dbfa428a2bc7d24bbdd26c.avif
---

## Reverse

### 只是一只中蛇

![](https://img.halfcity.top/2026/11/11/9a5f602c43dbd226294d8c4e2bef40f3.avif)

查壳发现是 pyinstaller 打包，我们直接解包：

```txt
> pyinstxtractor-ng nativecurrent.exe
[+] Processing nativecurrent.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.13
[+] Length of package: 7597488 bytes
[+] Found 65 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: main.pyc
[+] Found 112 files in PYZ archive
[+] Successfully extracted pyinstaller archive: nativecurrent.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

![](https://img.halfcity.top/2026/11/11/95575722cb753cdfc731f7cbdc19d670.avif)

```py
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'main.py'
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from stream_core import verify
try:
    entered = input('Input flag: ')
except (EOFError, KeyboardInterrupt):
    entered = ''
print('Correct' if verify(entered) else 'Wrong')
```

发现这里导入了一个外部库，`stream_core.pyd` 这是一个 pyd 文件，我们直接使用 IDA 分析。

![](https://img.halfcity.top/2026/11/11/ce562b484fa18a4dd3e925a87efe5a11.avif)

这里注册了一个模块，我们去找找定义：

![](https://img.halfcity.top/2026/11/11/c15bd5a4045cb96ea6cfb409be640fa1.avif)

![](https://img.halfcity.top/2026/11/11/465b2ad1d1a346045fdb30a5de9e0486.avif)

这里的 `sub_180001000` 应该就是注册的方法了。

![](https://img.halfcity.top/2026/11/11/3f7310dffaaa7639976f81b0da8a8229.avif)

```c
__int64 __fastcall verify(char *a1, _BYTE *a2)
{
  void *v2; // rax
  int *v3; // rbx
  bool v5; // zf
  __m128i si128; // xmm2
  unsigned __int8 v7; // r11
  __m128 v8; // xmm3
  char *n0x100; // rcx
  __m128i v10; // xmm0
  __m128i v11; // xmm0
  __m128i v12; // xmm1
  __m128i v13; // xmm1
  __m128i v14; // xmm0
  __m128i v15; // xmm0
  __int64 v16; // rax
  __m128i v17; // xmm1
  __m128i v18; // xmm1
  unsigned int n0x100_1; // r10d
  char *v20; // r8
  char v21; // r9
  char v22; // al
  char *v23; // rcx
  __int64 v24; // r14
  __int64 v25; // rdi
  char v26; // si
  int v27; // ebp
  __int64 n0x22; // r11
  unsigned __int8 v29; // al
  _BYTE *v30; // rdx
  char v31; // r8
  char v32; // r9
  unsigned __int8 v33; // r10
  int v34; // r8d
  _BYTE *v35; // rcx
  char *v36; // rcx
  __int64 v37; // [rsp+28h] [rbp-140h] BYREF
  __int64 n34; // [rsp+30h] [rbp-138h] BYREF
  _QWORD v39[33]; // [rsp+38h] [rbp-130h] BYREF

  if ( !(unsigned int)PyArg_ParseTuple(a2, &unk_1800021EC, &v37) )
    return 0;
  v2 = PyUnicode_AsASCIIString(v37);
  v3 = (int *)v2;
  if ( !v2 )
  {
    PyErr_Clear();
    return Py_FalseStruct;
  }
  if ( (unsigned int)PyBytes_AsStringAndSize(v2, v39, &n34) )
  {
    if ( *v3 >= 0 )
    {
      v5 = (*(_QWORD *)v3)-- == 1;
      if ( v5 )
        Py_Dealloc(v3);
    }
    return 0;
  }
  if ( n34 == 34 )
  {
    si128 = _mm_load_si128((const __m128i *)&xmmword_1800021F0);
    v7 = 0;
    v8 = (__m128)_mm_load_si128((const __m128i *)&xmmword_180002200);
    n0x100 = 0;
    do
    {
      v10 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(n0x100), 0), si128), v8);
      v11 = _mm_packus_epi16(v10, v10);
      v12 = (__m128i)_mm_and_ps(
                       (__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128((int)n0x100 + 4), 0), si128),
                       v8);
      *(_DWORD *)((char *)&v39[1] + n0x100) = _mm_cvtsi128_si32(_mm_packus_epi16(v11, v11));
      v13 = _mm_packus_epi16(v12, v12);
      *(_DWORD *)((char *)&v39[1] + (unsigned int)(n0x100 + 4)) = _mm_cvtsi128_si32(_mm_packus_epi16(v13, v13));
      v14 = (__m128i)_mm_and_ps(
                       (__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128((int)n0x100 + 8), 0), si128),
                       v8);
      v15 = _mm_packus_epi16(v14, v14);
      *(_DWORD *)((char *)&v39[1] + (unsigned int)(n0x100 + 8)) = _mm_cvtsi128_si32(_mm_packus_epi16(v15, v15));
      v16 = (unsigned int)(n0x100 + 12);
      n0x100 = (unsigned int)(n0x100 + 16);
      v17 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(v16), 0), si128), v8);
      v18 = _mm_packus_epi16(v17, v17);
      *(_DWORD *)((char *)&v39[1] + v16) = _mm_cvtsi128_si32(_mm_packus_epi16(v18, v18));
    }
    while ( (unsigned int)n0x100 < 0x100 );
    n0x100_1 = 0;
    do
    {
      v20 = (char *)&v39[1] + n0x100_1;
      v21 = *v20;
      v22 = n0x100_1 + byte_180002160[n0x100_1 % 0xDuLL] + *v20;
      ++n0x100_1;
      v7 += v22;
      v23 = (char *)&v39[1] + v7;
      *v20 = *v23;
      *v23 = v21;
    }
    while ( n0x100_1 < 0x100 );
    v24 = v39[0];
    LOBYTE(v25) = 0;
    v26 = 0;
    v27 = 0;
    n0x22 = 0;
    do
    {
      v29 = v25 + 1;
      v30 = (char *)&v39[1] + (unsigned __int8)(v25 + 1);
      v25 = (unsigned __int8)(v25 + 2);
      v31 = *((_BYTE *)&v39[1] + v29);
      v32 = v26 + v31;
      *v30 = *((_BYTE *)&v39[1] + (unsigned __int8)(v26 + v31));
      *((_BYTE *)&v39[1] + (unsigned __int8)(v26 + v31)) = v31;
      v33 = 7 * n0x22 + 68;
      v34 = (unsigned __int8)((7 * n0x22 + 61)
                            ^ byte_180002160[n0x22 + 16]
                            ^ *(_BYTE *)(n0x22 + v24)
                            ^ *((_BYTE *)&v39[1] + (unsigned __int8)(*v30 + v31)));
      LOBYTE(v30) = *((_BYTE *)&v39[1] + v25);
      v26 = v32 + (_BYTE)v30;
      v35 = (char *)&v39[1] + (unsigned __int8)(v32 + (_BYTE)v30);
      *((_BYTE *)&v39[1] + v25) = *v35;
      *v35 = (_BYTE)v30;
      v36 = (unsigned int)(n0x22 + 1);
      n0x22 = (unsigned int)(n0x22 + 2);
      v27 |= v34
           | v33
           ^ (unsigned __int8)byte_180002160[v36 + 16]
           ^ *(unsigned __int8 *)(v36 + v24)
           ^ *((unsigned __int8 *)&v39[1] + (unsigned __int8)(*((_BYTE *)&v39[1] + v25) + (_BYTE)v30));
    }
    while ( (unsigned int)n0x22 < 0x22 );
    if ( *v3 >= 0 )
    {
      v5 = (*(_QWORD *)v3)-- == 1;
      if ( v5 )
        Py_Dealloc(v3);
    }
    if ( v27 )
      return Py_FalseStruct;
    return Py_TrueStruct;
  }
  else
  {
    if ( *v3 < 0 )
      return Py_FalseStruct;
    v5 = (*(_QWORD *)v3)-- == 1;
    if ( !v5 )
      return Py_FalseStruct;
    Py_Dealloc(v3);
    return Py_FalseStruct;
  }
}
```

第一个参数是 self，第二个参数应该就是 arg 了。

我们一边分析一边还原名字。

首先先解析参数，然后转 ascii `PyArg_ParseTuple(args, &unk_1800021EC, &arg_tuple)` `arg_str = PyUnicode_AsASCIIString(arg_tuple)`。

随后转字节 `PyBytes_AsStringAndSize(arg_str, arg_bytes, &str_len)` 。

这里数组 `_QWORD arg_bytes[33]` 都是 QWORD，一共有 256 + 8 字节的空间，所以应该是一个 buf。

```c
do
    {
      v10 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(n0x100), 0), si128), v8);
      v11 = _mm_packus_epi16(v10, v10);
      v12 = (__m128i)_mm_and_ps(
                       (__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128((int)n0x100 + 4), 0), si128),
                       v8);
      *(_DWORD *)((char *)&arg_bytes[1] + n0x100) = _mm_cvtsi128_si32(_mm_packus_epi16(v11, v11));
      v13 = _mm_packus_epi16(v12, v12);
      *(_DWORD *)((char *)&arg_bytes[1] + (unsigned int)(n0x100 + 4)) = _mm_cvtsi128_si32(_mm_packus_epi16(v13, v13));
      v14 = (__m128i)_mm_and_ps(
                       (__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128((int)n0x100 + 8), 0), si128),
                       v8);
      v15 = _mm_packus_epi16(v14, v14);
      *(_DWORD *)((char *)&arg_bytes[1] + (unsigned int)(n0x100 + 8)) = _mm_cvtsi128_si32(_mm_packus_epi16(v15, v15));
      v16 = (unsigned int)(n0x100 + 12);
      n0x100 = (unsigned int)(n0x100 + 16);
      v17 = (__m128i)_mm_and_ps((__m128)_mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(v16), 0), si128), v8);
      v18 = _mm_packus_epi16(v17, v17);
      *(_DWORD *)((char *)&arg_bytes[1] + v16) = _mm_cvtsi128_si32(_mm_packus_epi16(v18, v18));
    }
while ( (unsigned int)n0x100 < 0x100 );
```

这里先初始化 SBOX `arg_bytes`。

随后便是 KSA，这里有很明显的 RC4 的特征 `n0x100_1 + byte_180002160[n0x100_1 % 0xDuLL] + *v20`：

```c
    n0x100_1 = 0;
    do
    {
      v20 = (char *)&arg_bytes[1] + n0x100_1;
      v21 = *v20;
      v22 = n0x100_1 + byte_180002160[n0x100_1 % 0xDuLL] + *v20;
      ++n0x100_1;
      v7 += v22;
      v23 = (char *)&arg_bytes[1] + v7;
      *v20 = *v23;
      *v23 = v21;
    }
    while ( n0x100_1 < 0x100 );
```

其中 `byte_180002160` 的 0x00 ~ 0x0C 这13个字节就是用来打乱 SBOX 的密钥了。

观察计算 j 的部分发现被魔改了现在的逻辑应该是： `j = (j + i + key[i % key_len] + S[i]) & 0xFF`。

这里加上了一个 i。

随后就是魔改的 PRGA 产生密钥流并计算密文。这里每轮处理了两个字节。最后与 `byte_180002160` 的 0x10 ~ 0x31 这34个字节比较。

```c
input[k]   = (7*k + 61) ^ byte_180002160[k + 16]  ^ S[idx1]
input[k+1] = (7*k + 68) ^ byte_180002160[k + 17]  ^ S[idx2]
```

解密脚本如下：

```py
data = bytes([
    0xD8, 0x3A, 0x14, 0x75, 0xC2, 0x6B, 0xF1, 0x49, 0x9E, 0x05, 0xAC, 0x37, 0x24,
    0x00, 0x00, 0x00,
    0xE8, 0xE2, 0x3B, 0xD5, 0x6B, 0x4A, 0x51, 0x53, 0x55, 0x03, 0xEB, 0x24,
    0x70, 0x1D, 0x08, 0x8A, 0xB3, 0x72, 0xF7, 0x77, 0x68, 0x7E, 0xB0, 0xC0,
    0x05, 0x75, 0xF4, 0xA8, 0xA5, 0xAE, 0xD3, 0xAD, 0xF7, 0xBA,
    0x00, 0x00
])

key = data[0:13]
ct  = data[16:50]

# xmmword_1800021F0 = {0,1,2,3}
S = bytearray(range(256))

j = 0
for i in range(256):
    j = (j + i + key[i % 13] + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]

i = 0
j = 0

flag = bytearray(34)

for k in range(0, 34, 2):
    i = (i + 1) & 0xFF
    si = S[i]
    j = (j + si) & 0xFF
    S[i], S[j] = S[j], S[i]
    idx = (S[i] + S[j]) & 0xFF

    flag[k] = ((7 * k + 61) ^ ct[k] ^ S[idx]) & 0xFF

    i = (i + 1) & 0xFF
    si = S[i]
    j = (j + si) & 0xFF
    S[i], S[j] = S[j], S[i]
    idx = (S[i] + S[j]) & 0xFF

    flag[k + 1] = ((7 * k + 68) ^ ct[k + 1] ^ S[idx]) & 0xFF

print(flag)
print(flag.decode('ascii'))
```

输出如下：

```txt
> python native_decrypt.py
bytearray(b'flag{pyd_n4t1v3_rc4_n33d5_4_tw15t}')
flag{pyd_n4t1v3_rc4_n33d5_4_tw15t}
```

```txt
flag{pyd_n4t1v3_rc4_n33d5_4_tw15t}
```

### 银河售后中心·四：小程序回执

题目没给 AppID，猜测没有加密：

![](https://img.halfcity.top/2026/11/11/34bb17bf30ad343e345a7c72a9d48bce.avif)

![](https://img.halfcity.top/2026/11/11/e0fd58b2b6f487329ac4674494e20bf0.avif)

![](https://img.halfcity.top/2026/11/11/699bda6bc5309d38b1616682e8c0ad36.avif)

发现这里有 wasm 模块，使用 wasm2c 来反编译。

关键逻辑如下：

```c
void wasm2c_check_free(w2c_check* instance) {
  wasm_rt_free_funcref_table(&instance->w2c_0x5F_indirect_function_table);
  wasm_rt_free_memory(&instance->w2c_memory);
}

wasm_rt_func_type_t wasm2c_check_get_func_type(uint32_t param_count, uint32_t result_count, ...) {
  va_list args;
  
  if (param_count == 0 && result_count == 0) {
    va_start(args, result_count);
    if (true) {
      va_end(args);
      return w2c_check_t0;
    }
    va_end(args);
  }
  
  if (param_count == 0 && result_count == 1) {
    va_start(args, result_count);
    if (true && va_arg(args, int) == WASM_RT_I32) {
      va_end(args);
      return w2c_check_t1;
    }
    va_end(args);
  }
  
  if (param_count == 3 && result_count == 1) {
    va_start(args, result_count);
    if (true && va_arg(args, int) == WASM_RT_I32 && va_arg(args, int) == WASM_RT_I32 && va_arg(args, int) == WASM_RT_I32 && va_arg(args, int) == WASM_RT_I32) {
      va_end(args);
      return w2c_check_t2;
    }
    va_end(args);
  }
  
  return NULL;
}

void w2c_check_0x5F_wasm_call_ctors_0(w2c_check* instance) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

u32 w2c_check_input_ptr_0(w2c_check* instance) {
  FUNC_PROLOGUE;
  u32 var_i0;
  var_i0 = 1056u;
  FUNC_EPILOGUE;
  return var_i0;
}

u32 w2c_check_check_0(w2c_check* instance, u32 var_p0, u32 var_p1, u32 var_p2) {
  u32 var_l3 = 0, var_l4 = 0;
  FUNC_PROLOGUE;
  u32 var_i0, var_i1, var_i2, var_i3, var_i4, var_i5;
  var_i0 = 0u;
  var_l3 = var_i0;
  var_i0 = var_p0;
  var_i1 = 1056u;
  var_i0 = var_i0 != var_i1;
  if (var_i0) {goto var_B0;}
  var_i0 = var_p1;
  var_i1 = 24u;
  var_i0 = var_i0 != var_i1;
  if (var_i0) {goto var_B0;}
  var_i0 = 0u;
  var_l3 = var_i0;
  var_i0 = 0u;
  var_p0 = var_i0;
  var_L1: 
    var_i0 = var_p0;
    var_i1 = 5u;
    var_i0 = DIV_U(var_i0, var_i1);
    var_p1 = var_i0;
    var_i0 = var_p0;
    var_i1 = 1056u;
    var_i0 += var_i1;
    var_i0 = i32_load8_u_default32(&instance->w2c_memory, (u64)(var_i0));
    var_l4 = var_i0;
    var_i1 = 4294967169u;
    var_i0 += var_i1;
    var_i1 = 255u;
    var_i0 &= var_i1;
    var_i1 = 162u;
    var_i0 = var_i0 < var_i1;
    if (var_i0) {goto var_B0;}
    var_i0 = var_p0;
    var_i1 = 4294967284u;
    var_i0 += var_i1;
    var_i1 = 3u;
    var_i0 = var_i0 < var_i1;
    if (var_i0) {goto var_B2;}
    var_i0 = var_p0;
    var_i1 = 1024u;
    var_i0 += var_i1;
    var_i0 = i32_load8_u_default32(&instance->w2c_memory, (u64)(var_i0));
    var_i1 = var_p0;
    var_i2 = 11u;
    var_i1 *= var_i2;
    var_i2 = var_l4;
    var_i3 = var_p0;
    var_i4 = 29u;
    var_i3 *= var_i4;
    var_i4 = 109u;
    var_i3 += var_i4;
    var_i2 ^= var_i3;
    var_l4 = var_i2;
    var_i3 = var_p0;
    var_i4 = var_p1;
    var_i5 = 4294967291u;
    var_i4 *= var_i5;
    var_i3 += var_i4;
    var_p1 = var_i3;
    var_i4 = 1u;
    var_i3 += var_i4;
    var_i4 = 7u;
    var_i3 &= var_i4;
    var_i2 <<= (var_i3 & 31);
    var_i3 = var_l4;
    var_i4 = 255u;
    var_i3 &= var_i4;
    var_i4 = var_p1;
    var_i5 = 4294967295u;
    var_i4 ^= var_i5;
    var_i5 = 7u;
    var_i4 &= var_i5;
    var_i3 >>= (var_i4 & 31);
    var_i2 |= var_i3;
    var_i1 += var_i2;
    var_i2 = 55u;
    var_i1 += var_i2;
    var_i2 = 255u;
    var_i1 &= var_i2;
    var_i0 = var_i0 != var_i1;
    if (var_i0) {goto var_B0;}
    var_B2:;
    var_i0 = var_p0;
    var_i1 = 1u;
    var_i0 += var_i1;
    var_p0 = var_i0;
    var_i1 = 24u;
    var_i0 = var_i0 != var_i1;
    if (var_i0) {goto var_L1;}
  var_i0 = 0u;
  var_l3 = var_i0;
  var_i0 = 16u;
  var_p0 = var_i0;
  var_i0 = 0u;
  var_i0 = i32_load8_u_default32(&instance->w2c_memory, (u64)(var_i0) + 1069u);
  var_i1 = 8u;
  var_i0 <<= (var_i1 & 31);
  var_i1 = 0u;
  var_i1 = i32_load8_u_default32(&instance->w2c_memory, (u64)(var_i1) + 1068u);
  var_i2 = 16u;
  var_i1 <<= (var_i2 & 31);
  var_i0 |= var_i1;
  var_i1 = 0u;
  var_i1 = i32_load8_u_default32(&instance->w2c_memory, (u64)(var_i1) + 1070u);
  var_i0 |= var_i1;
  var_i1 = var_p2;
  var_i0 = var_i0 != var_i1;
  if (var_i0) {goto var_B0;}
  var_i0 = 2166136261u;
  var_p1 = var_i0;
  var_L3: 
    var_i0 = var_p2;
    var_i1 = var_p0;
    var_i0 >>= (var_i1 & 31);
    var_i1 = 255u;
    var_i0 &= var_i1;
    var_i1 = var_p1;
    var_i0 ^= var_i1;
    var_i1 = 16777619u;
    var_i0 *= var_i1;
    var_p1 = var_i0;
    var_i0 = var_p0;
    var_i1 = 4294967288u;
    var_i0 += var_i1;
    var_p0 = var_i0;
    var_i1 = 4294967288u;
    var_i0 = var_i0 != var_i1;
    if (var_i0) {goto var_L3;}
  var_i0 = var_p1;
  var_i1 = 3901582136u;
  var_i0 = var_i0 == var_i1;
  var_l3 = var_i0;
  var_B0:;
  var_i0 = var_l3;
  FUNC_EPILOGUE;
  return var_i0;
}
```

这里是密文：

```c
static const u8 data_segment_data_w2c_check_d0[] = {
  0x6b, 0x0d, 0x83, 0xa3, 0xb4, 0xa1, 0x8a, 0xfe, 0xd2, 0xba, 0x6a, 0x7f, 
  0x00, 0x00, 0x00, 0x84, 0x70, 0x3d, 0x4e, 0xc5, 0x9e, 0xcc, 0xed, 0xc6, 
};
```

导出函数 `u32 w2c_check_check(w2c_check* instance, u32 p0, u32 p1, u32 p2)` 这里就是主逻辑了。

`var_i1 = 1056u`  `var_i1 = 24u` 这里限定了缓冲区的长度和 flag 的长度。

随后会建立一系列的约束。

首先是可打印字符范围检查：

```c
var_i0 = var_l4;
var_i1 = 4294967169u;   // -127
var_i0 += var_i1;
var_i1 = 255u;
var_i0 &= var_i1;
var_i1 = 162u;
var_i0 = var_i0 < var_i1;
if (var_i0) goto var_B0;  // 失败
```

等价于：

```
33 <= b <= 126
```

也就是可打印 ASCII 范围。

后面跳过了第 12、13、14 字节

```c
var_i0 = var_p0;
var_i1 = 4294967284u;  // -12
var_i0 += var_i1;
var_i1 = 3u;
var_i0 = var_i0 < var_i1;
if (var_i0) {goto var_B2;}
```

因为 `var_p0` 是无符号 32 位，所以 `(i - 12) < 3`

```
i = 12, 13, 14
```

随后对其他未跳过的字节做如下变换：

```c
var_i0 = data[i];                 // memory[1024+i]
var_i1 = i * 11;

var_i2 = l4;                      // input[i]
var_i3 = i * 29 + 109;
var_i2 ^= var_i3;
l4 = var_i2;                      // x = input[i] ^ (i*29+109)

// p1 = i / 5
var_p1 = i / 5;

// i % 5 = i - 5*(i/5)
var_i3 = i;
var_i4 = p1;
var_i5 = -5;
var_i4 *= var_i5;
var_i3 += var_i4;
p1 = var_i3;                      // p1 = i % 5

// 左移量 = (i%5 + 1) & 7
var_i3 += 1;
var_i3 &= 7;

var_i2 <<= var_i3;

// 右移量 = (~(i%5)) & 7 = 7 - i%5
var_i3 = l4 & 255;
var_i4 = p1;
var_i4 ^= -1;
var_i4 &= 7;

var_i3 >>= var_i4;

var_i2 |= var_i3;
var_i1 += var_i2;
var_i1 += 55;
var_i1 &= 255;

if (data[i] != var_i1) fail;
```

即对：

```c
b = input[i]
x = b ^ ((i*29 + 109) & 0xff)
s1 = (i % 5) + 1
s2 = 7 - (i % 5)
term = (x << s1) | (x >> s2)
```

需满足：

```c
data[i] == ((i*11 + term + 55) & 0xff)
```

最后第 12、13、14 字节拼成 `p2`，并进行 FNV-1a 校验。

```c
p1 = 2166136261u;   // FNV offset basis
p0 = 16;

do {
    byte = (p2 >> p0) & 255;
    p1 ^= byte;
    p1 *= 16777619u;   // FNV prime
    p0 += -8;
} while (p0 != -8);
```

解密脚本如下：

```py
from z3 import *

data = [
    0x6b, 0x0d, 0x83, 0xa3, 0xb4, 0xa1, 0x8a, 0xfe,
    0xd2, 0xba, 0x6a, 0x7f, 0x00, 0x00, 0x00, 0x84,
    0x70, 0x3d, 0x4e, 0xc5, 0x9e, 0xcc, 0xed, 0xc6
]

bs = [BitVec(f'b{i}', 8) for i in range(24)]
sol = Solver()

# check 中的范围检查：每个字符必须在可打印 ASCII 范围内
# (b - 127) & 0xff >= 162  <=>  33 <= b <= 126
for b in bs:
    sol.add(b >= 33, b <= 126)

# 除 12、13、14 外，逐字节满足变换关系
for i in range(24):
    if i in (12, 13, 14):
        continue

    # x = input[i] ^ (i*29 + 109)
    c = (i * 29 + 109) & 0xff
    x = bs[i] ^ BitVecVal(c, 8)

    # p1 = i / 5
    # shift_left  = (i - 5*(i/5) + 1) & 7 = (i%5 + 1) & 7
    # shift_right = (~(i - 5*(i/5))) & 7 = 7 - (i%5)
    s1 = (i % 5 + 1) & 7
    s2 = 7 - (i % 5)

    term = (x << s1) | LShR(x, s2)

    # data[i] == (i*11 + term + 55) & 0xff
    expected = BitVecVal((i * 11 + 55) & 0xff, 8) + term
    sol.add(BitVecVal(data[i], 8) == expected)

# 第 12、13、14 字节拼成 p2：
# p2 = (b12 << 16) | (b13 << 8) | b14
p2 = Concat(bs[12], bs[13], bs[14])

# FNV-1a 校验：
# h = 2166136261
# for byte in [p2>>16, p2>>8, p2]:
#     h = (h ^ byte) * 16777619
h = BitVecVal(2166136261, 32)

for hi, lo in [(23, 16), (15, 8), (7, 0)]:
    byte = Extract(hi, lo, p2)
    h = (h ^ ZeroExt(24, byte)) * BitVecVal(16777619, 32)

sol.add(h == BitVecVal(3901582136, 32))

if sol.check() == sat:
    m = sol.model()
    body = ''.join(chr(m.eval(b).as_long()) for b in bs)
    print("flag{" + body + "}")
```

输出如下：

```txt
> python crack.py
flag{wxapkg_wasm_hunt_3bytes!}
```

```txt
flag{wxapkg_wasm_hunt_3bytes!}
```

### 第十一刻

![](https://img.halfcity.top/2026/11/11/7d82d5022f347832f201e65cc7fd71f9.avif)

![](https://img.halfcity.top/2026/11/11/d8361ca5dfe91bc353da3e3cc62ac127.avif)

抓包发现加载了 wasm 模块。反编译一下：

```txt
❯ wasm2c vault.wasm --output vault.c
```

wasm2c 生成的代码里，真正对外暴露的只有两个函数：

- w2c_vault_input_ptr → 固定返回 8192
- w2c_vault_check → 真正的校验函数

check 的开头：

```c
if (len != mem[4096]) return 0;          // 必须等于 42
if (ptr < 8192 || ptr >= 9088) return 0; // 指针范围检查
```

随后读取：

```c
rounds = mem[4100];   // = 11
seed   = mem[4104];   // 64-bit 种子
```

并把输入拷贝到 12288 起始的缓冲区，目标密文存放在 65536。

这一步确定了输入长度固定 42，处理后变成 11 个 u32，最终要和硬编码的 11 个 u32 完全相等。

w2c_vault_f76 是标准的 **splitmix64**：

```c
state += 0x9e3779b97f4a7c15;
z = state;
z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
return z ^ (z >> 31);
```

用种子 `0x36d84b66cd454d90` 连续跑 4 次，得到固定的 4 个 32-bit 密钥：

```txt
0x640e0c07, 0xc64c966a, 0x75b9b11f, 0xbecd29cd
```

它们被存放在 6160 起，供后续 mix 使用。

wasm2c 把 func77 翻译得非常直白：

```c
T  = ((p0 >> 4) ^ (p1 << 3)) + ((p1 >> 6) ^ (p0 << 5));
L  = keys[((p3 & 3) ^ p4)];
res = T ^ ((p2 ^ p1) + (L ^ p0));
```

这是一个典型的 ARX 混合。之前在 WAT 文本里因为栈不平衡看起来很迷惑，但 wasm2c 把求值顺序彻底固定下来，不再有歧义。

w2c_vault_f78 的核心逻辑是：

```c
prev = buf[n-1];               // 初始 prev
for (i = 0; i < n-1; i++) {
    next = buf[i+1];           // 仍然是旧值
    buf[i] = buf[i] + mix(prev, next, key, i, rot, keys);
    prev = buf[i];             // 更新 prev
}
// 最后一位
next = buf[0];                 // 已经是新值
buf[n-1] = buf[n-1] + mix(prev, next, key, n-1, rot, keys);
```

关键点有两个：

1. **更新公式是 new = old + mix(...)**。
2. 最后一位使用的 next 是已经更新过的 buf[0]（wrap-around）。

外层再套 67 轮，每轮密钥 key += 0x7F4A7C15，rot = (key >> 2) & 3。

因为每一步都是：

```txt
new[i] = old[i] + mix(prev, next, ...)
```

所以可以精确反推：

```txt
old[i] = new[i] - mix(prev, next, ...)
```

逆序恢复顺序如下：

1. 先用最后一步恢复 old[n-1]（此时 prev = new[n-2]，next = new[0] 都已知）。
2. 从 i = n-2 往前到 i = 1，此时 prev = new[i-1] 已知，next = old[i+1] 已经恢复。
3. 最后处理 i = 0（prev = old[n-1]，next = old[1]）。

求解脚本如下：

```py
import struct

MASK32 = 0xFFFFFFFF

def mix(p0, p1, p2, p3, p4, keys):
    t = (((p0 >> 4) ^ ((p1 << 3) & MASK32)) +
         ((p1 >> 6) ^ ((p0 << 5) & MASK32))) & MASK32
    L = keys[((p3 & 3) ^ p4) & 3]
    return (t ^ (((p2 ^ p1) + (L ^ p0)) & MASK32)) & MASK32

KEYS = [0x640e0c07, 0xc64c966a, 0x75b9b11f, 0xbecd29cd]

TARGET = [
    0xBA5588D8, 0xE5C92B0A, 0x3BBDDDB1, 0x84C048D3, 0x00CB89A1,
    0x63FA9E8E, 0x7A415167, 0x075808E7, 0x9F545092, 0xBE6960E3, 0x2178DF63
]

def one_round_forward(buf, key, keys):
    n = len(buf)
    rot = (key >> 2) & 3
    prev = buf[n-1]
    for i in range(n-1):
        nxt = buf[i+1]
        old_i = buf[i]
        m = mix(prev, nxt, key, i, rot, keys)
        buf[i] = (old_i + m) & MASK32
        prev = buf[i]
    nxt = buf[0]
    old_i = buf[n-1]
    m = mix(prev, nxt, key, n-1, rot, keys)
    buf[n-1] = (old_i + m) & MASK32

def inverse_round(after, key, keys):
    n = len(after)
    rot = (key >> 2) & 3
    before = [0] * n

    # 最后一步
    m = mix(after[n-2], after[0], key, n-1, rot, keys)
    before[n-1] = (after[n-1] - m) & MASK32

    # i = n-2 → 1
    for i in range(n-2, 0, -1):
        prev = after[i-1]
        nxt = before[i+1]
        m = mix(prev, nxt, key, i, rot, keys)
        before[i] = (after[i] - m) & MASK32

    # i = 0
    prev = before[n-1]
    nxt = before[1]
    m = mix(prev, nxt, key, 0, rot, keys)
    before[0] = (after[0] - m) & MASK32
    return before

def decrypt():
    buf = TARGET[:]
    keys_seq = []
    k = 0
    for _ in range(67):
        k = (k + 0x7F4A7C15) & MASK32
        keys_seq.append(k)

    for k in reversed(keys_seq):
        buf = inverse_round(buf, k, KEYS)

    data = struct.pack("<11I", *buf)
    flag = data[:42]
    print(flag.decode())

if __name__ == "__main__":
    decrypt()
```

```txt
> python freez_solver.py
flag{5938b5c7-af2f-6d9a-1c3f-d88d5298e832}
```

```txt
flag{5938b5c7-af2f-6d9a-1c3f-d88d5298e832}
```

### 提瓦特委托局·四：向着星辰与1&￥……%！

mainCRTStartup() 跟到 main()。

![](https://img.halfcity.top/2026/11/11/3b0b1b4231fdca7d5b99cf84ceb6afe0.avif)

```txt
Commission complete. Exception handled normally.
```

这里的意思似乎是会触发 SEH 调用 Handler 处理异常吗？

![](https://img.halfcity.top/2026/11/11/cf2d3268947d1b76bc32a4bc2c9098ef.avif)

这个函数已经见过很多次了，是 flag 的提取函数。

```c
_BOOL8 __fastcall sub_14000197E(_PVFV *First, _PVFV *Last, int a3, _QWORD *a4, int a5, int a6)
{
  sub_1400018AF(First: First, Last: Last);
  return memcmp(Buf1: First, Buf2: Last, Size: (size_t)&Size_) == 0;
}

void __fastcall sub_1400018AF(_PVFV *First, _PVFV *Last)
{
  _cxa_allocate_exception(thrown_size: (size_t)First);
  (this: (std::runtime_error *)First)->runtime_error(Last: (const char *)Last);
  _cxa_throw(First: First, lptinfo: (struct type_info *)Last, _ZTISt13runtime_error: `typeinfo for'std::runtime_error);
}
```

`sub_14000197E()` 似乎最后比较了密文与加密后的输入，`sub_1400018AF()` 直接触发了异常。

伪代码视图似乎没有体现对 CPP_EH_EXCEPTION 的处理过程。

这里我尝试直接动态调试找 Handler 但是似乎有点问题，程序没有断下在 Dispatch。

我们直接检查下汇编：

```asm
.text:00000001400018AF                    ; Attributes: bp-based frame fpd=20h
.text:00000001400018AF
.text:00000001400018AF                    ; void __fastcall sub_1400018AF(_PVFV *First, _PVFV *Last)
.text:00000001400018AF                    sub_1400018AF   proc near               ; CODE XREF: sub_14000197E+2E↓p
.text:00000001400018AF                                                            ; DATA XREF: .pdata:00000001400170C0↓o ...
.text:00000001400018AF
.text:00000001400018AF                    var_30          = qword ptr -30h
.text:00000001400018AF                    var_28          = dword ptr -28h
.text:00000001400018AF                    var_24          = dword ptr -24h
.text:00000001400018AF                    arg_0           = qword ptr  10h
.text:00000001400018AF
.text:00000001400018AF                    ; __unwind { // __gxx_personality_seh0
.text:00000001400018AF 000 55                             push    rbp
.text:00000001400018B0 008 57                             push    rdi
.text:00000001400018B1 010 56                             push    rsi
.text:00000001400018B2 018 53                             push    rbx
.text:00000001400018B3 020 48 83 EC 38                    sub     rsp, 38h
.text:00000001400018B7 058 48 8D 6C 24 30                 lea     rbp, [rsp+30h]
.text:00000001400018BC 058 48 89 4D 30                    mov     [rbp+20h+arg_0], rcx
.text:00000001400018C0 058 C7 45 FC 00 00                 mov     [rbp+20h+var_24], 0
.text:00000001400018C0 058 00 00
.text:00000001400018C7 058 EB 38                          jmp     short loc_140001901
.text:00000001400018C9                    ; ---------------------------------------------------------------------------
.text:00000001400018C9
.text:00000001400018C9                    loc_1400018C9:                          ; CODE XREF: sub_1400018AF+56↓j
.text:00000001400018C9 058 B9 10 00 00 00                 mov     ecx, 10h
.text:00000001400018CE 058 E8 A5 01 00 00                 call    __cxa_allocate_exception
.text:00000001400018D3 058 48 89 C3                       mov     rbx, rax
.text:00000001400018D6 058 48 8D 05 BB 27                 lea     rax, aNextWindow ; "next window"
.text:00000001400018D6 058 01 00
.text:00000001400018DD 058 48 89 C2                       mov     rdx, rax
.text:00000001400018E0 058 48 89 D9                       mov     rcx, rbx
.text:00000001400018E3                    ;   try {
.text:00000001400018E3 058 E8 A0 01 00 00                 call    _ZNSt13runtime_errorC1EPKc ; std::runtime_error::runtime_error(char const*)
.text:00000001400018E3                    ;   } // starts at 1400018E3
.text:00000001400018E8 058 4C 8B 05 71 33                 mov     r8, cs:off_140014C60
.text:00000001400018E8 058 01 00
.text:00000001400018EF 058 48 8D 05 5A 35                 lea     rax, _ZTISt13runtime_error ; `typeinfo for'std::runtime_error
.text:00000001400018EF 058 01 00
.text:00000001400018F6 058 48 89 C2                       mov     rdx, rax        ; _ZTISt13runtime_error
.text:00000001400018F9 058 48 89 D9                       mov     rcx, rbx
.text:00000001400018FC                    ;   try {
.text:00000001400018FC 058 E8 57 01 00 00                 call    __cxa_throw
.text:00000001400018FC                    ;   } // starts at 1400018FC
.text:0000000140001901                    ; ---------------------------------------------------------------------------
.text:0000000140001901
.text:0000000140001901                    loc_140001901:                          ; CODE XREF: sub_1400018AF+18↑j
.text:0000000140001901                                                            ; sub_1400018AF+C4↓j
.text:0000000140001901 058 83 7D FC 02                    cmp     [rbp+20h+var_24], 2
.text:0000000140001905 058 7E C2                          jle     short loc_1400018C9
.text:0000000140001907 058 EB 6C                          jmp     short loc_140001975
.text:0000000140001909                    ; ---------------------------------------------------------------------------
.text:0000000140001909                    ;   cleanup() // owned by 1400018E3
.text:0000000140001909 058 48 89 C7                       mov     rdi, rax        ; void *
.text:000000014000190C 058 48 89 D6                       mov     rsi, rdx
.text:000000014000190F 058 48 89 D9                       mov     rcx, rbx
.text:0000000140001912 058 E8 49 01 00 00                 call    __cxa_free_exception
.text:0000000140001917 058 48 89 F8                       mov     rax, rdi
.text:000000014000191A 058 48 89 F2                       mov     rdx, rsi
.text:000000014000191D 058 EB 00                          jmp     short $+2
.text:000000014000191F                    ; ---------------------------------------------------------------------------
.text:000000014000191F
.text:000000014000191F                    loc_14000191F:                          ; CODE XREF: sub_1400018AF+6E↑j
.text:000000014000191F                    ;   catch(std::runtime_error) // owned by 1400018FC
.text:000000014000191F 058 48 83 FA 01                    cmp     rdx, 1
.text:0000000140001923 058 74 08                          jz      short loc_14000192D
.text:0000000140001925 058 48 89 C1                       mov     rcx, rax
.text:0000000140001928 058 E8 B3 17 00 00                 call    _Unwind_Resume
.text:000000014000192D                    ; ---------------------------------------------------------------------------
.text:000000014000192D
.text:000000014000192D                    loc_14000192D:                          ; CODE XREF: sub_1400018AF+74↑j
.text:000000014000192D 058 48 89 C1                       mov     rcx, rax
.text:0000000140001930 058 E8 3B 01 00 00                 call    __cxa_begin_catch
.text:0000000140001935 058 48 89 45 F0                    mov     [rbp+20h+var_30], rax
.text:0000000140001939 058 C7 45 F8 00 00                 mov     [rbp+20h+var_28], 0
.text:0000000140001939 058 00 00
.text:0000000140001940 058 EB 22                          jmp     short loc_140001964
.text:0000000140001942                    ; ---------------------------------------------------------------------------
.text:0000000140001942
.text:0000000140001942                    loc_140001942:                          ; CODE XREF: sub_1400018AF+B9↓j
.text:0000000140001942 058 8B 45 FC                       mov     eax, [rbp+20h+var_24]
.text:0000000140001945 058 8D 14 00                       lea     edx, [rax+rax]
.text:0000000140001948 058 8B 45 F8                       mov     eax, [rbp+20h+var_28]
.text:000000014000194B 058 C1 E0 03                       shl     eax, 3
.text:000000014000194E 058 48 63 C8                       movsxd  rcx, eax
.text:0000000140001951 058 48 8B 45 30                    mov     rax, [rbp+20h+arg_0]
.text:0000000140001955 058 48 01 C8                       add     rax, rcx
.text:0000000140001958 058 48 89 C1                       mov     rcx, rax
.text:000000014000195B 058 E8 A7 FE FF FF                 call    sub_140001807
.text:0000000140001960 058 83 45 F8 01                    add     [rbp+20h+var_28], 1
.text:0000000140001964
.text:0000000140001964                    loc_140001964:                          ; CODE XREF: sub_1400018AF+91↑j
.text:0000000140001964 058 83 7D F8 02                    cmp     [rbp+20h+var_28], 2
.text:0000000140001968 058 7E D8                          jle     short loc_140001942
.text:000000014000196A 058 83 45 FC 01                    add     [rbp+20h+var_24], 1
.text:000000014000196E 058 E8 F5 00 00 00                 call    __cxa_end_catch
.text:0000000140001973 058 EB 8C                          jmp     short loc_140001901
.text:0000000140001975                    ; ---------------------------------------------------------------------------
.text:0000000140001975
.text:0000000140001975                    loc_140001975:                          ; CODE XREF: sub_1400018AF+58↑j
.text:0000000140001975 058 48 83 C4 38                    add     rsp, 38h
.text:0000000140001979 020 5B                             pop     rbx
.text:000000014000197A 018 5E                             pop     rsi
.text:000000014000197B 010 5F                             pop     rdi
.text:000000014000197C 008 5D                             pop     rbp
.text:000000014000197D 000 C3                             retn
.text:000000014000197D                    ; } // starts at 1400018AF
.text:000000014000197D                    sub_1400018AF   endp
```

注意这里：

```asm
.text:000000014000191F                    loc_14000191F:                          ; CODE XREF: sub_1400018AF+6E↑j
.text:000000014000191F                    ;   catch(std::runtime_error) // owned by 1400018FC
.text:000000014000191F 058 48 83 FA 01                    cmp     rdx, 1
.text:0000000140001923 058 74 08                          jz      short loc_14000192D
.text:0000000140001925 058 48 89 C1                       mov     rcx, rax
.text:0000000140001928 058 E8 B3 17 00 00                 call    _Unwind_Resume
```

这里跳转到了 `loc_14000192D` 并执行 `_Unwind_Resume` 从异常恢复。

这里跳转到 `loc_14000192D` 执行 `__cxa_begin_catch` 开始异常处理。随后跳转到 `loc_140001964` 并在里面跳转执行真实的异常处理的逻辑。

![](https://img.halfcity.top/2026/11/11/0265d8702677512ecbc6b8091ff70424.avif)

最后调用 `__cxa_end_catch` 结束异常处理。

如果还原成源码的话大致是这个样子：

```cpp
void sub_1400018AF(Window *windows)
{
    for (int i = 0; i <= 2; i++) {
        try {
            throw std::runtime_error("next window");
        }
        catch (std::runtime_error &e) {
            for (int j = 0; j <= 2; j++) {
                sub_140001807(&windows[j], i * 2);
            }
        }
    }
}
```

`sub_140001807` 这个函数就是关键的校验函数了。

伪代码有点问题，这里直接看汇编：

![](https://img.halfcity.top/2026/11/11/ebe633815d186819d07f1416493f03eb.avif)

```asm
.text:0000000140001807                    sub_140001807   proc near               ; CODE XREF: sub_1400018AF+AC↓p
.text:0000000140001807                                                            ; DATA XREF: .pdata:00000001400170B4↓o ...
.text:0000000140001807
.text:0000000140001807                    var_24          = qword ptr -24h
.text:0000000140001807                    var_1C          = dword ptr -1Ch
.text:0000000140001807                    var_18          = qword ptr -18h
.text:0000000140001807                    var_C           = dword ptr -0Ch
.text:0000000140001807                    var_8           = qword ptr -8
.text:0000000140001807                    arg_0           = qword ptr  10h
.text:0000000140001807                    arg_8           = dword ptr  18h
.text:0000000140001807
.text:0000000140001807 000 55                             push    rbp
.text:0000000140001808 008 48 89 E5                       mov     rbp, rsp
.text:000000014000180B 008 48 83 EC 50                    sub     rsp, 50h
.text:000000014000180F 058 48 89 4D 10                    mov     [rbp+arg_0], rcx
.text:0000000140001813 058 89 55 18                       mov     [rbp+arg_8], edx
.text:0000000140001816 058 48 8B 45 10                    mov     rax, [rbp+arg_0]
.text:000000014000181A 058 48 89 45 E8                    mov     [rbp+var_18], rax
.text:000000014000181E 058 48 8B 45 E8                    mov     rax, [rbp+var_18]
.text:0000000140001822 058 8B 00                          mov     eax, [rax]
.text:0000000140001824 058 89 45 FC                       mov     dword ptr [rbp+var_8+4], eax
.text:0000000140001827 058 48 8B 45 E8                    mov     rax, [rbp+var_18]
.text:000000014000182B 058 8B 40 04                       mov     eax, [rax+4]
.text:000000014000182E 058 89 45 F8                       mov     dword ptr [rbp+var_8], eax
.text:0000000140001831 058 C7 45 F4 00 00                 mov     [rbp+var_C], 0
.text:0000000140001831 058 00 00
.text:0000000140001838 058 EB 52                          jmp     short loc_14000188C
.text:000000014000183A                    ; ---------------------------------------------------------------------------
.text:000000014000183A
.text:000000014000183A                    loc_14000183A:                          ; CODE XREF: sub_140001807+89↓j
.text:000000014000183A 058 8B 55 18                       mov     edx, [rbp+arg_8]
.text:000000014000183D 058 8B 45 F4                       mov     eax, [rbp+var_C]
.text:0000000140001840 058 01 D0                          add     eax, edx
.text:0000000140001842 058 48 98                          cdqe
.text:0000000140001844 058 48 8D 14 85 00                 lea     rdx, ds:0[rax*4]
.text:0000000140001844 058 00 00 00
.text:000000014000184C 058 48 8D 05 0D 28                 lea     rax, dword_140014060
.text:000000014000184C 058 01 00
.text:0000000140001853 058 8B 04 02                       mov     eax, [rdx+rax]
.text:0000000140001856 058 89 45 E4                       mov     [rbp+var_1C], eax
.text:0000000140001859 058 8B 45 F8                       mov     eax, dword ptr [rbp+var_8]
.text:000000014000185C 058 89 45 E0                       mov     dword ptr [rbp+var_24+4], eax
.text:000000014000185F 058 8B 55 F8                       mov     edx, dword ptr [rbp+var_8]
.text:0000000140001862 058 8B 45 E4                       mov     eax, [rbp+var_1C]
.text:0000000140001865 058 01 D0                          add     eax, edx
.text:0000000140001867 058 BA 05 00 00 00                 mov     edx, 5          ; n5
.text:000000014000186C 058 89 C1                          mov     ecx, eax        ; int
.text:000000014000186E 058 E8 7C FF FF FF                 call    sub_1400017EF
.text:0000000140001873 058 33 45 E4                       xor     eax, [rbp+var_1C]
.text:0000000140001876 058 33 45 FC                       xor     eax, dword ptr [rbp+var_8+4]
.text:0000000140001879 058 89 45 DC                       mov     dword ptr [rbp+var_24], eax
.text:000000014000187C 058 8B 45 E0                       mov     eax, dword ptr [rbp+var_24+4]
.text:000000014000187F 058 89 45 FC                       mov     dword ptr [rbp+var_8+4], eax
.text:0000000140001882 058 8B 45 DC                       mov     eax, dword ptr [rbp+var_24]
.text:0000000140001885 058 89 45 F8                       mov     dword ptr [rbp+var_8], eax
.text:0000000140001888 058 83 45 F4 01                    add     [rbp+var_C], 1
.text:000000014000188C
.text:000000014000188C                    loc_14000188C:                          ; CODE XREF: sub_140001807+31↑j
.text:000000014000188C 058 83 7D F4 01                    cmp     [rbp+var_C], 1
.text:0000000140001890 058 7E A8                          jle     short loc_14000183A
.text:0000000140001892 058 48 8B 45 E8                    mov     rax, [rbp+var_18]
.text:0000000140001896 058 8B 55 FC                       mov     edx, dword ptr [rbp+var_8+4]
.text:0000000140001899 058 89 10                          mov     [rax], edx
.text:000000014000189B 058 48 8B 45 E8                    mov     rax, [rbp+var_18]
.text:000000014000189F 058 48 8D 50 04                    lea     rdx, [rax+4]
.text:00000001400018A3 058 8B 45 F8                       mov     eax, dword ptr [rbp+var_8]
.text:00000001400018A6 058 89 02                          mov     [rdx], eax
.text:00000001400018A8 058 90                             nop
.text:00000001400018A9 058 48 83 C4 50                    add     rsp, 50h
.text:00000001400018AD 008 5D                             pop     rbp
.text:00000001400018AE 000 C3                             retn
.text:00000001400018AE                    sub_140001807   endp
```

![](https://img.halfcity.top/2026/11/11/e37adcd011c9877f077fad6b68b58e37.avif)

大致的语义逻辑如下：

```c
void sub_140001807(uint32_t *p, int key)   // p 指向 8 字节块
{
    uint32_t v0 = p[0];
    uint32_t v1 = p[1];

    for (int i = 0; i <= 1; i++) {
        uint32_t t = table[key + i];                     // table = dword_140014060
        uint32_t tmp = rol32(t + v1, 5) ^ t ^ v0;        // 加法是 32 位模加
        v0 = v1;
        v1 = tmp;
    }

    p[0] = v0;
    p[1] = v1;
}
```

这是一个 2 轮、32 位半块、加法+循环左移+异或的 Feistel 网络。

每轮：

```
(v0, v1) -> (v1, rol32(t + v1, 5) ^ t ^ v0)
```

逆 Feistel，轮序反过来即可解密。

密文我们可以在最后的 cmp 中找到引用：

![](https://img.halfcity.top/2026/11/11/f6845dc0ad2146cff90f94dec0191fab.avif)

解密脚本如下：

```py
MASK = 0xFFFFFFFF

dword_140014060 = [
    0x13572468, 0xA1B2C3D4, 0x0BADF00D, 0x55AA33CC,
    0x31415926, 0x27182818, 0x00000000, 0x00000000,
]

Size_ = [0x7D, 0xE5, 0x74, 0xDB, 0x26, 0x51, 0xBA, 0xAE, 0x8B, 0x8F, 0x88, 0x99, 0xF2, 0xFC, 0xED, 0x5C, 0xDA, 0x21, 0xE1, 0xB4, 0x0F, 0xA3, 0xFF, 0xF1]

def rol32(x, n):
    x &= MASK
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK

# 对每个 8 字节块，按 key = 4, 2, 0 逆序解密
buf = bytearray(Size_)
for off in range(0, len(buf) - 7, 8):
    p0 = int.from_bytes(buf[off:off+4], "little")
    p1 = int.from_bytes(buf[off+4:off+8], "little")
    v0, v1 = p0, p1

    for key in (4, 2, 0):
        # 逆 Feistel：轮序 1,0
        for i in (1, 0):
            t = dword_140014060[key + i] & MASK
            nv1 = v0
            nv0 = (v1 ^ rol32((t + nv1) & MASK, 5) ^ t) & MASK
            v0, v1 = nv0, nv1

    buf[off:off+4] = v0.to_bytes(4, "little")
    buf[off+4:off+8] = v1.to_bytes(4, "little")

flag = bytes(buf)
print("flag{" + flag.decode() + "}")
```

输出如下：

```txt
> python tiwate.py
flag{except10ns_are_the_path!}
```

```txt
flag{except10ns_are_the_path!}
```

### 曼波维修部·三：重写了，但没完全重写

![](https://img.halfcity.top/2026/11/11/9b5929b490ea88ed691bdf48e1621818.avif)

这里可以看到非常多的文件名，rust 程序的特征很明显，标准库里面有大量编译期嵌入的硬编码字符串。

很多都与 panic 处理有关，但是其实把 panic 关了还是会有让人难以理解。

```c
__int64 *__fastcall main(__int64 *a1, char **a2, char **a3)
{
  return sub_16D10(
           sub_17B20: (__int64 (__fastcall *)(int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, __int64, int, int, char, int, int, int, struct _Unwind_Exception *, int, int, int, char, __int64, int))sub_17B20,
           a2: (__int64 *)(int)a1,
           a3: (__int64 *)a2,
           a4: 0);
}
```

进入 main 函数调用 `lang::start()` 进入真正的 main 函数：

![](https://img.halfcity.top/2026/11/11/1067b1e95ca615b4ca578e30a82ab411.avif)

```c
  v12 = sub_33740(a1: (volatile signed __int32 **)v11, a2: &v10);
  v13 = v2;
  if ( (v12 & 1) != 0 )
  {
    v14[0] = v13;
    sub_54770(a1: (__int64)aCalledResultUn, a2: 43, a3: (__int64)v14, a4: (__int64)&off_58AD8, a5: (__int64)&off_58AC0);// "/mnt/d/ai-community/problem/W4-03/author/challenge.rs"
  }
```

这里的 v12 应该就是 Result，(v12 & 1) != 0取低位也就是 Result 和 Err 取一个枚举值。

这里应该是 `if let Err(e) = challenge::start()` 大致这种逻辑。

当然 rust 的库函数分析起来很麻烦，这个程序也没有符号，只能大致依靠逻辑猜测一下。

![](https://img.halfcity.top/2026/11/11/10bde760cf41db1802cf03e837666ee2.avif)

这里开头就获取了锁，函数异常的大，可能是一个库函数，这里的开头应该是初始化 string 然后输出，像这样：

```c
__int64 __fastcall sub_17B20()
{
  str *str_0; // rax
  __int64 v1; // rdx
  __int64 v2; // rdx
  __int64 v3; // rax
  __int64 v4; // rdx
  void *v5; // rax
  void *n30; // rdx
  str *str_1; // rax
  __int64 v8; // rdx
  void *v10; // [rsp+70h] [rbp-58h] BYREF
  __int64 v11[3]; // [rsp+88h] [rbp-40h] BYREF
  __int64 v12; // [rsp+A0h] [rbp-28h]
  __int64 v13; // [rsp+A8h] [rbp-20h]
  _QWORD v14[3]; // [rsp+B0h] [rbp-18h] BYREF

  str_0 = (str *)String::new(Rewritten_duty_passphrase:_n: aRewrittenDutyP, n27: 27);
  std::println(str_0, v1);
  sub_17E10(a1: &v10);
  v11[0] = (__int64)sub_40040();
  v12 = sub_33740((volatile signed __int32 **)v11, &v10);
  v13 = v2;
  if ( (v12 & 1) != 0 )
  {
    v14[0] = v13;
    sub_54770((__int64)aCalledResultUn, 43, (__int64)v14, (__int64)&off_58AD8, (__int64)&str_aMntDAiCommunit_23);// "/mnt/d/ai-community/problem/W4-03/author/challenge.rs"
  }
  v3 = sub_193F0(&v10);
  v5 = (void *)sub_17D60(v3, v4);
  if ( (check(a1: v5, n30: n30) & 1) != 0 )
    str_1 = String::new(Rewritten_duty_passphrase:_n: aReviewPassedTe, n27: 56);
  else
    str_1 = String::new(Rewritten_duty_passphrase:_n: aRewriteComplet, n27: 46);
  std::println(str_1, v8);
  return sub_16C20(&v10);
}
```

随后我们可以思考，程序要求输入那么可能就会调用 read_line() 这个函数，而传入给 check 的 v5 应该是原始的输入或者是格式化后的输入。

`if ( (v12 & 1) != 0 )` 这里如果是判断是否读取成功的话 v12 应该就是 read_line() 的 Result 返回值。

后面的 unwrap() 逻辑正好是对 read_line() 的处理，如果 sub_33740 是 read_line() 那么 v11 就是 stdin 了。

后面的 v10 就是 input，那么 v3 就是 stream 那么 v5 就是处理过的函数。

一切就对上了。

恢复如下：

```c
__int64 __fastcall sub_17B20()
{
  str *str_0; // rax
  __int64 v1; // rdx
  __int64 v2; // rdx
  __int64 v3; // rax
  __int64 v4; // rdx
  void *v5; // rax
  void *n30; // rdx
  str *str_1; // rax
  __int64 v8; // rdx
  void *input; // [rsp+70h] [rbp-58h] BYREF
  __int64 stdin[3]; // [rsp+88h] [rbp-40h] BYREF
  __int64 Result_read_line; // [rsp+A0h] [rbp-28h]
  __int64 v13; // [rsp+A8h] [rbp-20h]
  _QWORD v14[3]; // [rsp+B0h] [rbp-18h] BYREF

  str_0 = (str *)String::new(Rewritten_duty_passphrase:_n: aRewrittenDutyP, n27: 27);
  std::println(str: str_0, v1);
  sub_17E10(a1: &input);
  stdin[0] = (__int64)::stdin();
  Result_read_line = io::stdin::read_line((volatile signed __int32 **)stdin, &input);
  v13 = v2;
  if ( (Result_read_line & 1) != 0 )
  {
    v14[0] = v13;
    sub_54770((__int64)aCalledResultUn, 43, (__int64)v14, (__int64)&off_58AD8, (__int64)&str_aMntDAiCommunit_23);// "/mnt/d/ai-community/problem/W4-03/author/challenge.rs"
  }
  v3 = String::to_bytes(&input);
  v5 = (void *)std::trim(v3, v4);
  if ( (check(a1: v5, n30: n30) & 1) != 0 )
    str_1 = (str *)String::new(Rewritten_duty_passphrase:_n: aReviewPassedTe, n27: 56);
  else
    str_1 = (str *)String::new(Rewritten_duty_passphrase:_n: aRewriteComplet, n27: 46);
  std::println(str: str_1, v8);
  return sub_16C20(&input);
}
```

如果我们使用 rust 来写大致如下：

```rust
fn main() {
    println!("Rewritten duty passphrase:");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    let s = input.trim();

    if challenge::check(s) {
        println!("Review passed. Technical debt successfully transferred.");
    } else {
        println!("Rewrite complete; passphrase problem remains.");
    }
}
```

让我们继续分析 check() 函数吧。

```c
char __fastcall check(void *a1, void *n30)
{
  __int64 v2; // rdx
  unsigned __int64 n0x18_2; // rdx
  __int64 v4; // rdx
  unsigned __int64 n8_1; // rdx
  unsigned __int64 n5; // [rsp+10h] [rbp-198h]
  char v8; // [rsp+1Fh] [rbp-189h]
  unsigned __int64 n0x18; // [rsp+28h] [rbp-180h]
  _QWORD v11[2]; // [rsp+58h] [rbp-150h] BYREF
  _BYTE s[24]; // [rsp+68h] [rbp-140h] BYREF
  _QWORD v13[2]; // [rsp+80h] [rbp-128h] BYREF
  __int64 v14; // [rsp+90h] [rbp-118h]
  unsigned __int64 n0x18_1; // [rsp+98h] [rbp-110h]
  _QWORD dest[24]; // [rsp+A0h] [rbp-108h] BYREF
  _BYTE s_1[8]; // [rsp+160h] [rbp-48h] BYREF
  _QWORD v18[2]; // [rsp+168h] [rbp-40h] BYREF
  __int64 v19; // [rsp+178h] [rbp-30h]
  unsigned __int64 n8; // [rsp+180h] [rbp-28h]
  __int64 v21; // [rsp+188h] [rbp-20h]
  _QWORD v22[3]; // [rsp+190h] [rbp-18h]

  if ( n30 != (char *)&off_18 + 6 )
    return 0;
  v22[2] = 5;
  v22[1] = 1;
  v11[0] = a1;
  v11[1] = 5;
  if ( (sub_18DB0(v11, &off_58890) & 1) != 0 || *((_BYTE *)a1 + 29) != 125 )
    return 0;
  memset(s: s, c: 0, n: sizeof(s));
  v13[0] = sub_188C0(0, n24: 24);
  v13[1] = v2;
  while ( 1 )
  {
    v14 = sub_18DA0(v13);
    n0x18_1 = n0x18_2;
    if ( (v14 & 1) == 0 )
      break;
    n0x18 = n0x18_1;
    memcpy(dest: dest, src: &src_, n: sizeof(dest));
    if ( n0x18 >= 0x18 )
      sub_547FF(n0x18, 24, &str_aMntDAiCommunit_4);// "/mnt/d/ai-community/problem/W4-03/author/challenge.rs"
    n5 = dest[n0x18] + 5LL;
    if ( n5 < 5 )
      sub_55830(&str_aMntDAiCommunit_5);        // "/mnt/d/ai-community/problem/W4-03/author/challenge.rs"
    if ( n5 >= 0x1E )
      sub_547FF(n5, 30, &str_aMntDAiCommunit_6);// "/mnt/d/ai-community/problem/W4-03/author/challenge.rs"
    s[n0x18] = *((_BYTE *)a1 + n5);
  }
  memset(s: s_1, c: 0, n: sizeof(s_1));
  v18[0] = sub_188C0(0, n24: 8);
  v18[1] = v4;
  while ( 1 )
  {
    v19 = sub_18DA0(v18);
    n8 = n8_1;
    if ( (v19 & 1) == 0 )
      break;
    v21 = 0x2179654B74735572LL;
    if ( n8 >= 8 )
      sub_547FF(n8, 8, &str_aMntDAiCommunit_1); // "/mnt/d/ai-community/problem/W4-03/author/challenge.rs"
    v8 = *((_BYTE *)&v22[-1] + n8);
    v22[0] = 0x30626E344D743463LL;
    s_1[n8] = *((_BYTE *)v22 + n8) ^ v8;
  }
  sub_17650(s: s, n24: 24, s: s_1, n8: 8);
  return sub_188B0(s: s, &qword_9BED) & 1;
}
```

`0x2179654B74735572` `0x30626E344D743463` 似乎是 ascii 码的 key。

直接解析就是 `'!yeKtsUr'` `'0bn4Mt4c'` 如果是小端序看的话就是 `'rUstKey!'` `'c4tM4nb0'` 两个词。

将 nxx 这种名字都换成 len 可以看到：

```c
if ( inner_len >= 0x18 )
if ( (sub_18DB0(v11, &off_58890) & 1) != 0 || input[29] != '}' )
```

```asm
.data.rel.ro:0000000000058890 E8 9B 00 00 00…    off_58890       dq offset unk_9BE8      ; DATA XREF: check+84↑o

.rodata:0000000000009BE8 66                 unk_9BE8        db  66h ; f             ; DATA XREF: .data.rel.ro:off_58890↓o
.rodata:0000000000009BE9 6C                                 db  6Ch ; l
.rodata:0000000000009BEA 61                                 db  61h ; a
.rodata:0000000000009BEB 67                                 db  67h ; g
.rodata:0000000000009BEC 7B                                 db  7Bh ; {
```

因此这里来检测了输入的格式，随后从被 src_ 初始化的 dest 中提取 5 到 29 也就是后面的字符。

因此 src_ 应该是一个索引表，我们 dump 出来验证一下，确实如此：

```c
unsigned long src_[24] = {
    0x0000000000000003, 0x000000000000000E, 0x0000000000000001, 0x000000000000000C, 
    0x0000000000000017, 0x000000000000000A, 0x0000000000000015, 0x0000000000000008, 
    0x0000000000000013, 0x0000000000000006, 0x0000000000000011, 0x0000000000000004, 
    0x000000000000000F, 0x0000000000000002, 0x000000000000000D, 0x0000000000000000, 
    0x000000000000000B, 0x0000000000000016, 0x0000000000000009, 0x0000000000000014, 
    0x0000000000000007, 0x0000000000000012, 0x0000000000000005, 0x0000000000000010
};
```

后续使用 key 初始化 s_1 派生密钥，并使用构建好的索引对 key 做变换。

`qword_9BED` 应该就是密文，`sub_17650` 就是最后的加密函数。

![](https://img.halfcity.top/2026/11/11/cb9b78ffd7087ddfdd21df31d9622b37.avif)

函数很复杂，但是我们注意到了大量的 n0x100 和 ` _BYTE sa[256]; // [rsp+A8h] [rbp-170h] BYREF` 以及 `  memset(s: sa, c: 0, n: sizeof(sa))`。

这个是 RC4 的 SBOX 的特征。

猜测可能是 RC4 加密。

大致流程如下：

```rust
fn check(input: &str) -> bool {
    if input.len() != 30 { return false; }
    if !input.starts_with("flag{") { return false; }
    if input.as_bytes()[29] != b'}' { return false; }

    let mut s = [0u8; 24];

    // 按 dest 表从 input[5..29] 中取 24 个字符
    for i in 0..24 {
        let idx = dest[i] + 5;
        if idx < 5 || idx >= 30 { panic!(); }
        s[i] = input.as_bytes()[idx];
    }

    // 生成 8 字节密钥
    let mut key = [0u8; 8];
    for i in 0..8 {
        let a = bytes_of(0x2179654B74735572)[i]; // "rUstKey!"
        let b = bytes_of(0x30626E344D743463)[i]; // "c4tM4nb0"
        key[i] = b ^ a;
    }

    rc4(&mut s, &key);

    s == target
}
```

解密脚本如下：

```py
src = [
    0x03, 0x0E, 0x01, 0x0C,
    0x17, 0x0A, 0x15, 0x08,
    0x13, 0x06, 0x11, 0x04,
    0x0F, 0x02, 0x0D, 0x00,
    0x0B, 0x16, 0x09, 0x14,
    0x07, 0x12, 0x05, 0x10,
]

target = bytes([
    0xE9, 0xA8, 0x79, 0x7B, 0xC5, 0x32, 0xD9, 0xDA,
    0x26, 0xFA, 0x31, 0x90, 0x4C, 0xBE, 0x96, 0x6F,
    0x1C, 0x93, 0xB8, 0x42, 0x70, 0x9D, 0xE2, 0x8C,
])

key = bytes([
    0x11, 0x61, 0x07, 0x39,
    0x7F, 0x0B, 0x1B, 0x11,
])

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0

    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = 0
    j = 0
    out = bytearray()

    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out.append(c ^ k)

    return bytes(out)

t = rc4(target, key)

# body[src[i]] = t[i]
body = bytearray(24)
for i, idx in enumerate(src):
    body[idx] = t[i]

flag = b"flag{" + bytes(body) + b"}"
print(flag.decode())
```

输出如下：

```txt
> python rusty.py
flag{rewr1te_it_in_rust_now!!}
```

```txt
flag{rewr1te_it_in_rust_now!!}
```

### 空空の蛇

#### 静态分析

![](https://img.halfcity.top/2026/11/11/af36584e0b0941c5c34c6027de23bda6.avif)

查壳发现是 pyinstaller 打包的。

我们先解包：

```txt
> pyinstxtractor-ng frozenwhisper.exe
[+] Processing frozenwhisper.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.13
[+] Length of package: 7696660 bytes
[+] Found 64 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: main.pyc
[+] Found 112 files in PYZ archive
[+] Successfully extracted pyinstaller archive: frozenwhisper.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

然后反编译一下 pyc 文件：

![](https://img.halfcity.top/2026/11/11/e41db10cc962c6008938586e251672ec.avif)

这里出现了很奇怪的现象，主程序一运行就自己退出？

然而实测这里依旧会提示我输入 flag 并检验，所以这肯定隐藏了什么逻辑：

```txt
> frozenwhisper.exe
Input flag: asd
Wrong
```

```py
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'pyiboot01_bootstrap.py'
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import sys
import pyimod02_importers
pyimod02_importers.install()
import os
if not hasattr(sys, 'frozen'):
    sys.frozen = True
sys.prefix = sys._MEIPASS
sys.exec_prefix = sys.prefix
sys.base_prefix = sys.prefix
sys.base_exec_prefix = sys.exec_prefix
VIRTENV = 'VIRTUAL_ENV'
if VIRTENV in os.environ:
    os.environ[VIRTENV] = ''
    del os.environ[VIRTENV]
python_path = []
for pth in sys.path:
    python_path.append(os.path.abspath(pth))
    sys.path = python_path
try:
    import encodings
except ImportError:
    pass
if sys.warnoptions:
    import warnings
import pyimod03_ctypes
pyimod03_ctypes.install()
if sys.platform.startswith('win'):
    import pyimod04_pywin32
    pyimod04_pywin32.install()
for entry in os.listdir(sys._MEIPASS):
    entry = os.path.join(sys._MEIPASS, entry)
    if os.path.isdir(entry) and entry.endswith('.egg'):
            sys.path.append(entry)
```

启动流程似乎也没有什么问题，这样找下去感觉不太行，既然有输入提示的字符串我们可以尝试直接去找找。

如果没有加密的话应该就可以定位到有问题的文件。

![](https://img.halfcity.top/2026/11/11/285acf0f1a6141fbb0a628da870cbac6.avif)

很惊讶竟然是在 `python313.dll` 里面，所以这里似乎是 pyinstaller 内嵌的解释器被魔改了，向里面嵌入了异常的字节码。

这里似乎就是字节码所在的位置，同时名字似乎就叫 `_fwh_main`。

![](https://img.halfcity.top/2026/11/11/8ec508e623acf63cdd37876c7f143ed5.avif)

IDA 无法加载符号文件，所以这里的文件 hash 无法匹配任何的 python 解释器版本，完全肯定了这个解释器被修改过。

![](https://img.halfcity.top/2026/11/11/c2f0a759b0abaa3ef63fe6e9f0f6f76e.avif)

定位到目标字符串。

这应该是一个 Frozen 模块。

![](https://img.halfcity.top/2026/11/11/83f365faf071cbf29e65171ea390b59f.avif)

找到附近可能的 `cb_object` 结构：

```py
import ida_bytes

anchor = 0x1804A846B
for ea in range(anchor, anchor - 0x400, -1):
    b = ida_bytes.get_byte(ea)
    if b in (0x63, 0xE3):
        print(f"candidate TYPE_CODE at 0x{ea:X}")
```

输出如下：

```txt
candidate TYPE_CODE at 0x1804A83C1
candidate TYPE_CODE at 0x1804A8316
candidate TYPE_CODE at 0x1804A8313
candidate TYPE_CODE at 0x1804A82E7
candidate TYPE_CODE at 0x1804A82C2
candidate TYPE_CODE at 0x1804A82BC
candidate TYPE_CODE at 0x1804A8296
candidate TYPE_CODE at 0x1804A816C
candidate TYPE_CODE at 0x1804A8109
candidate TYPE_CODE at 0x1804A8105
candidate TYPE_CODE at 0x1804A8100
candidate TYPE_CODE at 0x1804A80B6
candidate TYPE_CODE at 0x1804A80AB
candidate TYPE_CODE at 0x1804A8095
candidate TYPE_CODE at 0x1804A807E
```

`0x1804A83C1` 应该就是目标了，尝试转储结构并提取字节码：

```py
import ida_bytes

START = 0x1804A83C1
SIZE  = 0x400
OUT   = r"D:\data\blog\ctf\spark_2026\resources\week4\fwh_main.bin"

data = bytearray()
for i in range(SIZE):
    data.append(ida_bytes.get_byte(START + i))

with open(OUT, "wb") as f:
    f.write(data)

print(f"[+] dumped {len(data)} bytes from 0x{START:X} to {OUT}")
print("[+] first 32 bytes:", data[:32].hex())
```

```txt
[+] dumped 1024 bytes from 0x1804A83C1 to D:\data\blog\ctf\spark_2026\resources\week4\fwh_main.bin
[+] first 32 bytes: 630000000000000000000000000500000003000000f39000000095001e005b01
```

我本地的 cpython 是 3.14 的，这里我将下载一个 3.13 的版本：

```txt
> uv python install 3.13.0rc3
Installed Python 3.13.0rc3 in 18.45s
 + cpython-3.13.0rc3-windows-x86_64-none (python3.13.exe)
```

不过这里似乎有点问题无法解析，观察发现应该是 co_code 被出题人魔改了，我们可以自己解析一下：

**`co_consts`（常量池）**
位于 `0x1804A846B` 开始的元组，长度 5：

```
0x1804A846B: 29 05          ; TYPE_SMALL_TUPLE, 5 elements
0x1804A846D: 4E             ; None
0x1804A846E: 7A 0C          ; "Input flag: "
0x1804A847C: DA 00          ; ""
0x1804A847E: DA 07          ; "Correct"
0x1804A8487: DA 05          ; "Wrong"
```

**`co_names`（全局名称）**
位于 `0x1804A848E` 开始的元组，长度 5：

```
0x1804A848E: 29 05          ; TYPE_SMALL_TUPLE, 5 elements
0x1804A8490: DA 05          ; "input"
0x1804A8497: DA 08          ; "EOFError"
0x1804A84A1: DA 11          ; "KeyboardInterrupt"
0x1804A84B4: DA 05          ; "print"
```

**`co_varnames`（局部变量）**
位于 `0x1804A84BC` 开始的元组，长度 1：

```
0x1804A84BC: F0 01 00 00 00  	; TYPE_REF
0x1804A84C1: 29 01          	; TYPE_SMALL_TUPLE, 1 element
0x1804A84C2: 72 88 01 00 00 00	; TYPE_REF, 指向之前的某个对象
```

**`co_name` 与 `co_qualname`**

```
0x1804A84D2: DA 09          ; co_name = "_fwh_main"
0x1804A84EB: 80 00 F0 02 03 05 12 DC 0F 14 90 5E D3 0F 24 88 04 F4 06 00 05 0A 94 7A A0 24 D7 17 27 D1 17 27 88 29 D5 04 35 A8 57 D5 04 35 F8 F4 05 00 0D 15 D4 16 27 D0 0B 28 F3 00 01 05 12 D8 0F 11 8A 04 F0 03 01 05 12 FA 73 0F 00 00 00 82 0B 30 00 B0 12 41 05 03 C1 04 01 41 05 03 DA 08 "_MEIPASS"
```

但是这里无法直接调用 `marshal.loads` 加载，也许是被魔改了？

根据函数的命名方式推测，发现还能找到一些别的 Frozen 模块。

![](https://img.halfcity.top/2026/11/11/f19333b02857a6be829612153e8a577f.avif)

我们批量提取出来：

```py
import sys
import pefile

DLL = sys.argv[1] if len(sys.argv) > 1 else "python313.dll"
PREFIX = "_fwh_"

def is_printable_ascii(b):
    return all(0x20 <= c < 0x7F for c in b)

def main():
    pe = pefile.PE(DLL)

    for s in pe.sections:
        sec_name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if sec_name != '.rdata':
            continue
        rva_base = s.VirtualAddress
        data = s.get_data()
        print(f"[*] .rdata RVA=0x{rva_base:X} size=0x{len(data):X}")

        count = 0
        i = 0
        while i < len(data) - 2:
            b0 = data[i]
            if b0 in (0xDA, 0x7A):
                length = data[i + 1]
                if 1 <= length <= 0x40 and i + 2 + length <= len(data):
                    payload = data[i + 2:i + 2 + length]
                    if is_printable_ascii(payload):
                        try:
                            text = payload.decode('ascii')
                        except Exception:
                            i += 1
                            continue
                        if text.startswith(PREFIX):
                            rva = rva_base + i
                            print(f"0x{rva:010X}  0x{b0:02X}  len={length:02d}  {text!r}")
                            count += 1
                        i += 2 + length
                        continue
            i += 1

        print(f"\n[*] total _fwh_ entries: {count}")

if __name__ == "__main__":
    main()
```

发现他们确实都可以被找到，同时也都是合法的 marshal 字符串：

```txt
> python scan.py
[*] .rdata RVA=0x376000 size=0x25E200
0x00004A82A5  0xDA  len=11  '_fwh_length'
0x00004A82D2  0xDA  len=08  '_fwh_key'
0x00004A82DC  0xDA  len=13  '_fwh_expected'
0x00004A830C  0xDA  len=10  '_fwh_check'
0x00004A84D2  0xDA  len=09  '_fwh_main'

[*] total _fwh_ entries: 5
```

我们需要写一个自定义的解析器来对 co_object 进行分析。

因为我们需要对无法解析的应用标注  REF 而不是提示解析失败：

```py
import sys
import pefile

FLAG_REF = 0x80
T_NULL=ord('0'); T_NONE=ord('N'); T_FALSE=ord('F'); T_TRUE=ord('T')
T_STOPITER=ord('S'); T_ELLIPSIS=ord('.')
T_INT=ord('i'); T_INT64=ord('I'); T_BINARY_FLOAT=ord('g')
T_LONG=ord('l'); T_STRING=ord('s'); T_INTERNED=ord('t')
T_REF=ord('r'); T_TUPLE=ord('('); T_SMALL_TUPLE=ord(')')
T_CODE=ord('c'); T_UNICODE=ord('u')
T_ASCII=ord('a'); T_ASCII_INTERNED=ord('A')
T_SMALL_ASCII=ord('z'); T_SMALL_ASCII_INTERNED=ord('Z')
T_DICT=ord('{'); T_LIST=ord('[')

class REF:
    def __init__(self, idx): self.idx = idx
    def __repr__(self): return f"REF({self.idx})"

class Parser:
    def __init__(self, data, base_rva=0):
        self.data = data
        self.pos = 0
        self.base = base_rva
        self.refs = []

    def off(self): return self.base + self.pos

    def rb(self):
        if self.pos >= len(self.data):
            raise ValueError(f"eof @ 0x{self.off():X}")
        v = self.data[self.pos]; self.pos += 1; return v

    def rbytes(self, n):
        if self.pos + n > len(self.data):
            raise ValueError(f"eof @ 0x{self.off():X}")
        v = self.data[self.pos:self.pos+n]; self.pos += n; return v

    def ru32(self): return int.from_bytes(self.rbytes(4), 'little')
    def ri32(self): return int.from_bytes(self.rbytes(4), 'little', signed=True)
    def ri64(self): return int.from_bytes(self.rbytes(8), 'little', signed=True)

    def obj(self, depth=0):
        if depth > 64: raise ValueError(f"depth @ 0x{self.off():X}")
        t = self.rb()
        flag = t & FLAG_REF
        t &= ~FLAG_REF
        v = self._obj(t, depth)
        if flag: self.refs.append(v)
        return v

    def _obj(self, t, depth):
        if t in (T_NULL, T_NONE): return None
        if t == T_FALSE: return False
        if t == T_TRUE: return True
        if t == T_STOPITER: return StopIteration
        if t == T_ELLIPSIS: return Ellipsis
        if t == T_INT: return self.ri32()
        if t == T_INT64: return self.ri64()
        if t == T_BINARY_FLOAT:
            import struct
            return struct.unpack('<d', self.rbytes(8))[0]
        if t == T_LONG:
            n = self.ri32(); sign = -1 if n < 0 else 1
            v = 0
            for i in range(abs(n)):
                v |= int.from_bytes(self.rbytes(2), 'little') << (15*i)
            return sign * v
        if t in (T_STRING, T_INTERNED):
            n = self.ru32(); return self.rbytes(n)
        if t == T_UNICODE:
            n = self.ru32(); return self.rbytes(n).decode('utf-8', errors='replace')
        if t in (T_ASCII, T_ASCII_INTERNED):
            n = self.ru32(); return self.rbytes(n).decode('ascii', errors='replace')
        if t in (T_SMALL_ASCII, T_SMALL_ASCII_INTERNED):
            n = self.rb(); return self.rbytes(n).decode('ascii', errors='replace')
        if t == T_TUPLE:
            n = self.ru32(); return tuple(self.obj(depth+1) for _ in range(n))
        if t == T_SMALL_TUPLE:
            n = self.rb(); return tuple(self.obj(depth+1) for _ in range(n))
        if t == T_LIST:
            n = self.ru32(); return [self.obj(depth+1) for _ in range(n)]
        if t == T_DICT:
            d = {}
            while True:
                k = self.obj(depth+1)
                if k is None: break
                v = self.obj(depth+1)
                d[k] = v
            return d
        if t == T_REF:
            idx = self.ri32()
            if idx < len(self.refs): return self.refs[idx]
            return REF(idx)  # 容错
        if t == T_CODE:
            return self._code(depth)
        raise ValueError(f"unknown 0x{t:02X} @ 0x{self.off()-1:X}")

    def _code(self, depth):
        co = {'_start': self.off() - 1}
        co['argcount'] = self.ri32()
        co['posonly'] = self.ri32()
        co['kwonly'] = self.ri32()
        co['nlocalsplus'] = self.ri32()
        co['framesize'] = self.ri32()
        co['flags'] = self.ri32()
        co['co_code'] = self.obj(depth+1)
        co['co_consts'] = self.obj(depth+1)
        co['co_names'] = self.obj(depth+1)
        co['co_localsplusnames'] = self.obj(depth+1)
        co['co_localspluskinds'] = self.obj(depth+1)
        co['co_filename'] = self.obj(depth+1)
        co['co_name'] = self.obj(depth+1)
        co['co_qualname'] = self.obj(depth+1)
        co['co_firstlineno'] = self.ri32()
        co['co_linetable'] = self.obj(depth+1)
        co['co_exceptiontable'] = self.obj(depth+1)
        return co


def find_anchor(pe, co_name_rva, expected_name, max_back=0x400):
    """从 co_name_rva 往前扫描 29/28 元组头，验证 name 字段起点是否 == co_name_rva"""
    off_name = pe.get_offset_from_rva(co_name_rva)
    start_off = max(0, off_name - max_back)
    end_off = min(len(pe.__data__), off_name + 0x100)
    data = pe.__data__[start_off:end_off]
    base_rva = pe.get_rva_from_offset(start_off)
    rel_name = off_name - start_off

    for i in range(rel_name):
        if data[i] not in (T_SMALL_TUPLE, T_TUPLE):
            continue
        p = Parser(data, base_rva=base_rva)
        p.pos = i
        field_rvas = []

        def f():
            field_rvas.append(p.off())
            return p.obj()

        try:
            consts = f()
            names = f()
            varnames = f()
            kinds = f()
            filename = f()
            name = f()
            qualname = f()
            firstlineno = p.ri32()
            linetable = f()
            exceptiontable = f()
        except Exception:
            continue

        if field_rvas[5] == co_name_rva and name == expected_name:
            return {
                'anchor_rva': base_rva + i,
                'consts': consts,
                'names': names,
                'varnames': varnames,
                'kinds': kinds,
                'filename': filename,
                'name': name,
                'qualname': qualname,
                'firstlineno': firstlineno,
                'linetable': linetable,
                'exceptiontable': exceptiontable,
                'field_rvas': field_rvas,
            }
    return None


def fmt(v, indent=0):
    if isinstance(v, bytes):
        try:
            s = v.decode('ascii')
            if s.isprintable() and all(0x20 <= ord(c) < 0x7F for c in s):
                return f"b{s!r}"
        except Exception:
            pass
        return f"bytes({v.hex()})"
    if isinstance(v, tuple):
        if not v: return "()"
        pad = "  " * indent
        return "(\n" + ",\n".join(pad + "  " + fmt(x, indent+1) for x in v) + "\n" + pad + ")"
    return repr(v)


def dump_result(name_rva, result):
    print(f"\n{'='*64}")
    print(f"anchor @ RVA 0x{result['anchor_rva']:X}  name @ 0x{name_rva:X}")
    print(f"{'='*64}")
    for k in ('consts', 'names', 'varnames', 'kinds',
              'filename', 'name', 'qualname'):
        print(f"\n{k}:")
        print("  " + fmt(result[k], 1).replace("\n", "\n  "))
    print(f"\nfirstlineno: {result['firstlineno']}")
    print(f"linetable: {fmt(result['linetable'])}")
    print(f"exceptiontable: {fmt(result['exceptiontable'])}")
    print(f"\nfield_rvas: {[hex(x) for x in result['field_rvas']]}")


def main():
    DLL = sys.argv[1] if len(sys.argv) > 1 else "python313.dll"
    pe = pefile.PE(DLL)

    targets = [
        ("_fwh_check", 0x4A830C),
        ("_fwh_main",  0x4A84D2),
    ]

    for name, name_rva in targets:
        print(f"\n[*] searching anchor for {name!r} @ 0x{name_rva:X} ...")
        result = find_anchor(pe, name_rva, name)
        if result:
            dump_result(name_rva, result)
        else:
            print(f"[!] no anchor found for {name!r}")


if __name__ == "__main__":
    main()
```

输出如下：

```txt
> python parse.py

[*] searching anchor for '_fwh_check' @ 0x4A830C ...

================================================================
anchor @ RVA 0x4A828E  name @ 0x4A830C
================================================================

consts:
  (
      None,
      False,
      'ascii',
      REF(1)
    )

names:
  (
      REF(277),
      '_fwh_length',
      REF(324),
      'UnicodeEncodeError',
      'range',
      '_fwh_key',
      '_fwh_expected'
    )

varnames:
  (
      's',
      REF(255),
      'diff',
      'i'
    )

kinds:
  b'    '

filename:
  REF(24)

name:
  '_fwh_check'

qualname:
  REF(496)

firstlineno: 1190
linetable: bytes(8000dc070a88318376941bd3071cd80f14f002030515d80f108f7889789807d30f208804f006000c0d8044dc0d12943390749339d60d1d8801d8080c906191179c38a041ac03ac48ab0dd12435d11b36d11136bc2dc801d13a4ad1104ad1084a8a04f103000e1ee00b0f90318939d00414f8f40b000c1ef300010515d90f14f003010515fa)
exceptiontable: bytes(9611413400c1340a420103c20001420103)

field_rvas: ['0x4a828e', '0x4a829e', '0x4a82eb', '0x4a82fe', '0x4a8307', '0x4a830c', '0x4a8318', '0x4a8321', '0x4a83ab']

[*] searching anchor for '_fwh_main' @ 0x4A84D2 ...

================================================================
anchor @ RVA 0x4A846B  name @ 0x4A84D2
================================================================

consts:
  (
      None,
      'Input flag: ',
      '',
      'Correct',
      'Wrong'
    )

names:
  (
      'input',
      'EOFError',
      'KeyboardInterrupt',
      'print',
      REF(496)
    )

varnames:
  (
      REF(392)
    )

kinds:
  b' '

filename:
  REF(24)

name:
  '_fwh_main'

qualname:
  REF(505)

firstlineno: 1202
linetable: bytes(8000f002030512dc0f14905ed30f248804f40600050a947aa024d71727d117278829d50435a857d50435f8f405000d15d41627d00b28f300010512d80f118a04f003010512fa)
exceptiontable: bytes(820b3000b012410503c10401410503)

field_rvas: ['0x4a846b', '0x4a848e', '0x4a84c0', '0x4a84c7', '0x4a84cd', '0x4a84d2', '0x4a84dd', '0x4a84e6', '0x4a8531']
```

这里成功解析了 `_fwh_main` 和 `_fwh_check` 这两个 co_object。

但是这里还有 `_fwh_expected` `_fwh_key` ` _fwh_length` 没有被找到：

```txt
0x00004A82A5  0xDA  len=11  '_fwh_length'
0x00004A82D2  0xDA  len=08  '_fwh_key'
0x00004A82DC  0xDA  len=13  '_fwh_expected'
0x00004A830C  0xDA  len=10  '_fwh_check'
0x00004A84D2  0xDA  len=09  '_fwh_main'
```

猜测他们应该是全局变量，并且定义在父模块的 co_consts 里面。

让我们先找找都有哪些 frozen 模块：

```py
import sys
import pefile

DLL = "python313.dll"
pe = pefile.PE(DLL)

results = []
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode('ascii', 'replace') != '.rdata':
        continue
    rva_base = s.VirtualAddress
    data = s.get_data()
    i = 0
    while i < len(data) - 2:
        b0 = data[i]
        if b0 in (0x7A, 0xDA):
            length = data[i+1]
            if 1 <= length <= 0x40 and i + 2 + length <= len(data):
                payload = data[i+2:i+2+length]
                try:
                    text = payload.decode('ascii')
                    if text.startswith("<frozen ") and text.endswith(">"):
                        results.append((rva_base + i, b0, text))
                except Exception:
                    pass
        i += 1

results.sort(key=lambda x: x[0])
print(f"[*] found {len(results)} <frozen ...> strings\n")
print(f"{'RVA':>12}  {'tag':>4}  text")
print("-" * 80)
for rva, tag, text in results:
    print(f"0x{rva:010X}  0x{tag:02X}  {text}")
```

输出如下：

```txt
> python modules.py
[*] found 24 <frozen ...> strings

         RVA   tag  text
--------------------------------------------------------------------------------
0x0000378EA8  0xDA  <frozen getpath>
0x000048B214  0xDA  <frozen importlib._bootstrap>
0x0000499061  0xDA  <frozen importlib.machinery>
0x00004991CD  0xDA  <frozen __phello__.ham>
0x00004997D3  0xDA  <frozen posixpath>
0x000049E8F4  0xDA  <frozen os>
0x00004A90E7  0xDA  <frozen _sitebuiltins>
0x00004AA632  0xDA  <frozen importlib.util>
0x00004AD20C  0xDA  <frozen __phello__>
0x00004AD58C  0xDA  <frozen genericpath>
0x00004AF511  0xDA  <frozen ntpath>
0x00004B649E  0xDA  <frozen codecs>
0x00004C061C  0xDA  <frozen io>
0x00004C0B8D  0xDA  <frozen __phello__.ham.eggs>
0x00004C1243  0xDA  <frozen importlib._bootstrap_external>
0x00004D0A4C  0xDA  <frozen __phello__.spam>
0x00004D0FB0  0xDA  <frozen zipimport>
0x00004D76DE  0xDA  <frozen runpy>
0x00004DB5D3  0xDA  <frozen _collections_abc>
0x00004E6487  0xDA  <frozen stat>
0x00004E76D1  0xDA  <frozen frozen_only>
0x00004E7AC7  0xDA  <frozen abc>
0x00004E9729  0xDA  <frozen __hello__>
0x00004EA7CF  0xDA  <frozen site>
```

注意到这两行：

```txt
0x000049E8F4  0xDA  <frozen os>
0x00004A90E7  0xDA  <frozen _sitebuiltins>
```

`<frozen os>` 的 RVA 是 0x000049E8F4 而 `<frozen _sitebuiltins>` 的 RVA 是 0x00004A90E7。

比对一下之前的发现：

```txt
_fwh_check:
anchor @ RVA 0x4A828E  name @ 0x4A830C
_fwh_main:
anchor @ RVA 0x4A846B  name @ 0x4A84D2
```

可以看到 `_fwh_check` 和 `_fwh_main` 都落在了 `<frozen os>` 内部。

因此 `<frozen os>` 可能就是他们的父模块，这和看雪的[这篇文章](https://bbs.kanxue.com/thread-292776.htm)很像，同时这也能解释 `_fwh_main` 是如何加载的。

os 模块一定在初始化的时候被加载使用。

此时分析到这里的时候我看着这些导出的 Py 函数，总感觉有一股眼熟的感觉，似乎在哪里见过。仔细一想，这不就是 il2cpp 的导出命令方式吗？

所以我们很容易就可以猜测到这里的 python311.dll 其实就类似 libil2cpp.dll 这样的后端。

它自身维护一个 runtime 并导出 api 供前端调用。

很好现在我有了先前可以参考的经验接下来就比较好办了。

思考意思我们其实可以直接 call 这个 dll 导出的函数来访问 runtime 的数据，无论静态的结构如何魔改，运行时一定都会回归到归一的结构。

由于我们不需要像和 il2cpp 交互那样需要频繁询问数据，这里就不需要注入 dll 了，简单写一个 frida 脚本即可。

#### 动态分析

我们现在需要校验的逻辑以及密钥和密文。

pyinstaller 打包的程序会在运行时释放内部依赖到临时目录并新开进程，我们需要检测 python313.dll 加载的那一个并attach。

服务端的脚本如下，检测真实进程并注入 frida 脚本，最后写回 pyc 文件：

```py
import frida
import time
import os
import struct
import marshal

DLL = "python313.dll"
JS_PATH = "fwh_dump.js"
OUT_DIR = "dumped_code_objects"

PY313_MAGIC = b'\xf3\x0d\x0d\x0a'

def build_pyc_header(magic=PY313_MAGIC, mtime=0, source_size=0):
    return (magic
            + struct.pack('<I', 0)
            + struct.pack('<I', mtime)
            + struct.pack('<I', source_size))

def on_message(msg, data):
    if msg["type"] == "send":
        payload = msg.get("payload", {})
        if payload.get("type") == "code_object":
            name = payload.get("name", "unknown").replace("/", "_").replace("@", "_at_")
            size = int(payload.get("size", 0))
            os.makedirs(OUT_DIR, exist_ok=True)

            marshal_data = bytes(data)

            header = build_pyc_header()
            pyc_path = os.path.join(OUT_DIR, f"{name}.pyc")
            with open(pyc_path, "wb") as f:
                f.write(header)
                f.write(marshal_data)

            verify = ""
            try:
                code = marshal.loads(marshal_data)
                verify = f" | co_name={code.co_name!r}, co_code_len={len(code.co_code)}"
            except Exception as e:
                verify = f" | [verify failed: {e}]"

            print(f"[+] saved {pyc_path} ({size + 16} bytes){verify}")
        else:
            print(f"[JS] {payload.get('m', '')}")
    elif msg["type"] == "error":
        print(f"[ERR] {msg.get('description')}")
    elif msg["type"] == "log":
        print(f"[LOG] {msg['payload']}")

def find_target():
    device = frida.get_local_device()
    for p in device.enumerate_processes():
        if "frozenwhisper" not in p.name.lower():
            continue
        try:
            session = device.attach(p.pid)
            res = {}
            script = session.create_script(f"""
                var m = Process.findModuleByName("{DLL}");
                send({{found: !!m, base: m ? m.base.toString() : null}});
            """)
            script.on("message", lambda msg, data: res.update(msg["payload"]))
            script.load()
            session.detach()
            if res.get("found"):
                return p.pid, res.get("base")
        except Exception:
            continue
    return None, None

def main():
    print("[*] wating for frozenwhisper.exe")
    pid = None
    for _ in range(300):
        pid, base = find_target()
        if pid:
            break
        time.sleep(0.1)
    if not pid:
        print("[-] python313.dll not found")
        return

    print(f"[+] target pid={pid}  {DLL} base={base}")
    session = frida.attach(pid)
    with open(JS_PATH, encoding="utf-8") as f:
        js = f.read()
    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("[+] script loaded")
    input("[*] press Enter to quit\n")

if __name__ == "__main__":
    main()
```

frida 脚本如下，动态查找导出函数，先获取 GIL，随后调用 API 来转储运行时的数据：

```js
var DLL = "python313.dll";
var done = false;
var gotFlag = false;

function log(s) { try { send({ m: String(s) }); } catch (e) { } }

function tryInstall() {
    if (done) return;
    try {
        var mod = Process.findModuleByName(DLL);
        if (!mod) return;

        var pIsInit = mod.findExportByName("Py_IsInitialized");
        var pGILE = mod.findExportByName("PyGILState_Ensure");
        var pGILR = mod.findExportByName("PyGILState_Release");
        var pImportAdd = mod.findExportByName("PyImport_AddModule");
        var pImportMod = mod.findExportByName("PyImport_ImportModule");
        var pGetDict = mod.findExportByName("PyModule_GetDict");
        var pDictGet = mod.findExportByName("PyDict_GetItemString");
        var pGetAttr = mod.findExportByName("PyObject_GetAttrString");
        var pBytes = mod.findExportByName("PyBytes_AsStringAndSize");
        var pTupleSize = mod.findExportByName("PyTuple_Size");
        var pTupleGet = mod.findExportByName("PyTuple_GetItem");
        var pErrClear = mod.findExportByName("PyErr_Clear");
        var pCallFn = mod.findExportByName("PyObject_CallFunctionObjArgs");

        if (!pIsInit || !pGILE || !pGILR || !pImportAdd || !pGetDict ||
            !pDictGet || !pGetAttr || !pBytes) {
            log("[-] missing exports"); done = true; return;
        }

        var IsInit = new NativeFunction(pIsInit, "int", []);
        var GILE = new NativeFunction(pGILE, "int", []);
        var GILR = new NativeFunction(pGILR, "void", ["int"]);
        var ImportAdd = new NativeFunction(pImportAdd, "pointer", ["pointer"]);
        var ImportMod = pImportMod
            ? new NativeFunction(pImportMod, "pointer", ["pointer"]) : null;
        var GetDict = new NativeFunction(pGetDict, "pointer", ["pointer"]);
        var DictGet = new NativeFunction(pDictGet, "pointer", ["pointer", "pointer"]);
        var GetAttr = new NativeFunction(pGetAttr, "pointer", ["pointer", "pointer"]);
        var Bytes = new NativeFunction(pBytes, "int", ["pointer", "pointer", "pointer"]);
        var TupleSize = pTupleSize
            ? new NativeFunction(pTupleSize, "int64", ["pointer"]) : null;
        var TupleGet = pTupleGet
            ? new NativeFunction(pTupleGet, "pointer", ["pointer", "int64"]) : null;
        var Clear = pErrClear ? new NativeFunction(pErrClear, "void", []) : function () { };
        var CallFn = pCallFn
            ? new NativeFunction(pCallFn, "pointer",
                ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer"]) : null;

        if (IsInit() === 0) return;
        done = true;
        log("module base = " + mod.base);

        function getBytes(obj) {
            try {
                Clear();
                var buf = Memory.alloc(Process.pointerSize);
                var len = Memory.alloc(8);
                if (Bytes(obj, buf, len) !== 0) { Clear(); return null; }
                var ptr = buf.readPointer();
                var n = len.readS64();
                if (!ptr || ptr.isNull() || n < 0 || n > 0x100000) return null;
                if (n === 0) return { bytes: new Uint8Array(0), len: 0, hex: "" };
                var arr = new Uint8Array(ptr.readByteArray(n));
                var hex = '';
                for (var i = 0; i < arr.length; i++)
                    hex += ('0' + arr[i].toString(16)).slice(-2);
                return { bytes: arr, len: n, hex: hex };
            } catch (e) { Clear(); return null; }
        }

        function getStr(obj) {
            try {
                Clear();
                var pUtf8 = mod.findExportByName("PyUnicode_AsUTF8");
                if (!pUtf8) return null;
                var Utf8 = new NativeFunction(pUtf8, "pointer", ["pointer"]);
                var c = Utf8(obj);
                if (!c || c.isNull()) { Clear(); return null; }
                return c.readCString();
            } catch (e) { Clear(); return null; }
        }

        function dumpCodeObject(label, funcObj) {
            if (!funcObj || funcObj.isNull()) {
                log("[" + label + "] object is NULL");
                return;
            }
            log("\n[" + label + "] dumping ...");

            // func -> __code__
            var codeObj = GetAttr(funcObj, Memory.allocUtf8String("__code__"));
            if (!codeObj || codeObj.isNull()) {
                log("[" + label + "] no __code__ (not a function?)");
                Clear();
                // 有可能直接就是 code object
                codeObj = funcObj;
            }

            // co_code
            var coCode = GetAttr(codeObj, Memory.allocUtf8String("co_code"));
            var bCode = coCode ? getBytes(coCode) : null;
            if (bCode) {
                log("[" + label + "] co_code (" + bCode.len + " bytes):");
                log("  " + bCode.hex);
            } else {
                log("[" + label + "] co_code = <unreadable>");
            }
            Clear();

            // co_names
            var coNames = GetAttr(codeObj, Memory.allocUtf8String("co_names"));
            if (coNames && !coNames.isNull() && TupleSize && TupleGet) {
                var n = Number(TupleSize(coNames));
                var names = [];
                for (var i = 0; i < n; i++) {
                    var item = TupleGet(coNames, i);
                    var s = item ? getStr(item) : null;
                    names.push(s);
                }
                log("[" + label + "] co_names (" + n + "): " + JSON.stringify(names));
            }
            Clear();

            // co_varnames / co_localsplusnames
            var varnames = GetAttr(codeObj, Memory.allocUtf8String("co_localsplusnames"));
            if (!varnames || varnames.isNull()) {
                varnames = GetAttr(codeObj, Memory.allocUtf8String("co_varnames"));
            }
            if (varnames && !varnames.isNull() && TupleSize && TupleGet) {
                var n = Number(TupleSize(varnames));
                var vars = [];
                for (var i = 0; i < n; i++) {
                    var item = TupleGet(varnames, i);
                    var s = item ? getStr(item) : null;
                    vars.push(s);
                }
                log("[" + label + "] co_varnames (" + n + "): " + JSON.stringify(vars));
            }
            Clear();

            // co_consts
            var coConsts = GetAttr(codeObj, Memory.allocUtf8String("co_consts"));
            if (coConsts && !coConsts.isNull() && TupleSize && TupleGet) {
                var n = Number(TupleSize(coConsts));
                log("[" + label + "] co_consts (" + n + "):");
                for (var i = 0; i < n; i++) {
                    var item = TupleGet(coConsts, i);
                    if (!item || item.isNull()) { log("  [" + i + "] <null>"); continue; }
                    var b = getBytes(item);
                    if (b && b.len > 0) {
                        log("  [" + i + "] bytes(" + b.len + ") " + b.hex);
                        continue;
                    }
                    Clear();
                    var s = getStr(item);
                    if (s !== null) { log("  [" + i + "] str " + JSON.stringify(s)); continue; }
                    Clear();
                    // 可能是 code object / int / None
                    var nestedCode = GetAttr(item, Memory.allocUtf8String("co_code"));
                    if (nestedCode && !nestedCode.isNull()) {
                        var subName = GetAttr(item, Memory.allocUtf8String("co_name"));
                        var subStr = subName ? getStr(subName) : "?";
                        log("  [" + i + "] <code " + JSON.stringify(subStr) + ">");
                        Clear();
                        continue;
                    }
                    Clear();
                    var pLong = mod.findExportByName("PyLong_AsLongLong");
                    if (pLong) {
                        var Long = new NativeFunction(pLong, "int64", ["pointer"]);
                        var iv = Long(item);
                        if (!(iv === -1n && mod.findExportByName("PyErr_Occurred"))) {
                            log("  [" + i + "] int " + iv);
                            continue;
                        }
                    }
                    Clear();
                    log("  [" + i + "] <other>");
                }
            }
            Clear();

            // marshal.dumps 整个 code object
            if (CallFn && ImportMod) {
                try {
                    Clear();
                    var marshalMod = ImportMod(Memory.allocUtf8String("marshal"));
                    if (marshalMod && !marshalMod.isNull()) {
                        var dumps = GetAttr(marshalMod, Memory.allocUtf8String("dumps"));
                        if (dumps && !dumps.isNull()) {
                            var bytesObj = CallFn(dumps, codeObj,
                                ptr(0), ptr(0), ptr(0), ptr(0));
                            if (bytesObj && !bytesObj.isNull()) {
                                var b = getBytes(bytesObj);
                                if (b) {
                                    log("[" + label + "] marshal.dumps = " +
                                        b.len + " bytes");
                                    send({
                                        type: "code_object",
                                        name: label,
                                        size: b.len
                                    }, b.bytes.buffer);
                                }
                            } else {
                                log("[" + label + "] marshal.dumps returned NULL");
                                Clear();
                            }
                        }
                    }
                } catch (e) {
                    log("[" + label + "] marshal.dumps error: " + e);
                    Clear();
                }
            }
        }

        var gil = GILE();
        try {
            var osModule = ImportAdd(Memory.allocUtf8String("os"));
            if (!osModule || osModule.isNull()) {
                log("[-] os not in sys.modules");
                return;
            }
            var osDict = GetDict(osModule);

            // 读 _fwh_key / _fwh_expected 并解密
            var keyObj = DictGet(osDict, Memory.allocUtf8String("_fwh_key"));
            var expObj = DictGet(osDict, Memory.allocUtf8String("_fwh_expected"));

            if (keyObj && !keyObj.isNull() && expObj && !expObj.isNull()) {
                var keyB = getBytes(keyObj);
                var expB = getBytes(expObj);
                if (keyB && expB) {
                    log("[+] _fwh_key      = bytes(" + keyB.len + ") " + keyB.hex);
                    log("[+] _fwh_expected = bytes(" + expB.len + ") " + expB.hex);
                    var out = new Uint8Array(expB.len);
                    for (var i = 0; i < expB.len; i++) {
                        out[i] = expB.bytes[i] ^ keyB.bytes[i % keyB.len];
                    }
                    gotFlag = true;
                }
            } else {
                log("[-] _fwh_key or _fwh_expected not found");
            }

            // dump _fwh_check / _fwh_main 的 code object
            var checkFn = DictGet(osDict, Memory.allocUtf8String("_fwh_check"));
            var mainFn = DictGet(osDict, Memory.allocUtf8String("_fwh_main"));

            if (checkFn && !checkFn.isNull()) dumpCodeObject("_fwh_check", checkFn);
            else log("[-] _fwh_check not in os.__dict__");

            if (mainFn && !mainFn.isNull()) dumpCodeObject("_fwh_main", mainFn);
            else log("[-] _fwh_main not in os.__dict__");

            // 如果没绑定到 os 模块，尝试从 __main__ 里找
            var mainMod = ImportAdd(Memory.allocUtf8String("__main__"));
            if (mainMod && !mainMod.isNull()) {
                var mainDict = GetDict(mainMod);
                if (mainDict && !mainDict.isNull()) {
                    var c2 = DictGet(mainDict, Memory.allocUtf8String("_fwh_check"));
                    var m2 = DictGet(mainDict, Memory.allocUtf8String("_fwh_main"));
                    if (c2 && !c2.isNull() && !(checkFn && !checkFn.isNull()))
                        dumpCodeObject("_fwh_check@main", c2);
                    if (m2 && !m2.isNull() && !(mainFn && !mainFn.isNull()))
                        dumpCodeObject("_fwh_main@main", m2);
                }
            }
        } catch (e) {
            log("[-] exception under GIL: " + e);
        } finally {
            GILR(gil);
        }
    } catch (e) {
        log("[-] outer error: " + e);
    }
}

setInterval(tryInstall, 200);
```

输出如下：

```txt
> python run.py
[*] wating for frozenwhisper.exe
[+] target pid=7680  python313.dll base=0x7ff8222b0000
[+] script loaded
[*] press Enter to quit
[JS] module base = 0x7ff8222b0000
[JS] [+] _fwh_key      = bytes(6) 31725a19436d
[JS] [+] _fwh_expected = bytes(33) 571e3b7e385d5f41057f315d4b4134462e5d5507362a1c5c422d69777318561a27
[JS]
[_fwh_check] dumping ...
[JS] [_fwh_check] co_code (264 bytes):
[JS]   95005b010000000000000000550035010000000000005b0200000000000000003a7700006101000067011e0055005205000000000000000000000000000000000000530235010000000000006e0153036e025b0900000000000000005b0100000000000000005501350100000000000035010000000000001300482e00006e0358215503050000005b0a000000000000000055035b0100000000000000005b0a000000000000000035010000000000002d060000050000002d0c00005b0c00000000000000005503050000002d0c00002d1400006e024d3000000b002000550253033a480000240021005b06000000000000000007006103000020001f00670166003d031f006601
[JS] [_fwh_check] co_names (7): ["len","_fwh_length","encode","UnicodeEncodeError","range","_fwh_key","_fwh_expected"]
[JS] [_fwh_check] co_varnames (4): ["s","data","diff","i"]
[JS] [_fwh_check] co_consts (4):
[JS]   [0] int -1
[JS]   [1] int 0
[JS]   [2] str "ascii"
[JS]   [3] int 0
[JS] [_fwh_check] marshal.dumps = 609 bytes
[+] saved dumped_code_objects\_fwh_check.pyc (625 bytes) | co_name='_fwh_check', co_code_len=264
[JS]
[_fwh_main] dumping ...
[JS] [_fwh_main] co_code (144 bytes):
[JS]   95001e005b010000000000000000530135010000000000006e005b0700000000000000005b090000000000000000550035010000000000002800000000000000610700005303350100000000000020006700530435010000000000002000670021005b0200000000000000005b0400000000000000003402070061050000200053026e001f004e3766003d031f006601
[JS] [_fwh_main] co_names (5): ["input","EOFError","KeyboardInterrupt","print","_fwh_check"]
[JS] [_fwh_main] co_varnames (1): ["text"]
[JS] [_fwh_main] co_consts (5):
[JS]   [0] int -1
[JS]   [1] str "Input flag: "
[JS]   [2] str ""
[JS]   [3] str "Correct"
[JS]   [4] str "Wrong"
[JS] [_fwh_main] marshal.dumps = 404 bytes
[+] saved dumped_code_objects\_fwh_main.pyc (420 bytes) | co_name='_fwh_main', co_code_len=144
```

![](https://img.halfcity.top/2026/11/11/ade86b0a31a48e41d71b5c676c76c328.avif)

接下来我们就可以拿去反编译了：

![](https://img.halfcity.top/2026/11/11/e57d24b4d0cda063b3617d4327840dea.avif)

![](https://img.halfcity.top/2026/11/11/6784aee09fdbe9443d220fba17712044.avif)

emmm 似乎 pyc 的语法有问题吗？可能是因为没有组织好调用的关系，理论上来说字节码不应该有错的，不然根本无法运行。

好吧既然它帮我们纠错了，我们直接分析即可。

整理一下输出和全局的变量还原的源码大致如下：

```py
_fwh_length   = 33
_fwh_key      = bytes.fromhex("31725a19436d")
_fwh_expected = bytes.fromhex("571e3b7e385d5f41057f315d4b4134462e5d5507362a1c5c422d69777318561a27")

def _fwh_check(s) -> bool:
    if len(s) != _fwh_length:
        return False
    else:
        try:
            data = s.encode('ascii')
        except UnicodeEncodeError:
            return False
        diff = 0
        for i in range(len(data)):
            diff |= data[i] ^ _fwh_key[i % len(_fwh_key)] ^ _fwh_expected[i]
        return diff == 0

def _fwh_main():
    try:
        text = input('Input flag: ')
    except (EOFError, KeyboardInterrupt):
        text = ''
    print('Correct' if _fwh_check(text) else 'Wrong')

os._fwh_main()
```

可以看到加密逻辑异常简单，就是简单的字节流异或加密。

解密脚本如下：

```py
key_hex      = "31725a19436d"
expected_hex = "571e3b7e385d5f41057f315d4b4134462e5d5507362a1c5c422d69777318561a27"

key      = bytes.fromhex(key_hex)
expected = bytes.fromhex(expected_hex)

print(f"[*] key      = {len(key)} bytes: {key.hex()}")
print(f"[*] expected = {len(expected)} bytes: {expected.hex()}")
print()

flag_bytes = bytes(
    expected[i] ^ key[i % len(key)]
    for i in range(len(expected))
)

print(f"[+] flag (hex) = {flag_bytes.hex()}")
print(f"[+] flag (raw) = {flag_bytes.decode('ascii', errors='replace')}")
```

输出如下：

```txt
> python decrypt.py
[*] key      = 6 bytes: 31725a19436d
[*] expected = 33 bytes: 571e3b7e385d5f41057f315d4b4134462e5d5507362a1c5c422d69777318561a27

[+] flag (hex) = 666c61677b306e335f6672307a336e5f6d3064756c335f31735f336e307567687d
[+] flag (raw) = flag{0n3_fr0z3n_m0dul3_1s_3n0ugh}
```

```txt
flag{0n3_fr0z3n_m0dul3_1s_3n0ugh}
```

### 阿萨拉下班指南·四：你管这叫小保险？

#### 静态分析

![](https://img.halfcity.top/2026/11/11/0e2d130ad1b109fe0a3cdf857d7f7337.avif)

查壳发现是 nuitka 打包的。

好巧啊，昨天还在想用 nuitka 给工具打包很好，今天美梦就破碎了。

```txt
> nuitka-extractor.exe D:\data\blog\ctf\spark_2026\resources\week4\challenge.exe
[+] Processing D:\data\blog\ctf\spark_2026\resources\week4\challenge.exe
[+] File type: PE
[+] Payload size: 3757344 bytes
[+] Payload compression: true
[+] Beginning extraction...
[+] Total files: 5
[+] Successfully extracted to D:\data\blog\ctf\spark_2026\resources\week4\challenge.exe_extracted
```

反编译后注意到 `challenge.dll` 这个文件，这应该就是我们需要解析的了。

nutika 会复刻原逻辑中 python 运行时的行为，所以这里即使是一个简单的语句翻译为 c 后也十分复杂，几乎和 rust 一样是天然的混淆。

所以我更可行的方案是动态调试找到关键的校验逻辑。

#### 动态分析

刚开始这不是我最后做的一道题，所以最开始我走了一点弯路，直到做到做到上一道题给了我一定的经验回到这一题我才有所突破，即使是 nutika 编译打包后的程序，依旧需要维护一个 python 的 runtime。

里面编译的所有函数都必须符合 python 自己的约束，所以理论上来说检验函数依旧会被注册到为 PyObject 并暴露在全局空间中。

但是这里我并没有看到 python 和 challenge 的 dll 加载到 challenge.exe 中，这里我们可以自己写一个简单的 Loader 将提取出来的 dll 加载到自己的程序里面，然后我们就可以精确地分析程序了。

这里我还是按照我最开始的思路走一遍。

我寄希望于可以用过分析 print 的函数调用栈定位程序，所以我从之前的项目中拿来了编译后的 minhook.x64.lib 并导入到这个项目中，然后 hook 了 `WriteConsoleW` 和 `WriteFile` 这两个 API：

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "MinHook/include/MinHook.h"

#pragma comment(lib, "minhook.x64.lib")

typedef BOOL(WINAPI* PFN_WriteConsoleW)(HANDLE, const void*, DWORD, LPDWORD, LPVOID);
typedef BOOL(WINAPI* PFN_WriteFile)(HANDLE, const void*, DWORD, LPDWORD, LPOVERLAPPED);

static PFN_WriteConsoleW orig_WriteConsoleW = NULL;
static PFN_WriteFile     orig_WriteFile = NULL;

static void PrintStack(void) {
    void* frames[48];
    USHORT n = CaptureStackBackTrace(0, 48, frames, NULL);
    for (int i = 0; i < n; i++) {
        HMODULE hMod = NULL;
        char modName[MAX_PATH] = "?";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)frames[i], &hMod) && hMod) {
            GetModuleFileNameA(hMod, modName, MAX_PATH);
            char* s = strrchr(modName, '\\');
            if (s) memmove(modName, s + 1, strlen(s + 1) + 1);
            printf("    #%02d %p  %s+0x%llx\n", i, frames[i], modName,
                (unsigned long long)((char*)frames[i] - (char*)hMod));
        }
        else {
            printf("    #%02d %p\n", i, frames[i]);
        }
    }
    fflush(stdout);
}

static int LooksInteresting(const char* s, int n) {
    if (n <= 0 || n > 4096) return 0;
    static const char* keys[] = { "Conf", "cargo", "handoff", "safe", "tiny", "support", NULL };
    for (int k = 0; keys[k]; k++) {
        int klen = (int)strlen(keys[k]);
        for (int i = 0; i + klen <= n; i++) {
            if (memcmp(s + i, keys[k], klen) == 0) return 1;
        }
    }
    return 0;
}

static BOOL WINAPI Hook_WriteConsoleW(HANDLE h, const void* buf, DWORD n, LPDWORD written, LPVOID r) {
    if (buf && n > 0 && n < 4096) {
        char narrow[4096] = { 0 };
        const wchar_t* w = (const wchar_t*)buf;
        for (DWORD i = 0; i < n && i < 4095; i++) {
            narrow[i] = (w[i] >= 0x20 && w[i] < 0x7f) ? (char)w[i] : (w[i] == L'\n' ? '\n' : '.');
        }
        if (LooksInteresting(narrow, (int)n)) {
            printf("\n===== [WriteConsoleW] ====\n  \"");
            for (DWORD i = 0; i < n && i < 200; i++) {
                wchar_t c = w[i];
                if (c == L'\n') printf("\\n");
                else if (c == L'\r') printf("\\r");
                else if (c >= 0x20 && c < 0x7f) putchar((char)c);
                else printf("\\x%04x", (unsigned int)c);
            }
            printf("\"\n  Stack:\n");
            PrintStack();
            printf("==========================\n\n");
            fflush(stdout);
        }
    }
    return orig_WriteConsoleW(h, buf, n, written, r);
}

static BOOL WINAPI Hook_WriteFile(HANDLE h, const void* buf, DWORD n, LPDWORD written, LPOVERLAPPED ov) {
    if (buf && n > 0 && n < 4096) {
        char narrow[4096] = { 0 };
        for (DWORD i = 0; i < n && i < 4095; i++) {
            unsigned char c = ((unsigned char*)buf)[i];
            narrow[i] = (c >= 0x20 && c < 0x7f) ? (char)c : (c == '\n' ? '\n' : '.');
        }
        if (LooksInteresting(narrow, (int)n)) {
            printf("\n===== [WriteFile] ====\n  \"");
            for (DWORD i = 0; i < n && i < 200; i++) {
                unsigned char c = ((unsigned char*)buf)[i];
                if (c == '\n') printf("\\n");
                else if (c == '\r') printf("\\r");
                else if (c >= 0x20 && c < 0x7f) putchar(c);
                else printf("\\x%02x", c);
            }
            printf("\"\n  Stack:\n");
            PrintStack();
            printf("======================\n\n");
            fflush(stdout);
        }
    }
    return orig_WriteFile(h, buf, n, written, ov);
}

static HMODULE LoadPython() {
    const char* c[] = { "python314.dll","python313.dll","python312.dll","python311.dll",NULL };
    for (int i = 0; c[i]; i++) {
        HMODULE h = LoadLibraryA(c[i]);
        if (h) { printf("[+] %s @ %p\n", c[i], h); return h; }
    }
    return NULL;
}

int main(int argc, char** argv) {
    
    HMODULE hp = LoadPython();
    if (!hp) return 1;

    if (MH_Initialize() != MH_OK) return 1;

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    void* pWCW = (void*)GetProcAddress(hK32, "WriteConsoleW");
    void* pWF = (void*)GetProcAddress(hK32, "WriteFile");

    MH_CreateHook(pWCW, &Hook_WriteConsoleW, (LPVOID*)&orig_WriteConsoleW);
    MH_CreateHook(pWF, &Hook_WriteFile, (LPVOID*)&orig_WriteFile);
    MH_EnableHook(pWCW);
    MH_EnableHook(pWF);
    printf("[+] Output hooks installed (filter on keywords)\n\n");

    HMODULE hCh = LoadLibraryA("challenge.dll");
    if (!hCh) { printf("[-] challenge.dll load fail\n"); return 1; }
    printf("[+] challenge.dll @ %p\n", hCh);

    typedef void(__fastcall* PFN_run)(int, const wchar_t**);
    PFN_run rc = (PFN_run)GetProcAddress(hCh, "run_code");
    if (!rc) { printf("[-] run_code not found\n"); return 1; }
    printf("[+] run_code @ %p\n[*] Calling...\n\n", rc);
    fflush(stdout);

    const wchar_t* av[] = { L"challenge.exe", NULL };
    rc(1, av);
    return 0;
}
```

输出如下：

```txt
> loader.exe

[+] python314.dll @ 00007FF83C950000
[+] Output hooks installed (filter on keywords)

[+] challenge.dll @ 00007FFFF5E70000
[+] run_code @ 00007FFFF5E76740
[*] Calling...


===== [WriteConsoleW] ====
  "Confidential cargo handoff: "
  Stack:
    #00 00007FF7FAD110A3  loader.exe+0x10a3
    #01 00007FF7FAD113EC  loader.exe+0x13ec
    #02 00007FFFE24522C4  python312.dll+0x2622c4
    #03 00007FFFE2452097  python312.dll+0x262097
    #04 00007FFFE23E1F70  python312.dll+0x1f1f70
    #05 00007FFFE23026A6  python312.dll+0x1126a6
    #06 00007FFFE224678C  python312.dll+0x5678c
    #07 00007FFFF5E8AB60  challenge.dll+0x1ab60
    #08 00007FFFF5E76058  challenge.dll+0x6058
    #09 00007FFFF5E8A27E  challenge.dll+0x1a27e
    #10 00007FFFF5E7AB07  challenge.dll+0xab07
    #11 00007FFFF5E94C12  challenge.dll+0x24c12
    #12 00007FFFF5E953B9  challenge.dll+0x253b9
    #13 00007FFFF5E9557A  challenge.dll+0x2557a
    #14 00007FFFF5EA16D3  challenge.dll+0x316d3
    #15 00007FFFF5E76749  challenge.dll+0x6749
    #16 00007FF7FAD11893  loader.exe+0x1893
    #17 00007FF7FAD139EF  loader.exe+0x39ef
    #18 00007FF92557DDA7  KERNEL32.DLL+0x2dda7
    #19 00007FF925FBEE4C  ntdll.dll+0x7ee4c
==========================

Confidential cargo handoff: 123

===== [WriteConsoleW] ====
  "Why does this tiny safe need full support?\r\n"
  Stack:
    #00 00007FF7FAD110A3  loader.exe+0x10a3
    #01 00007FF7FAD113EC  loader.exe+0x13ec
    #02 00007FFFE2432901  python312.dll+0x242901
    #03 00007FFFE243275F  python312.dll+0x24275f
    #04 00007FFFE226AD0D  python312.dll+0x7ad0d
    #05 00007FFFE224A7E4  python312.dll+0x5a7e4
    #06 00007FFFE22E9C49  python312.dll+0xf9c49
    #07 00007FFFE22ED348  python312.dll+0xfd348
    #08 00007FFFE22ED256  python312.dll+0xfd256
    #09 00007FFFE22ED1E0  python312.dll+0xfd1e0
    #10 00007FFFE224A726  python312.dll+0x5a726
    #11 00007FFFE224A7E4  python312.dll+0x5a7e4
    #12 00007FFFE23078C7  python312.dll+0x1178c7
    #13 00007FFFE2307465  python312.dll+0x117465
    #14 00007FFFE225EA07  python312.dll+0x6ea07
    #15 00007FFFE222AC76  python312.dll+0x3ac76
    #16 00007FFFE221BDEB  python312.dll+0x2bdeb
    #17 00007FFFE221A9FD  python312.dll+0x2a9fd
    #18 00007FFFE2217FA0  python312.dll+0x27fa0
    #19 00007FFFE22195FA  python312.dll+0x295fa
    #20 00007FFFE2218E42  python312.dll+0x28e42
    #21 00007FFFE220874E  python312.dll+0x1874e
    #22 00007FFFF5E8AB60  challenge.dll+0x1ab60
    #23 00007FFFF5E761BA  challenge.dll+0x61ba
    #24 00007FFFF5E8A27E  challenge.dll+0x1a27e
    #25 00007FFFF5E7AB07  challenge.dll+0xab07
    #26 00007FFFF5E94C12  challenge.dll+0x24c12
    #27 00007FFFF5E953B9  challenge.dll+0x253b9
    #28 00007FFFF5E9557A  challenge.dll+0x2557a
    #29 00007FFFF5EA16D3  challenge.dll+0x316d3
    #30 00007FFFF5E76749  challenge.dll+0x6749
    #31 00007FF7FAD11893  loader.exe+0x1893
    #32 00007FF7FAD139EF  loader.exe+0x39ef
    #33 00007FF92557DDA7  KERNEL32.DLL+0x2dda7
    #34 00007FF925FBEE4C  ntdll.dll+0x7ee4c
==========================

Why does this tiny safe need full support?
```

其实结果很不理想，这里可以两个不同的函数都会返回到看到在 0x161a0 这个 rva ，我们是可以分析定位到 main 的，但是思考一下。

nutika 调用 input 函数是需要通过这个字符串作为索引得到一个 input 函数的实例，随后再最终调用 input。

所以直接通过 input 应该就可以定位到 main。

![](https://img.halfcity.top/2026/11/11/454a905fbd2cd944d93c65261fe073a4.avif)

发现确实可以定位到 main，但是我们看一看 main 函数：

![](https://img.halfcity.top/2026/11/11/615d972f5a78df3d489d27777b8aaf8d.avif)

里面有大量的 nutika 调度器的代码，以及 python 原有的 GIL 调度，引用计数等。

在没有辅助的情况下，具体的逻辑几乎无法正常分析。

这时我重新思考了一下，才意识到可以利用 python 运行时的数据可以辅助进行分析。

frida 的服务端脚本如下：

```py
# run.py
# 用法：
#   python run.py                    # 自动找进程名含 loader/dump3/challenge 的进程
#   python run.py --pid 12345        # 指定 PID
#   python run.py --name loader.exe  # 指定进程名

import frida
import time
import os
import sys
import struct
import marshal
import argparse
import dis

# ---------------- 配置 ----------------
DLL = "python312.dll"
JS_PATH = "targeted_dump.js"
OUT_DIR = "dumped_code_objects"

# CPython 3.12 magic number: 0x0DCB (little endian: cb 0d 0d 0a)
PY312_MAGIC = b'\xcb\x0d\x0d\x0a'

# 自动匹配的进程名（小写包含即命中）
DEFAULT_KEYWORDS = ["loader", "challenge"]


# ---------------- pyc 头构造 ----------------
def build_pyc_header(magic=PY312_MAGIC, mtime=0, source_size=0):
    """构造 CPython 3.12 的 pyc 文件头（16 字节）"""
    return (
        magic
        + struct.pack('<I', 0)           # flags（3.7+ 新增，3.12 仍是 0 表示无 hash）
        + struct.pack('<I', mtime)       # mtime
        + struct.pack('<I', source_size) # 源码大小
    )


# ---------------- 消息回调 ----------------
def on_message(msg, data):
    if msg["type"] == "send":
        payload = msg.get("payload", {})

        if payload.get("type") == "code_object":
            name = payload.get("name", "unknown")
            name = name.replace("/", "_").replace("\\", "_").replace("@", "_at_")
            size = int(payload.get("size", 0))
            os.makedirs(OUT_DIR, exist_ok=True)

            marshal_data = bytes(data)
            pyc_path = os.path.join(OUT_DIR, f"{name}.pyc")

            with open(pyc_path, "wb") as f:
                f.write(build_pyc_header())
                f.write(marshal_data)

            print(f"[+] saved {pyc_path} ({size + 16} bytes)")

            # 立即解析，验证内容并打印摘要
            try:
                code = marshal.loads(marshal_data)
                print(f"    co_name      = {code.co_name!r}")
                print(f"    co_code_len  = {len(code.co_code)}")
                print(f"    co_names     = {list(code.co_names)}")
                print(f"    co_varnames  = {list(code.co_varnames)}")
                print(f"    co_consts    =")
                for i, c in enumerate(code.co_consts):
                    if isinstance(c, bytes):
                        print(f"      [{i}] bytes({len(c)}) {c.hex()}")
                    elif isinstance(c, str):
                        print(f"      [{i}] str  {c!r}")
                    elif isinstance(c, int):
                        print(f"      [{i}] int  {c}")
                    elif isinstance(c, type(code)):
                        print(f"      [{i}] <code {c.co_name!r}>")
                    else:
                        print(f"      [{i}] {type(c).__name__} {c!r}")

                # 如果字节码非空，直接 dis 一份
                if len(code.co_code) > 0:
                    print(f"\n--- dis.dis({code.co_name}) ---")
                    try:
                        dis.dis(code)
                    except Exception as e:
                        print(f"    [dis failed: {e}]")
                    print("--- end dis ---\n")
            except Exception as e:
                print(f"    [verify failed: {e}]")

        else:
            m = payload.get("m", "")
            if m:
                print(f"[JS] {m}")

    elif msg["type"] == "error":
        print(f"[ERR] {msg.get('description')}")
        if msg.get("stack"):
            print(msg["stack"])

    elif msg["type"] == "log":
        print(f"[LOG] {msg['payload']}")


# ---------------- 找目标进程 ----------------
def list_candidates(keywords):
    """返回所有匹配进程 [(pid, name), ...]"""
    try:
        device = frida.get_local_device()
    except Exception as e:
        print(f"[-] get_local_device failed: {e}")
        return []
    hits = []
    for p in device.enumerate_processes():
        nm = p.name.lower()
        for kw in keywords:
            if kw.lower() in nm:
                hits.append((p.pid, p.name))
                break
    return hits


def attach_and_check(pid, timeout=15.0):
    """attach 到 pid，检查 python312.dll 是否已加载"""
    try:
        session = frida.attach(pid)
    except Exception as e:
        print(f"[-] attach pid={pid} failed: {e}")
        return None, None

    probe_js = f"""
        var m = Process.findModuleByName("{DLL}");
        send({{found: !!m, base: m ? m.base.toString() : null}});
    """
    result = {"found": False, "base": None}
    def cb(msg, data):
        if msg["type"] == "send":
            result.update(msg["payload"])

    script = session.create_script(probe_js)
    script.on("message", cb)
    try:
        script.load()
        time.sleep(0.3)
    except Exception as e:
        print(f"[-] probe script failed on pid={pid}: {e}")
        session.detach()
        return None, None
    session.detach()

    return bool(result.get("found")), result.get("base")


# ---------------- 主流程 ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None, help="直接指定 PID")
    ap.add_argument("--name", type=str, default=None, help="指定进程名（模糊匹配）")
    ap.add_argument("--keywords", type=str, default=None,
                    help="逗号分隔的匹配关键词，默认 loader,dump3,dump2,dump,challenge")
    ap.add_argument("--dll", type=str, default=None, help=f"Python DLL 名，默认 {DLL}")
    ap.add_argument("--js", type=str, default=None, help=f"JS 脚本路径，默认 {JS_PATH}")
    ap.add_argument("--timeout", type=float, default=120.0, help="等待进程的超时秒数")
    args = ap.parse_args()

    dll_name = args.dll or DLL
    js_path = args.js or JS_PATH

    if not os.path.exists(js_path):
        print(f"[-] JS 脚本不存在: {js_path}")
        return

    keywords = DEFAULT_KEYWORDS
    if args.name:
        keywords = [args.name]
    if args.keywords:
        keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]

    print(f"[*] DLL       = {dll_name}")
    print(f"[*] JS_PATH   = {js_path}")
    print(f"[*] keywords  = {keywords}")

    # 1. 找目标
    pid = None
    base = None

    if args.pid:
        print(f"[*] 使用指定 PID = {args.pid}")
        found, base = attach_and_check(args.pid)
        if found:
            pid = args.pid
        else:
            print(f"[-] PID {args.pid} 已附加但未找到 {dll_name}")
            return
    else:
        print(f"[*] 等待进程出现（最多 {args.timeout:.0f} 秒）...")
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            cands = list_candidates(keywords)
            if cands:
                print(f"[*] 候选进程: {cands}")
                for c_pid, c_name in cands:
                    ok, cb = attach_and_check(c_pid)
                    if ok:
                        pid, base = c_pid, cb
                        print(f"[+] 命中: PID={pid} name={c_name} {dll_name} base={base}")
                        break
                if pid:
                    break
            time.sleep(0.2)

    if pid is None:
        print(f"[-] 未找到可附着的目标进程（含 {dll_name}）")
        return

    # 2. 正式 attach 并注入 dump 脚本
    print(f"[+] attach pid={pid} ...")
    session = frida.attach(pid)

    with open(js_path, encoding="utf-8") as f:
        js = f.read()
    # 如果命令行指定了不同 DLL，做一次替换
    if dll_name != "python312.dll":
        js = js.replace('"python312.dll"', f'"{dll_name}"')

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("[+] dump 脚本已加载，等待 JS 侧命中 __main__.verify ...")

    # 3. 等待用户回车或 JS 侧完成
    try:
        input("\n[*] 按 Enter 退出（此时可在 loader 控制台输入 123 继续触发 verify）\n")
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
        print("[*] 已 detach")


if __name__ == "__main__":
    main()
```

frida 脚本如下：

```js
var DLL = "python312.dll";
var done = false;
var initialized = false;

function log(s) { try { send({ m: String(s) }); } catch (e) { } }

// 导出的 C API
var fnIsInit, fnGILE, fnGILR, fnImportAdd, fnImportMod, fnGetModuleDict,
    fnGetDict, fnDictGet, fnDictNext, fnGetAttr, fnObjectType, fnUtf8,
    fnBytes, fnTupleSize, fnTupleGet, fnErrClear, fnCallFn, fnLong, fnRepr;

var PyFunction_Type = null, PyBytes_Type = null, PyUnicode_Type = null,
    PyLong_Type = null, PyTuple_Type = null;

function initFunctions(mod) {
    if (initialized) return true;
    function ex(name) {
        var p = mod.findExportByName(name);
        if (!p) { log("[-] missing export: " + name); return null; }
        return p;
    }
    var aIsInit = ex("Py_IsInitialized");
    var aGILE = ex("PyGILState_Ensure");
    var aGILR = ex("PyGILState_Release");
    var aImportAdd = ex("PyImport_AddModule");
    var aImportMod = ex("PyImport_ImportModule");
    var aGetModuleDict = ex("PyImport_GetModuleDict");
    var aGetDict = ex("PyModule_GetDict");
    var aDictGet = ex("PyDict_GetItemString");
    var aDictNext = ex("PyDict_Next");
    var aGetAttr = ex("PyObject_GetAttrString");
    var aObjectType = ex("PyObject_Type");
    var aUtf8 = ex("PyUnicode_AsUTF8");
    var aBytes = ex("PyBytes_AsStringAndSize");
    var aTupleSize = ex("PyTuple_Size");
    var aTupleGet = ex("PyTuple_GetItem");
    var aErrClear = ex("PyErr_Clear");
    var aCallFn = ex("PyObject_CallFunctionObjArgs");
    var aLong = ex("PyLong_AsLongLong");
    var aRepr = ex("PyObject_Repr");
    if (!aIsInit || !aGILE || !aImportAdd || !aGetDict || !aDictNext || !aGetAttr) {
        return false;
    }

    fnIsInit      = new NativeFunction(aIsInit,        "int",     []);
    fnGILE        = new NativeFunction(aGILE,          "int",     []);
    fnGILR        = new NativeFunction(aGILR,          "void",    ["int"]);
    fnImportAdd   = new NativeFunction(aImportAdd,     "pointer", ["pointer"]);
    fnImportMod   = aImportMod ? new NativeFunction(aImportMod, "pointer", ["pointer"]) : null;
    fnGetModuleDict = aGetModuleDict ? new NativeFunction(aGetModuleDict, "pointer", []) : null;
    fnGetDict     = new NativeFunction(aGetDict,       "pointer", ["pointer"]);
    fnDictGet     = aDictGet ? new NativeFunction(aDictGet, "pointer", ["pointer", "pointer"]) : null;
    fnDictNext    = new NativeFunction(aDictNext,      "int",     ["pointer","pointer","pointer","pointer"]);
    fnGetAttr     = new NativeFunction(aGetAttr,       "pointer", ["pointer","pointer"]);
    fnObjectType  = aObjectType ? new NativeFunction(aObjectType, "pointer", ["pointer"]) : null;
    fnUtf8        = aUtf8 ? new NativeFunction(aUtf8, "pointer", ["pointer"]) : null;
    fnBytes       = aBytes ? new NativeFunction(aBytes, "int", ["pointer","pointer","pointer"]) : null;
    fnTupleSize   = aTupleSize ? new NativeFunction(aTupleSize, "int64", ["pointer"]) : null;
    fnTupleGet    = aTupleGet ? new NativeFunction(aTupleGet, "pointer", ["pointer","int64"]) : null;
    fnErrClear    = aErrClear ? new NativeFunction(aErrClear, "void", []) : function(){};
    fnCallFn      = aCallFn ? new NativeFunction(aCallFn, "pointer",
                    ["pointer","pointer","pointer","pointer","pointer","pointer"]) : null;
    fnLong        = aLong ? new NativeFunction(aLong, "int64", ["pointer"]) : null;
    fnRepr        = aRepr ? new NativeFunction(aRepr, "pointer", ["pointer"]) : null;

    initialized = true;
    return true;
}

function safeAttr(obj, name) {
    if (!obj || obj.isNull()) return null;
    var r = fnGetAttr(obj, Memory.allocUtf8String(name));
    if (!r || r.isNull()) { fnErrClear(); return null; }
    return r;
}

function getStr(obj) {
    if (!obj || obj.isNull() || !fnUtf8) return null;
    var c = fnUtf8(obj);
    if (!c || c.isNull()) { fnErrClear(); return null; }
    return c.readCString();
}

function getBytes(obj) {
    if (!obj || obj.isNull() || !fnBytes) return null;
    var buf = Memory.alloc(Process.pointerSize);
    var len = Memory.alloc(8);
    if (fnBytes(obj, buf, len) !== 0) { fnErrClear(); return null; }
    var ptr = buf.readPointer();
    var n = len.readS64();
    if (!ptr || ptr.isNull() || n < 0 || n > 0x100000) return null;
    if (n === 0) return { bytes: new Uint8Array(0), len: 0, hex: "" };
    var arr = new Uint8Array(ptr.readByteArray(n));
    var hex = '';
    for (var i = 0; i < arr.length; i++) hex += ('0' + arr[i].toString(16)).slice(-2);
    return { bytes: arr, len: n, hex: hex };
}

function typeName(obj) {
    if (!obj || obj.isNull() || !fnObjectType) return null;
    var t = fnObjectType(obj);
    if (!t || t.isNull()) { fnErrClear(); return null; }
    var n = safeAttr(t, "__name__");
    if (!n) { fnErrClear(); return null; }
    return getStr(n);
}

// 遍历 dict，返回 [{k, v}, ...]
function dictIterate(dictPtr) {
    var out = [];
    if (!dictPtr || dictPtr.isNull() || !fnDictNext) return out;
    var pos = Memory.alloc(8);
    pos.writeS64(0);
    var kPtr = Memory.alloc(8);
    var vPtr = Memory.alloc(8);
    var safety = 0;
    while (fnDictNext(dictPtr, pos, kPtr, vPtr) !== 0) {
        if (++safety > 5000) break;
        out.push({ k: kPtr.readPointer(), v: vPtr.readPointer() });
    }
    return out;
}

// dump 一个 code object 的完整信息
function dumpCodeObject(label, codeObj) {
    if (!codeObj) { log("[" + label + "] code null"); return; }
    var coName = safeAttr(codeObj, "co_name");
    var coNameStr = coName ? getStr(coName) : "?";
    log("\n===== code object: " + label + " (co_name=" + coNameStr + ") =====");

    // co_varnames
    var varnames = safeAttr(codeObj, "co_varnames");
    if (varnames && fnTupleSize && fnTupleGet) {
        var n = Number(fnTupleSize(varnames));
        var arr = [];
        for (var i = 0; i < n; i++) {
            var it = fnTupleGet(varnames, i);
            arr.push(getStr(it));
        }
        log("  co_varnames(" + n + "): " + JSON.stringify(arr));
    }

    // co_names
    var names = safeAttr(codeObj, "co_names");
    if (names && fnTupleSize && fnTupleGet) {
        var n = Number(fnTupleSize(names));
        var arr = [];
        for (var i = 0; i < n; i++) {
            var it = fnTupleGet(names, i);
            arr.push(getStr(it));
        }
        log("  co_names(" + n + "): " + JSON.stringify(arr));
    }

    // co_consts
    var consts = safeAttr(codeObj, "co_consts");
    if (consts && fnTupleSize && fnTupleGet) {
        var n = Number(fnTupleSize(consts));
        log("  co_consts(" + n + "):");
        for (var i = 0; i < n; i++) {
            var item = fnTupleGet(consts, i);
            if (!item || item.isNull()) { log("    [" + i + "] <null>"); continue; }
            var tn = typeName(item);
            if (tn === "bytes") {
                var b = getBytes(item);
                if (b) { log("    [" + i + "] bytes(" + b.len + ") " + b.hex); continue; }
            }
            if (tn === "str") {
                var s = getStr(item);
                if (s !== null) { log("    [" + i + "] str " + JSON.stringify(s)); continue; }
            }
            if (tn === "int" && fnLong) {
                log("    [" + i + "] int " + Number(fnLong(item)));
                continue;
            }
            if (tn === "code") {
                var sn = safeAttr(item, "co_name");
                log("    [" + i + "] <code " + JSON.stringify(getStr(sn)) + ">");
                continue;
            }
            log("    [" + i + "] " + (tn || "?"));
        }
    }

    // co_code
    var coCode = safeAttr(codeObj, "co_code");
    if (coCode) {
        var b = getBytes(coCode);
        if (b) log("  co_code(" + b.len + "): " + b.hex);
    }

    // marshal.dumps 整个 code object 发给 Python 端保存
    if (fnCallFn && fnImportMod) {
        var marshalMod = fnImportMod(Memory.allocUtf8String("marshal"));
        if (marshalMod && !marshalMod.isNull()) {
            var dumps = safeAttr(marshalMod, "dumps");
            if (dumps) {
                var bytesObj = fnCallFn(dumps, codeObj, ptr(0), ptr(0), ptr(0), ptr(0));
                if (bytesObj && !bytesObj.isNull()) {
                    var mb = getBytes(bytesObj);
                    if (mb) {
                        var safeName = String(label).replace(/[^\w.-]/g, "_");
                        send({ type: "code_object", name: safeName, size: mb.len }, mb.bytes.buffer);
                    }
                } else { fnErrClear(); }
            }
        }
    }
}

// dump 一个 dict（比如 __main__.__dict__）
function dumpModuleDict(label, dictPtr, opts) {
    opts = opts || { skipDunder: true };
    var entries = dictIterate(dictPtr);
    log("\n########## [" + label + "] " + entries.length + " entries ##########");
    for (var e of entries) {
        var keyStr = getStr(e.k);
        if (keyStr === null) keyStr = "<non-str-key>";
        if (opts.skipDunder && keyStr.startsWith("__") && keyStr.endsWith("__")) continue;

        var tn = typeName(e.v) || "?";

        if (tn === "function") {
            log("  " + keyStr + " : function");
            var codeObj = safeAttr(e.v, "__code__");
            dumpCodeObject(keyStr, codeObj);
        } else if (tn === "builtin_function_or_method") {
            log("  " + keyStr + " : builtin_function_or_method");
        } else if (tn === "bytes") {
            var b = getBytes(e.v);
            if (b) log("  " + keyStr + " : bytes(" + b.len + ") " + b.hex);
        } else if (tn === "bytearray") {
            var b2 = getBytes(e.v);
            if (b2) log("  " + keyStr + " : bytearray(" + b2.len + ") " + b2.hex);
        } else if (tn === "str") {
            var s = getStr(e.v);
            if (s !== null) log("  " + keyStr + " : str " + JSON.stringify(s));
        } else if (tn === "int" && fnLong) {
            log("  " + keyStr + " : int " + Number(fnLong(e.v)));
        } else if (tn === "type") {
            log("  " + keyStr + " : type(class)");
        } else if (tn === "module") {
            log("  " + keyStr + " : module");
        } else {
            log("  " + keyStr + " : " + tn);
        }
    }
}

function tryInstall() {
    if (done) return;
    var mod = Process.findModuleByName(DLL);
    if (!mod) return;
    if (!initFunctions(mod)) { done = true; return; }

    if (fnIsInit() === 0) return;

    var gil = fnGILE();
    try {
        log("[*] GIL acquired, dumping ...");

        // 1) 打印所有已加载模块名（sys.modules）
        if (fnGetModuleDict) {
            var sysMods = fnGetModuleDict();
            if (sysMods && !sysMods.isNull()) {
                var entries = dictIterate(sysMods);
                var names = [];
                for (var e of entries) {
                    var s = getStr(e.k);
                    if (s) names.push(s);
                }
                log("[sys.modules] " + names.length + " modules: " + JSON.stringify(names));
            }
        }

        // 2) dump __main__.__dict__
        var mainMod = fnImportAdd(Memory.allocUtf8String("__main__"));
        if (mainMod && !mainMod.isNull()) {
            var mainDict = fnGetDict(mainMod);
            if (mainDict && !mainDict.isNull()) {
                dumpModuleDict("__main__", mainDict, { skipDunder: true });
            }
        } else { fnErrClear(); }

        // 3) 试试 os 模块（很多 Nuitka 混淆会把东西塞进 os）
        var osMod = fnImportAdd(Memory.allocUtf8String("os"));
        if (osMod && !osMod.isNull()) {
            var osDict = fnGetDict(osMod);
            if (osDict && !osDict.isNull()) {
                dumpModuleDict("os", osDict, { skipDunder: true });
            }
        } else { fnErrClear(); }

        done = true;
    } catch (e) {
        log("[-] exception: " + e);
        fnErrClear();
    } finally {
        fnGILR(gil);
    }
}

setInterval(tryInstall, 500);
```

输出非常多，这里会遍历全部的全局模块，我这里只提取 main 中的内容：

```txt
########## [**main**] 15 entries ##########
[JS]   KEY : bytes(8) 733466654b657921
[JS]   TARGET : bytes(24) 499ea0a2c4c7e3617ecfe4f6286288d6025e6279b1bdcd17
[JS]   warehouse_transform : compiled_function
[JS]   check_flag : compiled_function
[JS]   main : compiled_function
[JS]
```

这里我们得到了极其关键的内容，这个模块中含有两个全局变量 KEY 和 TARGET，应该就是密钥和密文。

同时还发现了暴露在全局的两个函数 `check_flag` 和 `warehouse_transform` 。

这里我们可以猜测可能 check 函数中会对输入预处理然后调用 transform 函数加密最后与 target 比较。

现在我们最想看到的就是这两个 object 的字段信息。

frida 脚本如下：

```js
// fwh_dump2.js
var DLL = "python312.dll";
var done = false;
var initialized = false;

function log(s) { try { send({ m: String(s) }); } catch (e) { } }

var fnIsInit, fnGILE, fnGILR, fnImportAdd, fnGetDict, fnGetAttr,
    fnUtf8, fnBytes, fnTupleSize, fnTupleGet, fnErrClear, fnCallFn,
    fnImportMod, fnLong, fnObjectType, fnRepr;

function initFunctions(mod) {
    if (initialized) return true;
    function ex(n) { return mod.findExportByName(n); }
    var a = {
        IsInit: ex("Py_IsInitialized"),
        GILE: ex("PyGILState_Ensure"),
        GILR: ex("PyGILState_Release"),
        ImportAdd: ex("PyImport_AddModule"),
        GetDict: ex("PyModule_GetDict"),
        GetAttr: ex("PyObject_GetAttrString"),
        Utf8: ex("PyUnicode_AsUTF8"),
        Bytes: ex("PyBytes_AsStringAndSize"),
        TupleSize: ex("PyTuple_Size"),
        TupleGet: ex("PyTuple_GetItem"),
        ErrClear: ex("PyErr_Clear"),
        CallFn: ex("PyObject_CallFunctionObjArgs"),
        ImportMod: ex("PyImport_ImportModule"),
        Long: ex("PyLong_AsLongLong"),
        ObjType: ex("PyObject_Type"),
        Repr: ex("PyObject_Repr"),
    };
    if (!a.IsInit || !a.GILE || !a.ImportAdd || !a.GetDict || !a.GetAttr) return false;
    fnIsInit = new NativeFunction(a.IsInit, "int", []);
    fnGILE = new NativeFunction(a.GILE, "int", []);
    fnGILR = new NativeFunction(a.GILR, "void", ["int"]);
    fnImportAdd = new NativeFunction(a.ImportAdd, "pointer", ["pointer"]);
    fnGetDict = new NativeFunction(a.GetDict, "pointer", ["pointer"]);
    fnGetAttr = new NativeFunction(a.GetAttr, "pointer", ["pointer", "pointer"]);
    fnUtf8 = new NativeFunction(a.Utf8, "pointer", ["pointer"]);
    fnBytes = new NativeFunction(a.Bytes, "int", ["pointer", "pointer", "pointer"]);
    fnTupleSize = new NativeFunction(a.TupleSize, "int64", ["pointer"]);
    fnTupleGet = new NativeFunction(a.TupleGet, "pointer", ["pointer", "int64"]);
    fnErrClear = new NativeFunction(a.ErrClear, "void", []);
    fnCallFn = new NativeFunction(a.CallFn, "pointer", ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer"]);
    fnImportMod = new NativeFunction(a.ImportMod, "pointer", ["pointer"]);
    fnLong = new NativeFunction(a.Long, "int64", ["pointer"]);
    fnObjectType = new NativeFunction(a.ObjType, "pointer", ["pointer"]);
    fnRepr = new NativeFunction(a.Repr, "pointer", ["pointer"]);
    initialized = true;
    return true;
}

function safeAttr(o, n) {
    if (!o || o.isNull()) return null;
    var r = fnGetAttr(o, Memory.allocUtf8String(n));
    if (!r || r.isNull()) { fnErrClear(); return null; }
    return r;
}
function getStr(o) {
    if (!o || o.isNull()) return null;
    var c = fnUtf8(o); if (!c || c.isNull()) { fnErrClear(); return null; }
    return c.readCString();
}
function getBytes(o) {
    if (!o || o.isNull()) return null;
    var buf = Memory.alloc(8), len = Memory.alloc(8);
    if (fnBytes(o, buf, len) !== 0) { fnErrClear(); return null; }
    var p = buf.readPointer(), n = len.readS64();
    if (!p || p.isNull() || n < 0 || n > 0x100000) return null;
    if (n === 0) return { bytes: new Uint8Array(0), len: 0, hex: "" };
    var arr = new Uint8Array(p.readByteArray(n));
    var hex = ''; for (var i = 0; i < arr.length; i++) hex += ('0' + arr[i].toString(16)).slice(-2);
    return { bytes: arr, len: n, hex: hex };
}
function typeName(o) {
    if (!o || o.isNull()) return null;
    var t = fnObjectType(o); if (!t || t.isNull()) { fnErrClear(); return null; }
    var n = safeAttr(t, "__name__"); if (!n) { fnErrClear(); return null; }
    return getStr(n);
}

function dumpCode(label, fnObj) {
    log("\n===== " + label + " =====");
    var tn = typeName(fnObj);
    log("  type = " + tn);
    // __name__
    var nameObj = safeAttr(fnObj, "__name__");
    if (nameObj) log("  __name__ = " + JSON.stringify(getStr(nameObj)));
    // 尝试 __code__
    var codeObj = safeAttr(fnObj, "__code__");
    if (!codeObj) {
        log("  __code__ = NULL (纯C编译函数)");
        // 试试 __doc__
        var docObj = safeAttr(fnObj, "__doc__");
        if (docObj) log("  __doc__ = " + JSON.stringify(getStr(docObj)));
        return;
    }
    // co_name
    var coName = safeAttr(codeObj, "co_name");
    if (coName) log("  co_name = " + JSON.stringify(getStr(coName)));
    // co_varnames
    var vn = safeAttr(codeObj, "co_varnames");
    if (vn) {
        var n = Number(fnTupleSize(vn)); var arr = [];
        for (var i = 0; i < n; i++) arr.push(getStr(fnTupleGet(vn, i)));
        log("  co_varnames(" + n + "): " + JSON.stringify(arr));
    }
    // co_names
    var nm = safeAttr(codeObj, "co_names");
    if (nm) {
        var n = Number(fnTupleSize(nm)); var arr = [];
        for (var i = 0; i < n; i++) arr.push(getStr(fnTupleGet(nm, i)));
        log("  co_names(" + n + "): " + JSON.stringify(arr));
    }
    // co_consts
    var cs = safeAttr(codeObj, "co_consts");
    if (cs) {
        var n = Number(fnTupleSize(cs));
        log("  co_consts(" + n + "):");
        for (var i = 0; i < n; i++) {
            var it = fnTupleGet(cs, i);
            if (!it || it.isNull()) { log("    [" + i + "] <null>"); continue; }
            var t = typeName(it);
            if (t === "bytes") {
                var b = getBytes(it);
                if (b) { log("    [" + i + "] bytes(" + b.len + ") " + b.hex); continue; }
            }
            if (t === "str") {
                var s = getStr(it);
                if (s !== null) { log("    [" + i + "] str " + JSON.stringify(s)); continue; }
            }
            if (t === "int") {
                log("    [" + i + "] int " + Number(fnLong(it))); continue;
            }
            if (t === "code") {
                var sn = safeAttr(it, "co_name");
                log("    [" + i + "] <code " + JSON.stringify(getStr(sn)) + ">");
                continue;
            }
            log("    [" + i + "] " + t);
        }
    }
    // co_code
    var cc = safeAttr(codeObj, "co_code");
    if (cc) {
        var b = getBytes(cc);
        if (b) log("  co_code(" + b.len + "): " + b.hex);
    }
    // marshal.dumps
    var mm = fnImportMod(Memory.allocUtf8String("marshal"));
    if (mm) {
        var dumps = safeAttr(mm, "dumps");
        if (dumps) {
            var bo = fnCallFn(dumps, codeObj, ptr(0), ptr(0), ptr(0), ptr(0));
            if (bo && !bo.isNull()) {
                var mb = getBytes(bo);
                if (mb) {
                    send({ type: "code_object", name: label, size: mb.len }, mb.bytes.buffer);
                }
            } else { fnErrClear(); }
        }
    }
}

function tryInstall() {
    if (done) return;
    var mod = Process.findModuleByName(DLL);
    if (!mod) return;
    if (!initFunctions(mod)) { done = true; return; }
    if (fnIsInit() === 0) return;

    var gil = fnGILE();
    try {
        var mainMod = fnImportAdd(Memory.allocUtf8String("__main__"));
        if (!mainMod || mainMod.isNull()) { fnErrClear(); return; }
        var mainDict = fnGetDict(mainMod);
        if (!mainDict || mainDict.isNull()) { fnErrClear(); return; }

        var targets = ["warehouse_transform", "check_flag", "main"];
        var foundAny = false;
        for (var name of targets) {
            var f = safeAttr(mainMod, name);   // 用 module.__getattr__ 走 __dict__
            if (!f) {
                var nk = Memory.allocUtf8String(name);
                // 退路：PyDict_GetItemString
                var dictGet = mod.findExportByName("PyDict_GetItemString");
                if (dictGet) {
                    var dg = new NativeFunction(dictGet, "pointer", ["pointer", "pointer"]);
                    f = dg(mainDict, nk);
                    if (f && f.isNull()) f = null;
                }
            }
            if (f) {
                foundAny = true;
                dumpCode(name, f);
            } else {
                log("\n[-] " + name + " not found in __main__");
            }
        }
        if (foundAny) done = true;
    } catch (e) {
        log("[-] exception: " + e);
        fnErrClear();
    } finally {
        fnGILR(gil);
    }
}

setInterval(tryInstall, 500);
```

输出如下：

```txt
===== warehouse_transform =====
[JS]   type = compiled_function
[JS]   __name__ = "warehouse_transform"
[JS]   co_name = "warehouse_transform"
[JS]   co_varnames(6): ["data","ordered","out","prev","i","value"]
[JS]   co_names(1): ["RuntimeError"]
[JS]   co_consts(2):
[JS]     [0] NoneType
[JS]     [1] str "Compiled function bytecode used"
[JS]   co_code(24): 9700740100000000000000006401ab010000000000008201
[+] saved dumped_code_objects\warehouse_transform.pyc (278 bytes)
    co_name      = 'warehouse_transform'
    co_code_len  = 24
    co_names     = ['RuntimeError']
    co_varnames  = ['data', 'ordered', 'out', 'prev', 'i', 'value']
    co_consts    =
      [0] NoneType None
      [1] str  'Compiled function bytecode used'

--- dis.dis(warehouse_transform) ---
  4           CALL_KW                  0
              CACHE
              CACHE
              POP_JUMP_IF_FALSE        1 (to L1)
              CACHE
      L1:     CACHE
              CACHE
              BINARY_OP                1 (&)
--- end dis ---

[JS]
===== check_flag =====
[JS]   type = compiled_function
[JS]   __name__ = "check_flag"
[JS]   co_name = "check_flag"
[JS]   co_varnames(1): ["text"]
[JS]   co_names(1): ["RuntimeError"]
[JS]   co_consts(2):
[JS]     [0] NoneType
[JS]     [1] str "Compiled function bytecode used"
[JS]   co_code(24): 9700740100000000000000006401ab010000000000008201
[+] saved dumped_code_objects\check_flag.pyc (234 bytes)
    co_name      = 'check_flag'
    co_code_len  = 24
    co_names     = ['RuntimeError']
    co_varnames  = ['text']
    co_consts    =
      [0] NoneType None
      [1] str  'Compiled function bytecode used'

--- dis.dis(check_flag) ---
 11           CALL_KW                  0
              CACHE
              CACHE
              POP_JUMP_IF_FALSE        1 (to L1)
              CACHE
      L1:     CACHE
              CACHE
              BINARY_OP                1 (&)
--- end dis ---

[JS]
===== main =====
[JS]   type = compiled_function
[JS]   __name__ = "main"
[JS]   co_name = "main"
[JS]   co_varnames(1): ["text"]
[JS]   co_names(1): ["RuntimeError"]
[JS]   co_consts(2):
[JS]     [0] NoneType
[JS]     [1] str "Compiled function bytecode used"
[JS]   co_code(24): 9700740100000000000000006401ab010000000000008201
[+] saved dumped_code_objects\main.pyc (228 bytes)
    co_name      = 'main'
    co_code_len  = 24
```

在这里我们无法通过这些 co_object 的 co_code 字段获取到字节码。

毕竟是 nutika 打包的，理论上是不会存在字节码的。

但是这的局部变量给了我们更多的信息，可以看到 main 函数 和 check 函数极其简单，就只有一个局部变量和异常。

同时 transform 函数加密逻辑需要的变量名泄露了，这对我们的分析也会有很大帮助。

既然现在的目标已经明确，由于 nutika 想要劫持函数调用到 native ，那么它就一定需要暴露一个指针到运行时，以供调用，而通过这个地址减去基址我们就可以得到这三个函数的 rva 了。

然后我们就可以尝试在 ida 中进行分析了。

frida 脚本如下：

```js
var DLL = "python312.dll";
var TARGET_MODULE = "challenge.dll";
var done = false;
var initialized = false;

function log(s) { try { send({ m: String(s) }); } catch (e) { } }

// ---------- C API 函数指针 ----------
var fnIsInit, fnGILE, fnGILR, fnImportAdd, fnGetAttr, fnUtf8, fnBytes,
    fnErrClear, fnCallFn, fnLong, fnObjType, fnFromStr, fnBytesNew,
    fnErrFetch, fnErrNormalize, fnObjRepr, fnListNew, fnListSetItem,
    fnLongFromLong, fnDictNext, fnGetModuleDict;

function initFunctions(mod) {
    if (initialized) return true;
    function ex(n) { return mod.findExportByName(n); }
    var a = {
        IsInit:     ex("Py_IsInitialized"),
        GILE:       ex("PyGILState_Ensure"),
        GILR:       ex("PyGILState_Release"),
        ImportAdd:  ex("PyImport_AddModule"),
        ImportMod:  ex("PyImport_ImportModule"),
        GetModuleDict: ex("PyImport_GetModuleDict"),
        GetAttr:    ex("PyObject_GetAttrString"),
        Utf8:       ex("PyUnicode_AsUTF8"),
        Bytes:      ex("PyBytes_AsStringAndSize"),
        BytesNew:   ex("PyBytes_FromStringAndSize"),
        ErrClear:   ex("PyErr_Clear"),
        CallFn:     ex("PyObject_CallFunctionObjArgs"),
        Long:       ex("PyLong_AsLongLong"),
        ObjType:    ex("PyObject_Type"),
        FromStr:    ex("PyUnicode_FromString"),
        ErrFetch:   ex("PyErr_Fetch"),
        ErrNorm:    ex("PyErr_NormalizeException"),
        ObjRepr:    ex("PyObject_Repr"),
        ListNew:    ex("PyList_New"),
        ListSet:    ex("PyList_SetItem"),
        LongFromL:  ex("PyLong_FromLong"),
        DictNext:   ex("PyDict_Next"),
    };
    if (!a.IsInit || !a.GILE || !a.ImportAdd || !a.GetAttr) return false;

    fnIsInit    = new NativeFunction(a.IsInit,    "int", []);
    fnGILE      = new NativeFunction(a.GILE,      "int", []);
    fnGILR      = new NativeFunction(a.GILR,      "void", ["int"]);
    fnImportAdd = new NativeFunction(a.ImportAdd, "pointer", ["pointer"]);
    fnGetAttr   = new NativeFunction(a.GetAttr,   "pointer", ["pointer","pointer"]);
    fnUtf8      = new NativeFunction(a.Utf8,      "pointer", ["pointer"]);
    fnBytes     = new NativeFunction(a.Bytes,     "int", ["pointer","pointer","pointer"]);
    fnErrClear  = new NativeFunction(a.ErrClear,  "void", []);
    fnCallFn    = new NativeFunction(a.CallFn,    "pointer", ["pointer","pointer","pointer","pointer","pointer","pointer"]);
    fnLong      = new NativeFunction(a.Long,      "int64", ["pointer"]);
    fnObjType   = new NativeFunction(a.ObjType,   "pointer", ["pointer"]);
    fnFromStr   = new NativeFunction(a.FromStr,   "pointer", ["pointer"]);
    if (a.BytesNew)   fnBytesNew  = new NativeFunction(a.BytesNew,  "pointer", ["pointer","int64"]);
    if (a.ErrFetch)   fnErrFetch  = new NativeFunction(a.ErrFetch,  "void", ["pointer","pointer","pointer"]);
    if (a.ErrNorm)    fnErrNormalize = new NativeFunction(a.ErrNorm, "void", ["pointer","pointer","pointer"]);
    if (a.ObjRepr)    fnObjRepr   = new NativeFunction(a.ObjRepr,   "pointer", ["pointer"]);
    if (a.ListNew)    fnListNew   = new NativeFunction(a.ListNew,   "pointer", ["int64"]);
    if (a.ListSet)    fnListSetItem = new NativeFunction(a.ListSet, "int", ["pointer","int64","pointer"]);
    if (a.LongFromL)  fnLongFromLong = new NativeFunction(a.LongFromL, "pointer", ["int"]);
    if (a.DictNext)   fnDictNext  = new NativeFunction(a.DictNext,  "int", ["pointer","pointer","pointer","pointer"]);
    if (a.GetModuleDict) fnGetModuleDict = new NativeFunction(a.GetModuleDict, "pointer", []);
    initialized = true;
    return true;
}

// ---------- 辅助 ----------
function safeAttr(o, n) {
    if (!o || o.isNull()) return null;
    var r = fnGetAttr(o, Memory.allocUtf8String(n));
    if (!r || r.isNull()) { fnErrClear(); return null; }
    return r;
}
function getStr(o) {
    if (!o || o.isNull()) return null;
    var c = fnUtf8(o); if (!c || c.isNull()) { fnErrClear(); return null; }
    return c.readCString();
}
function getBytes(o) {
    if (!o || o.isNull()) return null;
    var buf = Memory.alloc(8), len = Memory.alloc(8);
    if (fnBytes(o, buf, len) !== 0) { fnErrClear(); return null; }
    var p = buf.readPointer(), n = len.readS64();
    if (!p || p.isNull() || n < 0 || n > 0x100000) return null;
    if (n === 0) return { bytes: new Uint8Array(0), len: 0, hex: "" };
    var arr = new Uint8Array(p.readByteArray(n));
    var hex = ''; for (var i=0;i<arr.length;i++) hex += ('0'+arr[i].toString(16)).slice(-2);
    return { bytes: arr, len: n, hex: hex };
}
function typeName(o) {
    if (!o || o.isNull()) return null;
    var t = fnObjType(o); if (!t || t.isNull()) { fnErrClear(); return null; }
    var n = fnGetAttr(t, Memory.allocUtf8String("__name__"));
    if (!n || n.isNull()) { fnErrClear(); return null; }
    return getStr(n);
}

// 判断前 8 字节是否像函数 prologue
function looksLikePrologue(u8) {
    if (u8.length < 4) return false;
    // x64 常见 prologue：
    //   55                push rbp
    //   48 89 5c 24 XX    mov [rsp+XX], rbx
    //   48 83 ec XX       sub rsp, XX
    //   48 89 4c 24 08    mov [rsp+8], rcx
    //   48 89 54 24 10    mov [rsp+10], rdx
    //   40 53             push rbx (REX)
    //   40 55             push rbp (REX)
    //   41 54/55/56/57    push r12-r15
    var b = u8;
    if (b[0] === 0x55) return true;
    if (b[0] === 0x48 && (b[1] === 0x89 || b[1] === 0x83 || b[1] === 0x8b)) return true;
    if (b[0] === 0x40 && (b[1] === 0x53 || b[1] === 0x55 || b[1] === 0x56 || b[1] === 0x57)) return true;
    if (b[0] === 0x41 && (b[1] === 0x54 || b[1] === 0x55 || b[1] === 0x56 || b[1] === 0x57)) return true;
    if (b[0] === 0x53 || b[0] === 0x56 || b[0] === 0x57) return true;
    if (b[0] === 0x4c && b[1] === 0x8b && (b[2] === 0xdc || b[2] === 0xd9)) return true;
    return false;
}

// ---------- 核心：dump 一个 compiled_function 的所有 challenge.dll 指针 ----------
function findImplRVA(label, funcObj) {
    if (!funcObj || funcObj.isNull()) { log("\n[" + label + "] NULL object"); return null; }

    var challMod = Process.findModuleByName(TARGET_MODULE);
    if (!challMod) { log("[-] " + TARGET_MODULE + " not loaded"); return null; }
    var base = challMod.base;
    var size = challMod.size;
    var end = base.add(size);

    var pyMod = Process.findModuleByName(DLL);
    var pyBase = pyMod ? pyMod.base : null;
    var pyEnd = pyMod ? pyMod.base.add(pyMod.size) : null;

    log("\n========== [" + label + "] ==========");
    log("  obj @ " + funcObj + "  type = " + typeName(funcObj));
    log("  " + TARGET_MODULE + " @ " + base + "  size=0x" + size.toString(16) + "  (range " + base + " .. " + end + ")");
    if (pyBase) log("  " + DLL + " @ " + pyBase + "  size=0x" + pyMod.size.toString(16));

    var hits = [];
    for (var off = 0; off < 0x300; off += 8) {
        var v;
        try { v = funcObj.add(off).readPointer(); } catch (e) { break; }
        if (v.isNull()) continue;

        var tag = "", note = "";
        if (v.compare(base) >= 0 && v.compare(end) < 0) {
            var rva = v.sub(base).toInt32();
            var prohex = "??", u8 = null;
            try {
                u8 = new Uint8Array(v.readByteArray(8));
                prohex = Array.from(u8).map(b => ('0'+b.toString(16)).slice(-2)).join(' ');
            } catch (e) { prohex = "<unreadable>"; }

            if (u8 && looksLikePrologue(u8)) {
                tag = "★★★ [FUNC?]";
                note = "  ← 可能是 m_impl";
            } else {
                tag = " ★ [data]";
            }
            hits.push({ off: off, rva: rva, ptr: v, pro: prohex, isFunc: !!(u8 && looksLikePrologue(u8)) });
            log("  +0x" + off.toString(16).padStart(3,'0') + ": " + v +
                "   " + TARGET_MODULE + "+0x" + rva.toString(16) + "   bytes=[" + prohex + "]  " + tag + note);
        } else if (pyBase && v.compare(pyBase) >= 0 && v.compare(pyEnd) < 0) {
            log("  +0x" + off.toString(16).padStart(3,'0') + ": " + v +
                "   [" + DLL + "+0x" + v.sub(pyBase).toString(16) + "]");
        } else {
            log("  +0x" + off.toString(16).padStart(3,'0') + ": " + v + "   [other]");
        }
    }

    log("  → " + hits.length + " 个 " + TARGET_MODULE + " 指针");
    var funcs = hits.filter(h => h.isFunc);
    if (funcs.length > 0) {
        log("  → 推荐 m_impl:");
        for (var h of funcs) {
            log("      " + TARGET_MODULE + "+0x" + h.rva.toString(16) +
                "  = IDA 0x3530C" + h.rva.toString(16).padStart(4,'0'));
        }
    } else {
        log("  → 未找到函数 prologue 特征");
    }
    return funcs.length ? funcs[0].rva : null;
}

// ---------- 通用 dict 遍历（备用：从 sys.modules 找 __main__） ----------
function dictIterate(dictPtr) {
    var out = [];
    if (!dictPtr || dictPtr.isNull() || !fnDictNext) return out;
    var pos = Memory.alloc(8); pos.writeS64(0);
    var kP = Memory.alloc(8), vP = Memory.alloc(8);
    var safety = 0;
    while (fnDictNext(dictPtr, pos, kP, vP) !== 0) {
        if (++safety > 5000) break;
        out.push({ k: kP.readPointer(), v: vP.readPointer() });
    }
    return out;
}

// ---------- 主流程 ----------
function tryInstall() {
    if (done) return;
    var mod = Process.findModuleByName(DLL);
    if (!mod) return;
    if (!initFunctions(mod)) { done = true; return; }
    if (fnIsInit() === 0) return;

    var gil = fnGILE();
    try {
        var mainMod = fnImportAdd(Memory.allocUtf8String("__main__"));
        if (!mainMod || mainMod.isNull()) { fnErrClear(); return; }

        var funcWT = safeAttr(mainMod, "warehouse_transform");
        var funcCF = safeAttr(mainMod, "check_flag");
        var funcMain = safeAttr(mainMod, "main");
        var keyObj = safeAttr(mainMod, "KEY");
        var targetObj = safeAttr(mainMod, "TARGET");

        // 还没定义好，下一轮再试
        if (!funcWT) {
            fnErrClear();
            return;
        }
        done = true;

        if (keyObj) {
            var kb = getBytes(keyObj);
            if (kb) log("[+] KEY = " + kb.hex + "  (" + kb.len + "B)");
        }
        if (targetObj) {
            var tb = getBytes(targetObj);
            if (tb) log("[+] TARGET = " + tb.hex + "  (" + tb.len + "B)");
        }

        var rvaWT  = findImplRVA("warehouse_transform", funcWT);
        var rvaCF  = findImplRVA("check_flag",          funcCF);
        var rvaMain= findImplRVA("main",                 funcMain);

        log("\n================ 汇总 ================");
        log("warehouse_transform  m_impl RVA = 0x" + (rvaWT   ? rvaWT.toString(16)   : "?") +
            "  →  IDA: 0x3530C" + (rvaWT   ? rvaWT.toString(16).padStart(4,'0')   : "????"));
        log("check_flag           m_impl RVA = 0x" + (rvaCF   ? rvaCF.toString(16)   : "?") +
            "  →  IDA: 0x3530C" + (rvaCF   ? rvaCF.toString(16).padStart(4,'0')   : "????"));
        log("main                 m_impl RVA = 0x" + (rvaMain ? rvaMain.toString(16) : "?") +
            "  →  IDA: 0x3530C" + (rvaMain ? rvaMain.toString(16).padStart(4,'0') : "????"));
        log("=====================================");

    } catch (e) {
        log("[-] outer exception: " + e + "\n" + (e.stack || ""));
        fnErrClear();
    } finally {
        fnGILR(gil);
    }
}

setInterval(tryInstall, 500);
```

输出如下：

```txt
[JS] [+] KEY = 733466654b657921  (8B)
[JS] [+] TARGET = 499ea0a2c4c7e3617ecfe4f6286288d6025e6279b1bdcd17  (24B)
[JS]
========== [warehouse_transform] ==========
[JS]   obj @ 0x1822929ca40  type = compiled_function
[JS]   challenge.dll @ 0x7fffe2ad0000  size=0x49b000  (range 0x7fffe2ad0000 .. 0x7fffe2f6b000)
[JS]   python312.dll @ 0x7fffdfa20000  size=0x6b4000
[JS]   +0x000: 0x5   [other]
[JS]   +0x008: 0x7fffe2b19a80   challenge.dll+0x49a80   bytes=[1f 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x018: 0x18228ff23f0   [other]
[JS]   +0x020: 0x18228ff4180   [other]
[JS]   +0x030: 0x182292539f0   [other]
[JS]   +0x038: 0x1   [other]
[JS]   +0x040: 0x1   [other]
[JS]   +0x048: 0x1   [other]
[JS]   +0x050: 0x1   [other]
[JS]   +0x058: 0xffffffffffffffff   [other]
[JS]   +0x060: 0xffffffffffffffff   [other]
[JS]   +0x070: 0x18229296cf8   [other]
[JS]   +0x078: 0x7fffe2ad83b0   challenge.dll+0x83b0   bytes=[41 57 41 56 41 55 41 54]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x080: 0x7fffe2ad8290   challenge.dll+0x8290   bytes=[41 54 55 57 56 53 48 83]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x098: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x0b8: 0x18228ff23f0   [other]
[JS]   +0x0c0: 0x7fffe005e6b8   [python312.dll+0x63e6b8]
[JS]   +0x0f0: 0x1822929cc30   [other]
[JS]   +0x0f8: 0x1822929ca30   [other]
[JS]   +0x100: 0x4   [other]
[JS]   +0x108: 0x7fffe2b19a80   challenge.dll+0x49a80   bytes=[1f 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x118: 0x18228ff2430   [other]
[JS]   +0x120: 0x18228ff4180   [other]
[JS]   +0x130: 0x18229253c90   [other]
[JS]   +0x138: 0x1   [other]
[JS]   +0x140: 0x1   [other]
[JS]   +0x148: 0x1   [other]
[JS]   +0x150: 0x1   [other]
[JS]   +0x158: 0xffffffffffffffff   [other]
[JS]   +0x160: 0xffffffffffffffff   [other]
[JS]   +0x170: 0x182292c9198   [other]
[JS]   +0x178: 0x7fffe2ad5570   challenge.dll+0x5570   bytes=[41 55 41 54 55 57 56 53]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x180: 0x7fffe2ad8290   challenge.dll+0x8290   bytes=[41 54 55 57 56 53 48 83]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x198: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x1b8: 0x18228ff2430   [other]
[JS]   +0x1c0: 0x7fffe005e6b8   [python312.dll+0x63e6b8]
[JS]   +0x1d0: 0x1   [other]
[JS]   +0x1f0: 0x1822926ece0   [other]
[JS]   +0x1f8: 0x1822929cb30   [other]
[JS]   +0x200: 0x3   [other]
[JS]   +0x208: 0x7fffe2b19a80   challenge.dll+0x49a80   bytes=[1f 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x218: 0x7fffdff4c300   [python312.dll+0x52c300]
[JS]   +0x220: 0x18228ff4180   [other]
[JS]   +0x230: 0x18229253bb0   [other]
[JS]   +0x250: 0x1   [other]
[JS]   +0x258: 0xffffffffffffffff   [other]
[JS]   +0x260: 0xffffffffffffffff   [other]
[JS]   +0x270: 0x182292c9438   [other]
[JS]   +0x278: 0x7fffe2ad5f70   challenge.dll+0x5f70   bytes=[41 56 41 55 41 54 55 57]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x280: 0x7fffe2ad8290   challenge.dll+0x8290   bytes=[41 54 55 57 56 53 48 83]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x298: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x2b8: 0x7fffdff4c300   [python312.dll+0x52c300]
[JS]   +0x2c0: 0x7fffe005e6b8   [python312.dll+0x63e6b8]
[JS]   +0x2d0: 0x2   [other]
[JS]   +0x2f0: 0x1822927de30   [other]
[JS]   +0x2f8: 0x18229297330   [other]
[JS]   → 9 个 challenge.dll 指针
[JS]   → 推荐 m_impl:
[JS]       challenge.dll+0x83b0  = IDA 0x3530C83b0
[JS]       challenge.dll+0x8290  = IDA 0x3530C8290
[JS]       challenge.dll+0x5570  = IDA 0x3530C5570
[JS]       challenge.dll+0x8290  = IDA 0x3530C8290
[JS]       challenge.dll+0x5f70  = IDA 0x3530C5f70
[JS]       challenge.dll+0x8290  = IDA 0x3530C8290
[JS]
========== [check_flag] ==========
[JS]   obj @ 0x1822929cb40  type = compiled_function
[JS]   challenge.dll @ 0x7fffe2ad0000  size=0x49b000  (range 0x7fffe2ad0000 .. 0x7fffe2f6b000)
[JS]   python312.dll @ 0x7fffdfa20000  size=0x6b4000
[JS]   +0x000: 0x4   [other]
[JS]   +0x008: 0x7fffe2b19a80   challenge.dll+0x49a80   bytes=[20 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x018: 0x18228ff2430   [other]
[JS]   +0x020: 0x18228ff4180   [other]
[JS]   +0x030: 0x18229253c90   [other]
[JS]   +0x038: 0x1   [other]
[JS]   +0x040: 0x1   [other]
[JS]   +0x048: 0x1   [other]
[JS]   +0x050: 0x1   [other]
[JS]   +0x058: 0xffffffffffffffff   [other]
[JS]   +0x060: 0xffffffffffffffff   [other]
[JS]   +0x070: 0x182292c9198   [other]
[JS]   +0x078: 0x7fffe2ad5570   challenge.dll+0x5570   bytes=[41 55 41 54 55 57 56 53]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x080: 0x7fffe2ad8290   challenge.dll+0x8290   bytes=[41 54 55 57 56 53 48 83]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x098: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x0b8: 0x18228ff2430   [other]
[JS]   +0x0c0: 0x7fffe005e6b8   [python312.dll+0x63e6b8]
[JS]   +0x0d0: 0x1   [other]
[JS]   +0x0f0: 0x1822926ece0   [other]
[JS]   +0x0f8: 0x1822929cb30   [other]
[JS]   +0x100: 0x3   [other]
[JS]   +0x108: 0x7fffe2b19a80   challenge.dll+0x49a80   bytes=[20 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x118: 0x7fffdff4c300   [python312.dll+0x52c300]
[JS]   +0x120: 0x18228ff4180   [other]
[JS]   +0x130: 0x18229253bb0   [other]
[JS]   +0x150: 0x1   [other]
[JS]   +0x158: 0xffffffffffffffff   [other]
[JS]   +0x160: 0xffffffffffffffff   [other]
[JS]   +0x170: 0x182292c9438   [other]
[JS]   +0x178: 0x7fffe2ad5f70   challenge.dll+0x5f70   bytes=[41 56 41 55 41 54 55 57]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x180: 0x7fffe2ad8290   challenge.dll+0x8290   bytes=[41 54 55 57 56 53 48 83]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x198: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x1b8: 0x7fffdff4c300   [python312.dll+0x52c300]
[JS]   +0x1c0: 0x7fffe005e6b8   [python312.dll+0x63e6b8]
[JS]   +0x1d0: 0x2   [other]
[JS]   +0x1f0: 0x1822927de30   [other]
[JS]   +0x1f8: 0x18229297330   [other]
[JS]   +0x200: 0x1   [other]
[JS]   +0x208: 0x7fffe2b19f60   challenge.dll+0x49f60   bytes=[0d 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x218: 0x1822929cd88   [other]
[JS]   +0x220: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x228: 0x8   [other]
[JS]   +0x240: 0xffffffff   [other]
[JS]   +0x248: 0x182292539f0   [other]
[JS]   +0x260: 0x18228ff0ec0   [other]
[JS]   +0x268: 0x18228f8d4c0   [other]
[JS]   +0x278: 0x1822929cd40   [other]
[JS]   +0x280: 0x18229253ab0   [other]
[JS]   +0x288: 0x1000000000000   [other]
[JS]   +0x298: 0x30   [other]
[JS]   +0x2a0: 0x7fffe2b20921   challenge.dll+0x50921   bytes=[63 6f 6f 6f 6f 6f 00 5f]   ★ [data]
[JS]   +0x2a8: 0x182292cb910   [other]
[JS]   +0x2f0: 0x1822927df20   [other]
[JS]   +0x2f8: 0x1822926ef50   [other]
[JS]   → 8 个 challenge.dll 指针
[JS]   → 推荐 m_impl:
[JS]       challenge.dll+0x5570  = IDA 0x3530C5570
[JS]       challenge.dll+0x8290  = IDA 0x3530C8290
[JS]       challenge.dll+0x5f70  = IDA 0x3530C5f70
[JS]       challenge.dll+0x8290  = IDA 0x3530C8290
[JS]
========== [main] ==========
[JS]   obj @ 0x1822929cc40  type = compiled_function
[JS]   challenge.dll @ 0x7fffe2ad0000  size=0x49b000  (range 0x7fffe2ad0000 .. 0x7fffe2f6b000)
[JS]   python312.dll @ 0x7fffdfa20000  size=0x6b4000
[JS]   +0x000: 0x3   [other]
[JS]   +0x008: 0x7fffe2b19a80   challenge.dll+0x49a80   bytes=[21 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x018: 0x7fffdff4c300   [python312.dll+0x52c300]
[JS]   +0x020: 0x18228ff4180   [other]
[JS]   +0x030: 0x18229253bb0   [other]
[JS]   +0x050: 0x1   [other]
[JS]   +0x058: 0xffffffffffffffff   [other]
[JS]   +0x060: 0xffffffffffffffff   [other]
[JS]   +0x070: 0x182292c9438   [other]
[JS]   +0x078: 0x7fffe2ad5f70   challenge.dll+0x5f70   bytes=[41 56 41 55 41 54 55 57]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x080: 0x7fffe2ad8290   challenge.dll+0x8290   bytes=[41 54 55 57 56 53 48 83]  ★★★ [FUNC?]  ← 可能是 m_impl
[JS]   +0x098: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x0b8: 0x7fffdff4c300   [python312.dll+0x52c300]
[JS]   +0x0c0: 0x7fffe005e6b8   [python312.dll+0x63e6b8]
[JS]   +0x0d0: 0x2   [other]
[JS]   +0x0f0: 0x1822927de30   [other]
[JS]   +0x0f8: 0x18229297330   [other]
[JS]   +0x100: 0x1   [other]
[JS]   +0x108: 0x7fffe2b19f60   challenge.dll+0x49f60   bytes=[0d 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x118: 0x1822929cd88   [other]
[JS]   +0x120: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x128: 0x8   [other]
[JS]   +0x140: 0xffffffff   [other]
[JS]   +0x148: 0x182292539f0   [other]
[JS]   +0x160: 0x18228ff0ec0   [other]
[JS]   +0x168: 0x18228f8d4c0   [other]
[JS]   +0x178: 0x1822929cd40   [other]
[JS]   +0x180: 0x18229253ab0   [other]
[JS]   +0x188: 0x1000000000000   [other]
[JS]   +0x198: 0x30   [other]
[JS]   +0x1a0: 0x7fffe2b20921   challenge.dll+0x50921   bytes=[63 6f 6f 6f 6f 6f 00 5f]   ★ [data]
[JS]   +0x1a8: 0x182292cb910   [other]
[JS]   +0x1f0: 0x1822927df20   [other]
[JS]   +0x1f8: 0x1822926ef50   [other]
[JS]   +0x200: 0x1   [other]
[JS]   +0x208: 0x7fffe2b19f60   challenge.dll+0x49f60   bytes=[0d 00 00 00 00 00 00 00]   ★ [data]
[JS]   +0x218: 0x1822929ce88   [other]
[JS]   +0x220: 0x7fffdff8a600   [python312.dll+0x56a600]
[JS]   +0x228: 0x8   [other]
[JS]   +0x240: 0xffffffff   [other]
[JS]   +0x248: 0x182292539f0   [other]
[JS]   +0x260: 0x18228ff0ec0   [other]
[JS]   +0x268: 0x18228f8d4c0   [other]
[JS]   +0x278: 0x1822929ce40   [other]
[JS]   +0x280: 0x18229253ab0   [other]
[JS]   +0x288: 0x1000000000000   [other]
[JS]   +0x298: 0x30   [other]
[JS]   +0x2a0: 0x7fffe2b20921   challenge.dll+0x50921   bytes=[63 6f 6f 6f 6f 6f 00 5f]   ★ [data]
[JS]   +0x2a8: 0x182292cb940   [other]
[JS]   +0x2f0: 0x1822927e010   [other]
[JS]   +0x2f8: 0x182292cbab0   [other]
[JS]   → 7 个 challenge.dll 指针
[JS]   → 推荐 m_impl:
[JS]       challenge.dll+0x5f70  = IDA 0x3530C5f70
[JS]       challenge.dll+0x8290  = IDA 0x3530C8290
[JS]
================ 汇总 ================
[JS] warehouse_transform  m_impl RVA = 0x83b0  →  IDA: 0x3530C83b0
[JS] check_flag           m_impl RVA = 0x5570  →  IDA: 0x3530C5570
[JS] main                 m_impl RVA = 0x5f70  →  IDA: 0x3530C5f70
[JS] =====================================
```

这里我们成功得到了函数的 rva，我们可以在脚本中直接加上 ida 中的 image base，方便后续的分析。

本来在这里应该结果已经很明朗了，分析加密逻辑即可，但是观察函数：

![](https://img.halfcity.top/2026/11/11/48f234c0f7316538b755e78b4c28478b.avif)

但是这里看到开头的一堆变量就已经吓哭了，翻到下面有1700 行，已经比 rust 还离谱了。

这里面由于 python 中一切皆对象的原因，每一个运算符都是一个对象的 call，而每个运算符之间还会有大量的调度逻辑。

这里我们碰到了之前一样的问题，没有东西辅助这里要分析会很麻烦，动态调试跟输入也许可以，但是调度的逻辑本身不会变少，我们依旧需要正确识别调度器并逐步找到真实的逻辑。

此时还有一条路，之前我们发现加密算法似乎很简单，那么我们可以尝试直接对加密函数进行黑盒分析。

#### 黑盒分析

通过之前的变量名分析我们可以猜测源码的结构：

```py
def warehouse_transform(data):
    ordered = ...           # 某种顺序化
    out = bytearray(24)     # 或 []
    prev = ...              # 初始值
    for i in range(24):
        value = data[?]     # 从 data 取值
        out[i] = f(value, prev)
        prev = out[i]       # 或 prev = value
    return bytes(out)
```

可以看到源程序这样时才能做到与名字自洽，同时我们从反编译的结果中也可以确认一下：

![](https://img.halfcity.top/2026/11/11/24489a2c6a813889ba57cee9f9093c68.avif)

![](https://img.halfcity.top/2026/11/11/c34d3f68a975766e61f8f5f319af9fd7.avif)

这里可以确认源码中一定存在字节转换和迭代的结构。

接下来我们需要使用数据集来调用这个加密函数来反证我们的猜测。

我们先定义几个基础设施：

```js
// ---- 构造 PyBytes 对象 ----
function makeBytes(u8) {
    var buf = Memory.alloc(u8.length || 1);
    for (var i = 0; i < u8.length; i++) buf.add(i).writeU8(u8[i]);
    return fnBytesNew(buf, u8.length);   // PyBytes_FromStringAndSize
}

// ---- 调用目标函数，返回 PyBytes 解析结果 ----
function callTransform(funcWT, u8) {
    var obj = makeBytes(u8);
    fnErrClear();
    var r = fnCallFn(funcWT, obj, ptr(0), ptr(0), ptr(0), ptr(0));
    if (!r || r.isNull()) { fnErrClear(); return null; }
    return getBytes(r);                  // PyBytes_AsStringAndSize 解析
}

// ---- 十六进制 -> Uint8Array ----
function hex2u8(hex) {
    var u8 = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length; i += 2)
        u8[i/2] = parseInt(hex.substr(i, 2), 16);
    return u8;
}
```

完整的测试脚本模版如下：

```js
// quick_diff.js
var DLL = "python312.dll";
var done = false;
var initialized = false;

function log(s) { try { send({ m: String(s) }); } catch (e) { } }

var fnIsInit, fnGILE, fnGILR, fnImportAdd, fnGetAttr, fnBytes, fnErrClear, fnCallFn, fnBytesNew;

function initFunctions(mod) {
    if (initialized) return true;
    function ex(n) { return mod.findExportByName(n); }
    var a = {
        IsInit: ex("Py_IsInitialized"), GILE: ex("PyGILState_Ensure"), GILR: ex("PyGILState_Release"),
        ImportAdd: ex("PyImport_AddModule"), GetAttr: ex("PyObject_GetAttrString"),
        Bytes: ex("PyBytes_AsStringAndSize"), BytesNew: ex("PyBytes_FromStringAndSize"),
        ErrClear: ex("PyErr_Clear"), CallFn: ex("PyObject_CallFunctionObjArgs"),
    };
    if (!a.IsInit || !a.GILE || !a.CallFn || !a.BytesNew) return false;
    fnIsInit = new NativeFunction(a.IsInit, "int", []);
    fnGILE = new NativeFunction(a.GILE, "int", []);
    fnGILR = new NativeFunction(a.GILR, "void", ["int"]);
    fnImportAdd = new NativeFunction(a.ImportAdd, "pointer", ["pointer"]);
    fnGetAttr = new NativeFunction(a.GetAttr, "pointer", ["pointer", "pointer"]);
    fnBytes = new NativeFunction(a.Bytes, "int", ["pointer", "pointer", "pointer"]);
    fnErrClear = new NativeFunction(a.ErrClear, "void", []);
    fnCallFn = new NativeFunction(a.CallFn, "pointer", ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer"]);
    fnBytesNew = new NativeFunction(a.BytesNew, "pointer", ["pointer", "int64"]);
    initialized = true;
    return true;
}

function safeAttr(o, n) {
    if (!o || o.isNull()) return null;
    var r = fnGetAttr(o, Memory.allocUtf8String(n));
    if (!r || r.isNull()) { fnErrClear(); return null; }
    return r;
}

function getBytes(o) {
    if (!o || o.isNull()) return null;
    var buf = Memory.alloc(8), len = Memory.alloc(8);
    if (fnBytes(o, buf, len) !== 0) { fnErrClear(); return null; }
    var p = buf.readPointer(), n = Number(len.readS64());
    if (!p || p.isNull() || n <= 0 || n > 0x100000) return null;
    var arr = new Uint8Array(p.readByteArray(n));
    var hex = "";
    for (var i = 0; i < n; i++) hex += ("0" + arr[i].toString(16)).slice(-2);
    return { bytes: arr, len: n, hex: hex };
}

function makeBytes(u8) {
    var buf = Memory.alloc(u8.length);
    for (var i = 0; i < u8.length; i++) buf.add(i).writeU8(u8[i]);
    return fnBytesNew(buf, u8.length);
}

function callTransform(func, u8) {
    var obj = makeBytes(u8);
    fnErrClear();
    var r = fnCallFn(func, obj, ptr(0), ptr(0), ptr(0), ptr(0));
    if (!r || r.isNull()) { fnErrClear(); return null; }
    return getBytes(r);
}

function tryInstall() {
    if (done) return;
    var mod = Process.findModuleByName(DLL);
    if (!mod || !initFunctions(mod) || fnIsInit() === 0) return;

    var gil = fnGILE();
    try {
        var mainMod = fnImportAdd(Memory.allocUtf8String("__main__"));
        if (!mainMod || mainMod.isNull()) { fnErrClear(); return; }
        
        var funcWT = safeAttr(mainMod, "warehouse_transform");
        var targetObj = safeAttr(mainMod, "TARGET");
        var keyObj    = safeAttr(mainMod, "KEY");
        
        if (!funcWT || !targetObj) return;
        done = true;

        var target = getBytes(targetObj);
        log("TARGET = " + target.hex);
		
        // ...

    } catch (e) {
        log("error: " + e);
    } finally {
        fnGILR(gil);
    }
}

setInterval(tryInstall, 300);
```

后续将只展示填入模版中的测试内容。

然后我们开始对函数的签名进行探测：

```js
// A1: 参数 —— 期望 TypeError
var r = fnCallFn(funcWT, targetObj, keyObj, ptr(0), ptr(0), ptr(0));
// -> NULL (TypeError: takes 1 positional argument but 2 were given)

// A2: 单参数 TARGET 返回值
var r = fnCallFn(funcWT, targetObj, ptr(0), ptr(0), ptr(0), ptr(0));
var b = getBytes(r);
log("transform(TARGET) = " + (b ? b.hex : "NULL"));
// -> 7c53a1a8... 24 字节，不可打印

// A3: 8 字节输入 —— 期望 IndexError
var shortObj = makeBytes(new Uint8Array(8));
fnCallFn(funcWT, shortObj, ptr(0), ptr(0), ptr(0), ptr(0));
// -> NULL (IndexError: index out of range)

// A4: 32 字节输入 —— 验证取值逻辑
var longObj = makeBytes(new Uint8Array(32));
var r = fnCallFn(funcWT, longObj, ptr(0), ptr(0), ptr(0), ptr(0));
// -> 与 transform(24 zeros) 相同

// A6: check_flag 对照
var testObj = fnFromStr(Memory.allocUtf8String("test"));
var r = fnCallFn(funcCF, testObj, ptr(0), ptr(0), ptr(0), ptr(0));
log("check_flag('test') = " + Number(fnLong(r)));  // -> 0 (False)
```

此时我们基本可以确定这个函数要求传入 24 字节同时会返回 24 字节。

这是一个流式加密。

随后我们进行线性探测：

```js
// B1: 基准 —— 全零
var zerosU8 = new Uint8Array(24);
var zerosOut = callTransform(funcWT, zerosU8);
log("zeros = " + zerosOut.hex);   // b5e94fb4ff64ddfe...

// B3: 顺序字节 0..23
var seq = new Uint8Array(24);
for (var i = 0; i < 24; i++) seq[i] = i;
var seqOut = callTransform(funcWT, seq);

// B4: 只改 data[0] = 1
var onlyFirst = new Uint8Array(24); onlyFirst[0] = 1;
var r = callTransform(funcWT, onlyFirst);
// 与 zerosOut 做差分 -> 24 个字节全部 -1

// B5: 只改 data[23] = 1
var onlyLast = new Uint8Array(24); onlyLast[23] = 1;
var r = callTransform(funcWT, onlyLast);
// 与 zerosOut 做差分 -> 只有最后 1 字节 -1

// B6: 顺序敏感测试
var ab = new Uint8Array(24); ab[0]=1; ab[1]=2;
var ba = new Uint8Array(24); ba[0]=2; ba[1]=1;
var rAb = callTransform(funcWT, ab);
var rBa = callTransform(funcWT, ba);
// 前几字节不同 -> 无排序

// B7: 对合性测试
var r1 = callTransform(funcWT, targetB.bytes);       // transform(TARGET)
var r2 = callTransform(funcWT, r1.bytes);            // transform(transform(TARGET))
log("== TARGET ? " + (r2.hex === targetB.hex));      // -> false
```

随后进行精确扫描。

先确定单字节差异：

```js
for (var i = 0; i < 24; i++) {
    var d = new Uint8Array(24);
    d[i] = 1;
    var r = callTransform(funcWT, d);
    if (!r) { log("only[" + i + "] -> NULL"); continue; }
    var diff = [];
    for (var j = 0; j < 24; j++) {
        var delta = (r.bytes[j] - zerosOut.bytes[j]) & 0xff;
        diff.push(delta.toString(16).padStart(2, '0'));
    }
    log("only[" + i + "] = 1  delta = " + diff.join(' '));
}
```

输出：`S(i) = 4*(i%6) + i//6` 的排列 + `s(i)` 的符号（`ff` 表示 `-1`，`01` 表示 `+1`）

随后是累加：

```js
for (var k = 0; k < 24; k++) {
    var d = new Uint8Array(24);
    for (var j = 0; j <= k; j++) d[j] = 1;
    var r = callTransform(funcWT, d);
    if (!r) continue;
    var diff = [];
    for (var j = 0; j < 24; j++) {
        var delta = (r.bytes[j] - zerosOut.bytes[j]) & 0xff;
        diff.push(delta.toString(16).padStart(2, '0'));
    }
    log("data[0.." + k + "] = 1  delta = " + diff.join(' '));
}
```

输出：交叉验证 C1 的排列和符号；`k ≥ 6` 后差分出现 `+1` 和跳变，确认 `s(i)` 的符号交替。

参考如下条件：

- `only[0]=1` 全 `-1` ⇒ `s(0) = -1`，`prev -= data[0]`
- `only[6]=1` 从第 1 位起 `+1` ⇒ `s(6) = +1`，`prev += data[6]`
- `KEY` 参与解释了为什么 `transform(zeros)` 非零且单调递增

此时我们可以得出一个第一版的模型：

```py
prev = IV
for j in range(24):
    i = PERM[j]
    prev = (prev + s(i) * data[i] + KEY[j % 8]) & 0xFF
    out[j] = prev
```

关于 `KEY` 的初始推断:

对 `transform(zeros)` 做差分：

```txt
b5 e9 4f b4 ff 64 dd fe ...
  └─+34─┘
e9 - b5 = 0x34
4f - e9 = 0x66
b4 - 4f = 0x65
ff - b4 = 0x4b
64 - ff = 0x65  (mod 256)
dd - 64 = 0x79
fe - dd = 0x21
```

得到 **`KEY = b"s4feKey!"`**，这是从 `zeros` 输出的相邻差分直接反推的（假设 `KEY[i]` 是加性贡献）。

`IV` 从 `transform(zeros)[0] - KEY[0] = 0xb5 - 0x73 = 0x42` 得到。

这时模型自洽所有观测都被解释。

但是使用模型逆推 TARGET：

```py
def inverse_v1(target):
    data = [0] * 24
    prev = IV
    for j in range(24):
        i = PERM[j]
        # target[j] = (prev + s(i)*data[i] + KEY[j%8]) & 0xFF
        # => s(i)*data[i] = target[j] - prev - KEY[j%8]
        # 由于 s(i) ∈ {+1,-1}，除以 s(i) 等于乘 s(i)
        data[i] = ((target[j] - prev - KEY[j%8]) * s(i)) & 0xFF
        prev = target[j]
    return bytes(data)
```

输出: `b'l)V\x19G\x13!b\x1d+(Y\x9c]\xafS\x9eic\xa3S\xd3N\xd7'`

用模型反向验证：`transform(inverse(TARGET)) == TARGET`？

python

```
flag = inverse_v1(TARGET)
check = transform_v1(flag)
assert check == TARGET   # ❌ 失败
```



**模型不闭环**。这不是"逆推算错了"，而是**正向/反向用的是同一个错误模型，却算不出同一个结果**——说明模型的运算本身错了，不是数值精度问题。

这个信号非常强：

- 如果只是某个常量写错（比如 `KEY[3]` 错一个字节），`inverse` 和 `transform` 可能还是**同一对互逆**函数，`transform(inverse(T)) == T` 会成立（但 `inverse(T)` 不是真 flag）。
- 现在是 `transform(inverse(T)) != T`，说明 **`inverse` 不是 `transform` 的逆函数**——模型层面错了。

2.3 排查方向

要修正模型，必须找一个**新的观测点**。已有的数据（`zeros`、`only[i]=1`、累加）都被旧模型"解释"了，但**只是解释，不是唯一解释**。

关键洞察：**`s(i) = ±1` 的差分模式，对"加法"和"XOR"是兼容的**。

具体地，如果运算是 `prev + (KEY ^ data)`：

- `data[i] = 0` 时：`KEY ^ 0 = KEY`
- `data[i] = 1` 时：`KEY ^ 1 = KEY - 1`（如果 `KEY` 最低位是 1）或 `KEY + 1`（如果 `KEY` 最低位是 0）

对照 `KEY = b"s4feKey!"`：

- `KEY[0] = 0x73`（最低位 1）→ `KEY ^ 1 = 0x72 = KEY - 1` → **输出 -1** ✓
- `KEY[6] = 0x79`（最低位 1）→ `KEY ^ 1 = 0x78 = KEY - 1` → **输出 -1** ✗

等等，`only[6]=1` 的差分是 `+1`，而 `KEY[6] = 0x79` 最低位是 1，`XOR 1` 应该 -1。**这里矛盾了！**

说明 `PERM` 和 `s(i)` 的对应关系需要重新审视。或者 `s(i)` 不是单纯的符号，而是 `XOR` 的特殊结果。

------

三、重新审视：`s(i)` 到底是什么

回看 C1 的数据：

text

```
i=0:  ff ff ff ... ff          → s(0) = -1, 影响 j ∈ [0, 23]
i=1:  00 00 00 00 ff ff ...    → s(1) = -1, 影响 j ∈ [4, 23]
i=2:  00×8  ff×16              → s(2) = -1, 影响 j ∈ [8, 23]
i=3:  00×12 ff×12              → s(3) = -1, 影响 j ∈ [12, 23]
i=4:  00×16 ff×8               → s(4) = -1, 影响 j ∈ [16, 23]
i=5:  00×20 ff×4               → s(5) = -1, 影响 j ∈ [20, 23]
i=6:  00 01 01 01 ... 01       → s(6) = +1, 影响 j ∈ [1, 23]
i=7:  00×5 ff×19               → s(7) = -1, 影响 j ∈ [5, 23]
i=8:  00×9 01×15               → s(8) = +1, 影响 j ∈ [9, 23]
i=9:  00×13 ff×11              → s(9) = -1, 影响 j ∈ [13, 23]
i=10: 00×17 01×7               → s(10) = +1, 影响 j ∈ [17, 23]
i=11: 00×21 ff×3               → s(11) = -1, 影响 j ∈ [21, 23]
i=12: 00 00 01 01 ...          → s(12) = +1, 影响 j ∈ [2, 23]
...
```



**问题**：`only[i]=1` 的差分，是 `+1` 还是 `-1`，取决于**变换当时的 `KEY[j%8]` 的最低位**，不取决于 `i` 本身。

如果模型是 `prev += KEY[j%8] ^ data[PERM[j]]`：

text

```
data[PERM[j]] = 1 时，增量 = KEY[j%8] ^ 1 - KEY[j%8]
               = (最低位为 1 时) -1
               = (最低位为 0 时) +1
```



**逐位置 `j` 验证**（关键一步）：

`KEY = b"s4feKey!"`，二进制最低位：

- `KEY[0] = 0x73` → 1 → `XOR 1` 使 -1
- `KEY[1] = 0x34` → 0 → `XOR 1` 使 +1
- `KEY[2] = 0x66` → 0 → `XOR 1` 使 +1
- `KEY[3] = 0x65` → 1 → `XOR 1` 使 -1
- `KEY[4] = 0x4b` → 1 → `XOR 1` 使 -1
- `KEY[5] = 0x65` → 1 → `XOR 1` 使 -1
- `KEY[6] = 0x79` → 1 → `XOR 1` 使 -1
- `KEY[7] = 0x21` → 1 → `XOR 1` 使 -1

理论上 `only[6]=1` 应该让 `j ∈ [1, 23]` 全部 `-1`（因为 `KEY[1..7]` 只有少数几个最低位是 0）。但**实测是 `+1`**，和 `KEY[6]=0x79`（最低位 1 → 应该 -1）矛盾。

**说明 `XOR` 的假设也有问题**——或者 `s(i)` 和 `KEY[j%8]` 的对应关系不是"按 `j` 查 `KEY[j%8]`"。

------

四、决定性验证：从 `transform(TARGET)[0]` 反推

不再纠结理论，直接用**已知输入输出对**做实验：

```
KEY        = b"s4feKey!"         （从 transform(zeros) 差分反推）
IV         = 0x42                 （从 transform(zeros)[0] - KEY[0]）
TARGET[0]  = 0x49
TARGET[1]  = 0x9e
TARGET[2]  = 0xa0
transform(TARGET)[0] = 0x7c
transform(TARGET)[1] = 0x53
```

手算三种候选：

`j = 0`，`PERM[0] = 0`，`data[0] = TARGET[0] = 0x49`，`KEY[0] = 0x73`：

| 运算                      | 计算                                        | 结果       | 是否等于 0x7c |
| :------------------------ | :------------------------------------------ | :--------- | :------------ |
| `prev + data`             | `0x42 + 0x49 = 0x8b`                        | `0x8b`     | ❌             |
| `prev - data`             | `0x42 - 0x49 = 0xf9`                        | `0xf9`     | ❌             |
| `prev + (KEY + data)`     | `0x42 + 0x73 + 0x49 = 0xfe`                 | `0xfe`     | ❌             |
| **`prev + (KEY ^ data)`** | `0x42 + (0x73 ^ 0x49) = 0x42 + 0x3a = 0x7c` | **`0x7c`** | **✓**         |

**`KEY ^ data` 命中。**

第二位交叉验证：

`j = 1`，`PERM[1] = 6`，`data[6] = TARGET[6] = 0x28`，`KEY[1] = 0x34`：

```
prev = 0x7c
0x7c + (0x34 ^ 0x28) = 0x7c + 0x1c = 0x98
```

**实测 `transform(TARGET)[1] = 0x53`，不匹配！**

`0x98 ≠ 0x53`。所以 `j=1` 的模型也错了——`PERM[1]` 可能不是 6。

回看 `transform(TARGET)` 完整输出：

```
7c 53 a1 a8 7d 81 9c f4 c7 11 ff d3 bc 66 15 b1 68 38 9c 44 d0 63 8a c0
```

逐位反推 `data[PERM[j]]`：

```
j=0: delta = 0x7c - 0x42 = 0x3a;  KEY[0]=0x73;  data[PERM[0]] = 0x73 ^ 0x3a = 0x49  ✓ TARGET[0]
j=1: delta = 0x53 - 0x7c = 0xd7;  KEY[1]=0x34;  data[PERM[1]] = 0x34 ^ 0xd7 = 0xe3  ✓ TARGET[1]
j=2: delta = 0xa1 - 0x53 = 0x4e;  KEY[2]=0x66;  data[PERM[2]] = 0x66 ^ 0x4e = 0x28  ✓ TARGET[2]
...
```

**说明 `PERM[j] = j`**（顺序映射），不是 `[0,6,12,18,...]`！

那 `s(i)` 和 `PERM` 从哪来的？

`only[i]=1` 的差分模式（阶梯式影响）不是来自 `PERM`，而是来自**累加链本身**：

```
prev = IV
for j in 0..23:
    prev = (prev + (KEY[j%8] ^ data[j])) & 0xFF   ← 注意是 data[j] 不是 data[PERM[j]]
    out[j] = prev
```

- 改 `data[0]`：影响 `out[0], out[1], ..., out[23]` 全部 → **全 -1** ✓
- 改 `data[1]`：`out[0]` 不受影响（`j=0` 时用 `data[0]`），`out[1..23]` 受影响 → **从第 1 位起** ✓
- 改 `data[2]`：**从第 2 位起** ✓

**但实测 `only[1]=1` 是"从第 4 位起"、`only[2]=1` 是"从第 8 位起"**——这不是 `j` 的阶梯，而是**每 4 字节取一次 `data[i//4]`**！

所以真实结构是：

```
for j in 0..23:
    i = j // 4          ← 每 4 个输出位置用同一个输入字节
    prev = (prev + (KEY[j%8] ^ data[i])) & 0xFF
    out[j] = prev
```

验证 `only[1]=1`（`data[1]=1`，影响 `i=1`，即 `j ∈ {4,5,6,7}` 起）：

- `j=0,1,2,3` 时 `i=0`，`data[0]=0`，无影响 → 前 4 字节不变 ✓
- `j=4..23` 时 `i ∈ {1,2,3,4,5}`，`data[1]=1` 影响 `i=1` 的 `j ∈ {4,5,6,7}`，但**之后 `i=2` 时 `data[1]` 不再参与**——**理论上 `only[1]=1` 应该只影响 `j ∈ {4,5,6,7}`，即 4 个字节**

但实测 `only[1]=1` 影响 `j ∈ [4, 23]` 共 20 个字节。**累加链让影响向后传播**：`out[4]` 变了，`out[5]` 依赖 `out[4]`，`out[6]` 依赖 `out[5]`……所以 `data[1]=1` 的扰动通过 `prev` 一路传到 `out[23]`。

**这解释了阶梯模式**：

- `data[i]` 在 `j = 4i` 处首次参与
- 之后通过 `prev` 链向后传播到 `j = 23`
- 所以 `data[i]=1` 影响 `j ∈ [4i, 23]`

**这就是 `S(i) = 4i`**，而不是 `4*(i%6) + i//6`。

再验证 `only[6]=1`（`data[6]=1`，首次参与 `j = 4*6 = 24`，**超出范围**）：

- 但实测 `only[6]=1` 影响 `j ∈ [1, 23]`，且是 `+1`！

**矛盾**——`i=6` 的 `4i=24` 超出 24，不应该被用到。说明 `i = j // 4` 不对。

回看 `only[i]=1` 的完整影响范围（`S(i)` = 首次影响位置）：

| `i`  | `S(i)` | `s(i)` 符号 |
| :--- | :----- | :---------- |
| 0    | 0      | -1          |
| 1    | 4      | -1          |
| 2    | 8      | -1          |
| 3    | 12     | -1          |
| 4    | 16     | -1          |
| 5    | 20     | -1          |
| 6    | **1**  | **+1**      |
| 7    | **5**  | -1          |
| 8    | **9**  | **+1**      |
| 9    | **13** | -1          |
| 10   | **17** | **+1**      |
| 11   | **21** | -1          |
| 12   | **2**  | **+1**      |
| 13   | **6**  | -1          |
| 14   | **10** | **+1**      |
| 15   | **14** | -1          |
| 16   | **18** | **+1**      |
| 17   | **22** | -1          |
| 18   | **3**  | -1          |
| 19   | **7**  | -1          |
| 20   | **11** | -1          |
| 21   | **15** | -1          |
| 22   | **19** | -1          |
| 23   | **23** | -1          |

**规律非常清晰**：

- `S(i) = 4*(i % 6) + (i // 6)`
- `s(i) = +1` 当 `i ∈ {6, 8, 10, 12, 14, 16}`，否则 `-1`

这是**两个不同维度的混合**：

- `i % 6` 决定"哪一组"（每组 4 个连续位置）
- `i // 6` 决定"组内偏移"（0..3，因为 24/6=4）

**为什么是 6 和 4？** 因为 24 = 6×4。`data` 被拆成 6 组、每组 4 个元素，但**读写顺序不同**：

- 读：`data[i]` 按 `i = 0..23` 顺序
- 写：`out[j]` 按 `S(i)` 的位置

这是个**转置**操作：`data` 按 `6×4` 矩阵行优先读，`out` 按 `4×6` 矩阵行优先写（等价于按 `6×4` 矩阵列优先写）。

5.1 用新结构重新验证

```
prev = IV
for j in 0..23:
    i = PERM[j]                  ← PERM[j] = 满足 S(i)=j 的 i
    prev = (prev + (KEY[j%8] ^ data[i])) & 0xFF
    out[j] = prev
```

其中 `PERM = [0, 6, 12, 18, 1, 7, 13, 19, 2, 8, 14, 20, 3, 9, 15, 21, 4, 10, 16, 22, 5, 11, 17, 23]`。

**这次 `PERM` 和 `S(i)` 是互逆的**：

- `S(0) = 0` → `PERM[0] = 0` ✓
- `S(6) = 1` → `PERM[1] = 6` ✓
- `S(12) = 2` → `PERM[2] = 12` ✓
- …

关于 `s(i)` 符号：

`only[i]=1` 的 `±1` 符号是 `KEY[j%8] ^ 1 - KEY[j%8]` 的结果：

- `j = S(i)` 是 `data[i]` 首次参与的位置
- 首次参与时，`delta = KEY[S(i) % 8] ^ 1 - KEY[S(i) % 8]`
- 如果 `KEY[S(i) % 8]` 最低位是 1 → `delta = -1` → 差分 `ff`
- 如果最低位是 0 → `delta = +1` → 差分 `01`

验证 `i=6`：`S(6) = 1`，`KEY[1] = 0x34`（最低位 0）→ `delta = +1` ✓
验证 `i=8`：`S(8) = 9`，`KEY[9%8] = KEY[1] = 0x34`（最低位 0）→ `delta = +1` ✓
验证 `i=12`：`S(12) = 2`，`KEY[2] = 0x66`（最低位 0）→ `delta = +1` ✓
验证 `i=0`：`S(0) = 0`，`KEY[0] = 0x73`（最低位 1）→ `delta = -1` ✓

**`s(i)` 完全不需要单独建模——它是 `KEY` 最低位 + `S(i) % 8` 的自动结果。**

```
// 已知 KEY[0] = 0x73, TARGET[0] = 0x49
// 已知 transform(TARGET)[0] = 0x7c
// 已知 IV = 0x42

// 手算验证 3 种候选：
//   + : 0x42 + (0x73 + 0x49) = 0xfe   ✗
//   ^ : 0x42 + (0x73 ^ 0x49) = 0x7c   ✓
//   - : 0x42 + (0x73 - 0x49) = 0x6c   ✗

// 在 Frida 里验证第二个字节：
//   transform(TARGET)[1] = 0x53
//   0x7c + (0x34 ^ 0xe3) = 0x7c + 0xd7 = 0x53   ✓
```

解密脚本如下：

```py
import sys

KEY = b"s4feKey!"
IV  = 0x42

PERM = [0, 6, 12, 18, 1, 7, 13, 19, 2, 8, 14, 20,
        3, 9, 15, 21, 4, 10, 16, 22, 5, 11, 17, 23]

TARGET_HEX = "499ea0a2c4c7e3617ecfe4f6286288d6025e6279b1bdcd17"
TARGET = bytes.fromhex(TARGET_HEX)


# def warehouse_transform(data: bytes) -> bytes:
#     if len(data) < 24:
#         raise ValueError(f"input too short: {len(data)} < 24")
#     out = bytearray(24)
#     prev = IV
#     for j in range(24):
#         prev = (prev + (KEY[j % 8] ^ data[PERM[j]])) & 0xFF
#         out[j] = prev
#     return bytes(out)


def warehouse_inverse(target: bytes) -> bytes:
    data = [0] * 24
    prev = IV
    for j in range(24):
        delta = (target[j] - prev) & 0xFF
        data[PERM[j]] = KEY[j % 8] ^ delta
        prev = target[j]
    return bytes(data)


def main():
    print(f"KEY      = {KEY!r}")
    print(f"IV       = 0x{IV:02x}")
    print(f"TARGET   = {TARGET.hex()}")

    flag = warehouse_inverse(TARGET)
    print("FLAG     = flag{" + flag.decode() + "}")


if __name__ == "__main__":
    sys.exit(main())

```

输出如下：

```txt
> python decrypt.py
KEY      = b's4feKey!'
IV       = 0x42
TARGET   = 499ea0a2c4c7e3617ecfe4f6286288d6025e6279b1bdcd17
FLAG     = flag{tiny_safe_hides_big_work}
```

我们来验证一下：

```txt
> challenge
Confidential cargo handoff: flag{tiny_safe_hides_big_work}
Handoff complete. Ten-second exit plan finally resumed.
```

```txt
flag{tiny_safe_hides_big_work}
```

