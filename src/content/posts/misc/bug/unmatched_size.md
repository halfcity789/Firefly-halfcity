---
title: oqs-sys库报错 error[E0080] attempt to compute 1_usize - 88_usize, which would overflow
description: error[E0080] attempt to compute 1_usize - 88_usize, which would overflow 在编译oqs-sys绑定库时报错,这里进行修复
published: 2026-07-05
category: 问题解决
tags: [OQS, rust]
pinned: false
draft: false
---

## 问题

```bash
error[E0080]: attempt to compute 1_usize - 88_usize, which would overflow                                                                                                                             
   --> D:\data\code\projects\daylight\daylight\target\debug\build\oqs-sys-2ebad065277a14bf\out/sig_bindings.rs:244:25
    |
244 |     ["Size of OQS_SIG"][::core::mem::size_of::<OQS_SIG>() - 88usize];
    |                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ evaluation of sig::_ failed here
For more information about this error, try rustc --explain E0080.                                                                                                                                     
error: could not compile oqs-sys (lib) due to 1 previous error
```

## 解决

OQS的版本太新了

```diff
- oqs = "0.11.0"
+ oqs = "0.9.0"
```

## 附

就说怎么总感觉不对，一看这oqs版本怎么变了啊。