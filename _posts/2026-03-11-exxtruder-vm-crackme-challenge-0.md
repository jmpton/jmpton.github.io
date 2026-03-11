---
title: Exxtruder's VM Crackme Challenge 0
categories: [writeups]
---

# Introduction:  Exxtruder's VM

* **Tools:** Ghidra 12.0.3
* **Crackme**: Get it [here](https://crackmes.one/crackme/692ca13c2d267f28f69b8224) (or [here](/assets/writeups/exxtruder-vm0/692ca13c2d267f28f69b8224.zip)); password should be `crackmes.one` or `crackmes.de`.
* **Solution:** [keygen](/assets/writeups/exxtruder-vm0/crackmevm0_keygen.py) and [disassembler](/assets/writeups/exxtruder-vm0/crackmevm0_disassembler.zip)

## Description

> "First stage of the VM Crackme challenge.
A very simple custom virtual machine, without obfuscation or encryption. The file deliberately contains extra compiler/linker information to make the task easier.
Task: Generate a Name/Serial pair. The verification algorithm is very simple. Patching is not allowed."

## How I solved it

I wanted to improve my skills with Ghidra and experiment a little bit with PyGhidra. As stated by the author of the challenge, the VM is deliberately simple and easy to understand, hence making it a good target to discover Ghidra's API and automate things a bit (by the way, I put my notes on PyGhidra [here](/categories/pyghidra/)). I followed these steps:

* Locate the bytecode
* Understand the format of instructions
* Write a disassembler
* Read the disassembled bytecode to understand the verification algorithm
* Write a keygen

# Analysis

## Locating the bytecode

Function `main` initialize 0x100 bytes to `\x00` on the stack:

```
140002baf 48 8d 55 a0           LEA         RDX=>local_128,[RBP + -0x60]; stack
140002bb3 b8 00 00 00 00        MOV         EAX,0x0   ; value to write
140002bb8 b9 20 00 00 00        MOV         ECX,0x20  ; count
140002bbd 48 89 d7              MOV         RDI,RDX   ; dest
140002bc0 f3 48 ab              STOSQ.REP   RDI       ; 0x20*8 = 0x100 bytes
```

Instruction `STOSQ` stores the value of `RAX` at the address pointed by `RDI` and increase `RDI` by `8`. I would have expected to see `MOV RAX, 0` instead of `MOV EAX, 0`; however, after checking with a debugger, the `MOV EAX, 0` instruction also sets the higher part of this register to `0`. 

Then, the bytecode is copied to this buffer:

```
140002be3 48 8d 15 16 14 00 00  LEA     RDX,[bytecode] ; source
140002bea 48 8d 45 a0           LEA     RAX=>local_128,[RBP + -0x60]; stack
140002bee 49 89 c8              MOV     R8,RCX; size
140002bf1 48 89 c1              MOV     RCX,RAX; dest
140002bf4 e8 9f 12 00 00        CALL    memcpy
```

There is also a size check to ensure no more than 0x100 bytes are copied (not shown here).

After that, the VM is called:

```
140002bf9 48 8d 45 a0           LEA     RAX=>local_128,[RBP + -0x60]
140002bfd ba 00 00 00 00        MOV     EDX,0x0 ; unused
140002c02 48 89 c1              MOV     RCX,RAX ; (copy of) bytecode
140002c05 e8 b9 ea ff ff        CALL    run_vm
```

## The VM

The VM is quite a lengthy function iterating over the bytecode and jumping to the appropriate virtual instruction handler. Among the things done when entering this function, we notice a local variable initialized to `0`, updated here and there during execution of the VM, and used as an index into the bytecode. I assumed it was the virtual program counter:

```
1400016ef c6 85 2f 01 00 00 00  MOV     byte ptr [RBP + pc],0x0 ; virtual EIP
...
14000170a 0f b6 85 2f 01 00 00  MOVZX   EAX,byte ptr [RBP + pc]
...
14000171d 48 8b 95 40 01 00 00  MOV     RDX,qword ptr [RBP + bytecode_]
140001724 48 01 d0              ADD     RAX,RDX
140001727 0f b6 00              MOVZX   EAX,byte ptr [RAX] ; opcode = bytecode[pc]
14000172a 88 85 fe 00 00 00     MOV     byte ptr [RBP + opc],AL
```

The second thing we notice is a call to a function named `get_info()`; it takes a single parameter, which is a byte from the bytecode (a virtual opcode retrieved from `bytecode[pc]`):

```
140001730 0f b6 85 fe 00 00 00  MOVZX   EAX,byte ptr [RBP + opc]
140001737 89 c1                 MOV     ECX,EAX
140001739 e8 de fd ff ff        CALL    get_info
```

## The Structure "opcode\_table" (array of `insn_info`)

The function `get_info()` loops over an array (called `opcode_table`) of structures of lengh 0x20 bytes. It reads the first field of each structure and compare it with the opcode received from the caller:

```
140001529 48 8d 05 50 3b 00 00  LEA     RAX,[opcode_table]
140001530 48 89 45 f8           MOV     qword ptr [RBP + ptrOpcTable],RAX=>opcode_table
140001534 eb 19                 JMP     enter_loop
...
140001536 48 8b 45 f8           MOV     RAX,qword ptr [RBP + ptrOpcTable] ; array of struct
14000153a 8b 10                 MOV     EDX,dword ptr [RAX]=>opcode_table ; read dword
14000153c 0f b6 45 10           MOVZX   EAX,byte ptr [RBP + inByte]   ; opcode (extends to dword)
140001540 39 c2                 CMP     EDX,EAX
140001542 75 06                 JNZ     dont_match
```

If the value doesn't match, the pointer to the array is increased by 0x20 so the input opcode can be compared against the next structure:

```
    ; dont_match  
14000154a 48 83 45 f8 20    ADD         qword ptr [RBP + ptrOpcTable],offset opcode_table[1].opcode ; 0x20
```

If the value match however, the pointer to the matching structure is returned:

```
    ; match
140001544 48 8b 45 f8       MOV         RAX=>opcode_table,qword ptr [RBP + ptrOpcTable]
140001548 eb 17             JMP         exit
```

Let's go to the array `opcode_table` (start address: `0x140005080`). I created structure of length 0x20 named `insn_info`, without knowing all the types nor names of its fields (I just used `uint32_t` and `uint64_t` at first); then I create a second one right after the first, and after that I felt a little bit dumb, because I realized didn't know for how long I'd have to do that. So I scrolled through the data until I reached what looked like the end of the array (end address: `0x140005b80`). Having the start address, the end address, and the size of an entry, I could compute the number of entries:

```python
>>> (0x140005b80-0x140005080)//0x20
88
```

That's it, 88 entries. So, on label `opcode_table` I could apply the type `insn_info[88]` and got a nicely formatted array. After That, it was time to return to the caller, the function `vm_run()`.

Back to the function `vm_run()` I wandered more, but this time knowing that a structure `insn_info` is accessed by the VM. By looking at where and how this structure was accessed, I ended up with the following:

```c
struct insn_info {
    uint32_t opcode;
    uint8_t padding1[4];
    char *ptrMnemonic;
    uint32_t operand_count;
    uint32_t operand1_type;
    uint32_t operand2_type;
    uint8_t padding2[4];
};
```

* **opcode:** Opcode of the virtual instruction
* **ptrMnemonic:** The name of the virtual instruction; a huge helper
* **operand\_count:** The number of operands used by the instruction. Can be 0, 1 or 2
* **operandx\_type:** The type of operand 1 and 2: Can be 0, 1 or 2

The type of an operand defines how it is accessed (more on this in the next sections):
* **0:** operand is a value that can be read directly
* **1:** operand is a pointer
* **2:** operand is a pointer to a pointer

## Instruction Format

Virtual instructions can be 1, 2 or 3 bytes long:

* 1 byte: instruction doesn't have operand (with exception, see below)
* 2 bytes: instruction has one operand
* 3 bytes: instruction has two operands

Let's note that for some 1-byte virtual instructions (e.g.: `in` and `out`), the VM uses hardcoded operands and they won't appear in the bytecode. For example:

```
140002916 48 8b 85 40 01 00 00       MOV    RAX,qword ptr [RBP + bytecode_]
14000291d 0f b6 80 fd 00 00 00       MOVZX  EAX,byte ptr [RAX + 0xfd] ; 0xfd is hardcoded 
140002924 88 85 ee 00 00 00          MOV    byte ptr [RBP + max_input_len],AL
```

In the example above, the offset `0xfd` is hardcoded, but it could have been encoded as an operand of the virtual instruction.

Depending on the virtual instruction being executed, some value are read and other are written. Read and write are made by functions `read_operand()` and `write_operand()`, respectively. They have the following prototypes:

* `read_operand(uint8_t* pBytecode, uint32_t type, uint8_t operand, uint8_t* pOut)`
* `write_operand(uint8_t* pBytecode, uint32_t type, uint8_t operand, uint8_t input)`

### Reading values

The function `read_operand()` has the following prototype:

`read_operand(uint8_t* pBytecode, uint32_t type, uint8_t operand, uint8_t* pOut)`

It allows to retrieve a value from `operand` (3rd argument) and returns it in the buffer pointed to by `pOut` (4th argument). The way the value is retrieved depends on the parameter `type` (2nd argument). The 1st argument, `pBytecode`, always points to the begining of the bytecode.

* For type `0`, operand value is directly written to output:

```
140001586 48 8b 55 28       MOV     RDX,qword ptr [RBP + output_]
14000158a 0f b6 45 20       MOVZX   EAX,byte ptr [RBP + operand_] ; get value
14000158e 88 02             MOV     byte ptr [RDX],AL   ; save to output
```

* For type `1`, there is 1 level of indirection; thus, `operand` is a pointer:

```
; resolve pointer
1400015f6 0f b6 45 20       MOVZX   EAX,byte ptr [RBP + operand_]
1400015fa 48 8b 55 10       MOV     RDX,qword ptr [RBP + pBytecode]
1400015fe 48 01 d0          ADD     RAX,RDX ; pointer to value
; get value
140001601 0f b6 00          MOVZX   EAX,byte ptr [RAX] ; get value
140001604 48 8b 55 28       MOV     RDX,qword ptr [RBP + output_]
140001608 88 02             MOV     byte ptr [RDX],AL   ; save to output
``` 

* For type `2`, there is a second level of indirection: `operand` is a pointer to a pointer:

```
; resolve 1st pointer
1400015b6 0f b6 45 20       MOVZX   EAX,byte ptr [RBP + operand_]
1400015ba 48 8b 55 10       MOV     RDX,qword ptr [RBP + pBytecode]
1400015be 48 01 d0          ADD     RAX,RDX
1400015c1 0f b6 00          MOVZX   EAX,byte ptr [RAX] ; get 1st pointer
...
; resolve 2nd pointer
1400015e8 48 01 d0          ADD     RAX,RDX  ; 2nd pointer
; get value
1400015eb 0f b6 00          MOVZX   EAX,byte ptr [RAX] ; get value
1400015ee 48 8b 55 28       MOV     RDX,qword ptr [RBP + output_]
1400015f2 88 02             MOV     byte ptr [RDX],AL ; save to output
```

### Writing values

The function `write_operand()` has the following prototype:

`write_operand(uint8_t* pBytecode, uint32_t type, uint8_t operand, uint8_t input)`

Here, the value to write is given by `input` (4th argument). Where to write it depends on `type` and `operand` (2nd and 3rd arguments, respectively). And again, the 1st argument `pBytecode` still points to the beginning of the bytecode.

How types are checked in this case differs a little bit from the `read_function()`: here, it's either type `2` or "anything else". I'm not sure if there is any write operation involving a type `0` operand, but I put it here anyway.

* Type `0` or `1`: operand is a pointer:

```
; resolve pointer
1400016a7 0f b6 45 20       MOVZX   EAX,byte ptr [RBP + operand_]
1400016ab 48 8b 55 10       MOV     RDX,qword ptr [RBP + pBytecode_]
1400016af 48 01 c2          ADD     RDX,RAX ; pointer to dest
; write value
1400016b2 0f b6 45 28       MOVZX   EAX,byte ptr [RBP + input_]
1400016b6 88 02             MOV     byte ptr [RDX],AL ; write value to dest
```

* Type `2`: operand is a pointer to a pointer:

```
; resolve 1st pointer
140001651 0f b6 45 20       MOVZX   EAX,byte ptr [RBP + operand_]
140001655 48 8b 55 10       MOV     RDX,qword ptr [RBP + pBytecode_]
140001659 48 01 d0          ADD     RAX,RDX
14000165c 0f b6 00          MOVZX   EAX,byte ptr [RAX] ; get 1st pointer
...
; resolve 2nd pointer
140001683 48 01 c2          ADD     RDX,RAX ; 2nd pointer
; write value
140001686 0f b6 45 28       MOVZX   EAX,byte ptr [RBP + input_]
14000168a 88 02             MOV     byte ptr [RDX],AL ; write to dest
```

# Disassembled bytecode

I wrote a little disassembler to print virtual instructions into Ghidra's console output. It's available [here](/assets/writeups/exxtruder-vm0/crackmevm0_disassembler.zip). In order to execute it, unzip the archive to the folder of your choice and set the path to this folder in Ghidra's Script Manager (see [there](/posts/pyghidra-00-config/) for an example configuration). I put the full disassembly in appendix.

## Checking lengths

* Name length must be 10 chars
* Serial length must be 8 chars

```
; check lengths
0x22: 18 b9 0a | cmp [0xb9], 0xa	; compare length 1
0x25: 1e 6a    | jne 0x6a
0x27: 18 c3 08 | cmp [0xc3], 0x8	; compare length 2
0x2a: 1e 6a    | jne 0x6a
```

## Checking the serial

The name is put in uppercase (code not shown), and after that we get to the check. It is a serie of comparisons betwen chars at given offsets:

```
; offset 0x6a == bad boy bad boy what you gonna do
0x49: 19 af c1 | cmp [0xaf], [0xc1]	; name[1] == serial[7]
0x4c: 1e 6a    | jne 0x6a
0x4e: 19 b1 bc | cmp [0xb1], [0xbc] ; name[3] == serial[2]
0x51: 1e 6a    | jne 0x6a
0x53: 19 b0 bf | cmp [0xb0], [0xbf]	; name[2] == serial[5]
0x56: 1e 6a    | jne 0x6a
0x58: 19 b4 ba | cmp [0xb4], [0xba]	; name[6] == serial[0]
0x5b: 1e 6a    | jne 0x6a
0x5d: 19 b7 bd | cmp [0xb7], [0xbd]	; name[9] == serial[3]
0x60: 1e 6a    | jne 0x6a
```

A working example:
* name: ABCDEFGHIJ
* serial: GXDJXCXB

I also write a keygen, available [here](/assets/writeups/exxtruder-vm0/crackmevm0_keygen.py).

# Appendix: full dissassembly

```
; print("Enter name:")
0x00: 00 fc 72 | mov [0xfc], 0x72 ; offset to data
0x03: 00 fd 0b | mov [0xfd], 0xb  ; len data
0x06: 2d       | out bytecode[0xfc:0cfc+[0xfd]] 

; input name
0x07: 00 fc ae | mov [0xfc], 0xae	; input buffer 1
0x0a: 00 fd 0b | mov [0xfd], 0xb	; max input length 1
0x0d: 2e       | in  bytecode[0xfc:0xfc+[0xfd]] ;input name
0x0e: 01 b9 fd | mov [0xb9], [0xfd]	; write input name length

; print("Enter serial:")
0x11: 00 fc 7d | mov [0xfc], 0x7d	; offset to data
0x14: 00 fd 0d | mov [0xfd], 0xd	; offset to length
0x17: 2d       | out bytecode[0xfc:0cfc+[0xfd]]	

; input serial
0x18: 00 fc ba | mov [0xfc], 0xba	; input buffer 2
0x1b: 00 fd 09 | mov [0xfd], 0x9	; max input length 2
0x1e: 2e       | in  bytecode[0xfc:0xfc+[0xfd]]	; input serial
0x1f: 01 c3 fd | mov [0xc3], [0xfd] ; write input serial length

; check lengths: 
; name must be 10 chars 
; serial must be 8 chars
0x22: 18 b9 0a | cmp [0xb9], 0xa	; compare length 1
0x25: 1e 6a    | jne 0x6a
0x27: 18 c3 08 | cmp [0xc3], 0x8	; compare length 2
0x2a: 1e 6a    | jne 0x6a

; loop: name to upper
0x2c: 00 c4 00 | mov [0xc4], 0x0	; init counter
0x2f: 00 c5 ae | mov [0xc5], 0xae	; input name
0x32: 04 c5 c4 | add [0xc5], [0xc4] ; TODO: virtual eflags
0x35: 55 c5 c6 | cmp [@0xc5] -> 0x0, [0xc6]	; name[i] < 0x61 ?
0x38: 24 42    | jb 0x42	; skip if true
0x3a: 55 c5 c7 | cmp [@0xc5] -> 0x0, [0xc7] ; name[i] > 0x7A ?
0x3d: 20 42    | ja 0x42	; skip if true
0x3f: 3f c5 df | and [@0xc5] -> 0x0, 0xdf ; to upper
0x42: 16 c4    | inc 0xc4	; counter
0x44: 19 c4 b9 | cmp [0xc4], [0xb9]	; cmp i, len(name)
0x47: 1e 2f    | jne 0x2f	; next char

; check
; working example:
; idx:		0123456789
; name:		ABCDEFGHIJ
; serial:	GXDJXCXB
0x49: 19 af c1 | cmp [0xaf], [0xc1]	; name[1] == serial[7]
0x4c: 1e 6a    | jne 0x6a
0x4e: 19 b1 bc | cmp [0xb1], [0xbc] ; name[3] == serial[2]
0x51: 1e 6a    | jne 0x6a
0x53: 19 b0 bf | cmp [0xb0], [0xbf]	; name[2] == serial[5]
0x56: 1e 6a    | jne 0x6a
0x58: 19 b4 ba | cmp [0xb4], [0xba]	; name[6] == serial[0]
0x5b: 1e 6a    | jne 0x6a
0x5d: 19 b7 bd | cmp [0xb7], [0xbd]	; name[9] == serial[3]
0x60: 1e 6a    | jne 0x6a

; good boy
0x62: 00 fc 9d | mov [0xfc], 0x9d	; "Serial CORRECT!"
0x65: 00 fd 11 | mov [0xfd], 0x11
0x68: 2d       | out bytecode[0xfc:0cfc+[0xfd]]
0x69: 2c       | end

; bad boy
0x6a: 00 fc 8a | mov [0xfc], 0x8a	; "Serial incorect."
0x6d: 00 fd 13 | mov [0xfd], 0x13
0x70: 2d       | out bytecode[0xfc:0cfc+[0xfd]]
0x71: 2c       | end
```

---
EOF
