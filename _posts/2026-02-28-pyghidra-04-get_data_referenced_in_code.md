---
title: PyGhidra - Get Data Referenced in a Code Unit
category: [braindump, pyghidra]
tags: [ghidra, pyghidra, python]
---

> Tested with Ghidra 12.0.3
{: .prompt-info }

# Introduction

Let's look at the following disassembly:

```
140001529 LEA  RAX,[opcode_table]; opcode_table is at 0x140005080
```

I want to retrieve the data at `0x140005080` because I want to do Python things on them. in order to do so, I also need the length of these data. Here it is `0xB00` bytes; I won't explain how I get this length for it is of no importance for the purpose of this post. Just recall that we need to known in advance the length of the data to retrieve.

Keywords to dig in the doc:
* `Reference`
* `CodeUnit`
* `MemoryBlock`

The code shown below also use `jpype.JByte()` to create an output buffer; it is required to use the method `getBytes()`. There may be other ways, I don't really know; here I'm using what I saw in one of the example script (`./ghidra_12.0.3_PUBLIC/Ghidra/Features/PyGhidra/ghidra_scripts/PyGhidraBasics.py`).

# Code

```python
# Get data referenced in a code unit
#@author silma
#@category _MyScripts
#@keybinding 
#@menupath 
#@toolbar 


"""
Target asm block:
14000151c 55                         PUSH   RBP
14000151d 48 89 e5                   MOV    RBP,RSP
140001520 48 83 ec 10                SUB    RSP,0x10
140001524 89 c8                      MOV    EAX,ECX
140001526 88 45 10                   MOV    byte ptr [RBP + inByte],AL
140001529 48 8d 05 50 3b 00 00       LEA    RAX,[opcode_table] ; <-- here

target insn address: 0x140001529
target bytes: 48 8d 05 50 3b 00 00
target instruction: LEA RAX,[0x140005080]
"""

# Set those variable according to your needs
TARGET_ADDRESS = 0x140001529
ENTRY_COUNT = 88
ENTRY_SIZE = 0x20
TARGET_DATA_LEN = ENTRY_COUNT * ENTRY_SIZE

import binascii
import jpype

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import Reference


def get_data_from_ref(ref: Reference) -> bytes:
    """
    adapted from PyGhidraBasics.py
    """
   
    byte_array = jpype.JByte[TARGET_DATA_LEN]  # <java class 'byte[]'>
    dest = ref.getToAddress()  # Address
    block_name = currentProgram.memory.getBlock(dest).getName()  # str
    block = currentProgram.memory.getBlock(block_name) # MemoryBlock
    count = block.getBytes(dest, byte_array)  # int
    return bytes(byte_array)


def get_target_code_unit(a: int) -> CodeUnit:
    # Create an 'Address' object
    target_addr = address_factory.getDefaultAddressSpace().getAddress(a)
    target_cu = listing.getCodeUnitContaining(target_addr)
    assert(target_cu.getAddress() == target_addr)
    target_func = f_mgr.getFunctionContaining(target_addr)  # Function
    print(f"target code unit '{target_cu}' found in function '{target_func}'")
    return target_cu


address_factory = currentProgram.getAddressFactory()
listing = currentProgram.getListing()
f_mgr = currentProgram.getFunctionManager()  

target_cu = get_target_code_unit(TARGET_ADDRESS)
    
# https://github.com/NationalSecurityAgency/ghidra/discussions/3655
# Either cu.getPrimaryReference(i) || cu.getAddress(i), where i is operand index.
# Here, instruction is 'LEA RAX,[0x140005080]':
#   operand[0] is RAX
#   operand[1] is the reference we want
# And if cu.getAddress() is called with no parameter, we get 'TARGET_ADDRESS'.
ref = target_cu.getPrimaryReference(1)
data = get_data_from_ref(ref)
print(data)
```

---
EOF
