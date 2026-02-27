---
title: PyGhidra - List Instructions of a Function
category: [braindump, pyghidra]
tags: [ghidra, pyghidra, python]
---

> Tested with Ghidra 12.0.3
{: .prompt-info }


# Introduction

Build the list of functions of a program and disassemble a randomly choosen one. To disassemble the function of your choice, set `USE_RANDOM` to `False` and `INDEX` to the corresponding value in the list.

A few keywords to dig in the doc:
* Interfaces: `FunctionManager`, `Listing`
* Objects: `Function`, `Address`, `CodeUnit`

# Code

```py
# List instructions of a randomly selected function
#@author 
#@category _MyScripts
#@keybinding 
#@menupath 
#@toolbar 

# Set USE_RANDOM = False to work with the function at funcs_list[INDEX] 
INDEX = 1
USE_RANDOM = True  

import random
from ghidra.program.model.listing import FunctionIterator, Function, CodeUnit
from ghidra.program.model.lang import OperandType


def choose_function(all_funcs: FunctionIterator) -> Function:
    funcs_list = []
    for f in all_funcs:
        funcs_list.append(f)

    if USE_RANDOM:
        random.seed()
        idx = random.randrange(0, len(funcs_list), step=1)
    else:
        idx = INDEX

    f = funcs_list[idx]

    return f

def list_function_body(f: Function):
    f_body = f.getBody()  # AdressSet; [address start, address end]
    code_units = listing.getCodeUnits(f_body, True)  # CodeUnitRecordIterator; forward=True
    for cu in code_units:
        addr = cu.getAddress()
        length = cu.getLength()
        n_operands = cu.getNumOperands()
        operands_repr = f"-"
        if n_operands > 0:
            i = 0
            operands_repr = f""
            while i < n_operands:
                otype = cu.getOperandType(i)
                orepr = cu.getDefaultOperandRepresentation(i)
                operands_repr += f"operand #{i}: {orepr} (type: {otype}); "
                i += 1
        
        print(f"{addr}: {cu}")
        print(f"  instruction details: insn length: {length}; number of operands: {n_operands}")
        print(f"  operands details: {operands_repr}")


f_mgr = currentProgram.getFunctionManager()  
listing = currentProgram.getListing()  # Listing
all_funcs = f_mgr.getFunctions(True)

f = choose_function(all_funcs)
print(f"Using function '{f}'")

list_function_body(f)
```

---
EOF
