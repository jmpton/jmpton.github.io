---
title: PyGhidra - List Blocks of a Function
category: [braindump, pyghidra]
tags: [ghidra, pyghidra, python]
---

> Tested with Ghidra 12.0.3
{: .prompt-info }

# Introduction

List the code blocks of a randomly (or not; more information in [previous post](/posts/pyghidra-02-list_function_body)) choosen function and disassemble them. Also, the source(s) and destination(s) of each blocks are listed.

Keywords to dig in the doc:
* `BasicBlockModel`
* `CodeBlockImpl`
* `CodeBlockReference`
* `AddressRange`
* `AddressSet`

# Code

```py
# List basic blocks of a randomly selected function
#@author silma
#@category _MyScripts
#@keybinding 
#@menupath 
#@toolbar 


# Set USE_RANDOM = False to work with the function at funcs_list[INDEX] 
INDEX = 11
USE_RANDOM = True  

import random
from ghidra.program.model.listing import FunctionIterator, Function, CodeUnit
from ghidra.program.model.lang import OperandType
from ghidra.program.model.address import AddressSet

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor


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


def list_function_blocks(f: Function):
    
    bbm = BasicBlockModel(currentProgram)
    blocks = bbm.getCodeBlocksContaining(f.getBody(), monitor)  # SimpleBlockIterator
    
    for i, b in enumerate(blocks):  # CodeBlockImpl
        
        block_start_addr = b.getFirstStartAddress()  # Address
        #block_all_entrypoints = b.getStartAddresses()
        n_sources = b.getNumSources(monitor)  # int
        n_dests = b.getNumDestinations(monitor)

        block_ranges = b.getAddressRanges(True)  # AddressRangeIterator
        for range_ in block_ranges:
            block_min_addr = range_.getMinAddress()  # Address
            block_max_addr = range_.getMaxAddress()  # Address
            break
        assert(block_min_addr == block_start_addr)

        block_sources = b.getSources(monitor)  # CodeBlockReferenceIterator
        block_destinations = b.getDestinations(monitor)  # CodeBlockReferenceIterator
        
        print(f"block {i} disassembly:")
        as_ = AddressSet(block_min_addr, block_max_addr)  # AddressSet
        cu = listing.getCodeUnits(as_, True)
        for insn in cu:
            print(f"  {insn.getAddress()} {insn}")

        print(f"Block {i} details:")
        print(f"  block range: {block_min_addr} - {block_max_addr}")
        print(f"  sources flow (n = {n_sources}):")
        while block_sources.hasNext():
            n = block_sources.next()  # CodeBlockReference
            s = n.getSourceAddress()  # Address
            r = n.getReferent()  # Address
            d = n.getReference()  # Address
            print(f"    {n}: source block @{s} flows from {r} to {d}")
            assert(d == block_start_addr)
        print(f"  destinations flow: (n = {n_dests})")
        while block_destinations.hasNext():
            n = block_destinations.next() # CodeBlockReference
            s = n.getSourceAddress()
            r = n.getReferent()  # Address
            d = n.getReference() # Address
            print(f"    {n}: block {i} flows from {r} to {d}")
            assert(s == block_start_addr)
        print("===============")
        i += 1
        

monitor = ConsoleTaskMonitor()
f_mgr = currentProgram.getFunctionManager()  
listing = currentProgram.getListing()  # Listing
all_funcs = f_mgr.getFunctions(True)

f = choose_function(all_funcs)
print(f"Using function '{f}'")

list_function_blocks(f)
```

---
EOF



