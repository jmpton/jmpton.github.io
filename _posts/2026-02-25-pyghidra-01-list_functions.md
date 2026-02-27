title: PyGhidra - Listing Functions
category: [braindump, pyghidra]
tags: [ghidra, pyghidra, python]
---

> Tested with Ghidra 12.0.3
{: .prompt-info }

# Context

I've spent the last years or so reapeating to whoever wanted to hear it that "One day, I'll switch to Ghidra!". The thing is, I couldn't switch abruptly because I never learnt the Java things, and doing Python 2.7 made me meh. With PyGhidra around however, I'd like to give it a try. So I'm starting to explore Ghidra's API step by step, and see where it brings me.

# Configuration

see [there](posts/pyghidra-00-config/)

# Code

```
#@category _MyScripts
#@keybinding 
#@menupath 
#@toolbar 

# Types seen:
# -----------
#   currentProgram  : <java class 'ghidra.program.database.ProgramDB'>
#   func_mgr        : <java class 'ghidra.program.database.function.FunctionManagerDB'>
#   all_funcs       : <java class 'ghidra.program.database.function.FunctionManagerDB.FunctionIteratorDB'>
#   f               : <java class 'ghidra.program.database.function.FunctionDB'>
#   f_params        : <java class 'ghidra.program.model.listing.Parameter[]'>
#   ParameterDB     : <java class 'ghidra.program.database.function.ParameterDB'>
#   f_entry         : <java class 'ghidra.program.model.address.GenericAddress'>
#   f_offset        : <java class 'JLong'>

func_mgr = currentProgram.getFunctionManager()  # FunctionManagerDB
all_funcs = func_mgr.getFunctions(True)  # FunctionIterator; forward=True

for f in all_funcs:
    if monitor.isCancelled():
        break
    f_name = f.getName()
    f_params = f.getParameters()  # Parameter[]
    f_entry = f.getEntryPoint()  # GenericAddress
    f_offset = f_entry.getOffset()

    print(f"{hex(f_offset)}:{f_name} (n args: {len(f_params)})")
```
