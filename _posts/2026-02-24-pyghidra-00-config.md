---
title: PyGhidra Configuration
category: [braindump, pyghidra]
tags: [ghidra, pyghidra, python]
---

> Tested with Ghidra 12.0.3
{: .prompt-info }

# Start PyGhidra

```
./ghidra_12.0.3_PUBLIC/support/pyghidraRun
```

* Open or create a project
* Open the _CodeBrowser_ window (only if it's not already open):
    * Clic Tools -> Run Tool -> CodeBrowser

# Configuring Scripts Path

* In _CodeBrower_: clic Window -> Script Manager
    * The _Script Manager_ window pops
* In the _Script Manager_ window, right pane (the one listing scripts name and description):
    * Right clic -> Script Directories
    * The _Bundle Manager_ window pops
* In the _Bundle Manager_ window, clic on the green 'plus' sign
    * Navigate to the directory of your choice and validate

# Script header

A script header contains some metadata:

```
┌[~/dev/ghidra_scripts/pyghidra/v12.0.3]
└╼[silma@myrtille:$ cat helloworld.py 

#@author 
#@category _MyScripts
#@keybinding 
#@menupath 
#@toolbar 

print("Hello from PyGhidra!")

```

* The `#@category` is the name under which the script will be found
* Once the script is created:
    * In the _Script Manager_ window, clic on the '_refresh_' button
    * The new category (here `_MyScripts`) should appear in the left pane
    * Select the category,  then the script (right pane), and Clic on the '_Run Script_' button
* If everything went well, the output should be visible in the '_Console - Scripting_' window

