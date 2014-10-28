JMP2IT v1.1 - Created by Adam Kramer [2014] - Inspired by Malhost-Setup

This will allow you to transfer EIP control to a specified offset within a file
containing shellcode and then pause to support a malware analysis investigation

The file will be mapped to memory and maintain a handle, allowing shellcode
to egghunt for second stage payload as would have happened in original loader

* Warning: Patches are dynamically written to disk - ensure you have a backup *

Usage: jmp2it.exe [file containing shellcode] [file offset to transfer EIP to]

Example: jmp2it.exe malware.doc 0x15C

 = Explaination: The file will be mapped and code at 0x15C will immediately run
  
Example: jmp2it.exe malware.doc 0x15C pause

  = Explaination: As above, but the first two bytes swapped to cause a pause loop
  
Example: jmp2it.exe malware.doc 0x15C addhandle another.doc pause

  = Explaination: As above, but will create additional handle to specified file

Optional extras (to be added after first two parameters):

addhandle <path to file> - Create an arbatory handle to a specified file
  
Only one of the following two may be used:

  pause - First two bytes of shellcode to be replaced with 0 byte JMP

  pause_int3 - First byte replaced with INT3 breakpoint [launch via debugger!]
  
Note: In these cases, you will be presented with the original bytes so
      you can patch them back in once paused inside a debugger and resume
