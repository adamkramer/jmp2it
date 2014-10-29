** JMP2IT v1.4 - Created by Adam Kramer [2014] - Inspired by Malhost-Setup **

This will allow you to transfer EIP control to a specified offset within a file
containing shellcode and then pause to support a malware analysis investigation

The file will be mapped to memory and maintain a handle, allowing shellcode
to egghunt for second stage payload as would have happened in original loader

Patches / self modifications are dynamically written to jmp2it-flypaper.out

Usage: jmp2it.exe [file containing shellcode] [file offset to transfer EIP to]

Example: jmp2it.exe malware.doc 0x15C

  Explaination: The file will be mapped and code at 0x15C will immediately run
  
Example: jmp2it.exe malware.doc 0x15C pause

  Explaination: As above, with JMP SHORT 0xFE inserted pre-offset causing loop
  
Example: jmp2it.exe malware.doc 0x15C addhandle another.doc pause

  Explaination: As above, but will create additional handle to specified file

Optional extras (to be added after first two parameters):

  addhandle [path to file] - Create an arbatory handle to a specified file
  
Only one of the following two may be used:

  pause - Inserts JMP SHORT 0xFE just before offset causing infinite loop
  
  pause_int3 - Inserts INT3 just before offset [launch via debugger!]

Note: In these cases, you will be presented with step by step instructions
      on what you need to do inside a debugger to resume the analysis
      
