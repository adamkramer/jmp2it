jmp2it
======

Transfer EIP control to shellcode during malware analysis investigation

Help file:
This will allow you to transfer EIP control to a specified offset within a file
containing shellcode and then pause to support a malware analysis investigation

The file will be mapped to memory and maintain a handle, allowing shellcode
to egghunt for second stage payload as would have happened in original loader

* Warning: Patches are dynamically written to disk - ensure you have a backup *
* 
Usage: jmp2it.exe <file containing shellcode> <file offset to transfer EIP to>
Example: jmp2it.exe malware.doc 0x15C

Optional extras as 3rd parameter (only one may be used):
pause - First two bytes of shellcode to be replaced with 0 byte JMP
pause_int3 - First byte replaced with INT3 breakpoint <only launch in debugger!>
Note: In these cases, you will be presented with the original bytes 
so you can patch them back in once paused inside a debugger and resume
