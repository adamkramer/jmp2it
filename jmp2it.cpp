/*  This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>. 
	
	Created by Adam Kramer [2014] - Email: adamkramer at hotmail dot com */

#include "stdafx.h"
#include "windows.h"
#include <stdio.h>

int main(int argc, char *argv[])
{

	/* Intro line */
	printf("** JMP2IT v1.4 - Created by Adam Kramer [2014] - Inspired by Malhost-Setup **\n");
	
	/* Check that we have received the required arguments - if not, display help page */
	if (argc < 3)
	{
		printf("This will allow you to transfer EIP control to a specified offset within a file\n");
		printf("containing shellcode and then pause to support a malware analysis investigation\n");
		printf("The file will be mapped to memory and maintain a handle, allowing shellcode\n");
		printf("to egghunt for second stage payload as would have happened in original loader\n");
		printf("-------------------------------------------------------------------------------\n");
		printf("Patches / self modifications are dynamically written to jmp2it-flypaper.out\n");
		printf("-------------------------------------------------------------------------------\n");
		printf("Usage: jmp2it.exe <file containing shellcode> <file offset to transfer EIP to>\n");
		printf("Example: jmp2it.exe malware.doc 0x15C\n");
		printf("  Explaination: The file will be mapped and code at 0x15C will immediately run\n");
		printf("Example: jmp2it.exe malware.doc 0x15C pause\n");
		printf("  Explaination: As above, with JMP SHORT 0xFE inserted pre-offset causing loop\n");
		printf("Example: jmp2it.exe malware.doc 0x15C addhandle another.doc pause\n");
		printf("  Explaination: As above, but will create additional handle to specified file\n");
		printf("-------------------------------------------------------------------------------\n");
		printf("Optional extras (to be added after first two parameters):\n");
		printf("  addhandle <path to file> - Create an arbatory handle to a specified file\n");
		printf("Only one of the following two may be used:\n");
		printf("  pause - Inserts JMP SHORT 0xFE just before offset causing infinite loop\n");
		printf("  pause_int3 - Inserts INT3 just before offset <launch via debugger!>\n");
		printf("Note: In these cases, you will be presented with step by step instructions\n");
		printf("      on what you need to do inside a debugger to resume the analysis\n");
		return 1;
	} 

	/* Check that arguement 2 is a legimitmate memory address */
	if (strlen(argv[2]) < 3 || (argv[2][0] != '0' && argv[2][1] != 'x'))
	{
		printf("Error: Parameter 2 must begin 0x to signify a hex offset has been used\n");
		return 1;
	}
	
	/* Convert argument 1 to wide char pointer */
	wchar_t w[MAX_PATH];
	size_t size_of_w = sizeof(w);
	mbstowcs_s(&size_of_w, w, argv[1], MAX_PATH);
	LPWSTR pFile = w;

	/* Copy original file to temp 'flypaper' file */
	CopyFile(pFile, L"jmp2it-flypaper.out", FALSE);
	pFile = L"jmp2it-flypaper.out";

	/* Create handle to requested file */
	HANDLE hFile = CreateFile(pFile, GENERIC_ALL, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	/* Error catching for handle creation */
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error: Unable to create handle to file - check path to file\n");
		return 1;
	}

	/* Check if offset is greater than the size of the file */
	if (GetFileSize(hFile, NULL) < (DWORD)strtol(argv[2], NULL, 16))
	{
		printf("Error: Offset is larger than selected file size");
		return 1;
	}

	/* Check if 'addhandle' parameter has been requested */
	/* N.B. Argument loading is a little messy - will tidy up if more functionality is added */
	if (argc > 4 && !strcmp(argv[3], "addhandle"))
	{
	
		wchar_t z[MAX_PATH];
		size_t size_of_z = sizeof(z);
		mbstowcs_s(&size_of_z, z, argv[4], MAX_PATH);
		LPWSTR pAddHandleFile = z;

		HANDLE pAddHandle = CreateFile (pAddHandleFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		/* Error catching for handle creation */
		if (pAddHandle == INVALID_HANDLE_VALUE)
		{
			printf("Error: Unable to create handle to file (addhandle param) - check path to file\n");
			return 1;
		}

	} else if (argc > 5 && !strcmp(argv[4], "addhandle"))
	{
		wchar_t z[MAX_PATH];
		size_t size_of_z = sizeof(z);
		mbstowcs_s(&size_of_z, z, argv[5], MAX_PATH);
		LPWSTR pAddHandleFile = z;

		HANDLE pAddHandle = CreateFile (pAddHandleFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		/* Error catching for handle creation */
		if (pAddHandle == INVALID_HANDLE_VALUE)
		{
			printf("Error: Unable to create handle to file (addhandle param) - check path to file\n");
			return 1;
		}

	/* If they have requested 'addhandle', but not provided enough parameters (i.e. not the path) */
	} else if (argc == 4 && !strcmp(argv[3], "addhandle") || (argc == 5 && !strcmp(argv[4], "addhandle")))
	{
		printf("Error: Insufficient parameters to use 'addhandle' functionality\n");
		return 1;
	}

	/* Map file into memory */
	HANDLE pMap = CreateFileMapping(hFile, NULL, PAGE_EXECUTE_READWRITE, 0, 0, NULL);
	LPVOID lpBase = MapViewOfFile(pMap, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);

	/* Handle errors with the memory mapping */
	if (!lpBase)
	{
		printf("Error: Unable to map file to memory\n");
		return 1;
	}

	/* Calculate shellcode location based on mapped memory offset */
	int iOffset = strtol(argv[2], NULL, 16);
	lpBase = (char*)lpBase + iOffset;

	/* Prepare function pointer to shellcode address */
	int (*pFunction)() = (int(*)(void))lpBase;
	
	/* Version 2 of breakpoint code - nothing in the user's code is modified */
	if ((argc > 3 && !strcmp(argv[3], "pause")) || (argc > 5 && !strcmp(argv[5], "pause")))
	{
		printf("** As requested, the process has been paused ** \n\n" \
			    "To proceed with debugging:\n" \
			    "1. Load a debugger and attach it to this process\n" \
				"2. If it has paused, instruct it to start running again\n" \
				"3. Pause the process after a few seconds\n" \
				"4. NOP the EF BE infinite loop which you should be on\n" \
				"5. Step to the CALL immediately after and then 'step into' it\n\n" \
				" === You will then be at the shellcode ===\n ");

		__asm{ loc: jmp loc } // Assembly infinite loop

	/* INT3 version */
	} else if ((argc > 3 && !strcmp(argv[3], "pause_int3")) || (argc > 5 && !strcmp(argv[5], "pause_int3")))
	{

		if (!IsDebuggerPresent())
		{
			printf("Error: pause_int3 can only be used within the context of a debugger\n");
			return 1;
		}

	  	printf("** As requested, the process has been paused using INT3 ** \n\n" \
			    "To proceed with debugging:\n" \
			    "1. It should already be running within a debugger...\n" \
				"2. If it has paused, instruct it to start running again\n" \
				"3. Pause the process after a few seconds\n" \
				"4. NOP the INT3 break which you should be on\n" \
				"5. Step to the CALL immediately after and then 'step into' it\n\n" \
				" === You will then be at the shellcode ===\n ");

		__asm{ int 3 }

	} else {

		printf("Executing without pausing, expect the program to crash if the memory location is incorrect\n");

	}

	pFunction(); // Execute the shellcode

}
