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

using namespace System;

int main(int argc, char *argv[])
{
	/* Intro line */
	Console::WriteLine(L"** JMP2IT - Created by Adam Kramer [2014] - Inspired by Malhost-Setup **");
	
	/* Check that we have received the required arguments */
	if (argc < 3)
	{
		Console::WriteLine(L"This will allow you to transfer EIP control to a specified offset within a file");
		Console::WriteLine(L"containing shellcode and then pause to support a malware analysis investigation");
		Console::WriteLine(L"The file will be mapped to memory and maintain a handle, allowing shellcode");
		Console::WriteLine(L"to egghunt for second stage payload as would have happened in original loader");
		Console::WriteLine(L"-------------------------------------------------------------------------------");
		Console::WriteLine(L"* Warning: Patches are dynamically written to disk - ensure you have a backup *");
		Console::WriteLine(L"-------------------------------------------------------------------------------");
		Console::WriteLine(L"Usage: jmp2it.exe <file containing shellcode> <file offset to transfer EIP to>");
		Console::WriteLine(L"Example: jmp2it.exe malware.doc 0x15C");
		Console::WriteLine(L"  Explaination: The file will be mapped and code at 0x15C will immediately run");
		Console::WriteLine(L"Example: jmp2it.exe malware.doc 0x15C pause");
		Console::WriteLine(L"  Explaination: As above, but the first two bytes swapped to cause a pause loop");
		Console::WriteLine(L"Example: jmp2it.exe malware.doc 0x15C addhandle another.doc pause");
		Console::WriteLine(L"  Explaination: As above, but will create additional handle to specified file");
		Console::WriteLine(L"-------------------------------------------------------------------------------");
		Console::WriteLine(L"Optional extras (to be added after first two parameters):");
		Console::WriteLine(L"  addhandle <path to file> - Create an arbatory handle to a specified file");
		Console::WriteLine(L"Only one of the following two may be used:");
		Console::WriteLine(L"  pause - First two bytes of shellcode to be replaced with 0 byte JMP");
		Console::WriteLine(L"  pause_int3 - First byte replaced with INT3 breakpoint <launch via debugger!>");
		Console::WriteLine(L"Note: In these cases, you will be presented with the original bytes so");
		Console::WriteLine(L"      you can patch them back in once paused inside a debugger and resume");
		return 1;
	}

	/* Check that arguement 2 is a legimitmate memory address */
	if (strlen(argv[2]) < 3 || (argv[2][0] != '0' && argv[2][1] != 'x'))
	{
		Console::WriteLine(L"Error: Parameter 2 must begin 0x to signify a hex offset has been used");
		return 1;
	}
	
	/* Convert argument 1 to wide char pointer */
	wchar_t w[MAX_PATH];
	size_t size_of_w = sizeof(w);
	mbstowcs_s(&size_of_w, w, argv[1], MAX_PATH);
	LPWSTR pFile = w;

	/* Create handle to requested file */
	HANDLE hFile = CreateFile(pFile, GENERIC_ALL, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	/* Error catching for handle creation */
	if (hFile == INVALID_HANDLE_VALUE)
	{
		Console::WriteLine(L"Error: Unable to create handle to file - check path to file");
		return 1;
	}

	/* Check if 'addhandle' parameter has been requested */
	/* N.B. Argument load is a little messy - will tidy up if more functionality is added */
	if (!strcmp(argv[3], "addhandle"))
	{
	
		wchar_t z[MAX_PATH];
		size_t size_of_z = sizeof(z);
		mbstowcs_s(&size_of_z, z, argv[4], MAX_PATH);
		LPWSTR pAddHandleFile = z;

		HANDLE pAddHandle = CreateFile (pAddHandleFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		/* Error catching for handle creation */
		if (pAddHandle == INVALID_HANDLE_VALUE)
		{
			Console::WriteLine(L"Error: Unable to create handle to file (addhandle param) - check path to file");
			return 1;
		}

	} else if (!strcmp(argv[4], "addhandle"))
	{
		wchar_t z[MAX_PATH];
		size_t size_of_z = sizeof(z);
		mbstowcs_s(&size_of_z, z, argv[5], MAX_PATH);
		LPWSTR pAddHandleFile = z;

		HANDLE pAddHandle = CreateFile (pAddHandleFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		/* Error catching for handle creation */
		if (pAddHandle == INVALID_HANDLE_VALUE)
		{
			Console::WriteLine(L"Error: Unable to create handle to file (addhandle param) - check path to file");
			return 1;
		}
	}

	/* Create backup file */
	Console::WriteLine(L"Automatically generating backup of input file as JMP2IT-InputFile.BAK");
	CopyFile(pFile, L"JMP2IT-InputFile.BAK", FALSE);

	/* Map file into memory */
	HANDLE pMap = CreateFileMapping(hFile, NULL, PAGE_EXECUTE_READWRITE, 0, 0, NULL);

	LPVOID lpBase = MapViewOfFile(pMap, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);

	/* Handle errors with the memory mapping */
	if (!lpBase)
	{
		Console::WriteLine(L"Error: Unable to map file to memory");
		return 1;
	}

	/* Calculate shellcode location based on mapped memory offset */
	int iOffset = strtol(argv[2], NULL, 16);
	lpBase = (char*)lpBase + iOffset;

	/* If 'pause' command entered, swap out bytes */
	if (!strcmp(argv[3], "pause") || !strcmp(argv[5], "pause"))
	{
		char* pFirstTwo = (char*)lpBase;
		char byte1 = pFirstTwo[0];
		char byte2 = pFirstTwo[1];

		pFirstTwo[0] = '\xEB';
		pFirstTwo[1] = '\xFE';

		Console::WriteLine(L"Swapping first two bytes of shellcode: {0:X} {1:X} with EB FE to generate pause", byte1, byte2);

	} else if (!strcmp(argv[3], "pause_int3") || !strcmp(argv[5], "pause_int3")) 
	{
		char* pFirstTwo = (char*)lpBase;
		char byte1 = pFirstTwo[0];

		pFirstTwo[0] = '\xCC';

		Console::WriteLine(L"First byte replaced with INT3 pointer (CC). Once program is pauses in a debugger at the breakpoint, replace CC (INT3) with the original byte: {0:X}\n", byte1);
	}

	/* Transfer EIP control */
	Console::WriteLine(L"Calling requested function within mapped file...");
	Console::WriteLine(L"Note: Expect the program to crash if the memory location is incorrect");
	
	int (*pFunction)() = (int(*)(void))lpBase;
	pFunction();

}
