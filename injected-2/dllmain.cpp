// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <windows.h>

#include<TlHelp32.h>

#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>


WCHAR fileName[] = L"secret.txt";
SIZE_T fileNameLength = 0;

PIMAGE_IMPORT_DESCRIPTOR getImportTable(PBYTE baseAddr) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) baseAddr;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(baseAddr + (DWORD) dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY dataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importTable = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddr + dataDirectory.VirtualAddress);

	//printf("dosHeader magic: %x\n", dosHeader->e_magic);
	//printf("ntHeader signature: %s\n", &(ntHeader->Signature)); // should be PE
	//printf("optionalHeader magic: %x\n", optionalHeader.Magic); // should be 0x10b
	//printf("dataDirectory (size): %x\n", dataDirectory.Size);
	//printf("dataDirectory (relative virtual addr): %x\n", dataDirectory.VirtualAddress);
	//printf("import table: %x\n", importTable);

	return importTable;
}

void PatchImportAddressTable(CHAR * targetDllName, CHAR * targetFunctionName, PROC hook, PROC *originalFunction)
{
	CHAR buffer[100];
	SIZE_T targetDllNameLength = strlen(targetDllName);

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	IMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
	PIMAGE_THUNK_DATA currentThunk;
	PIMAGE_THUNK_DATA currentOriginalThunk;
	DWORD currentFuncAddress;
	PIMAGE_IMPORT_BY_NAME pOriginalFuncData;

	PBYTE baseAddr = (PBYTE) GetModuleHandle(NULL);
	pImageImportDescriptor = getImportTable(baseAddr);
	char *currentDllName;
	for (int i = 0; pImageImportDescriptor[i].Characteristics; ++i) {
		imageImportDescriptor = pImageImportDescriptor[i];
		currentDllName = (char *)(baseAddr + imageImportDescriptor.Name);

		OutputDebugStringA(currentDllName);

		if (0 == strncmp(currentDllName, targetDllName, targetDllNameLength)) {
			
			currentThunk = (PIMAGE_THUNK_DATA) (baseAddr + imageImportDescriptor.FirstThunk);
			currentOriginalThunk = (PIMAGE_THUNK_DATA) (baseAddr + imageImportDescriptor.OriginalFirstThunk);
			while (currentOriginalThunk->u1.Function) {
				pOriginalFuncData = (PIMAGE_IMPORT_BY_NAME)(baseAddr + currentOriginalThunk->u1.Function);
				currentFuncAddress = (DWORD)(currentThunk->u1.AddressOfData);

				OutputDebugStringA(pOriginalFuncData->Name);
				OutputDebugStringA("qqqqqqqqqqq");
				if(0 == strncmp(pOriginalFuncData->Name, targetFunctionName, strlen(targetFunctionName))) {
					OutputDebugStringA("hi");
					if (NULL != originalFunction)
						*originalFunction = (PROC) currentFuncAddress;
					OutputDebugStringA("jasjkoasdjklasdjkl");

					sprintf_s(buffer, "thunk: %x\n", (PBYTE)currentThunk);
					OutputDebugStringA(buffer);
					currentThunk->u1.AddressOfData = (DWORD) hook;
					
					OutputDebugStringA("bingo");
					OutputDebugStringA("bingo");
					OutputDebugStringA("bingo");
					OutputDebugStringA("bingo");
					OutputDebugStringA("bingo");
					OutputDebugStringA("bingo");
					OutputDebugStringA("bingo");

					/*printf("bingo!\n");
					
					printf("%x\n", currentOriginalThunk);
					printf("%x\n", currentThunk);
					printf("original: %s (%x)\n", pOriginalFuncData->Name, pOriginalFuncData->Hint);
					printf("normal: (%x)\n", currentFuncAddress);
					printf("normal: (%x)\n", GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle"));*/
				}
				currentOriginalThunk++;
				currentThunk++;
			}
		}
		pImageImportDescriptor++;
	}
	OutputDebugStringA("Done.");
}

//PROC OriginalCreateFile;
//HANDLE WINAPI HookCreateFile(
//  _In_     LPCTSTR               lpFileName,
//  _In_     DWORD                 dwDesiredAccess,
//  _In_     DWORD                 dwShareMode,
//  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//  _In_     DWORD                 dwCreationDisposition,
//  _In_     DWORD                 dwFlagsAndAttributes,
//  _In_opt_ HANDLE                hTemplateFile
//) {
//	  OutputDebugStringA("stam");
//	  return ((HANDLE (WINAPI *)(
//  _In_     PCHAR,
//  _In_     DWORD,
//  _In_     DWORD,
//  _In_opt_ LPSECURITY_ATTRIBUTES,
//  _In_     DWORD,
//  _In_     DWORD,
//  _In_opt_ HANDLE))OriginalCreateFile)("C:\\Users\\ISE\\Desktop\\z.txt", dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
//}

PROC GetModuleFileNameWOriginal;
DWORD WINAPI GetModuleFileNameWHook(
  _In_opt_ HMODULE hModule,
  _Out_    LPCWSTR lpFilename,
  _In_     DWORD   nSize
  ) {
	  OutputDebugStringA("working");
	  DWORD ans = ((DWORD (WINAPI *)(_In_opt_ HMODULE, _Out_ LPCWSTR, _In_ DWORD))GetModuleFileNameWOriginal)(hModule, lpFilename, nSize);
	  return ans;
}

void Hook() {
	PatchImportAddressTable("KERNEL32.dll", "GetModuleFileNameW", (PROC) GetModuleFileNameWHook, &GetModuleFileNameWOriginal);
}

void UnHook() {
	//PatchImportAddressTable("NtosKrnl.lib", "ZwQueryDirectoryFile", (PROC) ZwQueryDirectoryFileHook, NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugStringA("hooking...");
		Hook();
		OutputDebugStringA("done");
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		//OutputDebugStringA("unhooking...");
		//UnHook();
		//OutputDebugStringA("done");
		break;
	}

	return TRUE;
}
