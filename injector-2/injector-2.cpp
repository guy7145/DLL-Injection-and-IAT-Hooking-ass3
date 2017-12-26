// injector-2.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <string>
using namespace std;

void injectDll(char * dllLocation, int pid) {
	SIZE_T locationsStrLength = strlen(dllLocation);

	FARPROC loadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (!loadLibrary) {
		printf("GetProcAddress error: %d\n", GetLastError());
		exit(1);
	}

	HMODULE m = ((HMODULE(WINAPI *)(LPCSTR))loadLibrary)(dllLocation);
	if (m == 0) {
		printf("error loading dll: %x\n", GetLastError());
		exit(2);
	} else printf("dll path and LoadLibraryA addr OK\n");

	HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (!process) {
		printf("process not found: %d", pid);
		exit(3);
	}

	LPVOID remoteString = VirtualAllocEx(process, NULL, locationsStrLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	SIZE_T bytesWritten;
	WriteProcessMemory(process, remoteString, dllLocation, locationsStrLength, &bytesWritten);

	DWORD threadId;
	HANDLE remoteThread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, remoteString, 0, &threadId);
	if (!remoteThread) {
		printf("error creating remote thread: %d\n", GetLastError());
		exit(6);
	}

	CloseHandle(process);
}


int _tmain(int argc, _TCHAR* argv[])
{
	/*int pid;
	cin >> pid;
	GetProcessList( );*/
	/*printf("Before:");
	CloseHandle(OpenProcess(0, FALSE, GetCurrentProcessId()));

	PatchImportAddressTable("KERNEL32.dll", "CloseHandle", (PROC) CloseHandleEvil, &CloseHandleOriginal);

	printf("After:");
	CloseHandle(OpenProcess(0, FALSE, GetCurrentProcessId()));

	printf("DONE.");*/

	char dllLocation[] = "C:\\Users\\ISE\\Desktop\\injection\\Debug\\injected-2.dll";
	SIZE_T locationsStrLength = strlen(dllLocation);

	if (argc != 2) {
		printf("expected 1 argument");
		exit(-1);
	}
	int pid = stoi(argv[1]);
	OutputDebugStringA("injecting dll...");
	injectDll(dllLocation, pid);
	OutputDebugStringA("done.");
	return 0;
}