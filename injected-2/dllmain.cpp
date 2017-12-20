// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <string>


void PatchImportAddressTable() 
{
	DWORD baseAdr = (DWORD) GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) baseAdr;
	printf("%x\n", (WORD)dosHeader->e_magic);
	PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS)(baseAdr + (DWORD) dosHeader->e_lfanew);
	printf("%s\n", &(peHeader->Signature));
	
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		PatchImportAddressTable();
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

