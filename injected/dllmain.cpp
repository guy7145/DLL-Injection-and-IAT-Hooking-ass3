// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>

#define MAX_TITLE_LENGTH 150
BOOL CALLBACK windowCallback(_In_ HWND hwnd, _In_ LPARAM lParam) {
	WCHAR title[MAX_TITLE_LENGTH];
	DWORD targetPid = (DWORD)lParam;
	DWORD thisWndPid;
	GetWindowThreadProcessId(hwnd, &thisWndPid);
	
	if (thisWndPid != targetPid)
		return TRUE;
	
	int oldTitleLength = GetWindowText(hwnd, title, MAX_TITLE_LENGTH);
	wsprintf(title + oldTitleLength, L" was PWNED By Guy and Nitzan");
	SetWindowText(hwnd, title);
	return FALSE;
}

void ChangeTitle() {
	DWORD current_pid = GetCurrentProcessId();
	EnumWindows(windowCallback, current_pid);
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
		ChangeTitle();
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

