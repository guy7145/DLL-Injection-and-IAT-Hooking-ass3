// injected.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

extern "C" __declspec(dllexport) int doNothing();
__declspec(dllexport) int doNothing()
{
	return 0;
}