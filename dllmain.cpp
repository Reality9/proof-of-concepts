// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "process attach", MB_OK);
		break;
	case DLL_PROCESS_DETACH:
		MessageBoxA(NULL, "DLL_PROCESS_DETACH", "process detach", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
		MessageBoxA(NULL, "DLL_THREAD_ATTACH", "thread attach", MB_OK);
		break;
	case DLL_THREAD_DETACH:
		MessageBoxA(NULL, "DLL_THREAD_ATTACH", "thread detach", MB_OK);
		break;
	}
	return TRUE;
}

