// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>


DWORD WINAPI ThreadRun(LPVOID p)
{
	while (1)
	{
		Sleep(3000);
		OutputDebugStringA("test");
	}
	return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			CloseHandle(CreateThread(0,0,ThreadRun,0,0,0));
			printf("dll中获取的 基址 %08x  镜像大小 %08x",(DWORD)hModule,(DWORD)lpReserved);
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

