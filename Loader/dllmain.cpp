#include <windows.h>
#include "MemoryModulePP.h"
#include "resource.h"

BOOL LoadDllFromRes(PVOID *pDllData, DWORD *dwDllSize, HMODULE hModule)
{
	HRSRC		hRes;

#ifdef _DEBUG
	hRes = FindResource(hModule, MAKEINTRESOURCE(IDR_DLL1), TEXT("DLL"));
#else
	hRes = FindResource(hModule, MAKEINTRESOURCE(IDR_DLL2), TEXT("DLL"));
#endif

	if (hRes == NULL)
	{
		return FALSE;
	}

	*pDllData = (PVOID)LoadResource(hModule, hRes);
	*dwDllSize = SizeofResource(hModule, hRes);

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	PVOID			pDllData = NULL;
	DWORD			dwDllSize = 0;
	PMEMORYMODULE	pMemdll = NULL;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if (LoadDllFromRes(&pDllData, &dwDllSize, hModule))
		{
			pMemdll = MemoryLoadLibrary(pDllData, dwDllSize);
		}
		//unload Loader
		return FALSE;
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

