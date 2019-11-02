#include <windows.h>
#include <tchar.h>
#include <Shlwapi.h>
#include "ntdll.h"
#include "detours.h"

#define XTRAP_DEVICE_NAME L"\\Device\\X6va067"

//win10
NTSTATUS
NTAPI
NtUserBuildHwndList(
	IN HANDLE hdesk,
	IN HANDLE hwndNext,
	IN BOOLEAN fEnumChildren,
	IN BOOLEAN fRemoveImmersive,
	IN DWORD idThread,
	IN ULONG cHwndMax,
	OUT HANDLE *phwndFirst,
	OUT PULONG pcHwndNeeded
);

using fnNtUserBuildHwndList = decltype(NtUserBuildHwndList);
using fnNtQuerySystemInformation = decltype(NtQuerySystemInformation);
using fnNtQueryObject = decltype(NtQueryObject);
using fnNtOpenProcess = decltype(NtOpenProcess);

fnNtUserBuildHwndList* pfnNtUserBuildHwndList = NULL;
fnNtQuerySystemInformation* pfnNtQuerySystemInformation = NULL;
fnNtQueryObject* pfnNtQueryObject = NULL;
fnNtOpenProcess* pfnNtOpenProcess = NULL;

VOID SuspendXTrapDriver()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG size = 0x1000;
	PSYSTEM_HANDLE_INFORMATION HandleInfo = NULL;
	POBJECT_NAME_INFORMATION ObjectNameInfo = NULL;
	HANDLE hObject;
	ULONG RetLen;

	while (1)
	{
		HandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);
		status = pfnNtQuerySystemInformation(SystemHandleInformation, HandleInfo, size, NULL);
		if (NT_SUCCESS(status))
		{
			break;
		}
		free(HandleInfo);
		size = size * 2;
	}

	for (int i = 0; i < HandleInfo->NumberOfHandles; i++)
	{
		if (HandleInfo->Handles[i].UniqueProcessId == GetCurrentProcessId()
			&& HandleInfo->Handles[i].ObjectTypeIndex == 0x24) //File index is 0x24 in win10 17134
		{
			hObject = (HANDLE)HandleInfo->Handles[i].HandleValue;
			ObjectNameInfo = (POBJECT_NAME_INFORMATION)malloc(0x1000);
			RtlZeroMemory(ObjectNameInfo, 0x1000);
			status = pfnNtQueryObject(hObject, ObjectNameInformation, ObjectNameInfo, 0x1000, &RetLen);
			if (!NT_SUCCESS(status))
			{
				free(ObjectNameInfo);
				continue;
			}
			if (!wcsnicmp(ObjectNameInfo->Name.Buffer, XTRAP_DEVICE_NAME, wcslen(XTRAP_DEVICE_NAME)))
			{
				//close device handle and the xtrap driver will stop working
				CloseHandle(hObject);
			}
			free(ObjectNameInfo);
		}
	}

	free(HandleInfo);
}

BOOL IsExcludedProcess(HANDLE PID)
{
	HANDLE hProcess;
	NTSTATUS status;
	OBJECT_ATTRIBUTES oa = { 0 };
	CLIENT_ID ClientId = { 0 };
	TCHAR FullPath[MAX_PATH];
	PTCHAR FileName;
	DWORD size = sizeof(FullPath) / sizeof(TCHAR);
	BOOL flag;

	InitializeObjectAttributes(&oa, NULL, NULL, NULL, NULL);
	ClientId.UniqueProcess = PID;
	status = pfnNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &ClientId);
	if (NT_SUCCESS(status))
	{
		flag = QueryFullProcessImageName(hProcess, 0, FullPath, &size);
		CloseHandle(hProcess);
		if (flag)
		{
			FileName = PathFindFileName(FullPath);
			if(!_tcsicmp(FileName, TEXT("cheatengine-x86_64.exe"))
				|| !_tcsicmp(FileName, TEXT("x32dbg.exe")))
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

NTSTATUS
NTAPI
MyNtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_opt_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
)
{
	NTSTATUS status;

	switch (SystemInformationClass)
	{
	case SystemProcessInformation:
		status = pfnNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		if (NT_SUCCESS(status))
		{
			PSYSTEM_PROCESS_INFORMATION info;
			info = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
			info->NextEntryOffset = 0;
			info->NumberOfThreads = 0;
		}
		return status;
		break;

	case SystemModuleInformation:
		status = pfnNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		if (NT_SUCCESS(status))
		{
			PRTL_PROCESS_MODULES info;
			info = (PRTL_PROCESS_MODULES)SystemInformation;
			info->NumberOfModules = 0;
		}
		return status;
		break;

	default:
		break;
	}

	return pfnNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS
NTAPI
MyNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{
	if (IsExcludedProcess(ClientId->UniqueProcess))
	{
		DesiredAccess = 0;
	}
	return pfnNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS
NTAPI
MyNtUserBuildHwndList(
	IN HANDLE hdesk,
	IN HANDLE hwndNext,
	IN BOOLEAN fEnumChildren,
	IN BOOLEAN fRemoveImmersive,
	IN DWORD idThread,
	IN ULONG cHwndMax,
	OUT HANDLE *phwndFirst,
	OUT PULONG pcHwndNeeded
)
{
	return STATUS_UNSUCCESSFUL;
}

VOID InstallHook()
{
	DetourTransactionBegin();
	DetourAttach((PVOID*)&pfnNtUserBuildHwndList, MyNtUserBuildHwndList);
	DetourAttach((PVOID*)&pfnNtQuerySystemInformation, MyNtQuerySystemInformation);
	DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		//xtrap scans peheader in memory, so we erase "MZ" to prevent our module from being found
		memset(hModule, 0, 2);

		pfnNtUserBuildHwndList = (fnNtUserBuildHwndList*)DetourFindFunction("win32u.dll", "NtUserBuildHwndList");
		pfnNtQuerySystemInformation = (fnNtQuerySystemInformation*)DetourFindFunction("ntdll.dll", "NtQuerySystemInformation");
		pfnNtQueryObject = (fnNtQueryObject*)DetourFindFunction("ntdll.dll", "NtQueryObject");
		pfnNtOpenProcess = (fnNtOpenProcess*)DetourFindFunction("ntdll.dll", "NtOpenProcess"); //may not be necessary
		SuspendXTrapDriver();
		InstallHook();
		OutputDebugString(TEXT("BypassXTrap Done!\n"));
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

