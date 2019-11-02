#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <tchar.h>

typedef DWORD(WINAPI *_NtCreateThreadEx32)(
	PHANDLE					ThreadHandle,
	ACCESS_MASK			DesiredAccess,
	LPVOID						 ObjectAttributes,
	HANDLE						 ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID						 lpParameter,
	BOOL						 CreateSuspended,
	DWORD						 dwStackSize,
	DWORD						 dw1,
	DWORD						dw2,
	LPVOID						 Unknown
	);

typedef DWORD64(WINAPI *_NtCreateThreadEx64)(
	PHANDLE					ThreadHandle,
	ACCESS_MASK			 DesiredAccess,
	LPVOID						ObjectAttributes,
	HANDLE						ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID						lpParameter,
	BOOL						CreateSuspended,
	DWORD64					 dwStackSize,
	DWORD64					dw1,
	DWORD64					 dw2,
	LPVOID						Unknown
	);

BOOL EnableDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))		// 1
		return FALSE;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);	// 2
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;	// visual
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);	// 3

	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;
	return TRUE;
}

BOOL IsVistaOrLater() {
	OSVERSIONINFO osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);

	if (osvi.dwMajorVersion >= 6)
		return TRUE;
	return FALSE;
}

BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pThreadParam) {
	HANDLE      hThread = NULL;
	FARPROC     pFunc = NULL;

	if (IsVistaOrLater())    // Vista, 7, Server2008
	{
		pFunc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
		if (pFunc == NULL)
		{
			printf("MyCreateRemoteThread() : GetProcAddress(\"NtCreateThreadEx\") failed!!! [%d]\n",
				GetLastError());
			return FALSE;
		}

		((_NtCreateThreadEx32)pFunc)(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pThreadParam,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);
		if (hThread == NULL)
		{
			printf("MyCreateRemoteThread() : NtCreateThreadEx() failed!!! [%d]\n", GetLastError());
			return FALSE;
		}
	}
	else                    // 2000, XP, Server2003
	{
		hThread = CreateRemoteThread(hProcess,
			NULL,
			0,
			pThreadProc,
			pThreadParam,
			0,
			NULL);
		if (hThread == NULL)
		{
			printf("MyCreateRemoteThread() : CreateRemoteThread() failed!!! [%d]\n", GetLastError());
			return FALSE;
		}
		else
		{
			CloseHandle(hThread);
		}
	}

	return TRUE;
}

BOOL Dll_Inject(DWORD dwPID, LPCWSTR szDllPath) {
	LPVOID lpThreadProc;
	HANDLE hProcess = NULL;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		printf("OpenProcess(%d) failed [%d]\n",
			dwPID, GetLastError());
		return FALSE;
	}

	LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_READWRITE);	//for x86 verison
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, 4096, NULL);	//for x86 verison
	lpThreadProc = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryW");	//for x86 verison

	if (!MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)lpThreadProc, pRemoteBuf))		// Difference of ThreadParam
	{
		printf("[ERROR] MyCreateRemoteThread() failed!!!\n");
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}

VOID Inject(LPCTSTR szExeName, LPCWSTR szDllPath)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnap;
	HANDLE hProcess;

	EnableDebugPrivilege();
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnap, &pe32))
	{
		CloseHandle(hSnap);
		return;
	}
	do
	{
		if (!_tcsicmp(pe32.szExeFile, szExeName))
		{
			if (Dll_Inject(pe32.th32ProcessID, szDllPath))
			{
				printf("Injection succeed!\n");
			}
			else
			{
				printf("Injection failed!\n");
			}
			CloseHandle(hSnap);
			return;
		}
	} while (Process32Next(hSnap, &pe32));

}

int main()
{
	WCHAR PathName[260];
	GetFullPathNameW(L"Loader.dll", 260, PathName, NULL);
	Inject(_T("trgame.exe"), PathName);
	return 0;
}
