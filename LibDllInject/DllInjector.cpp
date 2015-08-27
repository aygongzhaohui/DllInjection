#include "StdAfx.h"
#include "DllInjector.h"

#include <tchar.h>
#include <TlHelp32.h>


DllInjector::DllInjector(void) :
	m_dwPid(0),
	m_hTargetProcess(NULL),
	m_hRemoteThrd(NULL),
	m_hLoadRoutine(NULL),
	m_hFreeRoutine(NULL),
	m_strError(L"")
{
}


DllInjector::~DllInjector(void)
{
}

INT DllInjector::Initialize(DWORD processId, LPCTSTR dllName)
{
	assert(dllName);
	TCHAR tmp[512];
	m_dwPid = processId;
	::lstrcpyn(m_dllPath, dllName, sizeof(m_dllPath) - 1);
	::lstrcpyn(tmp, dllName, sizeof(tmp) - 1);
	LPTSTR name, p = _tcstok(tmp, L"\\/"); name = p;
	while ((p = _tcstok(NULL, L"\\/")) != NULL) name = p;
	::lstrcpyn(m_dllName, name, sizeof(m_dllName) - 1);
	try
	{
		m_hTargetProcess = ::OpenProcess(
							PROCESS_ALL_ACCESS,
							FALSE, m_dwPid);
		if (INVALID_HANDLE_VALUE == m_hTargetProcess)
		{
			m_strError = L"进程号找不到对应的进程句柄";
			throw 0x01;
		}
		m_hLoadRoutine = 
			(PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
		if (NULL == m_hLoadRoutine)
		{
			m_strError = L"获取LoadLibraryW地址失败";
			throw 0x02;
		}
		m_hFreeRoutine = 
			(PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
		if (NULL == m_hFreeRoutine)
		{
			m_strError = L"获取FreeLibrary地址失败";
			throw 0x03;
		}
	}
	catch (int e)
	{
		Destroy();
		return e;
	}
	return 0;
}

INT DllInjector::DoInject(bool bInject)
{
	LPVOID remoteMem = NULL;
	SIZE_T len = (1 + ::lstrlen(m_dllPath)) * sizeof(TCHAR);
	PTHREAD_START_ROUTINE routineAddr = bInject? m_hLoadRoutine : m_hFreeRoutine;
	try
	{
		if (bInject)
		{
			remoteMem = ::VirtualAllocEx(m_hTargetProcess, NULL, len, MEM_COMMIT, PAGE_READWRITE);
			if (NULL == remoteMem)
			{
				m_strError = L"在远程进程分配内存失败";
				throw 0x01;
			}
			if (!::WriteProcessMemory(m_hTargetProcess, remoteMem, m_dllPath, len,  NULL))
			{
				m_strError = L"在远程进程内存写入DLL路径失败";
				throw 0x02;
			}
		}
		else
		{
			HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->m_dwPid);
			if (INVALID_HANDLE_VALUE == hSnapshot)
			{
				m_strError = L"从远程进程获取CreateToolhelp32Snapshot失败";
				throw 0x03;
			}
			MODULEENTRY32W moduleEntry = { sizeof(moduleEntry) };
			BOOL bSearch = ::Module32First(hSnapshot, &moduleEntry);
			while (bSearch)
			{
				if (!_tcscmp(moduleEntry.szModule, this->m_dllName))
				{
					remoteMem = (LPVOID)moduleEntry.modBaseAddr;
					break;
				}
				bSearch = ::Module32Next(hSnapshot, &moduleEntry);
			}
			::CloseHandle(hSnapshot);
		}
		// 创建远程线程
		DWORD tid = 0;
		m_hRemoteThrd = ::CreateRemoteThread(m_hTargetProcess, NULL, 0, routineAddr, remoteMem, 0, &tid);
		if (NULL == m_hRemoteThrd)
		{
			m_strError = L"创建远程线程失败";	
			throw 0x03;
		}
		::WaitForSingleObject(m_hRemoteThrd, INFINITE);
		throw 0;
	}
	catch (int e)
	{
		if (remoteMem)
		{
			if (bInject)
				::VirtualFreeEx(m_hTargetProcess, NULL, len, MEM_RELEASE);
			if (m_hRemoteThrd)
			{
				::CloseHandle(m_hRemoteThrd);
				m_hRemoteThrd = NULL;
			}
		}
		return e;
	}
	return 0;
}

void DllInjector::Destroy()
{
	if (m_hTargetProcess)
		::CloseHandle(m_hTargetProcess);
	m_hLoadRoutine = NULL;
	m_hFreeRoutine = NULL;
	::memset(m_dllPath, 0, sizeof(m_dllPath));
	m_dwPid = 0;
}

DWORD DllInjector::GetPidByProcName(LPCTSTR appName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
		return -1;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	BOOL bSearch = ::Process32First(hSnapshot, &pe);
	while (bSearch)
	{
		if (!_tcscmp(pe.szExeFile, appName))
		{
			::CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
		bSearch = ::Process32Next(hSnapshot, &pe);
	}
	::CloseHandle(hSnapshot);
	return 0;
}
