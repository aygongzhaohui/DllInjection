#pragma once

#include <Windows.h>
#include <assert.h>

class DllInjector
{
public:
	DllInjector();
	~DllInjector(void);

public:
	INT Initialize(LPCTSTR appName, LPCTSTR dllName)
	{
		assert(appName);
		assert(dllName);
		DWORD pid = GetPidByProcName(appName);
		if (0 == pid)
		{
			m_strError = L"程序名称找不到对应进程";
			return -1;
		}
		return Initialize(pid, dllName);
	}

	INT Initialize(DWORD processId, LPCTSTR dllName);

	INT InjectDll()
	{
		return DoInject(true);
	}

	INT UninjectDll()
	{
		return DoInject(false);
	}

	void Destroy();

	LPCTSTR GetError()
	{ return m_strError; }

private:
	INT DoInject(bool bInject);

public:
	static DWORD GetPidByProcName(LPCTSTR appName);

private:
	DWORD m_dwPid;
	HANDLE m_hTargetProcess;
	TCHAR m_dllPath[512];
	TCHAR m_dllName[128];
	HANDLE m_hRemoteThrd;
	PTHREAD_START_ROUTINE m_hLoadRoutine;
	PTHREAD_START_ROUTINE m_hFreeRoutine;
	LPCTSTR m_strError;
};
