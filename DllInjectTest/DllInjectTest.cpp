// DllInjectTest.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "DllInjector.h"

#include <iostream>

int _tmain(int argc, _TCHAR* argv[])
{
	DllInjector injector;
	if (injector.Initialize(L"hexin.exe", L"F:/InjectDll.dll"))
	{
		::MessageBoxEx(NULL, injector.GetError(), L"Error", MB_OK, 0);
		return -1;
	}
	if (injector.InjectDll())
	{
		::MessageBoxEx(NULL, injector.GetError(), L"Error", MB_OK, 0);
		return -1;
	}
	::MessageBoxEx(NULL, L"�Ѿ����DLLע�룬���OK��ж��DLL", L"", MB_OK, 0);
	if (injector.UninjectDll())
	{
		::MessageBoxEx(NULL, injector.GetError(), L"Error", MB_OK, 0);
		return -1;
	}
	injector.Destroy();
	return 0;
}

