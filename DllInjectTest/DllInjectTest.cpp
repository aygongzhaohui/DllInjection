// DllInjectTest.cpp : 定义控制台应用程序的入口点。
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
	::MessageBoxEx(NULL, L"已经完成DLL注入，点击OK后卸载DLL", L"", MB_OK, 0);
	if (injector.UninjectDll())
	{
		::MessageBoxEx(NULL, injector.GetError(), L"Error", MB_OK, 0);
		return -1;
	}
	injector.Destroy();
	return 0;
}

