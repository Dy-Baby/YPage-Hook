
#pragma once

#include <Windows.h>


/*
* 页面异常Hook类
* 非线程安全
*/

class PageHook {


public:
	PageHook();

	~PageHook();

private:
	enum class Status
	{
		invalid,
		valid
	} m_status;


private:
	typedef void (*HookCallBack)(LPCONTEXT context);

public:
	DWORD m_oldProtect;
	LPVOID m_hookAddr;
	HookCallBack m_callback;

public:
	/*
	* 安装Hook
	*/
	BOOL install(LPVOID hookAddr, HookCallBack callback);

	/*
	* 卸载Hook
	*/
	BOOL uninstall();
	
};




