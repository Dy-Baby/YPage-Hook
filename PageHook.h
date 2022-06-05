
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
	} m_status = Status::invalid;


private:
	typedef void (*HookCallBack)(LPCONTEXT context);

public:
	DWORD m_oldProtect = NULL;
	LPVOID m_hookAddr;
	SIZE_T m_size;
	HookCallBack m_callback;

public:
	/*
	* 安装Hook
	*/
	BOOL install(LPVOID hookAddr, SIZE_T size, HookCallBack callback);

	/*
	* 卸载Hook
	*/
	BOOL uninstall();
	
};





