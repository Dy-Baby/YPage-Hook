
#pragma once

#include <Windows.h>


/*
* 页面异常Hook类
* 非线程安全
*/

class YPageHook {


public:
	YPageHook();

	~YPageHook();

private:
	enum class Status
	{
		invalid,
		valid
	} m_status;

	LPVOID m_exceptionHandlerHandle;


private:
	typedef void (*HookCallBack)(LPCONTEXT context);

public:
	enum class Error
	{
		duplicateAddress,
		setProtectFailed,
		repeatInstall,
		repeatUninstall,
	};

public:
	LPVOID m_hookAddr;
	HookCallBack m_callback;

public:
	/*
	* 安装Hook
	* 失败会抛出异常，参见enum class Error
	*/
	void install(LPVOID hookAddr, HookCallBack callback);

	/*
	* 卸载Hook
	* 失败会抛出异常，参见enum class Error
	*/
	void uninstall();
	
};


// #include "YPageHook.cpp"

