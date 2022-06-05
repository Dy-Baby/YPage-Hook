#include "PageHook.h"
#include <map>



static std::map<LPVOID, PageHook&> gs_pageHook_base;
static std::map<DWORD, PageHook&> gs_pageHook_step;


#pragma code_seg(".hook")



static LPVOID PageAlignment(LPVOID addr) {
	return (LPVOID)((UINT_PTR)addr & (UINT_PTR)(~0xfff));
}

static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {

	// 判断异常类型
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

		// 不管3721，先恢复一下这个页面的属性，避免find等函数被链接到同一页面，执行时也出现异常
		DWORD oldProtect;
		VirtualProtect(ExceptionInfo->ExceptionRecord->ExceptionAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);

		auto it = gs_pageHook_base.find(PageAlignment(ExceptionInfo->ExceptionRecord->ExceptionAddress));
		if (it == gs_pageHook_base.end()) {
			// 不是咱们设置的页面属性产生的异常，改回去

			VirtualProtect(ExceptionInfo->ExceptionRecord->ExceptionAddress, 1, oldProtect, &oldProtect);

			return EXCEPTION_CONTINUE_SEARCH;
		}

		// 执行的指令与我们的Hook位于同一页面
		
		// 同步一下页面属性
		it->second.m_oldProtect = oldProtect;

		// 获取发生异常的线程的上下文
		LPCONTEXT context = ExceptionInfo->ContextRecord;


		// 设置单步触发陷阱，用于单步后重新启用此Hook
		context->EFlags |= 0x100;

		// 用于识别是否咱们设置的单步
		gs_pageHook_step.insert(std::pair<DWORD, PageHook&>(GetCurrentThreadId(), it->second));


#ifdef _WIN64
		if ((LPVOID)context->Rip == it->second.m_hookAddr) {
#else
		if ((LPVOID)context->Eip == it->second.m_hookAddr) {
#endif
			// 是被hook的地址

			// 调用回调
			it->second.m_callback(context);
		}

		
		
		//异常处理完成 让程序继续执行
		return EXCEPTION_CONTINUE_EXECUTION;


	}
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		LPCONTEXT pContext = ExceptionInfo->ContextRecord;

		
		// 判断是否DR寄存器触发的异常
		if (pContext->Dr6 & 0xf) {
			// 排除DR寄存器触发的单步异常
		}
		else {
			// 单步异常

			auto it = gs_pageHook_step.find(GetCurrentThreadId());
			if (it == gs_pageHook_step.end()) {
				//不是咱们设置的单步断点，不处理
				return EXCEPTION_CONTINUE_SEARCH;
			}

			LPVOID hookAddr = it->second.m_hookAddr;
			DWORD* oldProtect = &it->second.m_oldProtect;

			gs_pageHook_step.erase(GetCurrentThreadId());


			// 恢复Hook
			VirtualProtect(hookAddr, 1, *oldProtect, oldProtect);


			// 不需要重设TF，单步异常自动将TF置0
			// 单步异常是陷阱类异常，无需修复ip

			// 异常处理完成 让程序继续执行
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		
	}

	return EXCEPTION_CONTINUE_SEARCH;
}



PageHook::PageHook() {
	m_status = Status::invalid;
	m_oldProtect = NULL;
	m_hookAddr = nullptr;
	m_callback = nullptr;

	//注册VEH
	AddVectoredExceptionHandler(TRUE, ExceptionHandler);

	
}

PageHook::~PageHook() {
	//移除VEH
	RemoveVectoredExceptionHandler(ExceptionHandler);

	uninstall();
}



BOOL PageHook::install(LPVOID hookAddr, HookCallBack callback) {

	if (m_status == Status::valid) {
		uninstall();
	}
	
	auto it = gs_pageHook_base.find(PageAlignment(hookAddr));

	if (it != gs_pageHook_base.end()) {
		return FALSE;
	}


	gs_pageHook_base.insert(std::pair<LPVOID, PageHook&>(PageAlignment(hookAddr), *this));

	m_hookAddr = hookAddr;
	m_callback = callback;
	m_status = Status::valid;
	
	if (!VirtualProtect(hookAddr, 1, PAGE_READWRITE, &m_oldProtect)) {
		
		uninstall();
		return FALSE;
	}

	return TRUE;
}

BOOL PageHook::uninstall() {
	if (m_status == Status::invalid) {
		return FALSE;
	}
	if (!VirtualProtect(m_hookAddr, 1, m_oldProtect, &m_oldProtect)) {
		return FALSE;
	}

	gs_pageHook_base.erase(PageAlignment(m_hookAddr));


	m_oldProtect = NULL;
	m_hookAddr = nullptr;
	m_callback = nullptr;

	m_status = Status::invalid;


	return TRUE;
}

#pragma code_seg()