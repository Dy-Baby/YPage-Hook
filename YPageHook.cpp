#include "YPageHook.h"
#include <map>


struct PageRecord {
	LPVOID pageBase;
	size_t count;
	DWORD protect;
};
static std::map<LPVOID, PageRecord> gs_pageHook_base;
static std::map<LPVOID, PageHook&> gs_pageHook_addr;
static std::map<DWORD, PageRecord&> gs_pageHook_step;




static LPVOID PageAlignment(LPVOID addr) {
	return (LPVOID)((UINT_PTR)addr & (UINT_PTR)(~0xfff));
}

static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {

	// 判断异常类型
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

		LPVOID pageBase = PageAlignment(ExceptionInfo->ExceptionRecord->ExceptionAddress);
		auto it_base = gs_pageHook_base.find(pageBase);
		if (it_base == gs_pageHook_base.end()) {
			// 不是咱们设置的页面属性产生的异常，忽略
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// 执行的指令与我们的Hook位于同一页面，恢复原有属性
		DWORD uselessProtect;
		VirtualProtect(pageBase, 0x1000, it_base->second.protect, &uselessProtect);


		// 获取发生异常的线程的上下文
		LPCONTEXT context = ExceptionInfo->ContextRecord;


		auto it_addr = gs_pageHook_addr.find(ExceptionInfo->ExceptionRecord->ExceptionAddress);
		if (it_addr != gs_pageHook_addr.end()) {
			// 是被hook的地址

			// 调用回调
			it_addr->second.m_callback(context);
		}

		// 设置单步触发陷阱，用于单步后重新启用此Hook
		context->EFlags |= 0x100;

		// 用于识别是否咱们设置的单步
		gs_pageHook_step.insert(std::pair<DWORD, PageRecord&>(GetCurrentThreadId(), it_base->second));
		
		
		//异常处理完成 让程序继续执行
		return EXCEPTION_CONTINUE_EXECUTION;


	}
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		LPCONTEXT pContext = ExceptionInfo->ContextRecord;

		// 判断是否DR寄存器触发的异常
		if (pContext->Dr6 & 0xf) {
			// 排除DR寄存器触发的单步异常
			return EXCEPTION_CONTINUE_SEARCH;
		}
		else {
			// 单步异常
			auto it = gs_pageHook_step.find(GetCurrentThreadId());
			if (it == gs_pageHook_step.end()) {
				//不是咱们设置的单步断点，不处理
				return EXCEPTION_CONTINUE_SEARCH;
			}

			
			DWORD uselessProtect;
			// 恢复Hook
			VirtualProtect(it->second.pageBase, 0x1000, PAGE_READWRITE, &uselessProtect);

			gs_pageHook_step.erase(GetCurrentThreadId());

			// 不需要重设TF，单步异常自动将TF置0
			// 单步异常是陷阱类异常，无需修复ip

			// 异常处理完成 让程序继续执行
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		
	}

	return EXCEPTION_CONTINUE_SEARCH;
}



YPageHook::YPageHook() {
	m_status = Status::invalid;
	m_hookAddr = nullptr;
	m_callback = nullptr;

	//注册VEH
	m_exceptionHandlerHandle = AddVectoredExceptionHandler(TRUE, ExceptionHandler);
}

YPageHook::~YPageHook() {
	//移除VEH
	RemoveVectoredExceptionHandler(m_exceptionHandlerHandle);

	uninstall();
}

void YPageHook::install(LPVOID hookAddr, HookCallBack callback) {

	if (m_status == Status::valid) {
		throw Error::repeatInstall;
	}
	
	auto it_addr = gs_pageHook_addr.find(hookAddr);
	if (it_addr != gs_pageHook_addr.end()) {
		throw Error::duplicateAddress;
	}

	LPVOID pageBase = PageAlignment(hookAddr);
	
	m_hookAddr = hookAddr;
	m_callback = callback;
	m_status = Status::valid;

	gs_pageHook_addr.insert(std::pair<LPVOID, PageHook&>(hookAddr, *this));
	auto it_base = gs_pageHook_base.find(pageBase);
	if (it_base == gs_pageHook_base.end()) {
		PageRecord pageRecord;
		pageRecord.count = 1;
		pageRecord.pageBase = pageBase;
		pageRecord.protect = 0;
		gs_pageHook_base.insert(std::pair<LPVOID, PageRecord>(pageBase, pageRecord));
		it_base = gs_pageHook_base.find(pageBase);
		if (!VirtualProtect(pageBase, 0x1000, PAGE_READWRITE, &it_base->second.protect)) {
			uninstall();
			throw Error::setProtectFailed;
		}
	}
	else {
		++it_base->second.count;
	}
}

void YPageHook::uninstall() {
	if (m_status == Status::invalid) {
		throw Error::repeatUninstall;
	}

	LPVOID pageBase = PageAlignment(m_hookAddr);
	auto it_base = gs_pageHook_base.find(pageBase);

	if (it_base != gs_pageHook_base.end()) {
		if (it_base->second.count == 1) {
			if (!VirtualProtect(pageBase, 0x1000, it_base->second.protect, &it_base->second.protect)) {
				throw Error::setProtectFailed;
			}
			gs_pageHook_base.erase(it_base);
		}
		else {
			--it_base->second.count;
		}
	}
	
	gs_pageHook_addr.erase(m_hookAddr);

	m_hookAddr = nullptr;
	m_callback = nullptr;

	m_status = Status::invalid;

}
