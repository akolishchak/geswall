//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2003-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __hin_h__
#define __hin_h__

#if defined(_NTDDK_) || defined(_NTIFS_)
#include "khin.h"
#endif

#if (_CONSOLE || _WINDOWS) // user mode
 #include <windows.h> 
#endif

namespace commonlib {

namespace hin {

	typedef PVOID HOOK_HANDLE;
    
	PVOID GetModuleBase(PCHAR Name);
	PVOID GetExportedFunc(PVOID Module, PCHAR Name);
	PVOID GetImportedFunc(PVOID Module, PCHAR Name);

	PBYTE AllocateTrampoline(VOID);
	VOID FreeTrampoline(PBYTE Trampoline);

	HOOK_HANDLE HookCode(PVOID Module, PBYTE Code, PBYTE NewCode, PVOID *PrevCode, PBYTE Trampoline);

	inline HOOK_HANDLE HookCode(PVOID Module, PVOID Code, PVOID NewCode, PVOID *PrevCode)
	{
		PBYTE Trampoline = AllocateTrampoline();
		if ( Trampoline == NULL ) return NULL;

		return HookCode(Module, (PBYTE)Code, (PBYTE)NewCode, PrevCode, Trampoline);
	}

	inline HOOK_HANDLE HookExported(PVOID Module, PCHAR FuncName, PVOID NewCode, PVOID *PrevCode)
	{
		PBYTE Func = (PBYTE) GetExportedFunc(Module, FuncName);
		if ( Func == NULL ) return NULL;
		return HookCode(Module, Func, NewCode, PrevCode);
	}

	inline HOOK_HANDLE HookExported(PCHAR ModuleName, PCHAR FuncName, PVOID NewCode, PVOID *PrevCode)
	{
		PVOID Module = GetModuleBase(ModuleName);
		if ( Module == NULL ) return NULL;
		return HookExported(Module, FuncName, NewCode, PrevCode);
	}

	VOID UnHook(HOOK_HANDLE Handle);
	
	struct MapHandle {
		SIZE_T Length;
		PVOID Mem;
#if defined(_NTDDK_) || defined(_NTIFS_)
		PMDL Mdl;
#else
		DWORD Protect;
#endif
	};
	typedef MapHandle *MAPHANDLE;

	PVOID MapForWrite(MAPHANDLE *Handle, PVOID Mem, ULONG Length);
	VOID UnMap(MAPHANDLE Handle);

#if defined(_NTDDK_) || defined(_NTIFS_)

	inline ULONG GetServiceIndex(PVOID _function) { return *(PULONG)((PUCHAR)_function+1); }

	enum ServiceType {
		srvSystem,
		srvWin32
	};

	NTSTATUS HookService(WCHAR *wcServiceProc, ULONG Index, PVOID NewServiceProc, PVOID *OriginalServiceProc, ServiceType Type = srvSystem);
	void UnHookService(WCHAR *wcServiceProc, ULONG Index, PVOID OriginalServiceProc, PVOID NewServiceProc, ServiceType Type = srvSystem);
#endif // #if defined(_NTDDK_) || defined(_NTIFS_)

} // namespace hin {

} // namespace commonlib {

#endif // __hin_h__