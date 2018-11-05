//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __win32hook_h__
#define __win32hook_h__

namespace Win32Hook {
    NTSTATUS Init(VOID);
    VOID Release(VOID);
	VOID SetServiceIndex(W32Func Service, ULONG Index);

	extern ULONG_PTR WindowsFromDCIndex;

	extern PEPROCESS InitProcess;
};

#endif // __win32hook_h__