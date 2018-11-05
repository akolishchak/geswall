//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __hook_h__
#define __hook_h__


namespace Hook {
	NTSTATUS Init(VOID);
	VOID Release(VOID);

    NTSTATUS GetProcessInfo(CHAR *Label, PEPROCESS Process, EntityAttributes &Attributes, 
                            Rule::RedirectStatus &Redirect, ULONG &RuleId);
    NTSTATUS SetProcessInfo(CHAR *Label, PEPROCESS Process, EntityAttributes &Attributes,
                            Rule::RedirectStatus Redirect, ULONG RuleId, AttrSetFunction Func);
	PFILE_OBJECT GetProcessFileObject(PEPROCESS Process);
	PUNICODE_STRING GetProcessFileName(PEPROCESS Process);
	NTSTATUS AddThreadMap(_ETHREAD *Thread, _EPROCESS *Process);
	_EPROCESS *GetCurrentProcess(VOID);

	BOOLEAN IsRedirectEnabled(Rule::RedirectStatus Redirect);
	
	enum RedirectType {
		rdrOpen,
		rdrOpenCreate
	};

	BOOLEAN GetRedirectName(NtObjectType NtType, PUNICODE_STRING ObjectName, PUNICODE_STRING Name);
	HANDLE GetProcessId(PEPROCESS Process);

	const WCHAR RedirectDir[] = L"\\SystemRoot\\geswall\\redirect\\";
};

#define STATUS_REDIRECT					(0x8c710567)


#endif // #ifndef __hook_h__

