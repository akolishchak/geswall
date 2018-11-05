//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2003-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __x86_h__
#define __x86_h__

namespace commonlib {

namespace x86 {

	enum CodeWidth {
		cwt16		= 1,
		cwt32		= 2,
		cwt64		= 3
	};

	VOID InitParse(CodeWidth Width);
	ULONG Parse(PBYTE Code);

	enum InjectType {
		injNone,
		injJump,
		injImportCall
	};

	struct _Trampoline {
		BYTE Prefix[64];
		BYTE Sufix[64];
	};

	struct InjectContext {
		InjectType Type;
		PBYTE Code;
		INT64 Content;
		INT64 AdjustedCode;
		PBYTE RvaOffset;
		INT64 Rva;
		INT64 AdjustedRva;
		_Trampoline *Trampoline;
	};

	PVOID InjectCode(PVOID Module, PBYTE Code, PBYTE NewCode, PVOID *PrevCode, _Trampoline *Trampoline);
	_Trampoline *RemoveInjection(InjectContext *Context);
};

} // namespace commonlib {

#endif // __x86_h__