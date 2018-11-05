//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswdrv_h__
#define __gswdrv_h__

#include "gesruledef.h"

class CGswDrv {
public:
	CGswDrv(void);
	~CGswDrv();
	bool IsValid(void);
	bool RefreshRules(void);
	bool AddRules(RulePack *Pack, DWORD PackLength);
	bool W32hooksetInit(void);
	bool W32hooksetSync(W32HooksetSyncParams *Params);
	bool W32hooksetRelease(void);
	bool SetAttributes(SetAttributesInfo *Info);
	bool GetSubjAttributes(const DWORD ProcessId, EntityAttributes *Attributes, ULONG *RuleId);
	bool GetCurrentSubjIntegrity(EntityAttributes *Attributes, ULONG *RuleId);
	GesRule::ModelType GetSubjIntegrity(const DWORD ProcessId);
	bool RefreshSettings(void);
	HANDLE GetProcessId(PVOID Process);
	bool GetNativeExecName(const DWORD ProcessId, wchar_t *ExecName, const DWORD ExecNameLength);
	bool GetObjectAttributes(const HANDLE hObject, const NtObjectType Type, const ULONG RuleId, EntityAttributes *Attributes);
	bool IsFileUntrusted(const wchar_t *FileName);
	int GetReleaseId(void);

private:
	HANDLE hDevice;
};

#endif // __gswdrv_h__