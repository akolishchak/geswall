//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "gswioctl.h"
#include "gesruledef.h"

#include "gswdrv.h"

CGswDrv::CGswDrv(void)
{
	hDevice = CreateFile(GESWALL_USER_DEVICE_NAME, MAXIMUM_ALLOWED, 
                         FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                         FILE_ATTRIBUTE_NORMAL, NULL);
}

CGswDrv::~CGswDrv()
{
	if ( hDevice != INVALID_HANDLE_VALUE ) CloseHandle(hDevice);
}

bool CGswDrv::IsValid(void)
{
	return hDevice != INVALID_HANDLE_VALUE;
}

bool CGswDrv::RefreshRules(void)
{
	DWORD BytesReturned;
    return DeviceIoControl(hDevice, GESWALL_IOCTL_REFRESH_RULES, NULL, 0, NULL, 0, &BytesReturned, NULL) == TRUE;
}

bool CGswDrv::AddRules(RulePack *Pack, DWORD PackLength)
{
	DWORD BytesReturned;
    return DeviceIoControl(hDevice, GESWALL_IOCTL_ADD_RULES, Pack, PackLength, NULL, 0, &BytesReturned, NULL) == TRUE;
}

bool CGswDrv::W32hooksetInit(void)
{
	DWORD BytesReturned;
    return DeviceIoControl(hDevice, GESWALL_IOCTL_W32HOOKSET_INIT, NULL, 0, NULL, 0, &BytesReturned, NULL) == TRUE;
}

bool CGswDrv::W32hooksetSync(W32HooksetSyncParams *Params)
{
	DWORD BytesReturned;
	return DeviceIoControl(hDevice, GESWALL_IOCTL_W32HOOKSET_SYNC, Params, sizeof W32HooksetSyncParams, NULL, 0, &BytesReturned, NULL) == TRUE;
}

bool CGswDrv::W32hooksetRelease(void)
{
	DWORD BytesReturned;
	return DeviceIoControl(hDevice, GESWALL_IOCTL_W32HOOKSET_RELEASE, NULL, 0, NULL, 0, &BytesReturned, NULL) == TRUE;
}

bool CGswDrv::SetAttributes(SetAttributesInfo *Info)
{
	DWORD BytesReturned;
	return DeviceIoControl(hDevice, GESWALL_IOCTL_SET_ATTRIBUTES, Info, sizeof SetAttributesInfo, NULL, 0, &BytesReturned, NULL) == TRUE;
}

bool CGswDrv::GetSubjAttributes(const DWORD ProcessId, EntityAttributes *Attributes, ULONG *RuleId)
{
	GetSubjAttributesInfo Info;
	memcpy(Info.Label, &GesRule::GswLabel, sizeof GesRule::GswLabel);
	Info.ProcessId = UlongToHandle(ProcessId);
	SubjAttributesInfo SubjInfo;
	DWORD BytesReturned;
	BOOL rc = DeviceIoControl(hDevice, GESWALL_IOCTL_GET_SUBJ_ATTRIBUTES, 
			&Info, sizeof Info, &SubjInfo, sizeof SubjInfo, &BytesReturned, NULL);
	if ( rc == TRUE ) {
		*Attributes = SubjInfo.Attr;
		*RuleId = SubjInfo.RuleId;
	}

	return rc == TRUE;
}

bool CGswDrv::GetCurrentSubjIntegrity(EntityAttributes *Attributes, ULONG *RuleId)
{
	SubjAttributesInfo SubjInfo;
	DWORD BytesReturned;
	BOOL rc = DeviceIoControl(hDevice, GESWALL_IOCTL_GET_CURRENT_SUBJ_ATTRIBUTES, 
								NULL, 0, &SubjInfo, sizeof SubjInfo, &BytesReturned, NULL);
	if ( rc == TRUE ) {
		*Attributes = SubjInfo.Attr;
		*RuleId = SubjInfo.RuleId;
	}

	return rc == TRUE;
}

GesRule::ModelType CGswDrv::GetSubjIntegrity(const DWORD ProcessId)
{
	GesRule::ModelType Integrity = GesRule::modUndefined;
	EntityAttributes Attributes;
	ULONG RuleId;
	if ( GetSubjAttributes(ProcessId, &Attributes, &RuleId) )
		Integrity = (GesRule::ModelType) Attributes.Param[GesRule::attIntegrity];

	return Integrity;
}

bool CGswDrv::RefreshSettings(void)
{
	DWORD BytesReturned;
	return DeviceIoControl(hDevice, GESWALL_IOCTL_REFRESH_SETTINGS, NULL, 0, NULL, 0, &BytesReturned, NULL) == TRUE;
}

HANDLE CGswDrv::GetProcessId(PVOID Process)
{
	HANDLE ProcessId = 0;
	DWORD BytesReturned;
	BOOL rc = DeviceIoControl(hDevice, GESWALL_IOCTL_GET_PROCESSID, 
								&Process, sizeof PVOID, &ProcessId, sizeof ProcessId, &BytesReturned, NULL);
	if ( rc == TRUE ) return ProcessId;
	return 0;
}

bool CGswDrv::GetNativeExecName(const DWORD ProcessId, wchar_t *ExecName, const DWORD ExecNameLength)
{
	HANDLE Pid = UlongToHandle(ProcessId);
	DWORD BytesReturned;
	BOOL rc = DeviceIoControl(hDevice, GESWALL_IOCTL_GET_PROCESS_EXECNAME, 
								&Pid, sizeof Pid, ExecName, ExecNameLength, &BytesReturned, NULL);
	return rc == TRUE;
}

bool CGswDrv::GetObjectAttributes(const HANDLE hObject, const NtObjectType Type, const ULONG RuleId, EntityAttributes *Attributes)
{
	GetObjectAttributesInfo Info;
	Info.hObject = hObject;
	Info.Type = Type;
	Info.RuleId = RuleId;
	memcpy(Info.Label, &GesRule::GswLabel, sizeof GesRule::GswLabel);

	ObjectAttributesInfo ObjectInfo;
	DWORD BytesReturned;
	BOOL rc = DeviceIoControl(hDevice, GESWALL_IOCTL_GET_OBJ_ATTRIBUTES, &Info, sizeof Info, &ObjectInfo, sizeof ObjectInfo, &BytesReturned, NULL);
	if ( rc == TRUE ) {
		*Attributes = ObjectInfo.Attr;
	}

	return rc == TRUE;
}


bool CGswDrv::IsFileUntrusted(const wchar_t *FileName)
{
	bool Result = false;

	HANDLE hFile = CreateFile(FileName, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) return Result;

	EntityAttributes Attributes;
	Result = GetObjectAttributes(hFile, nttFile, 0, &Attributes);
	CloseHandle(hFile);
	
	if ( Result && Attributes.Param[GesRule::attIntegrity] < GesRule::modTCB && Attributes.Param[GesRule::attIntegrity] > GesRule::modUndefined ) {
		return true;
	}

	return false;
}

int CGswDrv::GetReleaseId(void)
{
	LONG ReleaseId = 0;
	DWORD BytesReturned;
	BOOL rc = DeviceIoControl(hDevice, GESWALL_IOCTL_GET_RELEASE_ID, NULL, 0, &ReleaseId, sizeof ReleaseId, &BytesReturned, NULL);
	if ( rc == TRUE ) return ReleaseId;
	return 0;
}
