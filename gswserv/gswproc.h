//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswproc_h__
#define __gswproc_h__

#include "stdafx.h"
#include <rpcdce.h>
#include "ifgswrpc_h.h"

#include <string>

using namespace std;

namespace GswProc {

    error_status_t RefreshResources(void);
    error_status_t RefreshApp(int AppId);
    error_status_t RefreshApplications(void);
    error_status_t RefreshSettings(void);

    error_status_t QueryAuthorizationObject (HANDLE processId, wstring& objectName);
    error_status_t RegisterClient (HANDLE processId, HANDLE objectHandle, wstring& authorityHash);
    error_status_t WaitUiRequest(HANDLE processId, const wstring& authorityHash, int& RequestId, GUIRequestInfo& Request);
    error_status_t CancelWaitUiRequest(HANDLE processId, const wstring& authorityHash);
    error_status_t PutUiReply(HANDLE processId, const wstring& authorityHash, int RequestId, int Reply);

    error_status_t UpdateDb(HANDLE processId, const wstring& authorityHash, int& updateResult);
    error_status_t CheckUpdateDb(HANDLE processId, const wstring& authorityHash, int& updateResult);

    error_status_t GetProcessState(HANDLE processId, int& processState);
    error_status_t CancelPMWait(HANDLE processId);

    error_status_t GetDesktopHook(HANDLE processId, const wstring& desktopName, HHOOK& hook);
    error_status_t SetDesktopHook(HANDLE processId, const wstring& desktopName, HHOOK hook);

    error_status_t WaitProcessMarkerInfo(const HANDLE processId, ProcMarkerInfo& processInfo, int timeout);
	bool AccessCheck(GesRule::ModelType &Model, ULONG &Options);
	error_status_t SetModifier(const ModifierType Type, const DWORD ProcessId, const DWORD ThreadId);
	error_status_t GetNumberOfTrialDays(int &DaysNum);
	error_status_t SwitchToLicense(const wstring &LicenseFile, HANDLE hToken);

}; // namespace GswProc {

#endif // __gswproc_h__