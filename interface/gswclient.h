//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswclient_h__
#define __gswclient_h__

#ifdef __GSW_NO_STD_AFX__
 #include <windows.h>
#else 
 #include "stdafx.h"
#endif // __GSW_NO_STD_AFX__

#include "rpcclient.h"
#include "ifgswrpc_h.h"
#include "gswioctl.h"
#include "ifstatus.h"
#include "gesruledef.h"
#include "processexecutor/processexecutor.h"

#include <string>

using namespace std;

class GswClient {
public:
    GswClient(void);
    ~GswClient();
    ifstatus::Error RefreshResources(void);
    ifstatus::Error RefreshApp(int AppId);
    ifstatus::Error RefreshApplications(void);
    ifstatus::Error RefreshSettings(void);

    ifstatus::Error QueryAuthorizationObject(const HANDLE processId, wstring& objectName);
    ifstatus::Error RegisterClient(const HANDLE processId, const HANDLE objectHandle, wstring& authorityHash);

    ifstatus::Error PutReply(const HANDLE processId, const wstring& authorityHash, const int RequestId, const GUIReply Reply);
    ifstatus::Error UiRequest(const HANDLE processId, const wstring& authorityHash, int &RequestId, GUIRequestInfo &Request);
    ifstatus::Error CancelUiRequest(const HANDLE processId, const wstring& authorityHash);

    ifstatus::Error UpdateDb(const HANDLE processId, const wstring& authorityHash, int& updateResult);
    ifstatus::Error CheckUpdateDb(const HANDLE processId, const wstring& authorityHash, int& updateResult);

    ifstatus::Error GetProcessState(const HANDLE processId, GesRule::ModelType& processState);
    ifstatus::Error CancelPMWait(const HANDLE processId);

    ifstatus::Error GetDesktopHook(const HANDLE processId, const wstring& desktopName, HHOOK& hook);
    ifstatus::Error SetDesktopHook(const HANDLE processId, const wstring& desktopName, HHOOK hook);

    ifstatus::Error WaitProcessMarkerInfo(const HANDLE processId, ProcMarkerInfo& processInfo, int timeout);

    ifstatus::Error RegisterExecClient (const HANDLE processId);
    ifstatus::Error CreateProcess (const HANDLE processId, procexec::ExecType exec_type, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, BOOL bInheritHandles, DWORD dwCreationFlags, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, ExecResult& result);
    ifstatus::Error CreateProcessWait (const HANDLE processId, procexec::ExecType& exec_type, HANDLE& token, wstring& applicationName, wstring& commandLine, BOOL& inheritHandles, DWORD& creationFlags, wstring& currentDirectory, STARTUPINFOW &StartupInfo, int& requestId);
    ifstatus::Error CreateProcessResult (const HANDLE processId, int requestId, const ExecResult& result);
    ifstatus::Error CancelCreateProcessWait (const HANDLE processId);
	ifstatus::Error SetParamsModifier(const ModifierType Type, DWORD processId, DWORD threadId);
	ifstatus::Error GetNumberOfTrialDays(int &DaysNum);
	ifstatus::Error SwitchToLicense(const wstring &LicenseFile);

private:
    RpcClient Rpc;
};

#endif // __gswclient_h__