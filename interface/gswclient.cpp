//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifdef __GSW_NO_STD_AFX__
 #include <windows.h>
 #include <string>
 
 using namespace std;
#else 
 #include "stdafx.h"
#endif // __GSW_NO_STD_AFX__

#include "rpcclient.h"
#include "gswclient.h"
#include "ifgswrpc_h.h"
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

GswClient::GswClient(void)
{
    Rpc.Bind();
}

GswClient::~GswClient()
{
}

ifstatus::Error GswClient::RefreshResources(void)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        Res = (ifstatus::Error) GswrpcRefreshResources(Rpc);
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
}

ifstatus::Error GswClient::RefreshApp(int AppId)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        Res = (ifstatus::Error) GswrpcRefreshApp(Rpc, AppId);
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
}

ifstatus::Error GswClient::RefreshApplications(void)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        Res = (ifstatus::Error) GswrpcRefreshApplications(Rpc);
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
}

ifstatus::Error GswClient::RefreshSettings(void)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        Res = (ifstatus::Error) GswrpcRefreshSettings(Rpc);
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
}

ifstatus::Error GswClient::QueryAuthorizationObject(const HANDLE processId, wstring& objectName)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        wchar_t objName[512];

        objName [0] = 0;

        Res = (ifstatus::Error) GswrpcQueryAuthorizationObject(Rpc, HandleToLong (processId), objName);
        if (ifstatus::errSuccess == Res)
          objectName = objName;
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
} // QueryAuthorizationObject

ifstatus::Error GswClient::RegisterClient(const HANDLE processId, const HANDLE objectHandle, wstring& authorityHash)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        wchar_t authority[512];

        authority [0] = 0;

        Res = (ifstatus::Error) GswrpcRegisterClient(Rpc, HandleToLong (processId), HandleToLong (objectHandle), authority);
        if (ifstatus::errSuccess == Res)
          authorityHash = authority;
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
} // RegisterClient

ifstatus::Error GswClient::PutReply(const HANDLE processId, const wstring& authorityHash, const int RequestId, const GUIReply Reply)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        wchar_t authority[512];

        StringCchCopy (authority, 512, authorityHash.c_str ());

        Res = (ifstatus::Error) GswrpcPutReply(Rpc, HandleToLong (processId), authority, RequestId, Reply);
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
}

ifstatus::Error GswClient::UiRequest(const HANDLE processId, const wstring& authorityHash, int &RequestId, GUIRequestInfo &Request)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        wchar_t authority[512];

        StringCchCopy (authority, 512, authorityHash.c_str ());

        Res = (ifstatus::Error) GswrpcUiRequest(Rpc, HandleToLong (processId), authority, &RequestId, &Request);
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
}

ifstatus::Error GswClient::CancelUiRequest (const HANDLE processId, const wstring& authorityHash)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        wchar_t authority[512];

        StringCchCopy (authority, 512, authorityHash.c_str ());

        Res = (ifstatus::Error) GswrpcCancelUiRequest (Rpc, HandleToLong (processId), authority);
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
} // CancelUiRequest

ifstatus::Error GswClient::UpdateDb (const HANDLE processId, const wstring& authorityHash, int& updateResult)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        wchar_t authority[512];

        StringCchCopy (authority, 512, authorityHash.c_str ());

        Res = (ifstatus::Error) GswrpcUpdateDb (Rpc, HandleToLong (processId), authority, reinterpret_cast <int*> (&updateResult));
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
} // UpdateDb

ifstatus::Error GswClient::CheckUpdateDb (const HANDLE processId, const wstring& authorityHash, int& updateResult)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  RpcTryExcept {
      wchar_t authority[512];

      StringCchCopy (authority, 512, authorityHash.c_str ());

      Res = (ifstatus::Error) GswrpcCheckUpdateDb (Rpc, HandleToLong (processId), authority, reinterpret_cast <int*> (&updateResult));
  } RpcExcept(1) {
  } RpcEndExcept
  return Res;
} // CheckUpdateDb

ifstatus::Error GswClient::GetProcessState (const HANDLE processId, GesRule::ModelType& processState)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  RpcTryExcept {
      Res = (ifstatus::Error) GswrpcGetProcessState (Rpc, HandleToLong (processId), reinterpret_cast <int*> (&processState));
  } RpcExcept(1) {
  } RpcEndExcept
  return Res;
} // GetProcessState

ifstatus::Error GswClient::CancelPMWait (const HANDLE processId)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        Res = (ifstatus::Error) GswrpcCancelPMWait (Rpc, HandleToLong (processId));
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
} // CancelPMWait

ifstatus::Error GswClient::GetDesktopHook (const HANDLE processId, const wstring& desktopName, HHOOK& hook)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  RpcTryExcept{
      wchar_t desktop[512];

      StringCchCopy (desktop, 512, desktopName.c_str ());

      Res = (ifstatus::Error) GswrpcGetDesktopHook (Rpc, HandleToLong (processId), desktop, reinterpret_cast <unsigned int*> (&hook));
  } RpcExcept(1) {
  } RpcEndExcept
  return Res;
} // GetDesktopHook

ifstatus::Error GswClient::SetDesktopHook (const HANDLE processId, const wstring& desktopName, HHOOK hook)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  RpcTryExcept {
      wchar_t desktop[512];

      StringCchCopy (desktop, 512, desktopName.c_str ());

      Res = (ifstatus::Error) GswrpcSetDesktopHook (Rpc, HandleToLong (processId), desktop, HandleToLong (hook));
  } RpcExcept(1) {
  } RpcEndExcept
  return Res;
} // SetDesktopHook

ifstatus::Error GswClient::WaitProcessMarkerInfo (const HANDLE processId, ProcMarkerInfo& processInfo, int timeout)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  RpcTryExcept {
      Res = (ifstatus::Error) GswrpcWaitProcessMarkerInfo (Rpc, HandleToLong (processId), &processInfo, timeout);
  } RpcExcept(1) {
  } RpcEndExcept
  return Res;
} // WaitProcessMarkerInfo

ifstatus::Error GswClient::RegisterExecClient(const HANDLE processId)
{
    ifstatus::Error Res = ifstatus::errUnsuccess;
    RpcTryExcept {
        Res = (ifstatus::Error) GswrpcRegisterExecClient (Rpc, HandleToLong (processId));
    } RpcExcept(1) {
    } RpcEndExcept
    return Res;
} // RegisterClient

void ConvertToRpcStartupInfo(const STARTUPINFOW &StartupInfo, STARTUPINFO_t &RpcStartupInfo)
{
	RpcStartupInfo.cb = StartupInfo.cb;

	memset(RpcStartupInfo.lpReserved, 0, sizeof RpcStartupInfo.lpReserved);
	if ( StartupInfo.lpReserved != NULL )
		StringCbCopy(RpcStartupInfo.lpReserved, sizeof RpcStartupInfo.lpReserved, StartupInfo.lpReserved);

	memset(RpcStartupInfo.lpDesktop, 0, sizeof RpcStartupInfo.lpDesktop);
	if ( StartupInfo.lpDesktop != NULL )
		StringCbCopy(RpcStartupInfo.lpDesktop, sizeof RpcStartupInfo.lpDesktop, StartupInfo.lpDesktop);

	memset(RpcStartupInfo.lpTitle, 0, sizeof RpcStartupInfo.lpTitle);
	if ( StartupInfo.lpTitle != NULL )
		StringCbCopy(RpcStartupInfo.lpTitle, sizeof RpcStartupInfo.lpTitle, StartupInfo.lpTitle);

    RpcStartupInfo.dwX = StartupInfo.dwX;
    RpcStartupInfo.dwY = StartupInfo.dwY;
    RpcStartupInfo.dwXSize = StartupInfo.dwXSize;
    RpcStartupInfo.dwYSize = StartupInfo.dwYSize;
    RpcStartupInfo.dwXCountChars = StartupInfo.dwXCountChars;
    RpcStartupInfo.dwYCountChars = StartupInfo.dwYCountChars;
    RpcStartupInfo.dwFillAttribute = StartupInfo.dwFillAttribute;
    RpcStartupInfo.dwFlags = StartupInfo.dwFlags;
    RpcStartupInfo.wShowWindow = StartupInfo.wShowWindow;
    RpcStartupInfo.cbReserved2 = StartupInfo.cbReserved2;
    RpcStartupInfo.lpReserved2 = PtrToUlong(StartupInfo.lpReserved2);
    RpcStartupInfo.hStdInput = HandleToUlong(StartupInfo.hStdInput);
    RpcStartupInfo.hStdOutput = HandleToUlong(StartupInfo.hStdOutput);
    RpcStartupInfo.hStdError = HandleToUlong(StartupInfo.hStdError);

}
void ConvertToStartupInfo(STARTUPINFO_t &RpcStartupInfo, STARTUPINFOW &StartupInfo)
{
	StartupInfo.cb = RpcStartupInfo.cb;

	if ( RpcStartupInfo.lpReserved[0] != 0 ) 
		StartupInfo.lpReserved = RpcStartupInfo.lpReserved;
	else
		StartupInfo.lpReserved = NULL;

	if ( RpcStartupInfo.lpDesktop[0] != 0 )
		StartupInfo.lpDesktop = RpcStartupInfo.lpDesktop;
	else
		StartupInfo.lpDesktop = NULL;

	if ( RpcStartupInfo.lpTitle[0] != 0 )
		StartupInfo.lpTitle = RpcStartupInfo.lpTitle;
	else
		StartupInfo.lpTitle = NULL;

    StartupInfo.dwX = RpcStartupInfo.dwX;
    StartupInfo.dwY = RpcStartupInfo.dwY;
    StartupInfo.dwXSize = RpcStartupInfo.dwXSize;
    StartupInfo.dwYSize = RpcStartupInfo.dwYSize;
    StartupInfo.dwXCountChars = RpcStartupInfo.dwXCountChars;
    StartupInfo.dwYCountChars = RpcStartupInfo.dwYCountChars;
    StartupInfo.dwFillAttribute = RpcStartupInfo.dwFillAttribute;
    StartupInfo.dwFlags = RpcStartupInfo.dwFlags;
    StartupInfo.wShowWindow = RpcStartupInfo.wShowWindow;
    StartupInfo.cbReserved2 = RpcStartupInfo.cbReserved2;
    StartupInfo.lpReserved2 = (LPBYTE) UlongToPtr(RpcStartupInfo.lpReserved2);
    StartupInfo.hStdInput = UlongToHandle(RpcStartupInfo.hStdInput);
    StartupInfo.hStdOutput = UlongToHandle(RpcStartupInfo.hStdOutput);
    StartupInfo.hStdError = UlongToHandle(RpcStartupInfo.hStdError);

    StartupInfo.cb = sizeof(STARTUPINFOW);
}

ifstatus::Error GswClient::CreateProcess (const HANDLE processId, procexec::ExecType exec_type, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, BOOL bInheritHandles, DWORD dwCreationFlags, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, ExecResult& result)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  
  RpcTryExcept 
  {
	if ( lpStartupInfo == NULL || lpStartupInfo->cb < sizeof(STARTUPINFOW) ) return Res;
	STARTUPINFO_t RpcStartupInfo;
	ConvertToRpcStartupInfo(*lpStartupInfo, RpcStartupInfo);

    Res = (ifstatus::Error) GswrpcCreateProcess (Rpc, HandleToLong (processId), static_cast <int> (exec_type), lpApplicationName, lpCommandLine, bInheritHandles, dwCreationFlags, lpCurrentDirectory, RpcStartupInfo, &result);
  } 
  RpcExcept (1) 
  {
  } 
  RpcEndExcept

  return Res;
} // CreateProcess

ifstatus::Error GswClient::CreateProcessWait (const HANDLE processId, procexec::ExecType& exec_type, HANDLE& token, wstring& applicationName, wstring& commandLine, BOOL& inheritHandles, DWORD& creationFlags, wstring& currentDirectory, STARTUPINFOW &StartupInfo, int& requestId)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  STARTUPINFO_t RpcStartupInfo = { 0 };
  
  RpcTryExcept 
  {
    wchar_t      appName [1024] = { 0 };
    wchar_t      cmdLine [1024] = { 0 };
    wchar_t      currDir [1024] = { 0 };
    unsigned int int_token      = 0;

    Res = (ifstatus::Error) GswrpcCreateProcessWait (Rpc, HandleToLong (processId), reinterpret_cast <int*> (&exec_type), &int_token, appName, cmdLine, &inheritHandles, &creationFlags, currDir, &RpcStartupInfo, &requestId);
    if (ifstatus::errSuccess == Res)
    {
      token            = LongToHandle (int_token);
      applicationName  = appName;
      commandLine      = cmdLine;
      currentDirectory = currDir;
	  ConvertToStartupInfo(RpcStartupInfo, StartupInfo);
    }
  } 
  RpcExcept (1) 
  {
  } 
  RpcEndExcept

  return Res;
} // CreateProcessWait

ifstatus::Error GswClient::CreateProcessResult (const HANDLE processId, int requestId, const ExecResult& result)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  
  RpcTryExcept 
  {
    Res = (ifstatus::Error) GswrpcCreateProcessResult (Rpc, HandleToLong (processId), requestId, const_cast <ExecResult*> (&result));
  } 
  RpcExcept (1) 
  {
  } 
  RpcEndExcept

  return Res;
} // CreateProcessResult

ifstatus::Error GswClient::CancelCreateProcessWait (const HANDLE processId)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  
  RpcTryExcept 
  {
    Res = (ifstatus::Error) GswrpcCancelCreateProcessWait (Rpc, HandleToLong (processId));
  } 
  RpcExcept (1) 
  {
  } 
  RpcEndExcept

  return Res;
} // CancelCreateProcessWait

ifstatus::Error GswClient::SetParamsModifier(const ModifierType Type, DWORD processId, DWORD threadId)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  
  RpcTryExcept 
  {
    Res = (ifstatus::Error) GswrpcSetParamsModifier(Rpc, Type, processId, threadId);
  } 
  RpcExcept (1) 
  {
  } 
  RpcEndExcept

  return Res;
}

ifstatus::Error GswClient::GetNumberOfTrialDays(int &DaysNum)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  
  RpcTryExcept 
  {
    Res = (ifstatus::Error) GswrpcGetNumberOfTrialDays(Rpc, &DaysNum);
  } 
  RpcExcept (1) 
  {
  } 
  RpcEndExcept

  return Res;
}

ifstatus::Error GswClient::SwitchToLicense(const wstring &LicenseFile)
{
  ifstatus::Error Res = ifstatus::errUnsuccess;
  
  RpcTryExcept 
  {
    wchar_t LicFile[512];
    StringCchCopy (LicFile, 512, LicenseFile.c_str ());
    Res = (ifstatus::Error) GswrpcSwitchToLicense(Rpc, LicFile);
  } 
  RpcExcept (1) 
  {
  } 
  RpcEndExcept

  return Res;
}