//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "rpcserv.h"
#include "ifgswrpc_h.h"
#include "ifstatus.h"
#include "gswproc.h"
#include "commonlib.h"

#include "guictrl/execsupport.h"

#include <string>

using namespace std;

namespace RpcServ {

RPC_IF_HANDLE IfSpec[] = {
    GSWRPC_v1_0_s_ifspec
};

wchar_t *Protocol[] = { L"ncalrpc" };
const unsigned int MaxCalls = 50;
static RPC_BINDING_VECTOR *BindingVector = NULL;

bool AccessCheck(handle_t IDL_handle, GesRule::ModelType &Model, ULONG &Options)
{
	RpcImpersonateClient(IDL_handle);
	bool Result = GswProc::AccessCheck(Model, Options);
	RpcRevertToSelf();
	return Result;
}

bool Init(void)
{
    RPC_STATUS st;

    for ( int i = 0; i < sizeof IfSpec / sizeof IfSpec[0]; i++ ) {
        st = RpcServerRegisterIfEx(IfSpec[i], NULL, NULL, RPC_IF_AUTOLISTEN, MaxCalls, NULL);
        if ( st != RPC_S_OK ) {
            trace("RpcServerRegisterIfEx error: %d\n", st);
            return false;
        }
    }

    for ( i = 0; i < sizeof Protocol / sizeof Protocol[0]; i++ ) {
        st = RpcServerUseProtseq(Protocol[i], RPC_C_PROTSEQ_MAX_REQS_DEFAULT, NULL);   
        if ( st != RPC_S_OK ) {
            trace("RpcServerUseProtseq error: %d\n", st);
            return false;
        }
    }

    st = RpcServerInqBindings(&BindingVector);
    if ( st != RPC_S_OK ) {
        Release();
        trace("RpcServerInqBindings error: %d\n", st);
        return false;
    }
    
    for ( int i = 0; i < sizeof IfSpec / sizeof IfSpec[0]; i++ ) {
        st = RpcEpRegister(IfSpec[i], BindingVector, NULL, NULL);
        if ( st != RPC_S_OK ) {
            Release();
            trace("RpcEpRegister error: %d\n", st);
            return false;
        }
    }

    return true;
}

void Release(void)
{
    RPC_STATUS st;

    if ( BindingVector != NULL ) {
        for ( int i = 0; i < sizeof IfSpec / sizeof IfSpec[0]; i++ ) {
            st = RpcEpUnregister(IfSpec[i], BindingVector, NULL);
            if ( st != RPC_S_OK ) {
                trace("RpcEpUnregister error: %d\n", st);
            }
        }

        st = RpcBindingVectorFree(&BindingVector);
        if ( st != RPC_S_OK ) {
            trace("RpcBindingVectorFree error: %d\n", st);
        }
    }

    for ( int i = 0; i < sizeof IfSpec / sizeof IfSpec[0]; i++ ) {
        st = RpcServerUnregisterIf(IfSpec[i], NULL, TRUE);
        if ( st != RPC_S_OK ) {
            trace("RpcServerUnregisterIf error: %d\n", st);
        }
    }
}

} // namespace RpcServ

error_status_t GswrpcRefreshResources(
    /* [in] */ handle_t IDL_handle)
{
    return GswProc::RefreshResources();
}

error_status_t GswrpcRefreshApp( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ int AppId)
{
    return GswProc::RefreshApp(AppId);
}

error_status_t GswrpcRefreshApplications(
    /* [in] */ handle_t IDL_handle)
{
    return GswProc::RefreshApplications();
}

error_status_t GswrpcQueryAuthorizationObject(
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [out] */ wchar_t objectName[ 512 ])
{
    RpcImpersonateClient(IDL_handle);
    
    wstring objName;

    error_status_t result =  GswProc::QueryAuthorizationObject (LongToHandle (processId), objName);
    if (ifstatus::errSuccess == result)
      StringCchCopy (objectName, 512, objName.c_str ());
    
    RpcRevertToSelf();

    return result;
}

error_status_t GswrpcRegisterClient(
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId, 
    /* [in] */ unsigned int objectHandle, 
    /* [out] */ wchar_t authorityHash[ 512 ])
{
    RpcImpersonateClient(IDL_handle);
    
    wstring authority;

    error_status_t result =  GswProc::RegisterClient (LongToHandle (processId), LongToHandle (objectHandle), authority);
    if (ifstatus::errSuccess == result)
      StringCchCopy (authorityHash, 512, authority.c_str ());
    
    RpcRevertToSelf();
    
    return result;
}


error_status_t GswrpcPutReply( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [in] */ wchar_t* authorityHash,
    /* [in] */ int RequestId,
    /* [in] */ int Reply)
{
    RpcImpersonateClient(IDL_handle);
    error_status_t result =  GswProc::PutUiReply (LongToHandle (processId), wstring (authorityHash), RequestId, Reply);
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcUiRequest( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [in] */ wchar_t authorityHash[ 512 ],
    /* [out] */ int *RequestId,
    /* [out] */ GUIRequestInfo *Request)
{
    RpcImpersonateClient(IDL_handle);

	authorityHash[512 - 1] = 0;
    error_status_t result = GswProc::WaitUiRequest (LongToHandle (processId), wstring (authorityHash), *RequestId, *Request);
    
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcCancelUiRequest( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [in] */ wchar_t authorityHash[ 512 ])
{
    RpcImpersonateClient(IDL_handle);

	authorityHash[512 - 1] = 0;
    error_status_t result = GswProc::CancelWaitUiRequest (LongToHandle (processId), wstring (authorityHash));
    
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcUpdateDb( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [in] */ wchar_t authorityHash[ 512 ],
    /* [out] */ int* updateResult)
{
    RpcImpersonateClient(IDL_handle);

	authorityHash[512 - 1] = 0;
    error_status_t result = GswProc::UpdateDb (LongToHandle (processId), wstring (authorityHash), *updateResult);
    
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcCheckUpdateDb( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [in] */ wchar_t authorityHash[ 512 ],
    /* [out] */ int* updateResult)
{
    RpcImpersonateClient(IDL_handle);

	authorityHash[512 - 1] = 0;
    error_status_t result = GswProc::CheckUpdateDb (LongToHandle (processId), wstring (authorityHash), *updateResult);
    
    RpcRevertToSelf();
    return result;
}


error_status_t GswrpcGetProcessState( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [out] */ int* processState)
{
	return ifstatus::errUnsuccess;

	RpcImpersonateClient(IDL_handle);

    error_status_t result = GswProc::GetProcessState (LongToHandle (processId), *processState);
    
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcCancelPMWait( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId)
{
	return ifstatus::errUnsuccess;

	RpcImpersonateClient(IDL_handle);

    error_status_t result = GswProc::CancelPMWait (LongToHandle (processId));
    
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcGetDesktopHook( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [in] */ wchar_t* desktopName,
    /* [out] */ unsigned int* hook_handle)
{
	return ifstatus::errUnsuccess;

	RpcImpersonateClient(IDL_handle);

    error_status_t result = GswProc::GetDesktopHook (LongToHandle (processId), wstring (desktopName), *(reinterpret_cast <HHOOK*> (hook_handle)));
    
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcSetDesktopHook( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [in] */ wchar_t* desktopName,
    /* [in] */ unsigned int hook_handle)
{
	return ifstatus::errUnsuccess;

	RpcImpersonateClient(IDL_handle);

    error_status_t result = GswProc::SetDesktopHook (LongToHandle (processId), wstring (desktopName), (HHOOK) LongToHandle (hook_handle));
    
    RpcRevertToSelf();
    return result;
}

error_status_t GswrpcWaitProcessMarkerInfo(
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId,
    /* [out] */ ProcMarkerInfo* processInfo,
    /* [in] */ int timeout)
{
	return ifstatus::errUnsuccess;

	RpcImpersonateClient(IDL_handle);

    error_status_t result = GswProc::WaitProcessMarkerInfo (LongToHandle (processId), *processInfo, timeout);
    
    RpcRevertToSelf();
    return result;
} // GswrpcWaitProcessMarkerInfo

error_status_t GswrpcRefreshSettings( 
    /* [in] */ handle_t IDL_handle)
{
	error_status_t result = GswProc::RefreshSettings();
    return result;
}

error_status_t GswrpcRegisterExecClient (
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId)
{
	return ifstatus::errUnsuccess;

	error_status_t result = ifstatus::errUnsuccess;

	RpcImpersonateClient(IDL_handle);

	result = (true == gswserv::guictrl::exec_support::registerClient (LongToHandle (processId))) ? 
             ifstatus::errSuccess : ifstatus::errUnsuccess;
  
	RpcRevertToSelf();
  
	return result;
} // GswrpcRegisterExecClient

error_status_t GswrpcCreateProcess (
    /* [in]         */ handle_t      IDL_handle,
    /* [in]         */ unsigned int  processId,
    /* [in]         */ int           exec_type,
    /* [in, string] */ LPCWSTR       applicationName,
    /* [in, string] */ LPWSTR        commandLine,
    /* [in]         */ BOOL          inheritHandles,
    /* [in]         */ DWORD         creationFlags,
    /* [in, string] */ LPCWSTR       currentDirectory,
    /* [out]		*/ STARTUPINFO_t lpStartupInfo,
    /* [out]        */ ExecResult*   result
  )
{
	return ifstatus::errUnsuccess;
} // GswrpcCreateProcess

error_status_t GswrpcCreateProcessWait (
    /* [in]         */ handle_t      IDL_handle,
    /* [in]         */ unsigned int  processId,
    /* [out]        */ int*          int_exec_type,
    /* [out]        */ unsigned int* parentToken,
    /* [out]        */ wchar_t*      applicationName /*[1024]*/,
    /* [out]        */ wchar_t*      commandLine /*[1024]*/,
    /* [out]        */ BOOL*         inheritHandles,
    /* [out]        */ DWORD*        creationFlags,
    /* [out]        */ wchar_t*      currentDirectory /*[1024]*/,
    /* [out]		*/ STARTUPINFO_t *lpStartupInfo,
    /* [out]        */ int*          requestId
  )
{
	return ifstatus::errUnsuccess;
} // GswrpcCreateProcessWait

error_status_t GswrpcCreateProcessResult (
    /* [in]         */ handle_t      IDL_handle,
    /* [in]         */ unsigned int  processId,
    /* [in]         */ int           requestId,
    /* [in]         */ ExecResult*   result
  )
{
	return ifstatus::errUnsuccess;
} // GswrpcCreateProcessResult

error_status_t GswrpcCancelCreateProcessWait ( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ unsigned int processId)
{
	return ifstatus::errUnsuccess;
} // GswrpcCancelCreateProcessWait

error_status_t GswrpcSetParamsModifier( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ ModifierType Type,
    /* [in] */ unsigned int ProcessId,
    /* [in] */ unsigned int ThreadId)
{
	GesRule::ModelType Model;
	ULONG Options;
	if ( !RpcServ::AccessCheck(IDL_handle, Model, Options) ) {
		if ( Type == modAlwaysTrusted || Model < GesRule::modTCB ) return ifstatus::errAccessDenied;
	}

	return GswProc::SetModifier(Type, ProcessId, ThreadId);
}

error_status_t GswrpcGetNumberOfTrialDays( 
    /* [in] */ handle_t IDL_handle,
    /* [out] */ int *DaysNum)
{
	return GswProc::GetNumberOfTrialDays(*DaysNum);
}

error_status_t GswrpcSwitchToLicense( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ wchar_t LicenseFile[ 512 ])
{
	LicenseFile[512 - 1] = 0;

    RpcImpersonateClient(IDL_handle);
	GesRule::ModelType Model;
	ULONG Options;
	GswProc::AccessCheck(Model, Options);
	if ( Model != GesRule::modTCB || !( Options & GesRule::oboKeepTrusted ) ) {
		RpcRevertToSelf();
		return ifstatus::errAccessDenied;
	}

	HANDLE hToken = NULL;
	OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, FALSE, &hToken);
	RpcRevertToSelf();
	if ( hToken == NULL ) return ifstatus::errUnsuccess;

	error_status_t Result = GswProc::SwitchToLicense(LicenseFile, hToken);
	CloseHandle(hToken);

	return Result;
}

void __RPC_FAR * __RPC_USER MIDL_user_allocate(size_t len)
{
    return(malloc(len));
}

void __RPC_USER MIDL_user_free(void __RPC_FAR * ptr)
{
    free(ptr);
}
