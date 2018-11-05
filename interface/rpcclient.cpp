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
#else 
 #include "stdafx.h"
#endif // __GSW_NO_STD_AFX__

#include "rpcclient.h"

RpcClient::RpcClient(void)
{
    hBinding = NULL;
    SecurityLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    Protocol = L"ncalrpc";
}

RpcClient::RpcClient(const wchar_t *_Server, const wchar_t *_Protocol, const ULONG _SecurityLevel)
{
    RpcClient();
    Bind(_Server, _Protocol, _SecurityLevel);
}

RpcClient::~RpcClient()
{
    UnBind();
}

bool RpcClient::Bind(const wchar_t *_Server, const wchar_t *_Protocol, const ULONG _SecurityLevel)
{
    if ( _Server != NULL ) Server = _Server;
    if ( _Protocol != NULL ) Protocol = _Protocol;
    SecurityLevel = _SecurityLevel;
    return Bind();
}

bool RpcClient::Bind(void)
{
    if ( hBinding != NULL ) UnBind();

    RPC_STATUS st;
    unsigned short *StringBinding;
    st = RpcStringBindingCompose(NULL, (wchar_t *)Protocol.c_str(), (wchar_t *)Server.c_str(), NULL, NULL, &StringBinding);
    if ( st != RPC_S_OK ) return false;

    st = RpcBindingFromStringBinding(StringBinding, &hBinding);
    RpcStringFree(&StringBinding);
    if ( st != RPC_S_OK ) return false;

    st = RpcBindingSetAuthInfo(hBinding, 0, SecurityLevel, RPC_C_AUTHN_WINNT, 0, 0);
    if ( st != RPC_S_OK ) {
        UnBind();
        return false;
    }

    return true;
}

bool RpcClient::UnBind(void)
{
    if ( hBinding == NULL ) return false;

    RPC_STATUS st = RpcBindingFree(&hBinding);
    if ( st != RPC_S_OK ) return false;

    hBinding = NULL;
    return true;
}

void __RPC_FAR * __RPC_USER MIDL_user_allocate(size_t len)
{
    return(malloc(len));
}

void __RPC_USER MIDL_user_free(void __RPC_FAR * ptr)
{
    free(ptr);
}
