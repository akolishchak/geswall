//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __rpcclient_h__
#define __rpcclient_h__

#include <string>

class RpcClient {
public:
	RpcClient(void);
	RpcClient(const wchar_t *_Server, const wchar_t *_Protocol, const ULONG _SecurityLevel);
	~RpcClient();

	bool Bind(void);
	bool Bind(const wchar_t *_Server, const wchar_t *_Protocol, const ULONG _SecurityLevel);
    bool UnBind(void);

	operator RPC_BINDING_HANDLE() { return hBinding; };

private:
	RPC_BINDING_HANDLE hBinding;
	ULONG SecurityLevel;
	std::wstring Server;
	std::wstring Protocol;

};

#endif // __rpcclient_h__