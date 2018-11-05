//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswserv_guictrl_exec_support_h_
 #define _gswserv_guictrl_exec_support_h_

#include "stdafx.h"
#include <rpcdce.h>

#include "smartclientmanager.h"
#include "execclient.h"
#include "sessionclientid.h"
#include "execrequest.h"
#include "execresponse.h"

#include "ifgswrpc_h.h"

#include <string>

using namespace std;

namespace gswserv {
namespace guictrl {

class exec_support;

class exec_support
{
  public:
   typedef SmartClientManager<exec_client, SessionClientId> client_manager;
   typedef client_manager::Client                           client;
   typedef client_manager::PtrToClient                      ptr_to_client;
   typedef client_manager::ClientId                         client_id;
   typedef Request::PtrToRequest                            ptr_to_request;
   typedef exec_request::PtrToRpcRequest                    ptr_to_rpc_request;
   typedef exec_response::PtrToRpcReply                     ptr_to_rpc_reply;
   typedef commonlib::SyncObject                            sync_object;
   typedef commonlib::Locker                                locker;
   typedef exec_request::ExecType                           ExecType;

  public:
   static bool   init  ();
   static void   clear ();
  
   static bool   registerClient (HANDLE processId);

   static bool   createProcess (HANDLE processId, ExecType exec_type, LPCWSTR applicationName, LPWSTR commandLine, BOOL inheritHandles, DWORD creationFlags, LPCWSTR currentDirectory, STARTUPINFO_t *lpStartupInfo, ExecResult& exec_result);
   static bool   createProcessWait (handle_t idl_handle, HANDLE processId, ExecType& exec_type, HANDLE& parentToken, wchar_t* applicationName, wchar_t* commandLine, BOOL& inheritHandles, DWORD& creationFlags, wchar_t* currentDirectory, STARTUPINFO_t *lpStartupInfo, int& requestId);
   static void   createProcessResult (handle_t idl_handle, HANDLE processId, int requestId, const ExecResult& result);
   static void   createProcessResult (handle_t idl_handle, HANDLE processId, const ptr_to_exec_response& response);
   static void   cancelCreateProcessWait (HANDLE processId);

  protected:
  private:
   exec_support () {}
   exec_support (const exec_support& right) {}
   exec_support& operator= (const exec_support& right) { return *this; }
   ~exec_support () {}

  private:
}; // exec_support

} // namespace guictrl
} // namespace gswserv 

#endif //_gswserv_guictrl_exec_support_h_
