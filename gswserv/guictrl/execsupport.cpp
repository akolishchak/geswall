//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "execsupport.h"
#include "execrequest.h"
#include "execresponse.h"

#include "commonlib/commondefs.h"

namespace gswserv {
namespace guictrl {

static exec_support::client_manager   m_manager;

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

static HANDLE duplicate_handle (HANDLE src_handle, DWORD src_process_id, DWORD dst_process_id);
static HANDLE duplicate_handle (HANDLE src_handle, HANDLE src_process_handle, HANDLE dst_process_handle);

bool exec_support::init ()
{
  return true;
} // init


void exec_support::clear ()
{
  m_manager.unregisterAllClients ();
} // clear

bool exec_support::registerClient (HANDLE processId)
{
  bool result = false;

  ptr_to_client client = ptr_to_client (new exec_client (processId));
  try
  {
    m_manager.registerClient (client_id (processId, client_id::srv_exec), client);
    result = true;
  }
  catch (GUICtrlException&)
  {
  }

  return result;
} // registerClient

bool exec_support::createProcess (HANDLE processId, ExecType exec_type, LPCWSTR applicationName, LPWSTR commandLine, BOOL inheritHandles, DWORD creationFlags, LPCWSTR currentDirectory, STARTUPINFO_t *lpStartupInfo, ExecResult& exec_result)
{
  bool result = false;

  ptr_to_client client = m_manager.getClient (client_id (processId, client_id::srv_exec));
  if (NULL != client.get ())
  {
    ptr_to_exec_request request (new exec_request (processId, exec_type, applicationName, commandLine, inheritHandles, creationFlags, currentDirectory, lpStartupInfo));
    if (NULL != request.get ())
    {
      ptr_to_exec_response response = ptr_to_exec_response (client->call (request, 30*1000), boost::detail::static_cast_tag ());
      if (NULL != response.get ())
      {
        result = response->getReply ();
        
        exec_result.m_result         = (true == result) ? TRUE : FALSE;
        exec_result.m_process_id     = response->getProcessId ();
        exec_result.m_thread_id      = response->getThreadId ();
        exec_result.m_process_handle = HandleToLong (response->getProcessHandle ());
        exec_result.m_thread_handle  = HandleToLong (response->getThreadHandle ());
      }  
    }
  }

  return result;
} // createProcess

struct impersonate_finalizer
{
  void operator () (int fake_data)
  {
    ::RevertToSelf ();
  }
}; // impersonate_finalizer

// string buffer size = 1024
bool exec_support::createProcessWait (handle_t idl_handle, HANDLE processId, ExecType& exec_type, HANDLE& parentToken, wchar_t* applicationName, wchar_t* commandLine, BOOL& inheritHandles, DWORD& creationFlags, wchar_t* currentDirectory, STARTUPINFO_t *lpStartupInfo, int& requestId)
{
  bool result = false;

  RpcImpersonateClient (idl_handle);
  scope_guard rpc_revert_guard = make_guard (0, impersonate_finalizer ());
  
  ptr_to_client client = m_manager.getClient (client_id (processId, client_id::srv_exec));
  if (NULL != client.get ())
  {
    //rpc_revert_guard.free ();
    
    ptr_to_exec_request request = ptr_to_exec_request (client->waitCall (Client::Const::infiniteTimeout), boost::detail::static_cast_tag ());
    if (NULL != request.get ())
    {
      HANDLE      dst_process_handle       = ::OpenProcess (PROCESS_DUP_HANDLE, FALSE, HandleToUlong (processId));
      scope_guard dst_process_handle_guard = make_guard (dst_process_handle, &::CloseHandle);  
      
      exec_type   = request->m_exec_type;
      parentToken = duplicate_handle (request->m_token, request->m_process_handle, dst_process_handle);
                    //duplicate_handle (request->m_token, request->m_processId, processId);
      
      request->m_applicationName.copy (applicationName, 1024);
      request->m_commandLine.copy (commandLine, 1024);
      request->m_currentDirectory.copy (currentDirectory, 1024);
	  request->m_StartupInfo.copy (lpStartupInfo);

	  if ( lpStartupInfo->hStdError != NULL )
		  lpStartupInfo->hStdError = HandleToUlong(duplicate_handle (UlongToHandle(lpStartupInfo->hStdError), request->m_process_handle, dst_process_handle));
	  if ( lpStartupInfo->hStdInput != NULL )
		  lpStartupInfo->hStdInput = HandleToUlong(duplicate_handle (UlongToHandle(lpStartupInfo->hStdInput), request->m_process_handle, dst_process_handle));
	  if ( lpStartupInfo->hStdOutput != NULL )
		  lpStartupInfo->hStdOutput = HandleToUlong(duplicate_handle (UlongToHandle(lpStartupInfo->hStdOutput), request->m_process_handle, dst_process_handle));

      inheritHandles = request->m_inheritHandles;
      creationFlags  = request->m_creationFlags;
      requestId      = request->getId ();
      result         = true;
    }
  } // if (NULL != client.get ())

  return result;
} // createProcessWait

void exec_support::createProcessResult (handle_t idl_handle, HANDLE processId, int requestId, const ExecResult& reply)
{
  createProcessResult (
    idl_handle, 
    processId, 
    ptr_to_exec_response (
      new exec_response (
        requestId, 
        (TRUE == reply.m_result), 
        reply.m_process_id,
        reply.m_thread_id,
        LongToHandle (reply.m_process_handle),
        LongToHandle (reply.m_thread_handle)
      )
    )
  );
} // createProcessResult

void exec_support::createProcessResult (handle_t idl_handle, HANDLE processId, const ptr_to_exec_response& response)
{
  RpcImpersonateClient (idl_handle);
  scope_guard rpc_revert_guard = make_guard (0, impersonate_finalizer ());
  
  ptr_to_client client = m_manager.getClient (client_id (processId, client_id::srv_exec));
  if (NULL != response.get () && NULL != client.get ())
  {
    //rpc_revert_guard.free ();
    
    ptr_to_exec_request request = ptr_to_exec_request (client->getRequest (response->getParentRequestId ()), boost::detail::static_cast_tag ());
    if (NULL != request.get ())
    {
      HANDLE      src_process_handle       = ::OpenProcess (PROCESS_DUP_HANDLE, FALSE, HandleToUlong (processId));
      scope_guard src_process_handle_guard = make_guard (src_process_handle, &::CloseHandle);  
      
      response->setProcessHandle (duplicate_handle (response->getProcessHandle (), src_process_handle, request->m_process_handle));
      response->setThreadHandle (duplicate_handle (response->getThreadHandle (), src_process_handle, request->m_process_handle));
      client->setReply (response->getParentRequestId (), response);
    }
  }  
} // createProcessResult

void exec_support::cancelCreateProcessWait (HANDLE processId)
{
  ptr_to_client client = m_manager.getClient (client_id (processId, client_id::srv_exec));
  if (NULL != client.get ())
    client->cancelWait ();
} // cancelCreateProcessWait

HANDLE duplicate_handle (HANDLE src_handle, DWORD src_process_id, DWORD dst_process_id)
{
  HANDLE dst_handle    = NULL;
  
  HANDLE h_src_process = ::OpenProcess (PROCESS_DUP_HANDLE, FALSE, src_process_id);
  if (NULL == h_src_process)
    return dst_handle;
    
  scope_guard h_src_process_guard = make_guard (h_src_process, &::CloseHandle);  
  
  HANDLE h_dst_process = ::OpenProcess (PROCESS_DUP_HANDLE, FALSE, dst_process_id);
  if (NULL == h_dst_process)
    return dst_handle;
    
  scope_guard h_dst_process_guard = make_guard (h_dst_process, &::CloseHandle);  
  
  dst_handle = duplicate_handle (src_handle, h_src_process, h_dst_process);
    
  return dst_handle;  
} // duplicateHandle

HANDLE duplicate_handle (HANDLE src_handle, HANDLE src_process_handle, HANDLE dst_process_handle)
{
  HANDLE dst_handle    = NULL;
  
  if (FALSE == ::DuplicateHandle (src_process_handle, src_handle, dst_process_handle, &dst_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
    dst_handle = NULL;
    
  return dst_handle;  
} // duplicate_handle

} // namespace guictrl {
} // namespace gswserv {

