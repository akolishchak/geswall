//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswserv_guictrl_exec_request_h_
 #define _gswserv_guictrl_exec_request_h_

#include "stdafx.h"
#include "rpcrequest.h"
#include "processexecutor/processexecutor.h"
#include "ifgswrpc_h.h"

#include <string>

namespace gswserv {
namespace guictrl {

struct StartupInfoW {
	StartupInfoW(STARTUPINFO_t *lpStartupInfo)
	{
		set(lpStartupInfo);
	}

	StartupInfoW(void)
	{
		cb = 0;
		dwX = 0;
		dwY = 0;
		dwXSize = 0;
		dwYSize = 0;
		dwXCountChars = 0;
		dwYCountChars = 0;
		dwFillAttribute = 0;
		dwFlags = 0;
		wShowWindow = 0;
		cbReserved2 = 0;
		lpReserved2 = NULL;
		hStdInput = NULL;
		hStdOutput = NULL;
		hStdError = NULL;
	}

	void set(STARTUPINFO_t *lpStartupInfo)
	{
		cb = lpStartupInfo->cb;
		lpReserved = lpStartupInfo->lpReserved;
		lpDesktop = lpStartupInfo->lpDesktop;
		lpTitle = lpStartupInfo->lpTitle;
		dwX = lpStartupInfo->dwX;
		dwY = lpStartupInfo->dwY;
		dwXSize = lpStartupInfo->dwXSize;
		dwYSize = lpStartupInfo->dwYSize;
		dwXCountChars = lpStartupInfo->dwXCountChars;
		dwYCountChars = lpStartupInfo->dwYCountChars;
		dwFillAttribute = lpStartupInfo->dwFillAttribute;
		dwFlags = lpStartupInfo->dwFlags;
		wShowWindow = lpStartupInfo->wShowWindow;
		cbReserved2 = lpStartupInfo->cbReserved2;
		lpReserved2 = (LPBYTE) UlongToPtr(lpStartupInfo->lpReserved2);
		hStdInput = UlongToHandle(lpStartupInfo->hStdInput);
		hStdOutput = UlongToHandle(lpStartupInfo->hStdOutput);
		hStdError = UlongToHandle(lpStartupInfo->hStdError);
	}

	void copy(STARTUPINFO_t *lpStartupInfo)
	{
		lpStartupInfo->cb = cb;
		lpReserved.copy(lpStartupInfo->lpReserved, 1024);
		lpDesktop.copy(lpStartupInfo->lpDesktop, 1024);
		lpTitle.copy(lpStartupInfo->lpTitle, 1024);
		lpStartupInfo->dwX = dwX;
		lpStartupInfo->dwY = dwY;
		lpStartupInfo->dwXSize = dwXSize;
		lpStartupInfo->dwYSize = dwYSize;
		lpStartupInfo->dwXCountChars = dwXCountChars;
		lpStartupInfo->dwYCountChars = dwYCountChars;
		lpStartupInfo->dwFillAttribute = dwFillAttribute;
		lpStartupInfo->dwFlags = dwFlags;
		lpStartupInfo->wShowWindow = wShowWindow;
		lpStartupInfo->cbReserved2 = cbReserved2;
		lpStartupInfo->lpReserved2 = PtrToUlong(lpReserved2);
		lpStartupInfo->hStdInput = HandleToUlong(hStdInput);
		lpStartupInfo->hStdOutput = HandleToUlong(hStdOutput);
		lpStartupInfo->hStdError = HandleToUlong(hStdError);
	}

    DWORD   cb;
    wstring lpReserved;
    wstring lpDesktop;
    wstring lpTitle;
    DWORD   dwX;
    DWORD   dwY;
    DWORD   dwXSize;
    DWORD   dwYSize;
    DWORD   dwXCountChars;
    DWORD   dwYCountChars;
    DWORD   dwFillAttribute;
    DWORD   dwFlags;
    WORD    wShowWindow;
    WORD    cbReserved2;
    LPBYTE  lpReserved2;
    HANDLE  hStdInput;
    HANDLE  hStdOutput;
    HANDLE  hStdError;
};

class exec_request;

class exec_request : public RpcRequest
{
  public: 
   typedef procexec::ExecType       ExecType;
   
  protected:
   typedef RpcRequest               base_type;
   typedef std::wstring             wstring;

  public:
   exec_request (HANDLE processId, ExecType exec_type, LPCWSTR applicationName, LPWSTR commandLine, BOOL inheritHandles, DWORD creationFlags, LPCWSTR currentDirectory, STARTUPINFO_t *lpStartupInfo)
    : RpcRequest (),
      m_processId (processId),
      m_exec_type (exec_type),
      m_token (open_thread_token ()),
      m_process_handle (::OpenProcess (PROCESS_DUP_HANDLE, FALSE, HandleToUlong (processId))),
	  m_StartupInfo (lpStartupInfo)
   {
     if (NULL != applicationName) 
       m_applicationName.assign (applicationName);

     if (NULL != commandLine) 
       m_commandLine.assign (commandLine);

     if (NULL != currentDirectory)
       m_currentDirectory.assign (currentDirectory);

     m_inheritHandles = inheritHandles;
     m_creationFlags  = creationFlags;
   } // exec_request

   exec_request (const exec_request& right) 
    : RpcRequest (right),
      m_processId (right.m_processId)
   {
   } // exec_request

   exec_request& operator= (const exec_request& right) 
   { 
     if (this != &right)
       exec_request (right).swap (*this);

     return *this; 
   } // operator=

   virtual ~exec_request ()
   {
     ::CloseHandle (m_token);
     ::CloseHandle (m_process_handle);
   } // ~exec_request
   
  protected:
   void swap (exec_request& right)
   {
     base_type::swap (right);

     HANDLE      processId        = m_processId;
     ExecType    exec_type        = m_exec_type;
     HANDLE      token            = m_token;
     HANDLE      process_handle   = m_process_handle;
     wstring     applicationName  = m_applicationName;
     wstring     commandLine      = m_commandLine;
     BOOL        inheritHandles   = m_inheritHandles;
     DWORD       creationFlags    = m_creationFlags;
     wstring     currentDirectory = m_currentDirectory;
	 StartupInfoW StartupInfo	  = m_StartupInfo;

     m_processId               = right.m_processId;
     m_exec_type               = right.m_exec_type;
     m_token                   = right.m_token;
     m_process_handle          = right.m_process_handle;
     m_applicationName         = right.m_applicationName;
     m_commandLine             = right.m_commandLine;    
     m_inheritHandles          = right.m_inheritHandles; 
     m_creationFlags           = right.m_creationFlags;  
     m_currentDirectory        = right.m_currentDirectory;
	 m_StartupInfo			   = right.m_StartupInfo;
                             
     right.m_processId         = processId;
     right.m_exec_type         = exec_type;
     right.m_token             = token;
     right.m_process_handle    = process_handle;
     right.m_applicationName   = applicationName; 
     right.m_commandLine       = commandLine;     
     right.m_inheritHandles    = inheritHandles;  
     right.m_creationFlags     = creationFlags;   
     right.m_currentDirectory  = currentDirectory;
	 right.m_StartupInfo	   = StartupInfo;
   } // swap
   
   HANDLE open_thread_token ()
   {
     HANDLE token = NULL;
     if (FALSE == ::OpenThreadToken (::GetCurrentThread (), TOKEN_ALL_ACCESS, FALSE, &token)) // TOKEN_IMPERSONATE |  | TOKEN_DUPLICATE
       token = NULL;
     return token;
   } // open_thread_token

   
  public:
   HANDLE   m_processId;
   ExecType m_exec_type;
   HANDLE   m_token;
   HANDLE   m_process_handle;
   wstring  m_applicationName;
   wstring  m_commandLine;
   BOOL     m_inheritHandles;
   DWORD    m_creationFlags;
   wstring  m_currentDirectory;
   StartupInfoW m_StartupInfo;

  private:
}; // exec_request

typedef boost::shared_ptr<exec_request>         ptr_to_exec_request;

} // namespace guictrl
} // namespace gswserv 

#endif //_gswserv_guictrl_exec_request_h_
