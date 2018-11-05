//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _guictrl_procmarkerclient_h_
 #define _guictrl_procmarkerclient_h_

#include <windows.h>
#include <stdio.h>

#include "uiclient.h"

#include <string>

using namespace std;

namespace gswserv {
namespace guictrl {

class ProcMarkerClient;

class ProcMarkerClient : public UIClient
{
  friend class ClientManager;

  //
  // types
  //
  public:
  protected:
  private:

  //
  // methods
  //
  public:
   ProcMarkerClient (HANDLE processId, const wstring& authorityHash)
    : UIClient (processId, authorityHash)
   {
//     wchar_t name [128];
//
//     swprintf (name, L"Global\\procmarker_pid_%u", processId);
//     m_userSemaphore = ObjectHolder (OpenSemaphoreW (SEMAPHORE_ALL_ACCESS, FALSE, name));
   } // ProcMarkerClient

   virtual ~ProcMarkerClient ()
   {

   } // ~ProcMarkerClient

   virtual void notification (const PtrToRpcRequest& request)
   {
     UIClient::notification (request);
//     if (NULL != request.get ())
//       ReleaseSemaphore (m_userSemaphore.get (), 1, NULL);
   } // notification

  protected:
  private:

  //
  // data
  //
  public:
  protected:
//   ObjectHolder m_userSemaphore;

  private:
}; // ProcMarkerClient

} // namespace guictrl
} // namespace gswserv 

#endif //_guictrl_procmarkerclient_h_
