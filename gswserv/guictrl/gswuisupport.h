//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_GSWUI_SUPPORT_H_
 #define _GUICTRL_GSWUI_SUPPORT_H_

#include "stdafx.h"
#include <rpcdce.h>

#include "smartclientmanager.h"
#include "gswuiclient.h"
#include "sessionclientid.h"
#include "gswuirequest.h"
#include "gswuiresponse.h"
#include "authoritychecker.h"

#include <string>

using namespace std;

namespace gswserv {
namespace guictrl {

class GsWuiSupport;

class GsWuiSupport
{
  public:
   typedef SmartClientManager<GsWuiClient, SessionClientId> GsWuiClientManager;
   typedef GsWuiClientManager::Client             Client;
   typedef GsWuiClientManager::PtrToClient        PtrToClient;
   typedef GsWuiClientManager::ClientId           ClientId;
   typedef Request::PtrToRequest                  PtrToRequest;
   typedef GsWuiRequest::PtrToGsWuiRequest        PtrToGsWuiRequest;
   typedef GsWuiResponse::PtrToGsWuiResponse      PtrToGsWuiResponse;
   typedef GsWuiRequest::PtrToRpcRequest          PtrToRpcRequest;
   typedef GsWuiResponse::PtrToRpcReply           PtrToRpcReply;
   typedef commonlib::SyncObject                  SyncObject;
   typedef commonlib::Locker                      Locker;

  public:
   static bool              init  ();
   static void              clear ();
  
   static GUIReply          queryReply (HANDLE processId, const RequestType type, const wstring& file1, const wstring& file2);

   static void              queryAuthorizationObject (HANDLE processId, wstring& objectName);
   static bool              registerClient (HANDLE processId, HANDLE objectHandle, wstring& authorityHash);

   static PtrToGsWuiRequest waitRequest (HANDLE processId, const wstring& authorityHash);
   static void              cancelWaitRequest (HANDLE processId, const wstring& authorityHash);

   static void              putReply (HANDLE processId, const wstring& authorityHash, int requestId, const GUIReply& reply);
   static void              putResponse (HANDLE processId, const wstring& authorityHash, const PtrToGsWuiResponse& response);
   
   static int               updateDb (HANDLE processId, const wstring& authorityHash);
   //static int               getUpdateDbResult (HANDLE processId, const wstring& authorityHash);
   static int               checkUpdateDb (HANDLE processId, const wstring& authorityHash);

  protected:
  private:
   GsWuiSupport () {}
   GsWuiSupport (const GsWuiSupport& right) {}
   GsWuiSupport& operator= (const GsWuiSupport& right) { return *this; }
   ~GsWuiSupport () {}

  private:
   //static GsWuiClientManager m_manager;
   //static AuthorityChecker   m_authorityChecker;
   //static int                m_timeout;
   //static SyncObject         m_update_sync;
}; // GsWuiSupport

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_GSWUI_SUPPORT_H_
