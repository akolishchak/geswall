//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_PROCMARKER_SUPPORT_H_
 #define _GUICTRL_PROCMARKER_SUPPORT_H_

#include "stdafx.h"

#include "ifgswrpc_h.h"

#include "smartclientmanager.h"
#include "procmarkerclient.h"
#include "processclientid.h"
#include "procmarkernotify.h"
#include "gesruledef.h"

#include "commonlib.h"

#include <string>
#include <map>
#include <list>

using namespace std;

namespace gswserv {
namespace guictrl {

class ProcMarkerSupport;

class ProcMarkerSupport
{
  public:
   typedef SmartClientManager<ProcMarkerClient, ProcessClientId> PMClientManager;
   typedef PMClientManager::Client                 Client;
   typedef PMClientManager::PtrToClient            PtrToClient;
   typedef PMClientManager::ClientId               ClientId;
   typedef Request::PtrToRequest                   PtrToRequest;
   typedef RpcRequest::PtrToRpcRequest             PtrToRpcRequest;
   typedef RpcRequest::PtrToRpcReply               PtrToRpcReply;
   typedef ProcMarkerNotify::PtrToProcMarkerNotify PtrToProcMarkerNotify;
   typedef commonlib::SyncObject                   SyncObject;
   typedef commonlib::Locker                       Locker;
   //typedef commonlib::IntrusiveAtomicCounter       IntrusiveAtomicCounter;

   struct HookInfo
   {
     HookInfo (HHOOK hook, HANDLE processId)
      : m_hook (hook),
        m_processId (processId)
     {
     }
     
     HHOOK                   m_hook;
     HANDLE                  m_processId;
   }; // HookInfo

   typedef boost::shared_ptr<HookInfo>            PtrToHookInfo;
   typedef map<const wstring, PtrToHookInfo>      HookResolver;

  public:
   static bool               init  ();
   static void               clear ();
  
   static void               changeProcessState (HANDLE processId, const GesRule::ModelType state);
   
   static GesRule::ModelType getProcessState (HANDLE processId);
   static void               cancelWait (HANDLE processId);

   static HHOOK              getDesktopHook (HANDLE processId, const wstring& desktopName);
   static bool               setDesktopHook (HANDLE processId, const wstring& desktopName, HHOOK hook);

   static bool               waitNotification (HANDLE processId, ProcMarkerInfo& processInfo, int timeout);

  protected:
   static PtrToClient        registerClient (HANDLE processId);

  private:
   ProcMarkerSupport () {}
   ProcMarkerSupport (const ProcMarkerSupport& right) {}
   ProcMarkerSupport& operator= (const ProcMarkerSupport& right) { return *this; }
   ~ProcMarkerSupport () {}

  private:
   static PMClientManager    m_manager;
   static HookResolver       m_hookResolver;
   static SyncObject         m_sync;
}; // ProcMarkerSupport

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_PROCMARKER_SUPPORT_H_
