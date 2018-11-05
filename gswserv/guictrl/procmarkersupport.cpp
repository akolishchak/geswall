//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "procmarkersupport.h"
#include "gswdrv.h"

namespace gswserv {
namespace guictrl {

ProcMarkerSupport::PMClientManager ProcMarkerSupport::m_manager;
ProcMarkerSupport::HookResolver    ProcMarkerSupport::m_hookResolver;
ProcMarkerSupport::SyncObject      ProcMarkerSupport::m_sync;

bool ProcMarkerSupport::init ()
{
  return true;
} // init

void ProcMarkerSupport::clear ()
{
  m_manager.unregisterAllClients ();
} // clear

void ProcMarkerSupport::changeProcessState (HANDLE processId, const GesRule::ModelType state)
{
  PtrToClient client = m_manager.getClient (ClientId (processId));
  if (NULL != client.get ())
    client->notification (PtrToProcMarkerNotify (new ProcMarkerNotify (processId, state)));
} // changeProcessState

GesRule::ModelType ProcMarkerSupport::getProcessState (HANDLE processId)
{
  CGswDrv drv;
  return drv.GetSubjIntegrity (HandleToLong (processId));
} // getProcessState

ProcMarkerSupport::PtrToClient ProcMarkerSupport::registerClient (HANDLE processId)
{  
  PtrToClient client;

  try
  {
    client = m_manager.getClient (ClientId (processId));
    if (NULL == client.get ())
    {
      client = PtrToClient (new ProcMarkerClient (processId, wstring (L""))); // authorityHash
      if (NULL != client.get ())
        m_manager.registerClient (ClientId (processId), client);
    }
  }
  catch (GUICtrlException&)
  {
    client = m_manager.getClient (ClientId (processId));
  }
  catch (...)
  {

  }

  return client;
} // getClient

void ProcMarkerSupport::cancelWait (HANDLE processId)
{
  try
  {
    PtrToClient client = m_manager.getClient (ClientId (processId));
    if (NULL != client.get ())
    {
      client->cancelWait ();
    }
  }
  catch (GUICtrlException&)
  {
  }
  catch (...)
  {
  }
} // cancelWait

HHOOK ProcMarkerSupport::getDesktopHook (HANDLE processId, const wstring& desktopName)
{
  Locker locker (m_sync);

  HHOOK hook = NULL;
  HookResolver::iterator i = m_hookResolver.find (desktopName);
  if (i != m_hookResolver.end ())
  {
    PtrToHookInfo hookInfo = (*i).second;
    //hookInfo->m_usageCounter.increment ();
    //hookInfo->addClient (processId);
    hook = hookInfo->m_hook;
  }

  return hook;
} // getDesktopHook

bool ProcMarkerSupport::setDesktopHook (HANDLE processId, const wstring& desktopName, HHOOK hook)
{
  Locker      locker (m_sync);
  bool        result = false;
  
  if (NULL != hook)
  {
    HookResolver::iterator i = m_hookResolver.find (desktopName);
    //if (i == m_hookResolver.end ())
    {
      PtrToHookInfo hookInfo (new HookInfo (hook, processId));
      if (NULL != hookInfo.get ())
      {
        //hookInfo->m_usageCounter.increment ();
        //hookInfo->addClient (processId);
        m_hookResolver [desktopName] = hookInfo;
        result = true;
      }
    }
  } // if (NULL != hook)
  else
  {
    HookResolver::iterator i = m_hookResolver.find (desktopName);
    if (i != m_hookResolver.end ())
    {
      PtrToHookInfo hookInfo = (*i).second;
      if (processId == hookInfo->m_processId)
      {
        //hookInfo->deleteClient (processId);
        //if (0 == hookInfo->clientsCount ())
        //if (0 == hookInfo->m_usageCounter.decrement ())
        {
          m_hookResolver.erase (desktopName);
          result = true;
        }
      }
    }
  } // else if (NULL != hook)
  
  if (true == result)
    m_manager.broadcastRequest (PtrToProcMarkerNotify (new ProcMarkerNotify (processId, hook)));
    
  return result;  
} // setDesktopHook

bool ProcMarkerSupport::waitNotification (HANDLE processId, ProcMarkerInfo& processInfo, int timeout)
{
  bool result = false;

  try
  {
    PtrToClient client = registerClient (processId);
    if (NULL != client.get ())
    {
      PtrToProcMarkerNotify request = PtrToProcMarkerNotify (client->waitCall (timeout), boost::detail::static_cast_tag ());
      if (NULL != request.get ())
      {
        processInfo.m_type         = request->getType ();
        processInfo.m_processState = request->getState ();
        //processInfo.m_hookHandle   = HandleToLong (request->getHook ());
        result = true;
      }
    }
  }
  catch (GUICtrlException&)
  {

  }
  catch (...)
  {

  }

  return result;  
} // waitNotification

} // namespace guictrl
} // namespace gswserv 

