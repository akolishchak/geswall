//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_UI_CLIENT_H_
 #define _GUICTRL_UI_CLIENT_H_

#include "stdafx.h"

#include <string>

#include "rpcclient.h"
#include "commonlib.h"

namespace gswserv {
namespace guictrl {

class UIClient;

class UIClient : public RpcClient
{
  friend class ClientManager;

  //
  // types
  //
  public:
  protected:
   typedef std::wstring                          wstring;
   typedef commonlib::ObjectHolder               ObjectHolder;
   typedef RpcClient                             base_type;

  private:

  //
  // methods
  //
  public:
   UIClient (HANDLE processId, const wstring& authorityHash)
    : RpcClient (authorityHash),
      m_processId (processId),
      m_hProcess (OpenProcess (SYNCHRONIZE, FALSE, HandleToUlong(processId)))
   {

   } // UIClient

   virtual ~UIClient ()
   {
     try
     {
       clear ();
     }
     catch (...)
     {
     }
   } // ~UIClient

   virtual bool isAlive ()
   {
     if (NULL == m_hProcess.get ())
       return false;

     //return (WAIT_OBJECT_0 != WaitForSingleObject (m_hProcess.get (), 0));
     return (WAIT_TIMEOUT == WaitForSingleObject (m_hProcess.get (), 0));
   } // isAlive

  protected:
   UIClient (const UIClient& right) 
    : RpcClient (right),
      m_processId (right.m_processId)//,
      //m_hProcess (right.m_hProcess)
   {
   } // UIClient

   UIClient& operator= (const UIClient& right) 
   { 
     if (this != &right)
       UIClient (right).swap (*this);

     return *this;
   } // operator=

   void swap (UIClient& right)
   {
     base_type::swap (right);

     HANDLE processId  = m_processId;

     m_processId       = right.m_processId;

     right.m_processId = processId;
   } // swap
   
  private:

  //
  // data
  //
  public:
  protected:
   HANDLE       m_processId;
   ObjectHolder m_hProcess;

  private:
}; // UIClient

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_UI_CLIENT_H_
