//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_SESSION_CLIENT_ID_H_
 #define _GUICTRL_SESSION_CLIENT_ID_H_

#include "stdafx.h"

#include <string>

using namespace std;

namespace gswserv {
namespace guictrl {

class SessionClientId;

class SessionClientId
{
  //
  // types
  //
  public:
   enum Service
   {
     srv_ui   = 0x00000000,
     srv_exec = 0x80000000
   }; // Service

  protected:
  private:

  //
  // methods
  //
  public:
   SessionClientId (Service srv = srv_ui) // token for current (impersonated) thread
    : m_clientId (srv ^ getSessionIdByThread ())
   {

   } // SessionClientId

   SessionClientId (HANDLE processId, Service srv = srv_ui)
    : m_clientId (srv ^ getSessionIdByProcessId (processId))
   {
     
   } // SessionClientId
   
   SessionClientId (DWORD externalId)
    : m_clientId (externalId)
   {
     
   } // SessionClientId

   SessionClientId (const SessionClientId& right) 
    : m_clientId (right.m_clientId)
   {
   } // SessionClientId

   virtual ~SessionClientId ()
   {
   } // ~SessionClientId

   SessionClientId& operator= (const SessionClientId& right) 
   { 
     if (this != &right)
       SessionClientId (right).swap (*this);
     
     return *this; 
   } // operator=

   unsigned int getId () const
   {
     return m_clientId;
   } // getId

   //unsigned int operator () const
   //{
   //  return m_clientId;
   //} // operator ()

   bool operator< (const SessionClientId& right) const
   {
     return (getId () < right.getId ());
   } // operator<

  protected:
   void swap (SessionClientId& right)
   {
     DWORD   sessionId = m_clientId;

     m_clientId       = right.m_clientId;

     right.m_clientId = sessionId;
   } // swap

  private:
   DWORD getSessionIdByThread ()
   {
     DWORD  sessionId = -1;
     HANDLE hToken    = NULL;

     HANDLE hThread = OpenThread (THREAD_QUERY_INFORMATION, FALSE, HandleToUlong(GetCurrentThreadId ()));
     if (NULL != hThread)
     {
       if (TRUE == OpenThreadToken (hThread, TOKEN_QUERY, FALSE, &hToken)) // TOKEN_IMPERSONATE |  | TOKEN_DUPLICATE
       {
         DWORD resultSize = 0;
         if (FALSE == GetTokenInformation (hToken, TokenSessionId, &sessionId, sizeof (sessionId), &resultSize))
           sessionId = -1;
     
         CloseHandle (hToken);
       } // if (TRUE == OpenThreadToken (hProcess, TOKEN_QUERY, &hToken))
       CloseHandle (hThread);
     } // if (NULL != hThread)

     return sessionId;
   } // getSessionIdByThread

   DWORD getSessionIdByProcessId (HANDLE processId)
   {
     DWORD  sessionId = -1;
     HANDLE hProcess  = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong(processId));

     if (NULL != hProcess)
     {
       HANDLE hToken = NULL;
       if (TRUE == OpenProcessToken (hProcess, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
       {
         DWORD resultSize = 0;
         if (FALSE == GetTokenInformation (hToken, TokenSessionId, &sessionId, sizeof (sessionId), &resultSize))
           sessionId = -1;

         CloseHandle (hToken);
       } // if (TRUE == OpenProcessToken (hProcess, TOKEN_QUERY, &hToken))
       CloseHandle (hProcess);
     } // if (NULL != hProcess)

     return sessionId;
   } // getSessionIdByProcessId
  
  //
  // data
  //
  public:
  protected:
   DWORD   m_clientId; // srv ^ session_id

  private:
}; // SessionClientId

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_SESSION_CLIENT_ID_H_
