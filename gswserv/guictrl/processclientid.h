//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_PROCESS_CLIENT_ID_H_
 #define _GUICTRL_PROCESS_CLIENT_ID_H_

#include "stdafx.h"

#include <string>

using namespace std;

namespace gswserv {
namespace guictrl {

class ProcessClientId;

class ProcessClientId
{
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
   ProcessClientId ()
    : m_processId (LongToHandle (GetCurrentProcessId ()))
   {

   } // SessionClientId

   ProcessClientId (HANDLE processId)
    : m_processId (processId)
   {
     
   } // SessionClientId
   
   ProcessClientId (const ProcessClientId& right) 
    : m_processId (right.m_processId)
   {
   } // SessionClientId

   virtual ~ProcessClientId ()
   {
   } // ~SessionClientId

   ProcessClientId& operator= (const ProcessClientId& right) 
   { 
     if (this != &right)
       ProcessClientId (right).swap (*this);

     return *this;
   } // operator=

   unsigned int getId () const
   {
     return HandleToLong (m_processId);
   } // getId

   bool operator< (const ProcessClientId& right) const
   {
     return (getId () < right.getId ());
   } // operator<

  protected:
   void swap (ProcessClientId& right)
   {
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
   const HANDLE m_processId;

  private:
}; // ProcessClientId

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_PROCESS_CLIENT_ID_H_
