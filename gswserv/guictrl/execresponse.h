//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswserv_guictrl_exec_response_h_
 #define _gswserv_guictrl_exec_response_h_

#include "stdafx.h"

#include "rpcreply.h"


namespace gswserv {
namespace guictrl {

class exec_response;

class exec_response : public RpcReply
{
  public: 
  protected:
   typedef RpcReply                                 base_type;

  public:
   exec_response (int parentRequestId, bool reply, unsigned int process_id, unsigned int thread_id, HANDLE process_handle, HANDLE thread_handle)
    : RpcReply (parentRequestId),
      m_reply (reply),
      m_process_id (process_id), 
      m_thread_id (thread_id),
      m_process_handle (process_handle), 
      m_thread_handle (thread_handle)
   {
   } // exec_response

   exec_response (const exec_response& right) 
    : RpcReply (right),
      m_reply (right.m_reply)
   {
   } // exec_response

   exec_response& operator= (const exec_response& right) 
   { 
     if (this != &right)
       exec_response (right).swap (*this);

     return *this; 
   } // operator=

   virtual ~exec_response ()
   {
   } // ~exec_response

   bool getReply () const
   {
     return m_reply;
   } // getReply
   
   unsigned int getProcessId () const
   {
     return m_process_id;
   } // getProcessId
   
   unsigned int getThreadId () const
   {
     return m_thread_id;
   } // getThreadId
   
   HANDLE getProcessHandle ()
   {
     return m_process_handle;
   } // getProcessHandle
   
   HANDLE getThreadHandle ()
   {
     return m_thread_handle;
   } // getThreadHandle
   
   void setProcessHandle (HANDLE process_handle)
   {
     m_process_handle = process_handle;
   } // setProcessHandle
   
   void setThreadHandle (HANDLE thread_handle)
   {
     m_thread_handle = thread_handle;
   } // setThreadHandle

  protected:
   void swap (exec_response& right)
   {
     base_type::swap (right);

     bool   reply            = m_reply;
     unsigned int process_id = m_process_id;
     unsigned int thread_id  = m_thread_id;
     HANDLE process_handle   = m_process_handle;
     HANDLE thread_handle    = m_thread_handle;

     m_reply          = right.m_reply;
     m_process_id     = right.m_process_id;
     m_thread_id      = right.m_thread_id;
     m_process_handle = right.m_process_handle;
     m_thread_handle  = right.m_thread_handle;

     right.m_reply          = reply;
     right.m_process_id     = process_id;
     right.m_thread_id      = thread_id;
     right.m_process_handle = process_handle;
     right.m_thread_handle  = thread_handle;
   } // swap

  protected:
  private:
   bool         m_reply;
   unsigned int m_process_id;
   unsigned int m_thread_id;
   HANDLE       m_process_handle;
   HANDLE       m_thread_handle;
}; // exec_response

typedef boost::shared_ptr<exec_response>         ptr_to_exec_response;

} // namespace guictrl
} // namespace gswserv 

#endif //_gswserv_guictrl_exec_response_h_
