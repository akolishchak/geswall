//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_RPC_REQUEST_H_
 #define _GUICTRL_RPC_REQUEST_H_

#include "request.h"

#include "commonlib.h"

namespace gswserv {
namespace guictrl {

class RpcRequest;
class RpcReply;

class RpcRequest : public Request
{
  public: 
   typedef boost::shared_ptr<RpcRequest>       PtrToRpcRequest;
   typedef boost::shared_ptr<RpcReply>         PtrToRpcReply;
   typedef commonlib::sync::CancelException    CancelException;
   typedef commonlib::sync::TimeoutException   TimeoutException;
   typedef commonlib::sync::SyncObject         SyncObject;
   typedef commonlib::sync::SyncObject::Locker Locker;

  protected:
   typedef Request                             base_type;

  public:
   RpcRequest ()
    : Request (),
      m_replyReady (false)
   {
   } // RpcRequest

   RpcRequest (const RpcRequest& right) 
    : Request (right),
      m_reply (right.m_reply), 
      m_replyReady (right.m_replyReady)
   {
   } // RpcRequest

   RpcRequest& operator= (const RpcRequest& right) 
   { 
     if (this != &right)
       RpcRequest (right).swap (*this);
     
     return *this; 
   } // operator=

   virtual ~RpcRequest ()
   {
     try
     {
       Locker locker (m_sync);
       m_sync.cancel ();
     }
     catch (...)
     {
     }
   } // ~RpcRequest

   void lock ()
   {
     m_sync.lock ();
   } // lock

   void unlock ()
   {
     m_sync.unlock ();
   } // unlock

   void wait (int timeout)
   {
     m_sync.wait (timeout);
   } // wait

   void notify ()
   {
     m_sync.notify ();
   } // notify

   void cancel ()
   {
     m_sync.cancel ();
   } // cancel

   void setReply (const PtrToRpcReply& reply)
   {
     m_reply      = reply;
     m_replyReady = true;
   } // setReply

   PtrToRpcReply getReply ()
   {
     return m_reply;
   } // getReply

   bool isReplyReady () const
   {
     return m_replyReady;
   } // isReplyReady

  protected:
   void swap (RpcRequest& right)
   {
     base_type::swap (right);

     bool          replyReady   = m_replyReady;
     PtrToRpcReply reply        = m_reply;
               
     m_replyReady               = right.m_replyReady;
     m_reply                    = right.m_reply;

     right.m_replyReady         = replyReady;
     right.m_reply              = reply;
   } // swap
   
  protected:
   bool                m_replyReady;
   PtrToRpcReply       m_reply;
  
  private:
   mutable SyncObject  m_sync;
}; // RpcRequest

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_RPC_REQUEST_H_
