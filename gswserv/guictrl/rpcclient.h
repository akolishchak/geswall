//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_RPC_CLIENT_H_
 #define _GUICTRL_RPC_CLIENT_H_

#include <string>
#include <map>

#include <boost/smart_ptr.hpp> 

#include "client.h"
#include "commonlib.h"

#include "rpcrequest.h"
#include "rpcreply.h"

namespace gswserv {
namespace guictrl {

class RpcClient;

class RpcClient : protected Client
{
  friend class ClientManager;
  //
  // types
  //
  public:
//   typedef Client::Const                         Const;
   enum Const
   {
     infiniteTimeout = Client::infiniteTimeout
   };
  
  protected:
   typedef std::wstring                          wstring;
   typedef commonlib::SyncObject                 SyncObject;
   typedef commonlib::Locker                     Locker;
   typedef boost::shared_ptr<RpcRequest>         PtrToRpcRequest;
   typedef boost::shared_ptr<RpcReply>           PtrToRpcReply;
   typedef std::map<int, PtrToRpcRequest>        RpcRequestQueue;
   typedef commonlib::AbstractLocker<RpcRequest> RpcRequestLocker;
   typedef commonlib::sync::CancelException      CancelException;
   typedef commonlib::sync::TimeoutException     TimeoutException;
   typedef commonlib::sync::SyncException        SyncException;
   typedef Client                                base_type;

  private:

  //
  // methods
  //
  public:
   RpcClient (const wstring& authorityHash)
    : Client (authorityHash)
   {

   } // RpcClient

   virtual ~RpcClient ()
   {
     try
     {
       clear ();
     }
     catch (...)
     {
     }
   } // ~RpcClient

   virtual PtrToRpcReply call (const PtrToRpcRequest& request, int timeout)
   {
     PtrToRpcReply reply;

     if (NULL != request.get ())
     {
       notification (request);

       try
       {
         RpcRequestLocker reqLocker (*request);

         if (false == request->isReplyReady ())
           request->wait (timeout);

         reply = request->getReply ();
       }
       catch (CancelException&)
       {
         removeRpcRequest (request->getId ());
       }
       catch (TimeoutException&) 
       {
         removeRpcRequest (request->getId ());
       }
       catch (SyncException&)
       {
         removeRpcRequest (request->getId ());
       }
     } // if (NULL != request.get ())

     return reply;
   } // call

   virtual void notification (const PtrToRpcRequest& request)
   {
     addRequest (request);
   } // notification

   virtual void setReply (int requestId, PtrToRpcReply reply)
   {
     PtrToRpcRequest request = getRpcRequest (requestId);
     if (NULL != request.get ())
     {
       RpcRequestLocker reqLocker (*request);
       request->setReply (reply);
       request->notify ();
     }
   } // setReply

   virtual PtrToRpcRequest getRequest (int requestId)
   {
     return getRpcRequest (requestId, false);
   } // getRequest

   virtual PtrToRpcRequest waitCall (int timeout)
   {
     PtrToRpcRequest request = PtrToRpcRequest (waitRequest (timeout), boost::detail::static_cast_tag ());

     if (NULL != request.get ())
     {
       Locker locker (m_sync);
       m_rpcRequestQueue [request->getId ()] = request;
     }

     return request;
   } // waitRequest

   virtual void cancelWait ()
   {
     Client::cancelWait ();
     cancelWaitReply ();
   } // cancelWait

   virtual void clear ()
   {
     cancelWait ();
   } // clear
   
   virtual int compareAuthorityHash (const wstring& authorityHash) const 
   {
     return Client::compareAuthorityHash (authorityHash);
   } // compareAuthorityHash
   
  protected:
   RpcClient (const RpcClient& right) 
    : Client (right)   
   {
   } // RpcClient

   RpcClient& operator= (const RpcClient& right) 
   { 
     if (this != &right)
       RpcClient (right).swap (*this);

     return *this;
   } // operator=

   void swap (RpcClient& right)
   {
     base_type::swap (right);
   } // swap

   PtrToRpcRequest getRpcRequest (int requestId, bool remove_it = true)
   {
     PtrToRpcRequest request;

     Locker locker (m_sync);

     if (0 < m_rpcRequestQueue.size ())
     {
       RpcRequestQueue::iterator i = m_rpcRequestQueue.find (requestId);
       if (i != m_rpcRequestQueue.end ())
       {
         request = (*i).second;
         if (true == remove_it)
           m_rpcRequestQueue.erase (i);
       }
     }

     return request;
   } // getRpcRequest

   PtrToRpcRequest removeRpcRequest (int requestId)
   {
     delRequest (requestId);
     return getRpcRequest (requestId);
   } // removeRpcRequest

   void cancelWaitReply ()
   {
     Locker locker (m_sync);

     if (0 < m_rpcRequestQueue.size ())
     {
       for (RpcRequestQueue::iterator i = m_rpcRequestQueue.begin (); i != m_rpcRequestQueue.end (); ++i)
       {
         PtrToRpcRequest  request = (*i).second;
         RpcRequestLocker reqLocker (*request);

         request->cancel ();
       } // for ()
     } // if (0 < m_hashResolver.size ())
   } // cancelWaitReply
   
  private:

  //
  // data
  //
  public:
  protected:
   RpcRequestQueue     m_rpcRequestQueue;

  private:
   mutable SyncObject  m_sync;
}; // RpcClient

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_RPC_CLIENT_H_
