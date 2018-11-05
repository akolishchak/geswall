//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_RPC_REPLY_H_
 #define _GUICTRL_RPC_REPLY_H_

namespace gswserv {
namespace guictrl {

class RpcReply;

class RpcReply
{
  public: 
   typedef boost::shared_ptr<RpcReply>         PtrToRpcReply;

  protected:

  public:
   explicit RpcReply (int parentRequestId)
    : m_parentRequestId (parentRequestId)
   {
   } // RpcReply

   RpcReply (const RpcReply& right) 
    : m_parentRequestId (right.m_parentRequestId)
   {
   } // RpcReply

   RpcReply& operator= (const RpcReply& right) 
   { 
     if (this != &right)
       RpcReply (right).swap (*this);

     return *this; 
   } // operator=

   virtual ~RpcReply ()
   {

   } // ~RpcReply

   int getParentRequestId () const
   {
     return m_parentRequestId;
   } // getParentRequestId

  protected:
   void swap (RpcReply& right)
   {
     int parentRequestId     = m_parentRequestId;

     m_parentRequestId       = right.m_parentRequestId;

     right.m_parentRequestId = parentRequestId;
   } // swap

  protected:
   int m_parentRequestId;

  private:
}; // RpcReply

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_RPC_REPLY_H_
