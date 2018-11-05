//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_GSWUI_RESPONSE_H_
 #define _GUICTRL_GSWUI_RESPONSE_H_

#include "stdafx.h"
#include "gsw/gswioctl.h"

#include "rpcreply.h"


namespace gswserv {
namespace guictrl {

class GsWuiResponse;

class GsWuiResponse : public RpcReply
{
  public: 
   typedef boost::shared_ptr<GsWuiResponse>         PtrToGsWuiResponse;

  protected:
   typedef RpcReply                                 base_type;

  public:
   GsWuiResponse (int parentRequestId, GUIReply reply)
    : RpcReply (parentRequestId),
      m_reply (reply)
   {
   } // GsWuiResponse

   GsWuiResponse (const GsWuiResponse& right) 
    : RpcReply (right),
      m_reply (right.m_reply)
   {
   } // GsWuiResponse

   GsWuiResponse& operator= (const GsWuiResponse& right) 
   { 
     if (this != &right)
       GsWuiResponse (right).swap (*this);

     return *this; 
   } // operator=

   virtual ~GsWuiResponse ()
   {
   } // ~GsWuiResponse

   GUIReply getReply () const
   {
     return m_reply;
   } // getReply

  protected:
   void swap (GsWuiResponse& right)
   {
     base_type::swap (right);

     GUIReply  reply = m_reply;

     m_reply         = right.m_reply;

     right.m_reply   = reply;
   } // swap

  protected:
  private:
   GUIReply  m_reply;
}; // GsWuiResponse

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_GSWUI_RESPONSE_H_
