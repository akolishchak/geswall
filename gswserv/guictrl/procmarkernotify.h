//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_PROCMARKER_NOTIFY_H_
 #define _GUICTRL_PROCMARKER_NOTIFY_H_

#ifndef __GSW_NO_STD_AFX__
 #include "stdafx.h"
#else
 #include <windows.h>
#endif // __GSW_NO_STD_AFX__ 

#include "rpcrequest.h"
#include "gesruledef.h"

namespace gswserv {
namespace guictrl {

class ProcMarkerNotify;

class ProcMarkerNotify : public RpcRequest
{
  public: 
   typedef boost::shared_ptr<ProcMarkerNotify>         PtrToProcMarkerNotify;

   enum Type
   {
     changeProcessState,
     changeHook
   };

  protected:
   typedef RpcRequest                                  base_type;

  public:
   ProcMarkerNotify (HANDLE processId, const GesRule::ModelType state)
    : RpcRequest (),
      m_processId (processId),
      m_state (state),
      m_hook (NULL),
      m_type (Type::changeProcessState)
   {
   } // ProcMarkerNotify

   ProcMarkerNotify (HANDLE processId, HHOOK hook)
    : RpcRequest (),
      m_processId (processId),
      m_state (GesRule::modUndefined),
      m_hook (hook),
      m_type (Type::changeHook)
   {
   } // ProcMarkerNotify

   ProcMarkerNotify (const ProcMarkerNotify& right) 
    : RpcRequest (right),
      m_processId (right.m_processId),
      m_state (right.m_state),
      m_hook (right.m_hook),
      m_type (right.m_type)
   {
   } // ProcMarkerNotify

   ProcMarkerNotify& operator= (const ProcMarkerNotify& right) 
   { 
     if (this != &right)
       ProcMarkerNotify (right).swap (*this);

     return *this;
   } // operator=

   virtual ~ProcMarkerNotify ()
   {
   } // ~ProcMarkerNotify
   
   GesRule::ModelType getState () const
   {
     return m_state;
   } // getState

   Type getType ()
   {
     return m_type;
   } // getType

   HHOOK getHook ()
   {
     return m_hook;
   } // getHook

  protected:
   void swap (ProcMarkerNotify& right)
   {
     base_type::swap (right);

     HANDLE             processId  = m_processId;
     GesRule::ModelType state      = m_state;
     HHOOK              hook       = m_hook;
     Type               type       = m_type;
     
     m_processId       = right.m_processId;
     m_state           = right.m_state;
     m_hook            = right.m_hook;
     m_type            = right.m_type;

     right.m_processId = processId;
     right.m_state     = state;
     right.m_hook      = hook;
     right.m_type      = type;
   } // swap
   
  protected:
   const Type               m_type;
   HANDLE                   m_processId;
   const GesRule::ModelType m_state;
   const HHOOK              m_hook;

  private:
}; // ProcMarkerNotify

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_PROCMARKER_NOTIFY_H_
