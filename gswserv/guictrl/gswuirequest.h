//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_GSWUI_REQUEST_H_
 #define _GUICTRL_GSWUI_REQUEST_H_

#include "stdafx.h"
#include "gsw/gswioctl.h"

#include "rpcrequest.h"

namespace gswserv {
namespace guictrl {

class GsWuiRequest;

class GsWuiRequest : public RpcRequest
{
  public: 
   typedef boost::shared_ptr<GsWuiRequest>         PtrToGsWuiRequest;

  protected:
   typedef RpcRequest                              base_type;

  public:
   GsWuiRequest (HANDLE processId, const RequestType type, const wstring& file1, const wstring& file2)
    : RpcRequest (),
      m_processId (processId),
      m_file1 (file1),
      m_file2 (file2),
      m_type (type)
   {
   } // GsWuiRequest

   GsWuiRequest (const GsWuiRequest& right) 
    : RpcRequest (right),
      m_processId (right.m_processId),
      m_file1 (right.m_file1),
      m_file2 (right.m_file2),
      m_type (right.m_type)
   {
   } // GsWuiRequest

   GsWuiRequest& operator= (const GsWuiRequest& right) 
   { 
     if (this != &right)
       GsWuiRequest (right).swap (*this);

     return *this; 
   } // operator=

   virtual ~GsWuiRequest ()
   {
   } // ~GsWuiRequest
   
   const wstring& getFile1 () const
   {
     return m_file1;
   } // getFile1
   
   const wstring& getFile2 () const
   {
     return m_file2;
   } // getFile2
   
   const RequestType& getType () const
   {
     return m_type;
   } // getType

  protected:
   void swap (GsWuiRequest& right)
   {
     base_type::swap (right);

     HANDLE      processId = m_processId;
     wstring     file1     = m_file1;
     wstring     file2     = m_file2;
     RequestType type      = m_type;

     m_processId           = right.m_processId;
     m_file1               = right.m_file1;
     m_file2               = right.m_file2;
     m_type                = right.m_type;

     right.m_processId     = processId;
     right.m_file1         = file1;    
     right.m_file2         = file2;    
     right.m_type          = type;     
   } // swap

  protected:
   HANDLE       m_processId;
   wstring      m_file1;
   wstring      m_file2;
   RequestType  m_type;

  private:
}; // GsWuiRequest

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_GSWUI_REQUEST_H_
