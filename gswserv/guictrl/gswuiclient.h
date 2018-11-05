//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_GSWUI_CLIENT_H_
 #define _GUICTRL_GSWUI_CLIENT_H_

#include "uiclient.h"

namespace gswserv {
namespace guictrl {

class GsWuiClient;

class GsWuiClient : public UIClient
{
  friend class ClientManager;

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
   GsWuiClient (HANDLE processId, const wstring& authorityHash)
    : UIClient (processId, authorityHash)
   {

   } // GsWuiClient

   virtual ~GsWuiClient ()
   {

   } // ~GsWuiClient

  protected:
  private:

  //
  // data
  //
  public:
  protected:
  private:
}; // GsWuiClient

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_GSWUI_CLIENT_H_
