//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswserv_guictrl_exec_client_h_
 #define _gswserv_guictrl_exec_client_h_

#include "uiclient.h"

namespace gswserv {
namespace guictrl {

class exec_client;

class exec_client : public UIClient
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
   exec_client (HANDLE processId)
    : UIClient (processId, L"")
   {

   } // exec_client

   virtual ~exec_client ()
   {

   } // ~exec_client

  protected:
  private:

  //
  // data
  //
  public:
  protected:
  private:
}; // exec_client

} // namespace guictrl
} // namespace gswserv 

#endif //_gswserv_guictrl_exec_client_h_
