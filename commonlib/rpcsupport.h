//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_rpcsupport_h_
 #define _commonlib_rpcsupport_h_
 
#include <windows.h>
//#include <rpcndr.h>

namespace commonlib {
namespace rpcsupport {

namespace client {

RPC_BINDING_HANDLE  bind ();
void                unbind (RPC_BINDING_HANDLE rpc_handle);

} // namespace client {

namespace server {

void                init ();
RPC_BINDING_VECTOR* registerServer (RPC_IF_HANDLE _interface, int max_calls = 50);
void                unregisterServer (RPC_IF_HANDLE _interface, RPC_BINDING_VECTOR* binding_vector);

} // namespace server {

} // namespace rpcsupport {
} // namespace commonlib {

#endif // _commonlib_rpcsupport_h_