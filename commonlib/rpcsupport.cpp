//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "rpcsupport.h"

#include "commondefs.h"
#include "exceptions.h"

namespace commonlib {
namespace rpcsupport {

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

namespace client {

RPC_BINDING_HANDLE bind ()
{
  RPC_BINDING_HANDLE result;
  RPC_STATUS         st;
  unsigned short*    binding_string;

  st = ::RpcStringBindingCompose (NULL, L"ncalrpc", L"", NULL, NULL, &binding_string);
  if (RPC_S_OK != st) 
    throw Exception (L"Error RpcStringBindingCompose", st);

  scope_guard binding_string_guard = make_guard (&binding_string, &::RpcStringFree);

  st = ::RpcBindingFromStringBinding (binding_string, &result);
  if (RPC_S_OK != st) 
    throw Exception (L"Error RpcBindingFromStringBinding", st);

  scope_guard result_guard = make_guard (&result, &::RpcBindingFree);

  st = ::RpcBindingSetAuthInfo (result, 0, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, 0, 0);
  if (RPC_S_OK != st)
    throw Exception (L"Error RpcBindingSetAuthInfo", st);

  result_guard.release ();

  return result;
} // bind

void unbind (RPC_BINDING_HANDLE rpc_handle)
{
    RPC_STATUS st = ::RpcBindingFree (&rpc_handle);
    if (RPC_S_OK != st) 
      throw Exception (L"Error RpcBindingFree", st);
} // unbind

} // namespace client {

namespace server {

//RPC_IF_HANDLE IfSpec[] = {
//    GSWRPC_v1_0_s_ifspec
//};

//static wchar_t*            Protocol[]    = { L"ncalrpc" };
//static RPC_BINDING_VECTOR* BindingVector = NULL;

struct server_unreg
{
  void operator () (RPC_IF_HANDLE _interface)
  {
    RPC_STATUS st = ::RpcServerUnregisterIf (_interface, NULL, TRUE);
    if (RPC_S_OK != st)
      throw Exception (L"Error RpcServerUnregisterIf", st);
  }
}; // server_unreg

void addProtocol (const wchar_t* protocol) // default L"ncalrpc"
{
  RPC_STATUS st = ::RpcServerUseProtseq (const_cast <wchar_t*> (protocol), RPC_C_PROTSEQ_MAX_REQS_DEFAULT, NULL);   
  if (RPC_S_OK != st)
    throw Exception (L"Error RpcServerUseProtseq", st);
} // addProtocol

void init ()
{
  addProtocol (L"ncalrpc");
} // init

RPC_BINDING_VECTOR* registerServer (RPC_IF_HANDLE _interface, int max_calls)
{
  RPC_BINDING_VECTOR* binding_vector;
  RPC_STATUS          st;

  st = ::RpcServerRegisterIfEx (_interface, NULL, NULL, RPC_IF_AUTOLISTEN, max_calls, NULL);
  if (RPC_S_OK != st) 
    throw Exception (L"Error RpcServerRegisterIfEx", st);
  
  scope_guard server_reg_guard = make_guard (_interface, server_unreg ());

  st = ::RpcServerInqBindings (&binding_vector);
  if (RPC_S_OK != st)
    throw Exception (L"Error RpcServerInqBindings", st);

  scope_guard server_bind_guard = make_guard (&binding_vector, &::RpcBindingVectorFree);
  
  st = ::RpcEpRegister (_interface, binding_vector, NULL, NULL);
  if (RPC_S_OK != st)
    throw Exception (L"Error RpcEpRegister", st);

  server_reg_guard.release ();
  server_bind_guard.release ();

  return binding_vector;
} // registerServer

void unregisterServer (RPC_IF_HANDLE _interface, RPC_BINDING_VECTOR* binding_vector)
{
  RPC_STATUS st;

  st = ::RpcEpUnregister (_interface, binding_vector, NULL);
  st = ::RpcBindingVectorFree (&binding_vector);
  st = ::RpcServerUnregisterIf (_interface, NULL, TRUE);
} // unregisterServer

} // namespace server {

} // namespace rpcsupport {
} // namespace commonlib {

void __RPC_FAR * __RPC_API midl_user_allocate (size_t cBytes) 
{ 
  return(malloc(cBytes)); 
} // midl_user_allocate

void __RPC_USER midl_user_free (void __RPC_FAR * p)
{
  free(p);
} // midl_user_free
