//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "configurator.h"
#include "w32registrynode.h"

#include <string>

namespace config {

#define CFG_ROOT_NODE_NAME L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\GeSWall\\Parameters"
#define CFG_CU_NODE_NAME   L"HKCU\\Software\\GentleSecurity\\GeSWall\\Parameters"
#define CFG_GP_NODE_NAME   L"HKLM\\Software\\Policies\\GentleSecurity\\GeSWall"
#define CFG_LM_NODE_NAME   L"HKLM\\Software\\GentleSecurity\\GeSWall"

const wchar_t* ROOT_NODE_NAME           = CFG_ROOT_NODE_NAME;
const wchar_t* STORAGE_NODE_NAME        = CFG_ROOT_NODE_NAME L"\\Storage";
const wchar_t* DRIVER_NODE_NAME         = CFG_ROOT_NODE_NAME;
const wchar_t* GSWL_POLICY_NAME         = CFG_ROOT_NODE_NAME L"\\GSWL";
const wchar_t* PROCESS_MARKER_NODE_NAME = CFG_CU_NODE_NAME L"\\ProcessMarker";
const wchar_t* UI_NODE_NAME             = CFG_ROOT_NODE_NAME L"\\UI";
const wchar_t* UPDATE_NODE_NAME         = CFG_ROOT_NODE_NAME L"\\Update";
const wchar_t* GP_NODE_NAME             = CFG_GP_NODE_NAME;
const wchar_t* LOG_WINDOW_NODE_NAME     = CFG_CU_NODE_NAME L"\\LogWindow2";
const wchar_t* NOTIFICATOR_NODE_NAME    = CFG_CU_NODE_NAME L"\\Notificator2";
const wchar_t* TRIALMANAGER_NODE_NAME   = CFG_CU_NODE_NAME L"\\TrialManager";
const wchar_t* APPSTAT_NODE_NAME		= CFG_CU_NODE_NAME L"\\LogCount\\Apps";

Configurator::PtrToINode Configurator::getServiceNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (ROOT_NODE_NAME), true));
} // getServiceNode
   
Configurator::PtrToINode Configurator::getStorageNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (STORAGE_NODE_NAME), true));
} // getStorageNode

Configurator::PtrToINode Configurator::getDriverNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (DRIVER_NODE_NAME), true));
} // getDriverNode

Configurator::PtrToINode Configurator::getGswlPolicyNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (GSWL_POLICY_NAME), true));
} // getGswlPolicyNode

Configurator::PtrToINode Configurator::getProcessMarkerNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (PROCESS_MARKER_NODE_NAME), true));
} // getProcessMarkerNode

Configurator::PtrToINode Configurator::getUiNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (UI_NODE_NAME), true));
} // getUiNode

Configurator::PtrToINode Configurator::getUpdateNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (UPDATE_NODE_NAME), true));
} // getUiNode

Configurator::PtrToINode Configurator::getGPNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (GP_NODE_NAME), true));
} // getUiNode

Configurator::PtrToINode Configurator::getLogWindowNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (LOG_WINDOW_NODE_NAME), true));
} // getLogWindowNode

Configurator::PtrToINode Configurator::getVendorNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (CFG_LM_NODE_NAME), true));
} // getVendorNode

Configurator::PtrToINode Configurator::getNotificatorNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (NOTIFICATOR_NODE_NAME), true));
} // getNotificatorNode

Configurator::PtrToINode Configurator::getTrialManagerNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (TRIALMANAGER_NODE_NAME), true));
} // getNotificatorNode

Configurator::PtrToINode Configurator::getAppStatNode ()
{
  return PtrToINode (new W32RegistryNode (wstring (APPSTAT_NODE_NAME), true));
} // getNotificatorNode


}; // namespace config {