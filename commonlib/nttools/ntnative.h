//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _NT_NATIVE_DEFS_H_
 #define _NT_NATIVE_DEFS_H_

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#undef PSLIST_ENTRY
#define PSLIST_ENTRY ::PSINGLE_LIST_ENTRY

namespace NT {

#ifdef __cplusplus
extern "C"
{
#endif

#pragma warning(disable: 4005)  // macro redefinition
#include <ntddk.h>
#pragma warning(default: 4005)

#include "ntextdefs.h"

#ifdef __cplusplus
} //extern "C"
#endif


} //namespace NT {

#pragma comment(lib, "ntdll.lib")

#endif //_NT_NATIVE_DEFS_H_
