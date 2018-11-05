//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _MACRO_RESOLVER_H_
 #define _MACRO_RESOLVER_H_

#include <stdafx.h>
#include <string>
 
using namespace std;

namespace macro {

typedef list <wstring>                    ResultList;

wstring process (const wstring& data, HANDLE processId);
wstring process (const wstring& data, HANDLE processId, const wstring& processName);

size_t  process (wstring& result, const wstring& data, HANDLE processId);
size_t  process (wstring& result, const wstring& data, HANDLE processId, const wstring& processName);

size_t  process (ResultList& result, const wstring& data, HANDLE processId);
size_t  process (ResultList& result, const wstring& data, HANDLE processId, const wstring& processName);

} // namespace macro

#endif //_MACRO_RESOLVER_H_
