//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _NT_NATIVE_TOOLS_H_
 #define _NT_NATIVE_TOOLS_H_

#include <string>
#include <list>
 
using namespace std;

namespace nttools {

typedef list<wstring>  StringList;

enum ObjectTypeIndex
{
  Any = 0,
  Driver,
  Device,
  SymbolicLink
};

static const wchar_t* ObjectType [] = 
{
  NULL,     
  L"Driver",     
  L"Device",
  L"SymbolicLink"
};

enum TransformType
{
  Nothing = 0,
  Toupper,
  Tolower
};

size_t  QueryXxx (const wstring& rootDir, StringList& objectNameList, const ObjectTypeIndex typeIndex, TransformType transformType = Nothing);
size_t  QueryXxx (const wstring& rootDir, StringList& objectNameList, const wchar_t* type, TransformType transformType = Nothing);
wstring QueryObjectType (const wstring& dirName, const wstring& objectName);
wstring QuerySymLinkTarget (const wstring& symLinkFullName, TransformType transformType = Nothing);
wstring QueryObjectName(::HANDLE Handle);
DWORD GetParentProcessId(DWORD ProcessId);

} // namespace nttools

#endif //_NT_NATIVE_TOOLS_H_
