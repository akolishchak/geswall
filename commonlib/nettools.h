//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __nettools_h__
#define __nettools_h__

#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <string>
#include "commonlib.h"
//#include "boost/smart_ptr.hpp"



namespace commonlib {
//typedef boost::shared_array<byte>          PtrToByte;

namespace nettools {

bool GetSidByName(const wchar_t *Name, PtrToByte &Sid);
bool GetStringSidByName(const wchar_t *Name, std::wstring &StringSid);
bool GetNameBySid(const byte *Sid, std::wstring &Name);
bool GetNameByStringSid(const wchar_t *StringSid, std::wstring &Name);


}; // namespace netools {


}; // namespace stdlib {

#endif // __nettools_h__

