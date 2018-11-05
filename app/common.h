//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __app_common_h__
#define __app_common_h__

#include <windows.h>
#include <string> 
#include <list> 
#include <boost/smart_ptr.hpp> 
#include "db/storage.h"
#include "commonlib/verinfo.h"
#include "gesruledef.h"
#include "commonlib/debug.h"

namespace App {

enum Option {
	Undefined			= 0,
	UseBinStubs			= 1,
	UserCreated			= 2,
	UserModified		= 4,
	FixDisplayName		= 8
};

const wchar_t FixNamePrefix[] = L"GeSWall.";
const size_t FixNamePrefixLength = sizeof FixNamePrefix / sizeof FixNamePrefix[0] - 1;

}; // namespace App {

#endif // __app_common_h__