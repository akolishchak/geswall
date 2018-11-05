//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//


#ifndef __stdafx_h__
#define __stdafx_h__

#ifndef _WIN32_IE
 #define _WIN32_IE 0x0501
#endif

#define _GSWUI_

#include <windows.h>
#include <shellapi.h>
#include <string>
#include <list>
#include "debug.h"
#include "gswioctl.h"
#include "gesruledef.h"
#include "verinfo.h"

#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>


#ifdef _DEBUG
#define trace commonlib::Debug::Write
#else
#define trace
#endif


#endif // __stdafx_h__