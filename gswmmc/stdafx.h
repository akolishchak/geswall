//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __stdafx_h__
#define __stdafx_h__


#ifndef UNICODE
#define UNICODE
#endif
#define FORCE_UNICODE

#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <mmc.h>
#include <gpedit.h>

#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

#include "gswioctl.h"

#include "list"
#include "string"
using namespace std;

#ifdef _DEBUG
#define trace commonlib::Debug::Write
#else
#define trace
#endif

#define IDC_UPDATE_DB				1000
#include "globals.h"


#endif