//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __stdafx_h__
#define __stdafx_h__

#include <windows.h>
#include <userenv.h>

#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

#include <string>
#define STRINGS_ONLY
#include <globals.h>
#include "commonlib/debug.h"

#ifdef _DEBUG
#define trace commonlib::Debug::Write
#else
#define trace
#endif


#endif // __stdafx_h__