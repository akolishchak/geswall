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
#include <list>
#include "debug.h"
#include "commonlib/tools.h"
#include "gswioctl.h"
#include "gesruledef.h"

#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>


#ifdef _DEBUG
#define trace commonlib::Debug::Write
#else
#define trace
#endif

#ifdef _DEBUG
#define START_COUNTER   __int64 t0, t1, f; \
                        QueryPerformanceCounter((LARGE_INTEGER *) &t0);
#define END_COUNTER(x)  QueryPerformanceCounter((LARGE_INTEGER *) &t1); \
                        QueryPerformanceFrequency((LARGE_INTEGER *) &f); \
                        trace(#x"(): total time = %.1lf msec\n", \
                            (double) ( t1 - t0 ) * 1000.0 / (double) f);
#else
#define START_COUNTER
#define END_COUNTER(x)
#endif

#define INTERFACE_SERVER

extern DWORD NtVersion;
extern bool bService;

#endif // __stdafx_h__