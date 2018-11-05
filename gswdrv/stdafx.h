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

extern "C" {
#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>
}
#include <csq.h>

#include <stdarg.h>
#include <stdio.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

namespace crypt {
    extern "C" {
        #include "mycrypt.h"
    }
}


#include "cpprt.h"

#define P "GESWALL: "


#if DBG
//#define trace DbgPrint
#define trace Log::DebugMessage
#else
#define	trace 
#endif


//#define trace Log::DebugMessage

#include "build.h"

#define ERR(x) trace(P"MESSAGE!!! %x detected in %s, line %d (build #%d)\n", \
                x, __FILE__, __LINE__, BUILD_VER )

#include "adapi.h"
#include "gswioctl.h"
#include "dispatch.h"
#include "rule.h"
#include "log.h"


extern ULONG NtVer;
extern UNICODE_STRING usRegParamName;
extern PDRIVER_OBJECT gDriverObject;

#endif   
