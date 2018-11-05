//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __stdfs_h__
#define __stdfs_h__

extern "C" {
#include <ntifs.h>
}

#include "cpprt.h"

#define P "GESWALL: "

#if DBG
#define trace DbgPrint
#else
#define  trace 
#endif

#include "build.h"

#define ERR(x) trace(P"MESSAGE!!! %x detected in %s, line %d (build #%d)\n", \
                x, __FILE__, __LINE__, BUILD_VER )

#include "gswioctl.h"
#include "dispatch.h"
#include "rule.h"
#include "log.h"


extern ULONG NtVer;
extern UNICODE_STRING usRegParamName;


extern PDEVICE_OBJECT gControlDevice;
extern PDRIVER_OBJECT gDriverObject;
extern ULONG NtVer;

//
//  Macro to validate our current IRQL level
//
#define VALIDATE_IRQL(_irp) ASSERT(KeGetCurrentIrql() <= APC_LEVEL)

#define IS_DESIRED_DEVICE_TYPE(_type) \
    (((_type) == FILE_DEVICE_DISK_FILE_SYSTEM) || \
     ((_type) == FILE_DEVICE_CD_ROM_FILE_SYSTEM) || \
     ((_type) == FILE_DEVICE_NETWORK_FILE_SYSTEM) || \
	 ((_type) == FILE_DEVICE_NAMED_PIPE))


#endif // __stdfs_h__