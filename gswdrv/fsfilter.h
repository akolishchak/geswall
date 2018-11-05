//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __fsfilter_h__
#define __fsfilter_h__


#define MAX_DEVNAME_LENGTH          (64)

namespace FsFilter {
    NTSTATUS Init(VOID);
    VOID DetachVdo(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice);

    enum TargetDeviceType {
        tdtCdo,
        tdtVdo
    };

    struct Extension : GswDispatch::Extension {
        TargetDeviceType TargetType;
        PUNICODE_STRING DeviceName;
    };

    struct CdoExtension : Extension {
        //
        // Entry for list of all attached devices
        //
        LIST_ENTRY Entry;
    };

    struct VdoExtension : Extension {
        //
        //  Pointer to the real (disk) device object that is associated with
        //  the file system device object we are attached to
        //
        PDEVICE_OBJECT StorageDevice;
        //
        // Refrence to file system CDO VDO comes from
        //
        PDEVICE_OBJECT Cdo;
        //
        // Entry for list of all attached devices
        //
        LIST_ENTRY Entry;
    };

	enum {
		DisableLogging	= false,
		EnableLogging	= true
	};

	BOOLEAN IsFileReadOnly(PFILE_OBJECT FileObject, bool LoggingMode);
	BOOLEAN IsRedirectedFile(PUNICODE_STRING FileName);

};

#include "fstools.h"

#endif // __fsfilter_h__