//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __ifstatus_h__
#define __ifstatus_h__

namespace ifstatus {

static const wchar_t* GlobalObjectName = L"Global\\{930621B8-83EB-407e-85C9-2C66178E4FED}";

enum Error {
    errSuccess              = 0,
    errUnsuccess            = 1,
    errNoMemory             = 2,
    errDriverNotFound       = 3,
    errDriverError          = 4,
	errAccessDenied			= 5,
	errServerInaccessible	= 6,
	errUpdateError			= 7
};

}; // namespace ifstatus

#endif // __ifstatus_h__