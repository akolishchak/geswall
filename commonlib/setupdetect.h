//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __setupdetect_h__
#define __setupdetect_h__

#include <windows.h>
#include <string>

namespace commonlib {

namespace SetupDetect
{
	 bool IsSetup(const std::wstring &fname);
}; // class SetupDetect

} // namespace commonlib

#endif // __setupdetect_h__