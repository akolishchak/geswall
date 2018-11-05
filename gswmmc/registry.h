//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __Registry_H__
#define __Registry_H__

#include <tchar.h>

// This function will register a component in the Registry.
// The component calls this function from its DllRegisterServer function.
HRESULT RegisterServer(HMODULE hModule, 
                       const CLSID& clsid, 
                       const _TCHAR* szFriendlyName) ;

// This function will unregister a component.  Components
// call this function from their DllUnregisterServer function.
HRESULT UnregisterServer(const CLSID& clsid) ;


// This function will register a Snap-In component.  Components
// call this function from their DllRegisterServer function.
HRESULT RegisterSnapin(const CLSID& clsid,         // Class ID
                       const _TCHAR* szNameString,   // NameString
                       const CLSID& clsidAbout,		// Class Id for About Class
					   const CLSID &clsidExtension, // Extension Id
					   const _TCHAR *szDescription, // Extension Description
                       const BOOL fSupportExtensions = FALSE);

HRESULT UnregisterSnapin(const CLSID& clsid);         // Class ID

#endif