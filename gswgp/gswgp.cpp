//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "config/w32registrynode.h"
#include <initguid.h>
#include "guids.h"


HINSTANCE g_hinst;
const wchar_t *ExtKeyName = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\";

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, void* lpvReserved)
{
    if ( fdwReason == DLL_PROCESS_ATTACH ) {
        g_hinst = hinstDLL;
		//commonlib::Debug::SetMode(commonlib::Debug::outFile);
		//trace("gswgp started\n");
    }
    
    return TRUE;
}


STDAPI DllRegisterServer(void)
{
	LPOLESTR strCLSID = NULL;
    HRESULT hr = StringFromCLSID(CLSID_GESWALL_GPO, &strCLSID);
	if ( !SUCCEEDED(hr) ) return hr;

	MAKE_TSTRPTR_FROMWIDE(wcCSGuid, strCLSID);

	std::wstring CSKeyName(ExtKeyName);
	CSKeyName += wcCSGuid;
    CoTaskMemFree(strCLSID);

	config::W32RegistryNode Reg(HKEY_LOCAL_MACHINE, std::wstring(CSKeyName));

	Reg.setString(std::wstring(L"DllName"), L"gswgp.dll", REG_EXPAND_SZ);
	Reg.setInt(std::wstring(L"EnableAsynchronousProcessing"), 0);
	Reg.setInt(std::wstring(L"NoBackgroundPolicy"), 0);
	Reg.setInt(std::wstring(L"NoGPOListChanges"), 1);
	Reg.setInt(std::wstring(L"NoMachinePolicy"), 0);
	Reg.setInt(std::wstring(L"NoUserPolicy"), 1);
	//Reg.setInt(std::wstring(L"NoSlowLink"), 1);
	Reg.setString(std::wstring(L"ProcessGroupPolicy"), L"ProcessGeSWallPolicy");

	return S_OK;
}


STDAPI DllUnregisterServer(void)
{
	config::W32RegistryNode Reg(HKEY_LOCAL_MACHINE);
	LPOLESTR strCLSID = NULL;
    HRESULT hr = StringFromCLSID(CLSID_GESWALL_GPO, &strCLSID);
	if ( !SUCCEEDED(hr) ) return hr;

	MAKE_TSTRPTR_FROMWIDE(wcCSGuid, strCLSID);

	std::wstring CSKeyName(ExtKeyName);
	CSKeyName += wcCSGuid;
    CoTaskMemFree(strCLSID);

	try {
		Reg.deleteNode(std::wstring(CSKeyName));
	} catch ( ... ) {};

	return S_OK;
}

