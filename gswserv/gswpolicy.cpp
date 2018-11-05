//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "gswpolicy.h"
#include "config/w32registrynode.h"
#include "config/configurator.h"
#include "gesruledef.h"

namespace GswPolicy {

ULONG IsolationTypesMask = 0;
ULONG IsolationOptions = 0;

bool IsIsolationRequired(const ThreatPointSubjectReq *Request)
{
	//
	// filter by type
	//
	ULONG Type = 1<<Request->ResourceType;
	if ( !( Type & IsolationTypesMask ) ) return false;
	
	if ( Request->ResourceType == nttNetwork ) return true;

	if ( IsolationOptions & GesRule::islCmdExe ) {
		static std::wstring ResolvedName;
		if ( ResolvedName.size() == 0 ) {
			wchar_t CmdExePath[MAX_PATH] = { 0 };
			if ( GetSystemDirectory(CmdExePath, sizeof CmdExePath / sizeof CmdExePath[0]) != 0 ) {
				StringCchCat(CmdExePath, sizeof CmdExePath / sizeof CmdExePath[0], L"\\cmd.exe");
				wcslwr(CmdExePath);
				commonlib::Tools::DOSNameToFullName(ResolvedName, CmdExePath);
			}
		}

		if ( wcsicmp(ResolvedName.c_str(), Request->FileName) == 0 ) {
			std::wstring Ext = Request->ResourceName;
			size_t Pos = Ext.find_last_of(L".");
			if ( Pos == std::wstring::npos ) return false; // no extension
			Ext.erase(0, Pos);
			if ( wcsicmp(Ext.c_str(), L".bat") == 0 || wcsicmp(Ext.c_str(), L".cmd") == 0 )
				return true;
			else
				return false;
		}

		if ( Request->Attr.Param[GesRule::attOptions] & GesRule::oboSetup ) {
			//
			// check for msiexec
			//
			std::wstring Ext = Request->ResourceName;
			size_t Pos = Ext.find_last_of(L".");
			if ( Pos == std::wstring::npos ) return false; // no extension
			Ext.erase(0, Pos);
			if ( wcsicmp(Ext.c_str(), L".msi") == 0 || wcsicmp(Ext.c_str(), L".msp") == 0 )
				return true;
			else
				return false;
		}
	}

	if ( IsolationOptions & GesRule::islRegisteredTypes ) {
		//
		// filter by file name (file extension)
		//
		std::wstring Ext = Request->ResourceName;
		size_t Pos = Ext.find_last_of(L".");
		if ( Pos == std::wstring::npos ) return false; // no extension
		Ext.erase(0, Pos);
		Ext.insert(0, L"HKEY_CLASSES_ROOT\\");
		try {
			W32RegistryNode Node(Ext, false);
			if ( Node.getString(L"").empty() ) throw commonlib::Exception(0);
		} catch ( ... ) {
			// not registered type;
			return false;
		}
		// registered type
		return true;
	}

	return true;
}

bool Init(void)
{
	config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
	IsolationTypesMask = Node->getUInt(L"IsolationTypesMask");
	IsolationOptions = Node->getUInt(L"IsolationOptions");

	return true;
}

}
