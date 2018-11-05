//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "policy.h"
#include "guids.h"
#include "update/app.h"
#include "config/configurator.h"
#include "db/storage.h"
#include "interface/gswclient.h"
#include "license/licensemanager.h"



DWORD CALLBACK ProcessGeSWallPolicy(
  DWORD dwFlags,
  HANDLE hToken,
  HKEY hKeyRoot,
  PGROUP_POLICY_OBJECT pDeletedGPOList,
  PGROUP_POLICY_OBJECT pChangedGPOList,
  ASYNCCOMPLETIONHANDLE pHandle,
  BOOL *pbAbort,
  PFNSTATUSMESSAGECALLBACK pStatusCallback
)
{
	//DebugBreak();
	commonlib::Debug::SetMode(commonlib::Debug::outDebugger);
	trace("ProcessGeSWallPolicy callback, dwFlags = %d\n", dwFlags);
	//
	// pass for irrelevant cases
	//
	if ( !( dwFlags & GPO_INFO_FLAG_MACHINE ) ||
		 ( dwFlags & GPO_INFO_FLAG_NOCHANGES && !( dwFlags & GPO_INFO_FLAG_FORCED_REFRESH ) )
	   ) {
		return ERROR_SUCCESS;
	}

    license::LicenseManager::LicenseEssentials License;
    license::LicenseManager::LicenseCopy(License);
	if ( License.Product == license::gswStandard ) return ERROR_SUCCESS;

	//
	// Must apply policy changes, get the list of GPO
	//
	DWORD rc = ERROR_SUCCESS;
	bool FreePolicy = true;
	PGROUP_POLICY_OBJECT Policy;
	GUID Extension = CLSID_GESWALL_GPO;
	rc = GetAppliedGPOList(GPO_LIST_FLAG_MACHINE, NULL, NULL, &Extension, &Policy);
	if ( rc != ERROR_SUCCESS ) {
		trace("GetAppliedGPOList failure, rc = %d\n", rc);
		FreePolicy = false;
		Policy = pChangedGPOList;
	}
	//
	// Go through the list
	//
	config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
	Storage::SetDBSetting(Node);
	bool DbUpdated = false;

	for ( PGROUP_POLICY_OBJECT Gpo = Policy; Gpo != NULL; Gpo = Gpo->pNext ) {
		//
		// Dump GPO
		//
        trace("GPO \'%-24.24S\' (Ver % 4X)\t[", (wchar_t*)(Gpo->lpDisplayName ? Gpo->lpDisplayName : L"(null)"), Gpo->dwVersion & 0xffff );
		switch ( Gpo->GPOLink ) {
			case GPLinkUnknown:	
				trace("GPLinkUnknown");
				break;

			case GPLinkMachine:	
				trace("GPLinkMachine");
				break;

			case GPLinkSite:
				trace("GPLinkSite");
				break;

			case GPLinkDomain:
				trace("GPLinkDomain");
				break;

			case GPLinkOrganizationalUnit:
				trace("GPLinkOrganizationalUnit");
				break;

			default:
				trace("GPLink = %d", Policy->GPOLink );
				break;
		}
		trace("] ");
		if ( Gpo->dwOptions & GPO_FLAG_DISABLE ) trace("\n\tThis agpo is disabled.");
		if ( Gpo->dwOptions & GPO_FLAG_FORCE ) trace("\n\tDo not override the settings in this gpo with settings in a subsequent gpo.");
		trace("FileSysPath = %S\n", Gpo->lpFileSysPath);

		if ( Gpo->dwOptions & GPO_FLAG_DISABLE ) continue;

		bool Update = true;
		if ( Gpo->GPOLink == GPLinkMachine ) {
			std::wstring ConnectString = Node->getString(L"connectString");
			if ( _wcsnicmp(ConnectString.c_str(), Gpo->lpFileSysPath, wcslen(Gpo->lpFileSysPath)) == 0 ) Update = false;
		}

		if ( Update ) {
			//
			// Get gpo database file and sync it with current
			//
			try {
				update::app::processAppDb(Gpo->lpFileSysPath, commonlib::Debug::outDebugger, License.Product);
			} catch ( ... ) {
			}
			DbUpdated = true;
		}

		if ( Gpo->dwOptions & GPO_FLAG_FORCE ) break;
	}

	Storage::close();
	if ( FreePolicy) FreeGPOList(Policy);

	if ( DbUpdated ) {
		//
		// notify driver
		//
		GswClient Client;
		Client.RefreshResources();
		Client.RefreshApplications();
	}

	//
	// take care of registry settings
	//
	Node = config::Configurator::getGswlPolicyNode();
	config::Configurator::PtrToINode GPNode = config::Configurator::getGPNode();
	int GPSecurityLevel = GPNode->getInt(L"SecurityLevel");
	if ( Node->getInt(L"SecurityLevel") != GPSecurityLevel ) {
		//
		// Update SecurityLevel if changed
		//
		Node->setInt(L"SecurityLevel", GPSecurityLevel);
		GswClient Client;
		Client.RefreshSettings();
	}

	return rc;
}
