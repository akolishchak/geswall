//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "reqgui.h"
#include "reqhandle.h"
#include "guictrl/gswuisupport.h"
//#include "guictrl/procmarkersupport.h"
#include "app/application.h"
#include "commonlib/commonlib.h"
#include "configurator.h"
#include "ifgswrpc_h.h"
#include "gswproc.h"
#include "license/licensemanager.h"


using namespace GesRule;

namespace ReqGui {

bool IsIsolatedProcess(const wchar_t *ProcessName)
{
	DWORD Pid = commonlib::Tools::GetProcessIdByName(ProcessName);
	if ( Pid == 0 )
		return false;

	CGswDrv Drv;
	return Drv.GetSubjIntegrity(Pid) < modTCB;
}
	
bool ThreatPointSubject(ThreatPointSubjectReq *Request, PVOID *Response, SIZE_T *ResponseSize, bool &CacheResult)
{
	bool bRes = false;

	bool bAskUser = true;
	if ( Request->Attr.Param[attOptions] & oboKeepTrusted ) {
		bRes = false;
		bAskUser = false;
	}

	if ( Request->Attr.Param[attOptions] & oboAutoIsolate ) {
		bRes = true;
		bAskUser = false;
	}

	if ( bAskUser ) {
		//
		// Check for ploNoPopups
		//
		config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
		if ( ( Request->Attr.Param[attOptions] & oboNoPopups ) || ( GesRule::TranslateSecurityLevel((GesRule::SecurityLevel)Node->getInt(L"SecurityLevel")) & GesRule::ploNoPopups ) ) {
			bRes = true;
			bAskUser = false;
		}
	}

	// if !bAskUser && msiexec && !Server then bAskUser = true
	if ( !bAskUser && Request->Attr.Param[attOptions] & oboSetup ) {
		license::LicenseManager::LicenseEssentials License;
		license::LicenseManager::LicenseCachedCopy(License);
		if ( License.Product != license::gswServer ) {
			bAskUser = true;
		}
	}
/*
	if ( bAskUser ) {
		//
		// If started from the isolated process with the same AppId then do not ask user
		// This is typically required to avoid duplicate messages for IE7-8
		//
		DWORD ParentPid = nttools::GetParentProcessId(HandleToUlong(Request->ProcessId));
		CGswDrv Drv;
		EntityAttributes Attributes;
		ULONG RuleId;
		if ( Drv.GetSubjAttributes(ParentPid, &Attributes, &RuleId) && Request->Attr.Param[attSubjectId] == Attributes.Param[attSubjectId] && Attributes.Param[attIntegrity] < modTCB )
			bAskUser = false;
	}
*/
	if ( !bAskUser ) {
//    if ( bRes ) gswserv::guictrl::ProcMarkerSupport::changeProcessState(Request->ProcessId, GesRule::modThreatPoint);
		return bRes;
	}

	std::wstring FileName = commonlib::Tools::FullNameToDOSName(Request->FileName);
	std::wstring ResourceName = commonlib::Tools::FullNameToDOSName(Request->ResourceName);
	GUIReply Reply = gswserv::guictrl::GsWuiSupport::queryReply(Request->ProcessId, (RequestType)Request->Type, FileName, ResourceName);

	bool bSaveReply = false;
	switch ( Reply ) {
		case gurUndefined:
		case gurNo:
			bRes = false;
			break;

		case gurYes:
			bRes = true;
			break;

		case gurNoAlways:
			Request->Attr.Param[attOptions] &= ~oboAutoIsolate;
			Request->Attr.Param[attOptions] |= oboKeepTrusted;
			bRes = false;
			bSaveReply = true;
			break;

		case gurYesAlways:
			Request->Attr.Param[attOptions] &= ~oboKeepTrusted;
			Request->Attr.Param[attOptions] |= oboAutoIsolate;
			bRes = true;
			bSaveReply = true;
			break;

		default:
			bRes = false;
			break;
	};

	if ( bSaveReply ) {
		int AppId = 0;
		if ( Request->RuleId != 0 && Request->Attr.Param[attSubjectId] != 0 &&
			Request->Attr.Param[attSubjectId] != Request->Attr.Param[attAutoSubjectId] ) {
			//
			// application already present in db then just update  it
			//
			// at first, get ApplicationItem for that application
			AppId = Request->Attr.Param[attSubjectId];
			App::Application Application(AppId, App::UserModified);
			Application.SetOptions(Request->Attr.Param[attOptions]);
			try {
				Application.StorageUpdate();
				if ( AppId != 0 ) GswProc::RefreshApp(AppId);
			} catch ( ... ) {
				AppId = 0;
			}
		}

		if ( AppId == 0 ) {
			//
			// it is unknown application - add it to database in unsorted group
			//
			App::Application Application(FileName.c_str());
			Application.SetOptions(Request->Attr.Param[attOptions]);
			Application.SetIntegrity((GesRule::ModelType)Request->Attr.Param[attIntegrity]);
			try {
				Application.StorageCreate(AppId);
				if ( AppId != 0 ) GswProc::RefreshApp(AppId);
			} catch ( ... ) {
				AppId = 0;
			}
		}
	}

//  if ( bRes )
//    gswserv::guictrl::ProcMarkerSupport::changeProcessState(Request->ProcessId, GesRule::modThreatPoint);

	return bRes;
}

bool IsolateTracked(NotIsolateTrackedReq *Request, PVOID *Response, SIZE_T *ResponseSize)
{
	bool bRes = false;

	//
	// Check for ploNoPopups
	//
	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCachedCopy(License);
	if ( License.Product == license::gswServer ) {
		//
		// check NoPopups policy in gswserv for Server Edition. For other products it is checked in gswui
		//
		config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
		if ( ( Request->Attr.Param[attOptions] & oboNoPopups ) || ( GesRule::TranslateSecurityLevel((GesRule::SecurityLevel)Node->getInt(L"SecurityLevel")) & GesRule::ploNoPopups ) ) {
			//
			// auto-isolate by default
			//
			return false;
		}
	}

	if ( NtVersion >= 0x0600 && Request->ProcessId != Request->ParentProcessId ) {
		//
		// if real parent is AppInfo then it is elevated application => no isolation required
		//
		bool IsAppInfo = false;
		SC_HANDLE hScManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
		if ( hScManager != NULL ) {
			SC_HANDLE hService = OpenService(hScManager, L"appinfo", SERVICE_QUERY_STATUS);
			if ( hService != NULL ) {
				SERVICE_STATUS_PROCESS Status;
				DWORD Length;
				if ( QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE) &Status, sizeof Status, &Length) && Status.dwProcessId == HandleToUlong(Request->ProcessId) ) {
					IsAppInfo = true;
				}
				CloseServiceHandle(hService);
			}
			CloseServiceHandle(hScManager);
		}

		if ( IsAppInfo == true )
			return true;
	}

	std::wstring FileName = commonlib::Tools::FullNameToDOSName(Request->FileName);
	GUIReply Reply = gswserv::guictrl::GsWuiSupport::queryReply(Request->ProcessId, (RequestType)Request->Type, 
							FileName, std::wstring(L""));

	switch ( Reply ) {
		case gurNo:
			bRes = true;
			break;

		case gurUndefined:
		case gurYes:
			bRes = false;
			break;

		default:
			bRes = false;
			break;
	}

	return bRes;
}


bool AccessSecretFile(AccessSecretFileReq *Request, PVOID *Response, SIZE_T *ResponseSize, bool &CacheResult)
{
	bool bRes = false;

	std::wstring ProcFileName = commonlib::Tools::FullNameToDOSName(Request->ProcFileName);
	std::wstring FileName = commonlib::Tools::FullNameToDOSName(Request->FileName);
	//
	// give access for directories
	//
	if ( !( GetFileAttributes(FileName.c_str()) & FILE_ATTRIBUTE_DIRECTORY ) ) {
		for (size_t i = FileName.size()-1; i >= 0; i-- )
			if ( FileName[i] == '\\' ) {
				FileName.resize(i+1);
				break;
			}
	}

	GUIReply Reply = gswserv::guictrl::GsWuiSupport::queryReply(Request->ProcessId, (RequestType)Request->Type, 
							ProcFileName, FileName);

	switch ( Reply ) {
		case gurNo:
			bRes = true;
			break;

		case gurUndefined:
		case gurYes:
			bRes = false;
			break;

		default:
			bRes = false;
			break;
	}

	return bRes;
}

} // namespace ReqGui {
