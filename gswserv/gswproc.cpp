//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "ifstatus.h"
#include "ifgswrpc_h.h"

#include "gswproc.h"
#include "commonlib/tools.h"
#include "gswdrv.h"
#include "gswioctl.h"
#include "macroresolver.h"
#include "commonlib.h"
#include "configurator.h"
#include "guictrl/gswuisupport.h"
#include "license/licensemanager.h"
#include "update/update.h"
#include "aci.h"
#include "gesruledef.h"
#include "paramsmodifier.h"

using namespace std;
using namespace commonlib::Tools;
using namespace Storage;
using namespace macro;
using namespace gswserv::guictrl;

namespace GswProc {

error_status_t RefreshResources(void)
{
  error_status_t   result = ifstatus::errUnsuccess;
  ResourceItemList resList;
  RuleRecordList   rulesList;
  
  if (true == GetResourceList (resList))
  {
    for (ResourceItemList::iterator i = resList.begin (); i != resList.end (); ++i)
    {
      switch ((*i)->Identity.Type)
      {
        case idnOwner:
        case idnPath:
             createRuleRecord (rulesList, (*i), LongToHandle(GetCurrentProcessId ()), 0);
             break;
      } // switch
    } // for (...)
    
    if ( 0 == rulesList.size () ) return ifstatus::errUnsuccess;

    DWORD packLength = getRulesPackLength(rulesList);
    commonlib::Tools::PtrToByte buf (new BYTE[packLength]);
    if ( NULL == buf.get () )
      return ifstatus::errNoMemory;

    RulePack* rulePack    = reinterpret_cast <RulePack*> (buf.get ());
    if ( !fillRulesPack(rulePack, rulesList) ) return ifstatus::errUnsuccess;
    //
    // write to config
    //
    config::Configurator::PtrToINode Node = config::Configurator::getDriverNode();
    Node->setBinary(L"RuleRecords", buf.get(), packLength);

    CGswDrv Drv;
    if ( !Drv.IsValid() ) return ifstatus::errDriverNotFound;
    if ( !Drv.RefreshRules() ) return ifstatus::errDriverError;
    result = ifstatus::errSuccess;

  } // if (true == GetResourceList (resList))
  
  return result;
} // RefreshResources

error_status_t RefreshApp(int AppId)
{
  error_status_t   result = ifstatus::errUnsuccess;
  ApplicationItem  appItem;
  
  if (true == GetApplicationItem (AppId, appItem))
  {
    if (parAppPath == appItem.Params.Type)
    {
      wstring         name;
      size_t          nameSize   = process (name, wstring (appItem.Identity.Path.Path), LongToHandle(GetCurrentProcessId ()));
      if (0 < nameSize)
      {
        CAci Aci;
        SetAttributesInfo attrInfo;
        memcpy(attrInfo.Label, &GesRule::GswLabel, sizeof GesRule::GswLabel);
        
        attrInfo.hObject = CreateFile (name.c_str (), FILE_GENERIC_READ | ACCESS_SYSTEM_SECURITY, 
                                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE != attrInfo.hObject)
        {
          attrInfo.ResType = nttFile;
          attrInfo.Attr    = appItem.Params.Attributes;
        
          CGswDrv Drv;
          if ( Drv.IsValid() ) 
          {
              if ( Drv.SetAttributes (&attrInfo) ) 
                  result = ifstatus::errSuccess;
              else
                  result = ifstatus::errDriverError;
          } else 
          {
              //
              // driver not started, we are probably called during setup
              // set attrinutes manually
              //
              if ( Aci.SetAttr(attrInfo.hObject, attrInfo.Attr, GesRule::GswLabel) ) 
                  result = ifstatus::errSuccess;
          }
          
          CloseHandle (attrInfo.hObject);
        } // if (INVALID_HANDLE_VALUE != attrInfo.hObject)
      } // if (0 < nameSize)
    } // if (idnPath == appItem.Identity.Type)
  } // if (true == GetApplicationItem (AppId, appItem))
  
  return result;
} // RefreshApp

error_status_t RefreshApplications(void)
{
  error_status_t      result = ifstatus::errUnsuccess;
  ApplicationItemList appList;
  
  if (true == GetApplicationList (parAppPath, appList))
  {
    CAci Aci;
    CGswDrv Drv;
    for (ApplicationItemList::iterator i = appList.begin (); i != appList.end (); ++i)
    {
      ApplicationItem& appItem = *(*i);
      wstring          name;
      size_t           nameSize   = process (name, wstring (appItem.Identity.Path.Path), LongToHandle(GetCurrentProcessId ()));
      if (0 < nameSize)
      {
        SetAttributesInfo attrInfo;
        memcpy(attrInfo.Label, &GesRule::GswLabel, sizeof GesRule::GswLabel);
        
        attrInfo.hObject = CreateFile (name.c_str (), FILE_GENERIC_READ | ACCESS_SYSTEM_SECURITY, 
                                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE != attrInfo.hObject)
        {
		  result = ifstatus::errUnsuccess;
          attrInfo.ResType = nttFile;
          attrInfo.Attr    = appItem.Params.Attributes;
        
          if ( Drv.IsValid() ) 
          {
              if ( !Drv.SetAttributes (&attrInfo) ) {
                result = ifstatus::errDriverError;
			  } else {
				result = ifstatus::errSuccess;
			  }
          }
		  if ( result != ifstatus::errSuccess )
          {
              //
              // driver not started, we are probably called during setup
              // set attrinutes manually
              //
              if ( !Aci.SetAttr(attrInfo.hObject, attrInfo.Attr, GesRule::GswLabel) ) {
				  CloseHandle (attrInfo.hObject);
                  result = ifstatus::errUnsuccess;
                  break;
              }
              result = ifstatus::errSuccess;
          }
         
          CloseHandle (attrInfo.hObject);
        } // if (INVALID_HANDLE_VALUE != attrInfo.hObject)
      } // if (0 < nameSize)
    } // for (...)
  } // if (true == GetApplicationItem (AppId, appItem))
  
  return result;
} // RefreshApplications

error_status_t RefreshSettings(void)
{
    CGswDrv Drv;
    return Drv.RefreshSettings() == true ? ifstatus::errSuccess : ifstatus::errDriverError;
}

error_status_t QueryAuthorizationObject (HANDLE processId, wstring& objectName)
{
  GsWuiSupport::queryAuthorizationObject (processId, objectName);
  return ifstatus::errSuccess;
} // QueryAuthorizationObject

error_status_t RegisterClient (HANDLE processId, HANDLE objectHandle, wstring& authorityHash)
{
  error_status_t result = ifstatus::errUnsuccess;

  if (true == GsWuiSupport::registerClient (processId, objectHandle, authorityHash))
    result = ifstatus::errSuccess;

  return result;
} // RegisterClient

error_status_t WaitUiRequest (HANDLE processId, const wstring& authorityHash, int& RequestId, GUIRequestInfo& Request)
{
  error_status_t      result = ifstatus::errUnsuccess;
  
  GsWuiSupport::PtrToGsWuiRequest request = GsWuiSupport::waitRequest (processId, authorityHash);
  if (NULL != request.get ())
  {
    RequestId = request->getId ();
    
    wcscpy(Request.FileName1, request->getFile1 ().c_str ());
    wcscpy(Request.FileName2, request->getFile2 ().c_str ());
    Request.Type = request->getType ();
    
    result = ifstatus::errSuccess;
  } // if (NULL != request.get ())
  
  return result;
} // WaitUiRequest

error_status_t CancelWaitUiRequest (HANDLE processId, const wstring& authorityHash)
{
  error_status_t      result = ifstatus::errSuccess;
  
  GsWuiSupport::cancelWaitRequest (processId, authorityHash);
  
  return result;
} // CancelWaitUiRequest

error_status_t PutUiReply (HANDLE processId, const wstring& authorityHash, int RequestId, int Reply)
{
  GesRule::ModelType Model;
  ULONG Options;
  if ( AccessCheck(Model, Options) == false ) return ifstatus::errAccessDenied;

  GsWuiSupport::putReply (processId, authorityHash, RequestId, static_cast <GUIReply> (Reply));
  return ifstatus::errSuccess;
} // PutUiReply

error_status_t UpdateDb (HANDLE processId, const wstring& authorityHash, int& updateResult)
{
  error_status_t      result = ifstatus::errSuccess;
  
  updateResult = GsWuiSupport::updateDb (processId, authorityHash);
  
  return result;
} // UpdateDb

error_status_t CheckUpdateDb (HANDLE processId, const wstring& authorityHash, int& updateResult)
{
  error_status_t result = ifstatus::errSuccess;

  updateResult = GsWuiSupport::checkUpdateDb (processId, authorityHash);

  return result;
} // CheckUpdateDb

error_status_t GetProcessState (HANDLE processId, int& processState)
{
  error_status_t result = ifstatus::errSuccess;

//  processState = ProcMarkerSupport::getProcessState (processId);

  return result;
} // GetProcessState

error_status_t CancelPMWait (HANDLE processId)
{
  error_status_t      result = ifstatus::errSuccess;
  
//  ProcMarkerSupport::cancelWait (processId);
  
  return result;
} // CancelPMWait

error_status_t GetDesktopHook (HANDLE processId, const wstring& desktopName, HHOOK& hook)
{
  error_status_t result = ifstatus::errUnsuccess;

//  hook = ProcMarkerSupport::getDesktopHook (processId, desktopName);
//  if (NULL != hook)
//    result = ifstatus::errSuccess;

  return result;
} // GetDesktopHook

error_status_t SetDesktopHook (HANDLE processId, const wstring& desktopName, HHOOK hook)
{
  error_status_t result = ifstatus::errUnsuccess;

//  if (true == ProcMarkerSupport::setDesktopHook (processId, desktopName, hook))
//    result = ifstatus::errSuccess;

  return result;
} // SetDesktopHook

error_status_t WaitProcessMarkerInfo (const HANDLE processId, ProcMarkerInfo& processInfo, int timeout)
{
  error_status_t result = ifstatus::errUnsuccess;

//  if (true == ProcMarkerSupport::waitNotification (processId, processInfo, timeout))
//    result = ifstatus::errSuccess;

  return result;
} // WaitProcessMarkerInfo

bool AccessCheck(GesRule::ModelType &Model, ULONG &Options)
{
	Model = GesRule::modUndefined;
	CGswDrv GswDrv;
	if ( !GswDrv.IsValid() || GswDrv.GetReleaseId() != RELEASE_ID ) {
		//
		// No driver or other release,  return true
		//
		return true;
	}
	EntityAttributes Attributes;
	ULONG RuleId;
	if ( GswDrv.GetCurrentSubjIntegrity(&Attributes, &RuleId) ) {
		Model = (GesRule::ModelType) Attributes.Param[GesRule::attIntegrity];
		Options = Attributes.Param[GesRule::attOptions];
		if ( Options & GesRule::oboGeSWall ) return true;
	}

	return false;
}

error_status_t SetModifier(const ModifierType Type, const DWORD ProcessId, const DWORD ThreadId)
{
	ParamsModifier::Set(Type, ProcessId, ThreadId);
	return ifstatus::errSuccess;
}

error_status_t GetNumberOfTrialDays(int &DaysNum)
{
	DaysNum = license::LicenseManager::GetNumberOfTrialDays();
	return ifstatus::errSuccess;
}

error_status_t SwitchToLicense(const wstring &LicenseFile, HANDLE hToken)
{
	Configurator::PtrToINode srv_node = Configurator::getServiceNode ();
	if ( NULL == srv_node.get() ) return ifstatus::errUnsuccess;

	std::wstring InstallDir = srv_node->getString (L"InstallDir");
	std::wstring CurrentLicenseFile = InstallDir + L"/license.xml";
	//
	// Perform following operations in the context of calling user
	// unless it is trusted license files
	//
	bool Impersonated = false;
	bool TrustedLicense = false;
	std::wstring LicensePro = InstallDir + L"/license_per.xml";
	std::wstring LicensePer = InstallDir + L"/license_pro.xml";
	if ( LicenseFile == LicensePro || LicenseFile == LicensePer ) TrustedLicense = true;

	if ( TrustedLicense == false ) {
		HANDLE hThread = GetCurrentThread();
		if ( FALSE == SetThreadToken(&hThread, hToken) ) return ifstatus::errUnsuccess;
		Impersonated = true;
	}

	HANDLE hFile;
/*
	hFile = CreateFile(CurrentLicenseFile.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) {
		int Err = GetLastError();
		if ( Impersonated ) RevertToSelf();
		if ( Err == ERROR_ACCESS_DENIED )
			return ifstatus::errAccessDenied;
		else
			return ifstatus::errUnsuccess;
	}
	CloseHandle(hFile);
*/
	//
	// Check new license first
	//
	// 1. Sanity checks
	//
	DWORD Attr = GetFileAttributes(LicenseFile.c_str());
	if ( Attr == INVALID_FILE_ATTRIBUTES || ( Attr & ( FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE ) ) ) {
		if ( Impersonated ) RevertToSelf();
		return ifstatus::errUnsuccess;
	}
	hFile = CreateFile(LicenseFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) {
		int Err = GetLastError();
		if ( Impersonated ) RevertToSelf();
		if ( Err == ERROR_ACCESS_DENIED )
			return ifstatus::errAccessDenied;
		else
			return ifstatus::errUnsuccess;
	}
	Attr = GetFileType(hFile);
	CloseHandle(hFile);
	if ( Attr == FILE_TYPE_CHAR || Attr == FILE_TYPE_PIPE ) {
		if ( Impersonated ) RevertToSelf();
		return ifstatus::errUnsuccess;
	}
	//
	// 2. content check
	//
	license::LicenseManager::LicenseEssentials NewLicense;
	if ( license::LicenseManager::getLicenseEssentials(NewLicense, LicenseFile.c_str()) == false ) {
		if ( Impersonated ) RevertToSelf();
		return ifstatus::errUnsuccess;
	}
	license::LicenseManager::LicenseEssentials CurrentLicense;
	license::LicenseManager::LicenseCopy(CurrentLicense);
	//
	// if current license is Freware Edition and new one is Pro
	// then check online status
	//
	if ( CurrentLicense.Product == license::gswStandard && NewLicense.Product == license::gswProfessional ) {
		wstring		 db_version;
		int			 db_version_number = Storage::GetDbVersion();
		wchar_t      db_version_buffer [65];
		_itow (db_version_number, db_version_buffer, 10);
		db_version.assign (db_version_buffer);

		bool check_update = false;
		try {
			if ( Impersonated == false ) {
				HANDLE hThread = GetCurrentThread();
				if ( FALSE == SetThreadToken(&hThread, hToken) ) return ifstatus::errUnsuccess;
			}
			check_update = update::checkDbUpdate(db_version, L"47", NewLicense.InstallId);
			if ( TrustedLicense ) {
				RevertToSelf();
				Impersonated = false;
			}
		} catch ( ... ) {
			check_update = false;
		}
		if ( check_update == false ) {
			if ( Impersonated ) RevertToSelf();
			return ifstatus::errServerInaccessible;
		}
	}

	if ( Impersonated ) RevertToSelf();

	//
	// License is alid, copy it over the current one
	//
	bool CleanupRequred = ( CurrentLicense.StateFlags & license::stateTrial ) && NewLicense.Product == license::gswStandard;
	if ( CopyFile(LicenseFile.c_str(), CurrentLicenseFile.c_str(), FALSE) == FALSE ) {
		int Err = GetLastError();
		//if ( Impersonated ) RevertToSelf();
		if ( Err == ERROR_ACCESS_DENIED )
			return ifstatus::errAccessDenied;
		else
			return ifstatus::errUnsuccess;
	}

	if ( CurrentLicense.Product == license::gswStandard && NewLicense.Product == license::gswProfessional ) {
		try {
			Storage::SetUpdateVersion(47);
		} catch ( ... ) {
			return ifstatus::errUnsuccess;
		}
	}
	//
	// if current license is trial and new one is Freeware Edition
	// then clean-up db
	//
	if ( CleanupRequred ) {
		try {
			Storage::CleanupForPersonalEdition();
		} catch ( ... ) {}
	}
	//
	// reload new license (required?)
	//
	license::LicenseManager::Refresh();

	return ifstatus::errSuccess;
}


}; // namespace GswProc