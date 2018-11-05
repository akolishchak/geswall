//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "app/common.h"
#include "application.h"
#include "commonlib/commonlib.h"
#include "commonlib/images.h"
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

using namespace commonlib;

namespace App {

wchar_t *Application::UndefinedStr = commonlib::VerInfo::UndefinedStr;

bool Application::Init(const wchar_t *_FileName, Storage::IdentityType Identity, ULONG _Options)
{
	Release();

	Options = _Options;
	FileName = _FileName;
	StringCchCopy(Item.FileName, sizeof Item.FileName / sizeof Item.FileName[0], _FileName);

	FillApplicationInfo(_FileName, Item, Options);
	//
	// Fill out ResourceItem part
	//
	Item.Params.Options = 0;
	Item.Params.Model = GesRule::GswLabel;
	Item.Params.GroupId = 0;
	Item.Params.Id = 0;
	memset(&Item.Params.Attributes, 0, sizeof Item.Params.Attributes);

	if ( Identity == Storage::idnUnknwon ) {
		Identity = Storage::idnContent;
		if ( IsIdentifiedByVerinfo(&Item) )
			Identity = Storage::idnContent;
		else
			Identity = Storage::idnPath;
	}

	switch ( Identity ) {
		case Storage::idnContent:
			if ( !SetVerinfoIdentity(&Item, Options) ) return false;

			StringCchCopy(Item.Identity.Info.FileName,
							sizeof Item.Identity.Info.FileName / sizeof Item.Identity.Info.FileName[0],
							FileName.c_str());
			StringCchCopy(Item.Params.Description,
							sizeof Item.Params.Description / sizeof Item.Params.Description[0],
							FileName.c_str());
			break;

		case Storage::idnPath:
			Item.Params.Type = Storage::parAppPath;
			Item.Identity.Type = Storage::idnPath;
			Item.Identity.Path.Options = 0;
			if ( Options & UserCreated ) {
				Item.Identity.Path.Options = Storage::dboUserCreated;
			}
			Item.Identity.Path.Type = nttFile;
			StringCchCopy(Item.Identity.Path.Path,
						sizeof Item.Identity.Path.Path / sizeof Item.Identity.Path.Path[0],
						FileName.c_str());
			StringCchCopy(Item.Params.Description,
						sizeof Item.Params.Description / sizeof Item.Params.Description[0],
						FileName.c_str());
			break;

		case Storage::idnDigest:
			{
			}
			break;

		default:
			return false;
	}
	
	bInited = true;
	return true;
}

bool Application::Init(const int _AppId, const ULONG _Options)
{
	Release();
	Options = _Options;
	try {
		bInited = Storage::GetApplicationItem(_AppId, Item);
	} catch ( ... ) {
	}
	return bInited;
}
bool Application::InitItem(const int _AppId, Storage::ApplicationItem &_Item)
{
	Release();
	Options =0;
	try {
		bInited = Storage::GetApplicationItem(_AppId, _Item);
		Item=_Item;
	} catch ( ... ) {
	}
	return bInited;
}

bool Application::Init(const Storage::ApplicationItem &_Item, const Group::UniqueId *_GroupUniqueId, ULONG _Options)
{
	Release();
	Options = _Options;

	Item = _Item;
	FileName = Item.FileName;
	if ( _GroupUniqueId != NULL ) GroupUniqueId = *_GroupUniqueId;

	bInited = true;
	return true;
}


void Application::StorageCreate(int &AppId)
{
	if ( !bInited /* || Item.Params.Attributes.Param[GesRule::attSubjectId] != 0 */ )
		throw Storage::StorageException(Storage::ErrorUnknown);
	Item.Params.Options = 0;
	Item.Params.Attributes.Param[GesRule::attSubjectId] = 0;
	if ( Options & UserCreated ) Item.Params.Options |= Storage::dboUserCreated;
	AppId = 0;
	wstring DisplayName = Item.Params.Description;
	while ( true ) {
		try {
			Storage::InsertApplication(Item, AppId);
		} catch( Storage::DisplayNameExistException ) {
			if ( Options & FixDisplayName ) {
				DisplayName.insert(0, FixNamePrefix);
				SetDisplayName(DisplayName.c_str());
				continue;
			} else {
				throw;
			}
		}
		break;
	}
	if ( AppId != 0 ) Item.Params.Attributes.Param[GesRule::attSubjectId] = AppId;
}

void Application::StorageCreate(const int GroupId, int &AppId)
{
	Item.Params.GroupId = GroupId;
	StorageCreate(AppId);
}

void Application::StorageMove(const int GroupId)
{
	Item.Params.GroupId = GroupId;
	StorageUpdate();
}

void Application::StorageUpdate(void)
{
	int AppId = Item.Params.Attributes.Param[GesRule::attSubjectId];
	if ( !bInited || AppId == 0 ) throw Storage::StorageException(Storage::ErrorUnknown);

	if ( Options & UserModified )
		Item.Params.Options |= Storage::dboUserModified;
	else
		Item.Params.Options &= ~(Storage::dboUserModified | Storage::dboUserCreated);

	wstring DisplayName = Item.Params.Description;
	while ( true ) {
		try {
			Storage::UpdateApplication(AppId, Item);
		} catch( Storage::DisplayNameExistException ) {
			if ( Options & FixDisplayName ) {
				DisplayName.insert(0, FixNamePrefix);
				SetDisplayName(DisplayName.c_str());
				continue;
			} else {
				throw;
			}
		}
		break;
	}
}

void Application::StorageDelete(void)
{
	int AppId = Item.Params.Attributes.Param[GesRule::attSubjectId];
	if ( !bInited || AppId == 0 ) throw Storage::StorageException(Storage::ErrorUnknown);

	Storage::DeleteApplication(AppId);
}

bool Application::IsNetworked(void)
{
	if ( !bInited ) return false;

	return false;
}

bool Application::IsUserCreated(void)
{
	if ( !bInited ) return false;
	return ( GetOptions() & Storage::dboUserCreated ) != 0;
}

bool Application::IsUserModified(void)
{
	if ( !bInited ) return false;
	return ( Item.Params.Options & Storage::dboUserModified ) != 0;
}

void Application::SetGroup(const int GroupId)
{
	Item.Params.GroupId = GroupId;
}

int Application::GetAppId(void)
{
	return Item.Params.Attributes.Param[GesRule::attSubjectId];
}

int Application::GetGroup(void)
{
	return Item.Params.GroupId;
}

void Application::SetGroupUniqueId(const Group::UniqueId &Id)
{
	GroupUniqueId = Id;
}

Group::UniqueId *Application::GetGroupUniqueId(void)
{
	return &GroupUniqueId;
}

void Application::SetIntegrity(GesRule::ModelType Integrity)
{
	Item.Params.Attributes.Param[GesRule::attIntegrity] = Integrity;
}

void Application::SetConfident(GesRule::ConfidentLevel Confident)
{
	Item.Params.Attributes.Param[GesRule::attConfident] = Confident;
}

void Application::SetSecurityLevel(SecurityLevel Level)
{
	switch ( Level ) {
		case selUntrusted:
			Item.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modUntrusted;
			//Item.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboJail;
			//Item.Params.Attributes.Param[GesRule::attOptions] = 0;
			break;

		case selAutoIsolated:
			Item.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
			Item.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboAutoIsolate;
			break;

		case selTrusted:
			Item.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
			Item.Params.Attributes.Param[GesRule::attOptions] = 0;
			break;

		case selAlwaysTrusted:
			Item.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
			Item.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboKeepTrusted;
			break;

		case selNoPopups:
			Item.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
			Item.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboNoPopups;

		default:
			break;
	}
}

Application::SecurityLevel Application::GetSecurityLevelCode(Storage::ApplicationItem &Item)
{
	long options=0, integrity=0;
		options   =	 Item.Params.Attributes.Param[GesRule::attOptions];
		integrity =  Item.Params.Attributes.Param[GesRule::attIntegrity];
		
		if((integrity == GesRule::modTCB) && (options & GesRule::oboKeepTrusted))
			return selAlwaysTrusted;
		else 
		if((integrity == GesRule::modTCB) && (options & GesRule::oboAutoIsolate))
			return selAutoIsolated;	
		else
		if((integrity == GesRule::modTCB) && !(options & (GesRule::oboKeepTrusted | GesRule::oboAutoIsolate | GesRule::oboNoPopups)))
			return selTrusted;
		else
		if( integrity == GesRule::modUntrusted )
			return selUntrusted;
		else
		if((integrity == GesRule::modTCB) && (options & GesRule::oboNoPopups))
			return selNoPopups;
}




void Application::SetOptions(ULONG Options)
{
	Item.Params.Attributes.Param[GesRule::attOptions] = Options;
}

void Application::AddOptions(ULONG Options)
{
	Item.Params.Attributes.Param[GesRule::attOptions] |= Options;
}

const wchar_t *Application::GetDisplayName(void)
{
	return Item.Params.Description;
}

void Application::SetDisplayName(const wchar_t *DisplayName)
{
	StringCchCopy(Item.Params.Description, sizeof Item.Params.Description / sizeof Item.Params.Description[0], DisplayName);
}

void Application::SetPathName(const wchar_t *_FileName)
{
	switch ( Item.Identity.Type ) {
		case Storage::idnContent:
			StringCchCopy(Item.Identity.Info.FileName,
							sizeof Item.Identity.Info.FileName / sizeof Item.Identity.Info.FileName[0],
							_FileName);
			break;

		case Storage::idnPath:
			StringCchCopy(Item.Identity.Path.Path,
						sizeof Item.Identity.Path.Path / sizeof Item.Identity.Path.Path[0],
						_FileName);
			break;

		case Storage::idnDigest:
			StringCchCopy(Item.Identity.Digest.FileName,
						sizeof Item.Identity.Digest.FileName / sizeof Item.Identity.Digest.FileName[0],
						_FileName);
			break;

		default:
			break;
	}
}

const wchar_t *Application::GetPathName(void)
{
	switch ( Item.Identity.Type ) {
		case Storage::idnContent:
			return Item.Identity.Info.FileName;

		case Storage::idnPath:
			return Item.Identity.Path.Path;

		case Storage::idnDigest:
			return Item.Identity.Digest.FileName;

		default:
			return NULL;
	}
}

void Application::SetProductUrl(const wchar_t *Url)
{
	StringCchCopy(Item.ProductURL, sizeof Item.ProductURL / sizeof Item.ProductURL[0], Url);
}

const wchar_t *Application::GetProductUrl(void)
{
	return Item.ProductURL;
}

GesRule::ModelType Application::GetIntegrity(void)
{
	return (GesRule::ModelType)Item.Params.Attributes.Param[GesRule::attIntegrity];
}


GesRule::ConfidentLevel Application::GetConfident(void)
{
	return (GesRule::ConfidentLevel)Item.Params.Attributes.Param[GesRule::attConfident];
}

ULONG Application::GetAppOptions(void)
{
	return Item.Params.Attributes.Param[GesRule::attOptions];
}

Storage::IdentityType Application::GetIdentityType(void)
{
	return Item.Identity.Type;
}

int Application::GetOptions(void)
{
	return Item.Options;
}

void Application::SetLabel(const LabelType Label)
{
	ULONG Options = 0;
	switch ( Label ) {
		case Label1:
			Options |= Storage::dboLabel1;
			break;
		case Label2:
			Options |= Storage::dboLabel2;
			break;
		case Label3:
			Options |= Storage::dboLabel3;
			break;
	}

	Item.Options |= Options;
}

void Application::CopyIdentity(const Application &App)
{
	Item.Identity = App.Item.Identity;
	switch ( Item.Identity.Type ) {
		case Storage::idnPath:
			Item.Params.Type = Storage::parAppPath;
			break;
		case Storage::idnContent:
			Item.Params.Type = Storage::parAppContent;
			break;
		case Storage::idnDigest:
			Item.Params.Type = Storage::parAppDigest;
			break;
	}
}

bool Application::CompareIdentity(const Application &App)
{
	if ( Item.Identity.Type != App.Item.Identity.Type ) return false;
	switch ( Item.Identity.Type ) {
		case Storage::idnContent:
			if ( Item.Identity.Info.Type != App.Item.Identity.Info.Type ||
				 0 != wcscmp(Item.Identity.Info.Content, App.Item.Identity.Info.Content) )
				return false;
			else
				return true;

		case Storage::idnPath:
			if ( Item.Identity.Path.Type != App.Item.Identity.Path.Type ||
				 0 != wcscmp(Item.Identity.Path.Path, App.Item.Identity.Path.Path) )
				 return false;
			else
				return true;

		case Storage::idnDigest:
			if ( Item.Identity.Digest.Type != App.Item.Identity.Digest.Type ||
				 0 != memcmp(Item.Identity.Digest.Digest, App.Item.Identity.Digest.Digest, Item.Identity.Digest.DigestSize) )
				 return false;
			else
				return true;

		default:
			return false;
	}
}

bool Application::FillApplicationInfo(const wchar_t *_FileName, Storage::ApplicationItem &AppItem, ULONG _Options)
{
	AppItem.Options = 0;
	if ( _Options & UserCreated ) 
		AppItem.Options = Storage::dboUserCreated;
	//
	// Fill out ApplicationInfo part
	//
	commonlib::VerInfo Version;
	if ( _Options & UseBinStubs ) {
		//
		// Try to get from binstub
		//
		std::wstring StubName = _FileName;
		StubName += L".verinfo";
		if ( !Version.Load(StubName.c_str()) ) {
			if ( Version.Init(_FileName) ) Version.Save(StubName.c_str());
		}
	} else {
		Version.Init(_FileName);
	}

	StringCchCopy(AppItem.FileName, sizeof AppItem.FileName / sizeof AppItem.FileName[0], _FileName);

	wchar_t *Value;
	Version.Get(L"InternalName", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.InternalName, sizeof AppItem.InternalName / sizeof AppItem.InternalName[0], Value);
	Version.Get(L"OriginalFilename", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.OriginalFilename, sizeof AppItem.OriginalFilename / sizeof AppItem.OriginalFilename[0], Value);
	Version.Get(L"ProductName", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.ProductName, sizeof AppItem.ProductName / sizeof AppItem.ProductName[0], Value);
	Version.Get(L"ProductVersion", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.ProductVersion, sizeof AppItem.ProductVersion / sizeof AppItem.ProductVersion[0], Value);
	Version.Get(L"CompanyName", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.CompanyName, sizeof AppItem.CompanyName / sizeof AppItem.CompanyName[0], Value);
	Version.Get(L"LegalCopyright", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.LegalCopyright, sizeof AppItem.LegalCopyright / sizeof AppItem.LegalCopyright[0], Value);
	Version.Get(L"FileDescription", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.FileDescription, sizeof AppItem.FileDescription / sizeof AppItem.FileDescription[0], Value);
	Version.Get(L"FileVersion", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.FileVersion, sizeof AppItem.FileVersion / sizeof AppItem.FileVersion[0], Value);
	Version.Get(L"Comments", &Value);
	if ( Value != NULL)// && wcscmp(Value, L"N/A") )
		StringCchCopy(AppItem.Comments, sizeof AppItem.Comments / sizeof AppItem.Comments[0], Value);
	AppItem.Lang = Version.GetLang();

	if ( _Options & UseBinStubs ) {
		//
		// Try to get from binstub
		//
		std::wstring StubName = _FileName;
		StubName += L".icon";
		byte *Buf;
		size_t Size;
		if ( !commonlib::LoadBinaryFile(StubName.c_str(), Buf, Size) ) {
			AppItem.IconSize = (int)commonlib::GetIcon(_FileName, AppItem.Icon, sizeof AppItem.Icon);
			commonlib::SaveBinaryFile(StubName.c_str(), AppItem.Icon, AppItem.IconSize);
		} else {
			if ( Size <= sizeof AppItem.Icon ) {
				memcpy(AppItem.Icon, Buf, Size);
				AppItem.IconSize = (int) Size;
			}
			delete[] Buf;
		}
	} else {
		AppItem.IconSize = (int)commonlib::GetIcon(_FileName, AppItem.Icon, sizeof AppItem.Icon);
	}

	commonlib::PtrToUCharArray Digest;
	if ( _Options & UseBinStubs ) {
		std::wstring StubName = _FileName;
		StubName += L".sha1";
		byte *Buf;
		size_t Size;
		if ( !commonlib::LoadBinaryFile(StubName.c_str(), Buf, Size) ) {
			size_t DigestSize = commonlib::QueryHash(CALG_SHA1, _FileName, Digest);
			memcpy(AppItem.SHA1, Digest.get(), min(sizeof AppItem.SHA1, DigestSize));
			commonlib::SaveBinaryFile(StubName.c_str(), AppItem.SHA1, sizeof AppItem.SHA1);
		} else {
			if ( Size <= sizeof AppItem.SHA1 ) {
				memcpy(AppItem.SHA1, Buf, Size);
			}
			delete[] Buf;
		}
		StubName = _FileName;
		StubName += L".md5";
		if ( !commonlib::LoadBinaryFile(StubName.c_str(), Buf, Size) ) {
			size_t DigestSize = commonlib::QueryHash(CALG_MD5, _FileName, Digest);
			memcpy(AppItem.MD5, Digest.get(), min(sizeof AppItem.MD5, DigestSize));
			commonlib::SaveBinaryFile(StubName.c_str(), AppItem.MD5, sizeof AppItem.MD5);
		} else {
			if ( Size <= sizeof AppItem.MD5 ) {
				memcpy(AppItem.MD5, Buf, Size);
			}
			delete[] Buf;
		}
	} else {
		size_t DigestSize = commonlib::QueryHash(CALG_SHA1, _FileName, Digest);
		memcpy(AppItem.SHA1, Digest.get(), min(sizeof AppItem.SHA1, DigestSize));
		DigestSize = commonlib::QueryHash(CALG_MD5, _FileName, Digest);
		memcpy(AppItem.MD5, Digest.get(), min(sizeof AppItem.MD5, DigestSize));
		DigestSize = commonlib::QueryHash(CALG_SHA_256, _FileName, Digest);
		memcpy(AppItem.SHA256, Digest.get(), min(sizeof AppItem.SHA256, DigestSize));
	}

	//
	// TODO: Check for certificate
	//

	return true;
}

bool Application::IsIdentifiedByVerinfo(const Storage::ApplicationItem *AppItem)
{
	return ( AppItem->InternalName[0] != 0 && wcscmp(AppItem->InternalName, UndefinedStr) ||
			 AppItem->OriginalFilename[0] != 0 && wcscmp(AppItem->OriginalFilename, UndefinedStr) || 
			 AppItem->ProductName[0] != 0 && wcscmp(AppItem->ProductName, UndefinedStr)
		   );
}

bool Application::SetVerinfoIdentity(Storage::ApplicationItem *AppItem, ULONG _Options)
{
	if ( !IsIdentifiedByVerinfo(AppItem) ) return false;

	AppItem->Params.Type = Storage::parAppContent;
	AppItem->Identity.Type = Storage::idnContent;
	AppItem->Identity.Info.Type = Storage::cntInternalName;
	AppItem->Identity.Info.Options = 0;
	if ( _Options & UserCreated ) 
		AppItem->Identity.Info.Options = Storage::dboUserCreated;

	std::wstring VerIdentity;
	commonlib::VerInfo Ver;
	std::wstring StubName = AppItem->FileName;
	StubName += L".verinfo";
	if ( !Ver.Load(StubName.c_str()) ) {
		Ver.Init(AppItem->FileName);
	}
	GetVerinfoIdentity(Ver, VerIdentity);
	StringCchCopy(AppItem->Identity.Info.Content, Storage::MaxContextLength, VerIdentity.c_str());
	return true;
}

void Application::GetVerinfoIdentity(const wchar_t *_FileName, std::wstring &Identity)
{
	commonlib::VerInfo Ver;
	if ( Ver.Init(_FileName) ) {
		GetVerinfoIdentity(Ver, Identity);
	}
}

void Application::GetVerinfoIdentity(commonlib::VerInfo &Ver, std::wstring &Identity)
{
	Identity.reserve(Storage::MaxContextLength);
	wchar_t *Value;
	Ver.Get(L"InternalName", &Value);
	if ( Value != NULL && Value[0] != 0 ) { 
		Identity.append(Value);
		Identity.append(L";");
	}
	Ver.Get(L"OriginalFilename", &Value);
	if ( Value != NULL && Value[0] != 0 ) { 
		Identity.append(Value);
	}

	if ( Identity.size() == 0 ) {
		Ver.Get(L"ProductName", &Value);
		if ( Value != NULL && Value[0] != 0 ) { 
			Identity.append(Value);
		}
		Identity.append(L";");
		Ver.Get(L"CompanyName", &Value);
		if ( Value != NULL && Value[0] != 0 )
			Identity.append(Value);
	}

	if ( Identity.size() > Storage::MaxContextLength)
		Identity.resize(Storage::MaxContextLength);
}

void Application::GetAppItem(const int AppId, const int RuleId, const wchar_t *FileName, Application &AppItem)
{
	if ( RuleId != 0 ) AppItem.Init(AppId, 0);
/*    
    if (0 >= app_name.size ())
    {
        wstring            object_name = drv_notify.get_process_file_name ();
        commonlib::VerInfo ver_info;
        wchar_t*           value;
        
        if (true == ver_info.Init (object_name.c_str ()))
        {
            ver_info.Get (L"ProductName", &value);
            if (NULL != value)
                app_name.assign (value);
        }
    }
*/    
    if ( AppItem.IsValid() == false )
	{
		wstring object_name = FileName;
		object_name.erase(0, object_name.find_last_of(L"\\")+1);
		AppItem.SetDisplayName(object_name.c_str());
	}
    
} // get_application_name


void Application::Release(void)
{
	if ( !bInited ) return;

	bInited = false;
	FileName = L"";
	memset(&Item, 0, sizeof Item);
	if ( hIcon != NULL ) DestroyIcon(hIcon);
	hIcon = NULL;
	Options = 0;
}
const wchar_t * Application::GetFileName(const Storage::ApplicationItem *AppItem)
{
	//if ( !bInited ) return;
	//return appItem.FileName;
	return AppItem->OriginalFilename;

}

void Application::Dump(int Mode)
{
    Debug::Write (Mode, "-------- %S\n",		GetDisplayName());
	Debug::Write (Mode, "Group = %x\n",         GetGroupUniqueId()->Code);
    Debug::Write (Mode, "Url = %S\n",           GetProductUrl());
    Debug::Write (Mode, "Path = %S\n",          GetPathName());
    Debug::Write (Mode, "IntegrityLevel = %d\n",GetIntegrity());
    Debug::Write (Mode, "IdentityType = %d\n",  GetIdentityType());
	Debug::Write (Mode, "AppOptions = %x\n",	GetAppOptions());
	Debug::Write (Mode, "Options = %x\n",		GetOptions());
}



}; // namespace App {