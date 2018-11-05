//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __application_h__
#define __application_h__

#include "app/common.h"
#include "app/rule.h"
#include "app/group.h"

namespace App {

class Application {
public:

	enum SecurityLevel {
		selUndefined		= 0,
		selUntrusted		= 1,
		selAutoIsolated		= 2,
		selTrusted			= 3,
		selAlwaysTrusted	= 4,
		selNoPopups			= 5
	};

	Application(void) : bInited(false), hIcon(NULL), Options(0) {}
	Application(const wchar_t *_FileName) : hIcon(NULL), Options(0)
	{ 
		Init(_FileName); 
	}
	Application(const int _AppId, const int _Options) : hIcon(NULL) { Init(_AppId, _Options); }
	Application(const Storage::ApplicationItem &_Item, const Group::UniqueId *_GroupUniqueId, const ULONG _Options) : hIcon(NULL) { Init(_Item, _GroupUniqueId, _Options); }
	~Application() { Release(); }

	bool Init(const wchar_t *_FileName, Storage::IdentityType Identity = Storage::idnUnknwon, ULONG _Options = 0);
	bool Init(const int _AppId, ULONG _Options = 0);
	bool InitItem(const int _AppId, Storage::ApplicationItem &_Item);
	bool Init(const Storage::ApplicationItem &_Item, const Group::UniqueId *_GroupUniqueId, ULONG _Options = 0);

	void StorageCreate(int &AppId);
	void StorageCreate(const int GroupId, int &AppId);
	void StorageMove(const int GroupId);
	void StorageUpdate(void);
	void StorageDelete(void);

	bool IsNetworked(void);
	bool IsUserCreated(void);
	bool IsUserModified(void);
	bool IsValid(void) { return bInited; }

	int GetAppId(void);
	void SetGroup(const int GroupId);
	int GetGroup(void);
	void SetGroupUniqueId(const Group::UniqueId &Id);
	Group::UniqueId *GetGroupUniqueId(void);
	void SetIntegrity(GesRule::ModelType Integrity);
	void SetConfident(GesRule::ConfidentLevel Confident);
	void SetSecurityLevel(SecurityLevel Level);
	SecurityLevel GetSecurityLevelCode(Storage::ApplicationItem &Item);
	void SetOptions(ULONG Options);
	void AddOptions(ULONG Options);
	const wchar_t *GetDisplayName(void);
	void SetDisplayName(const wchar_t *DisplayName);
	void SetPathName(const wchar_t *_FileName);
	const wchar_t *GetPathName(void);
	void SetProductUrl(const wchar_t *Url);
	const wchar_t *GetProductUrl(void);
	GesRule::ModelType GetIntegrity(void);
	GesRule::ConfidentLevel GetConfident(void);
	ULONG GetAppOptions(void);
	Storage::IdentityType GetIdentityType(void);
	void CopyIdentity(const Application &App);
	bool CompareIdentity(const Application &App);

	enum LabelType {
		Label1,
		Label2,
		Label3
	};

	void SetLabel(const LabelType Label);

	operator Storage::ApplicationItem *() { return &Item; };

	static bool FillApplicationInfo(const wchar_t *_FileName, Storage::ApplicationItem &AppItem, ULONG _Options);
	static bool IsIdentifiedByVerinfo(const Storage::ApplicationItem *AppItem);
	static bool SetVerinfoIdentity(Storage::ApplicationItem *AppItem, ULONG _Options);
	static void Application::GetVerinfoIdentity(const wchar_t *_FileName, std::wstring &Identity);
	static void GetVerinfoIdentity(commonlib::VerInfo &Ver, std::wstring &Identity);
	static void GetAppItem(const int AppId, const int RuleId, const wchar_t *FileName, Application &AppItem);
	static wchar_t *UndefinedStr;
	const wchar_t * GetFileName(const Storage::ApplicationItem *AppItem);


	void Dump(int Mode);

	RuleList Rules;

private:
	void Release(void);
	int GetOptions(void);

	bool bInited;
	HICON hIcon;
	ULONG Options;
	Storage::ApplicationItem Item;
	Group::UniqueId GroupUniqueId;

	std::wstring FileName;
};

typedef boost::shared_ptr<Application> PtrToApplication;
typedef std::vector<PtrToApplication> ApplicationList;


}; // namespace App {

#endif // __application_h__
