//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __rule_h__
#define __rule_h__

#include <boost/smart_ptr.hpp> 
#include "db/storage.h"
#include "gesruledef.h"

namespace App {

class Rule {
public:
	enum AccessType {
		actAllow				= GesRule::oboGrantAccess,
		actDeny					= GesRule::oboDenyAccess,
		actRedirect				= GesRule::oboRedirectAccess,
		actDenyRedirect			= GesRule::oboDenyRedirectAccess
	};

	Rule(const int AppId, const wchar_t *ResourceName, const NtObjectType ResourceType, const AccessType Access, const int _Options);
	Rule(Storage::ResourceItem *_Item, const int _Options);
	~Rule();

	void StorageCreate(int &ResId);
	void StorageCreate(const int AppId, int &ResId);
	void StorageUpdate(void);
	void StorageMove(const int AppId);
	void StorageDelete(void);

	bool IsValid(void) { return bInited; }
	bool IsUserCreated(void);
	bool IsUserModified(void);

	int GetAccessType(void);
	void SetAccessType(const int Access);
	const wchar_t *GetResourceName(void);
	NtObjectType GetResourceType(void);

	bool operator== (const Rule &r) const;

	void Dump(int Mode);

private:
	int GetOptions(void);

	bool bInited;
	bool bRelease;
	int Options;
	Storage::ResourceItem *Item;
};

typedef boost::shared_ptr<Rule> PtrToRule;

class RuleList {
public:
	RuleList(void);
	RuleList(const int AppId);
	void Load(const int AppId);
	bool push_back(PtrToRule &Res);
	void remove(const size_t Index);
	PtrToRule Find(const Rule &Res, size_t &FoundIndex);
	PtrToRule & operator[] (size_t Index);
	size_t size() { return List.size(); }
	void clear() { List.clear(); }

private:
	vector<PtrToRule> List;
	Storage::ResourceItemList ResList;
};


}; // namespace App {

#endif // __rule_h__