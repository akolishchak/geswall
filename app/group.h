//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __group_h__
#define __group_h__

#include <windows.h>
#include <string> 
#include <list> 
#include <boost/smart_ptr.hpp> 
#include "db/storage.h"
#include "gesruledef.h"

namespace App {

class Group {
public:
	struct UniqueId {
		UniqueId(void) { memset(this, 0, sizeof UniqueId); }
		UniqueId(int _Code) { Code = _Code; memset(&Guid, 0, sizeof Guid); }
		int Code;
		GUID Guid;
		bool operator< (const UniqueId &r) const { return memcmp(this, &r, sizeof UniqueId) < 0; }
		bool IsSet(void) const { return Code != 0 || Guid.Data1 != 0; }
	};

		
	static struct GroupItem
	{
	int GroupId;
	wchar_t GroupName[500];
	};
	std::vector<GroupItem> GroupArray;
	std::vector<GroupItem>::iterator z;
	GroupItem       GroupIt;

//	GroupItemStruct GroupLst;
	Group(const wchar_t *GroupName, const int GroupCode, const ULONG _Options);
	Group(const int GroupId);
	Group(const Storage::ParamsInfo &Params, const UniqueId *ParentUniqueId, const ULONG _Options);
	void StorageCreate(int &CreatedGroupId);
	void StorageCreate(const int ParentGroupId, int &CreatedGroupId);
	void StorageMove(const int GroupId);
	void StorageUpdate(void);
	void StorageDelete(void);

	void SetName(const wchar_t *GroupName);
	const wchar_t *GetName(void);
	int GetGroupId(void);
	UniqueId *GetGroupUniqueId(void);
	void SetParentGroupUniqueId(const UniqueId &Id);
	UniqueId *GetParentGroupUniqueId(void);
	bool IsParentGroupUniqueIdSet(void);

	bool IsUserCreated(void);
	bool IsUserModified(void);
	bool IsValid(void) { return bInited; }

	static int GetGroupId(const UniqueId &Id);
	static const wchar_t *GetDefaultName(const int Code);
	void GetGroupList(void);

	void Dump(int Mode);

private:
	int GetOptions(void);
	void GroupNode(int GroupId,std::wstring staticNode);
	
	static void AddCached(const UniqueId &Id, const int GroupId);
	static void DeleteCached(const UniqueId &Id);

	Storage::ParamsInfo Params;
	bool bInited;
	ULONG Options;
	UniqueId ParentGroupUniqueId;


}; // class Group

typedef boost::shared_ptr<Group> PtrToGroup;
typedef std::vector<PtrToGroup> GroupList;


}; // namespace App {

#endif // __group_h__
