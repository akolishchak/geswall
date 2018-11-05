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
#include "rule.h"

using namespace commonlib;

namespace App {

Rule::Rule(const int AppId, const wchar_t *ResourceName, const NtObjectType ResourceType, const AccessType Access, const int _Options)
{
	Options = _Options;
	Item = new Storage::ResourceItem;
	bRelease = true;

	Item->Params.Options = 0;
	memset(Item->Params.Attributes.Param, 0, sizeof Item->Params.Attributes.Param);
	Item->Params.Attributes.Param[GesRule::attObjectId] = AppId;
	Item->Params.Attributes.Param[GesRule::attOptions] = Access;

	Item->Identity.Path.Id = 0;
	Item->Identity.Path.ParentId = 0;
	Item->Identity.Type = Storage::idnPath;
	Item->Identity.Path.Type = ResourceType;
	Item->Identity.Path.param_type = Storage::parResourceApp;
	Item->Identity.Path.Options = 0;
	if ( _Options & UserCreated ) Item->Identity.Path.Options |= Storage::dboUserCreated;
	StringCchCopy(Item->Identity.Path.Path, sizeof Item->Identity.Path.Path / sizeof Item->Identity.Path.Path[0], ResourceName);

	bInited = true;
}

Rule::Rule(Storage::ResourceItem *_Item, const int _Options)
{
	Options = _Options;
	Item = _Item;
	bRelease = false;

	bInited = true;
}

Rule::~Rule()
{
	if ( bRelease ) delete Item;
}

void Rule::StorageCreate(int &ResId)
{
	Storage::InsertApplicationResource(*Item, ResId);
}

void Rule::StorageCreate(const int AppId, int &ResId)
{
	Item->Params.Attributes.Param[GesRule::attObjectId] = AppId;
	StorageCreate(ResId);
}

void Rule::StorageUpdate(void)
{
	if ( Options & UserModified ) 
		Item->Identity.Path.Options |= Storage::dboUserModified;
	else
		Item->Identity.Path.Options &= ~(Storage::dboUserModified |Storage::dboUserCreated);
	Storage::UpdateApplicationResource(*Item);
}

void Rule::StorageMove(const int AppId)
{
	Item->Params.Attributes.Param[GesRule::attObjectId] = AppId;
	StorageUpdate();
}

void Rule::StorageDelete(void)
{
	if ( Item->Identity.Path.Id == 0 ) throw Storage::StorageException(Storage::ErrorUnknown);
	Storage::DeleteApplicationResource(Item->Identity.Path.Id);
}

bool Rule::IsUserCreated(void)
{
	return ( GetOptions() & Storage::dboUserCreated ) != 0;
}

bool Rule::IsUserModified(void)
{
	return ( GetOptions() & Storage::dboUserModified ) != 0;
}

int Rule::GetAccessType(void)
{
	return Item->Params.Attributes.Param[GesRule::attOptions];
}

void Rule::SetAccessType(const int Access)
{
	Item->Params.Attributes.Param[GesRule::attOptions] = Access;
}

const wchar_t *Rule::GetResourceName(void)
{
	return Item->Identity.Path.Path;
}

NtObjectType Rule::GetResourceType(void)
{
	return Item->Identity.Path.Type;
}

int Rule::GetOptions(void)
{
	return Item->Identity.Path.Options;
}

bool Rule::operator==(const Rule &r) const
{
	return Item->Identity.Path.Type == r.Item->Identity.Path.Type &&
			!wcscmp(Item->Identity.Path.Path, r.Item->Identity.Path.Path);
}

void Rule::Dump(int Mode)
{
      Debug::Write (Mode, "--- Rule\n");
      Debug::Write (Mode, "\tResourceName = %S\n", GetResourceName());
      Debug::Write (Mode, "\tType = %d\n",         GetResourceType());
      Debug::Write (Mode, "\tAccess = %d\n",       GetAccessType());
	  Debug::Write (Mode, "\tOptions = %x\n",      GetOptions());
}

RuleList::RuleList(void)
{
}

RuleList::RuleList(const int AppId)
{
	Load(AppId);
}

void RuleList::Load(const int AppId)
{
	List.clear();
	ResList.clear();
	try {
		Storage::GetApplicationResources(AppId, ResList);
		for ( Storage::ResourceItemList::iterator i = ResList.begin(); i != ResList.end(); i++ ) {
			PtrToRule Res(new Rule(i->get(), 0));
			List.push_back(Res);
		}
	} catch ( ... ) {
	}
}

bool RuleList::push_back(PtrToRule &Res)
{
	List.push_back(Res);
	return true;
}

void RuleList::remove(const size_t Index)
{
	List.erase(List.begin() + Index);
}

PtrToRule RuleList::Find(const Rule &Res, size_t &FoundIndex)
{
	FoundIndex = 0;
	for ( vector<PtrToRule>::iterator i = List.begin(); i != List.end(); i++, FoundIndex++ )
		if ( Res == **i ) return *i;

	return PtrToRule();
}

PtrToRule & RuleList::operator[](size_t Index)
{
	return List[Index];
}

}; // namespace App {