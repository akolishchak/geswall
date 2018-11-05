//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <windows.h>
#include "pattern.h"
#include "commonlib/debug.h"
#include <strsafe.h>

using namespace commonlib;

namespace Ids {

Pattern::Pattern(const NtObjectType ResType, const Storage::IdsPatternType PatternType, const int Flags, const wchar_t *Pattern, const wchar_t *Message)
{
	Item = new Storage::IdsPatternItem;
	bRelease = true;

	Item->Id = 0;
	Item->Options = 0;
	Item->ResType = ResType;
	Item->PatternType = PatternType;
	Item->Flags = Flags;
	StringCchCopy(Item->Pattern, sizeof Item->Pattern / sizeof Item->Pattern[0], Pattern);
	StringCchCopy(Item->Message, sizeof Item->Message / sizeof Item->Message[0], Message);

	bInited = true;
}

Pattern::Pattern(Storage::IdsPatternItem *_Item)
{
	Item = _Item;
	bRelease = false;

	bInited = true;
}

Pattern::~Pattern()
{
	if ( bRelease ) delete Item;
}

void Pattern::StorageCreate(int &Id)
{
	if ( !bInited ) return;
	Storage::InsertIdsPattern(*Item, Id);
}

void Pattern::StorageUpdate(void)
{
	if ( !bInited ) return;
	Storage::UpdateIdsPattern(Item->Id, *Item);
}

void Pattern::StorageDelete(void)
{
	if ( !bInited ) return;
	Storage::DeleteIdsPattern(Item->Id);
}

void Pattern::SetMessage(const wchar_t *Message)
{
	if ( !bInited ) return;
	StringCchCopy(Item->Message, sizeof Item->Message / sizeof Item->Message[0], Message);
}

const wchar_t *Pattern::GetMessage(void)
{
	return Item->Message;
}

void Pattern::SetPatternType(const Storage::IdsPatternType PatternType)
{
	if ( !bInited ) return;
	Item->PatternType = PatternType;
}

Storage::IdsPatternType Pattern::GetPatternType(void)
{
	return Item->PatternType;
}

void Pattern::SetFlags(const int Flags)
{
	if ( !bInited ) return;
	Item->Flags = Flags;
}

int Pattern::GetFlags(void)
{
	return Item->Flags;
}

NtObjectType Pattern::GetResType(void)
{
	return Item->ResType;
}

const wchar_t *Pattern::GetPattern(void)
{
	return Item->Pattern;
}

int Pattern::GetId(void)
{
	return Item->Id;
}

bool Pattern::operator== (const Pattern &r) const
{
	return Item->ResType == r.Item->ResType && !wcscmp(Item->Pattern, r.Item->Pattern);
}

void Pattern::Dump(int Mode)
{
	Debug::Write (Mode, "--- IDS Pattern\n");
    Debug::Write (Mode, "\tResType = %d\n",		GetResType());
    Debug::Write (Mode, "\tPatternType = %d\n", GetPatternType());
    Debug::Write (Mode, "\tFlags = %d\n",		GetFlags());
    Debug::Write (Mode, "\tPattern = %S\n",		GetPattern());
    Debug::Write (Mode, "\tMessage = %S\n",		GetMessage());
    Debug::Write (Mode, "\tId = %d\n",			GetId());
}


PatternList::PatternList(bool _Preload)
{
	if ( _Preload ) Load();
}

void PatternList::Load(void)
{
	List.clear();
	PatternItemList.clear();
	try {
		Storage::GetIdsPatternsList(PatternItemList);
		for ( Storage::IdsPatternItemList::iterator i = PatternItemList.begin(); i != PatternItemList.end(); i++ ) {
			PtrToPattern _Pattern(new Pattern(i->get()));
			List.push_back(_Pattern);
		}
	} catch ( ... ) {
	}
}

bool PatternList::push_back(PtrToPattern &_Pattern)
{
	List.push_back(_Pattern);
	return true;
}

void PatternList::remove(const size_t Index)
{
	List.erase(List.begin() + Index);
}

PtrToPattern PatternList::Find(const Pattern &_Pattern, size_t &FoundIndex)
{
	FoundIndex = 0;
	for ( vector<PtrToPattern>::iterator i = List.begin(); i != List.end(); i++, FoundIndex++ )
		if ( _Pattern == **i ) return *i;

	return PtrToPattern();
}

PtrToPattern &PatternList::operator[](size_t Index)
{
	return List[Index];
}

} // namespace Ids


