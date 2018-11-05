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
#include "securityclass.h"

using namespace commonlib;

namespace App {

SecurityClass::SecurityClass(void)
{
	Params = new Storage::ParamsInfo;
	bRelease = true;

	Params->Id = 0;
	Params->GroupId = 0;
	Params->Model = GesRule::GswLabel;
	Params->Type = Storage::parResource;
	Params->Options = 0;
	Params->Description[0] = 0;
	memset(&Params->Attributes, 0, sizeof EntityAttributes);

	bInited = true;
}

SecurityClass::SecurityClass(int Id)
{
	Params = new Storage::ParamsInfo;
	bRelease = true;
	try {
		Storage::GetSecurityClass(Id, *Params);
		bInited = true;
	} catch ( ... ) { 
		bInited = false;
	}
}

SecurityClass::SecurityClass(const wchar_t *Name, const EntityAttributes &Attributes)
{
	Params = new Storage::ParamsInfo;
	bRelease = true;

	Params->Id = 0;
	Params->GroupId = 0;
	Params->Model = GesRule::GswLabel;
	Params->Type = Storage::parResource;
	Params->Options = 0;
	SetName(Name);
	Params->Attributes = Attributes;

	bInited = true;
}

SecurityClass::SecurityClass(Storage::ParamsInfo *_Params)
{
	Params = _Params;
	bRelease = false;
	bInited = true;
}

SecurityClass::~SecurityClass()
{
	if ( bRelease ) delete Params;
}

void SecurityClass::StorageCreate(int &Id)
{
	if ( !bInited ) return;
	Storage::InsertSecurityClass(*Params, Id);
}

void SecurityClass::StorageUpdate(void)
{
	if ( !bInited ) return;
	Storage::UpdateSecurityClass(Params->Id, *Params);
}

void SecurityClass::StorageDelete(void)
{
	if ( !bInited ) return;
	Storage::DeleteSecurityClass(Params->Id);
}

void SecurityClass::SetName(const wchar_t *Name)
{
	if ( !bInited ) return;
	StringCchCopy(Params->Description, sizeof Params->Description / sizeof Params->Description[0], Name);
}
	
const wchar_t *SecurityClass::GetName(void)
{
	if ( !bInited ) return NULL;
	return Params->Description;
}

void SecurityClass::SetAttributes(const EntityAttributes &Attributes)
{
	if ( !bInited ) return;
	Params->Attributes = Attributes;
}

const EntityAttributes *SecurityClass::GetAttributes(void)
{
	if ( !bInited ) return NULL;
	return &Params->Attributes;
}

int SecurityClass::GetId(void)
{
	return Params->Id;
}

bool SecurityClass::operator== (const SecurityClass &r) const
{
	return !memcmp(&Params->Attributes, &r.Params->Attributes, sizeof EntityAttributes) ||
		   !wcscmp(Params->Description, r.Params->Description);
}

void SecurityClass::Dump(int Mode)
{
	const ULONG *Param = &GetAttributes()->Param[0];
	Debug::Write (Mode, "--- Security Class\n");
    Debug::Write (Mode, "\tName = %S\n",		 GetName());
    Debug::Write (Mode, "\tAttributes = (%x, %x, %x, %x, %x, %x)\n", 
						Param[0], Param[1], Param[2], Param[3], Param[4], Param[5]);
    Debug::Write (Mode, "\tId = %d\n",			 GetId());
}

SecurityClassList::SecurityClassList(bool _Preload)
{
	if ( _Preload ) Load();
}

void SecurityClassList::Load(void)
{
	List.clear();
	ParamsList.clear();
	try {
		Storage::GetSucurityClassesList(ParamsList);
		for ( Storage::ParamsInfoList::iterator i = ParamsList.begin(); i != ParamsList.end(); i++ ) {
			PtrToSecurityClass Class(new SecurityClass(i->get()));
			List.push_back(Class);
		}
	} catch ( ... ) {
	}
}

bool SecurityClassList::push_back(PtrToSecurityClass &Class)
{
	List.push_back(Class);
	return true;
}

void SecurityClassList::remove(const size_t Index)
{
	List.erase(List.begin() + Index);
}

PtrToSecurityClass SecurityClassList::Find(const SecurityClass &Class, size_t &FoundIndex)
{
	FoundIndex = 0;
	for ( vector<PtrToSecurityClass>::iterator i = List.begin(); i != List.end(); i++, FoundIndex++ )
		if ( Class == **i ) return *i;

	return PtrToSecurityClass();
}

int SecurityClassList::GetClass(const wchar_t *Name)
{
	for ( vector<PtrToSecurityClass>::iterator i = List.begin(); i != List.end(); i++ )
		if ( !wcscmp((*i)->GetName(), Name) ) return (*i)->GetId();
	return 0;
}

PtrToSecurityClass &SecurityClassList::operator[](size_t Index)
{
	return List[Index];
}

} // namespace App {
