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
#include "resource.h"

using namespace commonlib;

namespace App {

Resource::Resource(const Storage::IdentityType Type, const wchar_t *ResourceName, 
				   const NtObjectType ObjectType, const int ClassId, const int _Options)
{
	Options = _Options;
	Res = new Storage::ResourceItem;
	bRelease = true;
	Res->Identity.Type = Type;
	SetName(ResourceName);
	switch ( Type ) {
		case Storage::idnPath:
			Res->Identity.Path.Id = 0;
			Res->Identity.Path.Options = 0;
			if ( Options & UserCreated ) Res->Identity.Path.Options = Storage::dboUserCreated;
			Res->Identity.Path.param_type = Storage::parResource;
			Res->Identity.Path.ParentId = 0;
			Res->Identity.Path.Type = ObjectType;
			break;

		case Storage::idnOwner:
			Res->Identity.Owner.Id = 0;
			Res->Identity.Owner.Options = 0;
			if ( Options & UserCreated ) Res->Identity.Owner.Options = Storage::dboUserCreated;
			Res->Identity.Owner.param_type = Storage::parResource;
			Res->Identity.Owner.ParentId = 0;
			Res->Identity.Owner.Type = ObjectType;
			break;
	}
	SetClassId(ClassId);

	bInited = true;
}

Resource::Resource(Storage::ResourceItem *_Res, const int _Options)
{
	Options = _Options;
	Res = _Res;
	bRelease = false;

	bInited = true;
}

Resource::~Resource()
{
	if ( bRelease ) delete Res;
}

void Resource::StorageCreate(int &Id)
{
	Storage::InsertGlobalResource(*Res, Id);
}

void Resource::StorageUpdate(void)
{
	switch ( Res->Identity.Type ) {
		case Storage::idnPath:
			if ( Options & UserModified ) 
				Res->Identity.Path.Options |= Storage::dboUserModified;
			else
				Res->Identity.Path.Options &= ~(Storage::dboUserModified | Storage::dboUserCreated);
			break;

		case Storage::idnOwner:
			if ( Options & UserModified ) 
				Res->Identity.Owner.Options |= Storage::dboUserModified;
			else
				Res->Identity.Owner.Options &= ~(Storage::dboUserModified | Storage::dboUserCreated);
			break;
	}
	Storage::UpdateGlobalResource(Res->Identity.GetId(), *Res);
}

void Resource::StorageDelete(void)
{
	Storage::DeleteGlobalResource(Res->Identity.Type, Res->Identity.GetId());
}

bool Resource::IsUserCreated(void)
{
	return ( GetOptions() & Storage::dboUserCreated ) != 0;
}
	
bool Resource::IsUserModified(void)
{
	return ( GetOptions() & Storage::dboUserModified ) != 0;
}

void Resource::SetName(const wchar_t *ResourceName)
{
	switch ( Res->Identity.Type ) {
		case Storage::idnPath:
			StringCchCopy(Res->Identity.Path.Path, sizeof Res->Identity.Path.Path / sizeof Res->Identity.Path.Path[0], ResourceName);
			break;

		case Storage::idnOwner:
			StringCchCopy(Res->Identity.Owner.Owner, sizeof Res->Identity.Owner.Owner / sizeof Res->Identity.Owner.Owner[0], ResourceName);
			break;
	}
}

const wchar_t *Resource::GetName(void)
{
	switch ( Res->Identity.Type ) {
		case Storage::idnPath:
			return Res->Identity.Path.Path;

		case Storage::idnOwner:
			return Res->Identity.Owner.Owner;
	}
	return NULL;
}

void Resource::SetClassId(const int ClassId)
{
	switch ( Res->Identity.Type ) {
		case Storage::idnPath:
			Res->Identity.Path.ParentId = ClassId;
			break;

		case Storage::idnOwner:
			Res->Identity.Owner.ParentId = ClassId;
			break;
	}
}

int Resource::GetClassId(void)
{
	switch ( Res->Identity.Type ) {
		case Storage::idnPath:
			return Res->Identity.Path.ParentId;

		case Storage::idnOwner:
			return Res->Identity.Owner.ParentId;
	}
	return 0;
}

void Resource::SetClassName(const wchar_t *_ClassName)
{
	ClassName = _ClassName;
}

const wchar_t *Resource::GetClassName(void)
{
	return ClassName.c_str();
}


NtObjectType Resource::GetObjectType(void)
{
	return Res->Identity.GetResourceType();
}

int Resource::GetOptions(void)
{
	switch ( Res->Identity.Type ) {
		case Storage::idnPath:
			return Res->Identity.Path.Options;

		case Storage::idnOwner:
			return Res->Identity.Owner.Options;
	}
	return 0;
}

bool Resource::operator== (const Resource &r) const
{
	if ( Res->Identity.Type != r.Res->Identity.Type || 
		 Res->Identity.GetResourceType() != r.Res->Identity.GetResourceType() ) return false;
	switch ( Res->Identity.Type ) {
		case Storage::idnPath:
			return 0 == wcscmp(Res->Identity.Path.Path, r.Res->Identity.Path.Path);

		case Storage::idnOwner:
			return 0 == wcscmp(Res->Identity.Owner.Owner, r.Res->Identity.Owner.Owner);
	}
	return false;
}

void Resource::Dump(int Mode)
{
	Debug::Write (Mode, "--- Resource\n");
    Debug::Write (Mode, "\tName = %S\n",		 GetName());
    Debug::Write (Mode, "\tType = %d\n",         GetObjectType());
    Debug::Write (Mode, "\tClassId = %d\n",      GetClassId());
	Debug::Write (Mode, "\tClassName = %S\n",    GetClassName());
	Debug::Write (Mode, "\tOptions = %x\n",      GetOptions());
}

ResourceList::ResourceList(bool _Preload)
{
	if ( _Preload ) Load();
}

void ResourceList::Load(void)
{
	try {
		Storage::GetResourceList(ResList);
		for ( Storage::ResourceItemList::iterator i = ResList.begin(); i != ResList.end(); i++ ) {
			PtrToResource Res(new Resource(i->get(), 0));
			List.push_back(Res);
		}
	} catch ( ... ) {
	}
}

bool ResourceList::push_back(PtrToResource &Res)
{
	List.push_back(Res);
	return true;
}

void ResourceList::remove(const size_t Index)
{
	List.erase(List.begin() + Index);
}

PtrToResource ResourceList::Find(const Resource &Res, size_t &FoundIndex)
{
	FoundIndex = 0;
	for ( vector<PtrToResource>::iterator i = List.begin(); i != List.end(); i++, FoundIndex++ )
		if ( Res == **i ) return *i;

	return PtrToResource();
}

PtrToResource & ResourceList::operator[](size_t Index)
{
	return List[Index];
}

} // namespace App {