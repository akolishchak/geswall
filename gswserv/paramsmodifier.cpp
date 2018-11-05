//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "paramsmodifier.h"
#include <map>
#include "syncobject.h"


namespace ParamsModifier {

struct ClientId {
	DWORD ProcessId;
	DWORD ThreadId;
	bool operator< (const ClientId &r) const
	{
		if ( ProcessId < r.ProcessId ) return true;
		if ( ProcessId > r.ProcessId ) return false;
		return ThreadId < r.ThreadId;
	}
};

std::map<ClientId, ModifierType> ModifierList;
commonlib::sync::SyncObject Lock;

void Set(const ModifierType Type, const DWORD ProcessId, const DWORD ThreadId)
{
	ClientId Id = { ProcessId, ThreadId };
	commonlib::sync::SyncObject::Locker Locker(Lock);
	if ( Type == modRemove ) {
		std::map<ClientId, ModifierType>::iterator i = ModifierList.find(Id);
		if ( i != ModifierList.end() ) ModifierList.erase(i);
	} else {
		ModifierList[Id] = Type;
	}
}

ModifierType Get(const DWORD ProcessId, const DWORD ThreadId)
{
	ClientId Id = { ProcessId, ThreadId };

	commonlib::sync::SyncObject::Locker Locker(Lock);
	std::map<ClientId, ModifierType>::iterator i = ModifierList.find(Id);
	if ( i != ModifierList.end() ) return i->second;

	return modNone;
}

void Apply(ModifierType Type, EntityAttributes *Attributes)
{
	switch ( Type ) {
		case modNone:
		case modRemove:
			break;

		case modAutoIsolate:
			Attributes->Param[GesRule::attOptions] |= GesRule::oboAutoIsolate;
			Attributes->Param[GesRule::attOptions] &= ~(GesRule::oboKeepTrusted | GesRule::oboPropogateTrusted);
			break;

		case modAlwaysTrusted:
			Attributes->Param[GesRule::attOptions] |= GesRule::oboKeepTrusted | GesRule::oboPropogateTrusted;
			Attributes->Param[GesRule::attOptions] &= ~GesRule::oboAutoIsolate;
			break;

		case modForceIsolation:
			Attributes->Param[GesRule::attOptions] |= GesRule::oboForceIsolation;
			Attributes->Param[GesRule::attOptions] &= ~(GesRule::oboKeepTrusted | GesRule::oboPropogateTrusted);
			break;
	}
}

} // namespace ParamsModifier {



