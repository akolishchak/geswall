//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __paramsmodifier_h__
#define __paramsmodifier_h__

#include "ifgswrpc_h.h"

namespace ParamsModifier {

	void Set(const ModifierType Type, const DWORD ProcessId, const DWORD ThreadId);
	ModifierType Get(const DWORD ProcessId, const DWORD ThreadId);
	void Apply(ModifierType Type, EntityAttributes *Attributes);
	inline void Apply(const DWORD ProcessId, const DWORD ThreadId, EntityAttributes *Attributes)
	{
		Apply(Get(ProcessId, ThreadId), Attributes);
	}
}; // namespace ParamsModifier {

#endif // __paramsmodifier_h__