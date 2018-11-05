//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __acidyn_h__
#define __acidyn_h__

namespace AciDyn {
	NTSTATUS Init(VOID);
	NTSTATUS LoadSubjectRules(PEPROCESS Process, EntityAttributes *Attributes, ULONG *RuleId);
	NTSTATUS UnloadSubjectRules(ULONG RuleId);
	NTSTATUS LoadSubjectRules(ULONG RuleId);

	NTSTATUS DisableRedirect(PEPROCESS Subject);
};


#endif // __acidyn_h__