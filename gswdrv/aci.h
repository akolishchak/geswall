//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __aci_h__
#define __aci_h__

#include "rule.h"
#include "hook.h"

namespace Aci {

    NTSTATUS Init(VOID);
    VOID Release(VOID);
    NTSTATUS AddRuleRecord(RuleRecord *Record);
    NTSTATUS Refresh(VOID);
	NTSTATUS LoadRules(RulePack *Pack, SIZE_T PackLength);
	NTSTATUS UnloadRules(ULONG RuleId);

    NTSTATUS GetObjectInfo(CHAR *Label, PVOID Object, PVOID RelatedObject,
                           NtObjectType NtType, EntityAttributes &Attributes, ULONG RuleId = 0);
    NTSTATUS SetObjectInfo(CHAR *Label, PVOID Object, PVOID RelatedObject,
                           NtObjectType NtType, EntityAttributes &Attributes, BOOLEAN WorkerItem = FALSE);
    NTSTATUS SetObjectInfo(CHAR *Label, HANDLE hObject, NtObjectType NtType, EntityAttributes &Attributes);

    NTSTATUS GetSubjectInfo(CHAR *Label, PVOID Object, EntityAttributes &Attributes, 
                            Rule::RedirectStatus &Redirect, ULONG &RuleId);
    NTSTATUS SetSubjectInfo(CHAR *Label, PVOID Object, EntityAttributes &Attributes, 
                            Rule::RedirectStatus Redirect, ULONG RuleId);
    NTSTATUS OrSubjectInfo(CHAR *Label, PVOID Object, EntityAttributes &Attributes, 
                            Rule::RedirectStatus Redirect, ULONG RuleId);

	NTSTATUS SetSubjectInfoPermanent(CHAR *Label, PVOID Object, EntityAttributes &Attributes);
};


#endif // __aci_h__