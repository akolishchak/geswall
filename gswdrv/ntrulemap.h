//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __ntrulemap_h__
#define __ntrulemap_h__

#include "rule.h"
#include "gesrule.h"

namespace NtRuleMap {

    Rule::RuleResult AccessObject(Rule::ObjectAccessType AccessType, PEPROCESS Subject, 
                     EntityAttributes &SubjectAttributes, ULONG RuleId,
                     PVOID Object, EntityAttributes &ObjectAttributes, 
                     NtObjectType NtType, PVOID RelatedObject, ACCESS_MASK Access, 
					 Rule::AefCommand &Command, Rule::RedirectStatus &Redirect);

	Rule::RuleResult MapSubject(PEPROCESS Subject, EntityAttributes &SubjectAttributes, 
                        PFILE_OBJECT Object, EntityAttributes &ObjectAttributes, 
                        ULONG &RuleId, Rule::AefCommand &Command, Rule::RedirectStatus &Redirect);

    Rule::RuleResult CreateSubject(PEPROCESS ParentSubject, EntityAttributes &ParentAttributes,
                                   Rule::RedirectStatus ParentRedirect, ULONG ParentRuleId,
                                   PEPROCESS ChildSubject, EntityAttributes &ChildAttributes,
                                   Rule::RedirectStatus &ChildRedirect, ULONG &ChildRuleId,
                                   EntityAttributes &ObjectAttributes, PFILE_OBJECT FileObject,
								   Rule::AefCommand &Command);
	Rule::RedirectStatus DeleteSubject(PEPROCESS Subject, EntityAttributes &Attributes, 
									Rule::RedirectStatus Redirect, ULONG RuleId,
									Rule::AefCommand &Command);

    GesRule::ObjectType MapObjectType(NtObjectType Type);
    GesRule::ActionType MapActionType(ACCESS_MASK Access, NtObjectType NtType);

	NTSTATUS GetSettings(VOID);
	NTSTATUS Log(Rule::ObjectAccessType AccessType, _EPROCESS *Subject, EntityAttributes &SubjectAttributes, ULONG RuleId,
		PVOID Object, NtObjectType NtType, PVOID RelatedObject, PUNICODE_STRING _ObjectName, ULONG_PTR ObjectContext, Rule::RuleResult Result);
    NTSTATUS Init(VOID);

	extern WCHAR *AccessLogDir;
	extern ULONG PolicyOptions;
	extern ULONG TypesMask;
	extern GesRule::NotificationLevel Notification;
	extern GesRule::AccessLogLevel AccessLog;
};


#endif // __ntrulemap_h__
