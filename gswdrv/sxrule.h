//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __sxrule_h__
#define __sxrule_h__

#include "rule.h"

namespace SxRule {

    enum IntegrityLevel {
        iglUndefined    = 0,
        iglUntrusted    = 1,
        iglTrusted      = 2
    };

    enum ConfidentLevel {
        cflUndefined    = 0,
        cflLeakSource   = 1,
        cflPublic       = 2,
        cflClassified   = 3,
        cflSecret       = 4,
        cflTopSecret    = 5
    };

    enum ActionType {
        actRead,
        actModify
    };

    Rule::RuleResult AccessObject(Rule::ObjectAccessType AccessType, 
                     PEPROCESS Subject, EntityAttributes &SubjectAttributes, 
                     PVOID Object, EntityAttributes &ObjectAttributes, 
                     NtObjectType NtType, PVOID RelatedObject, ACCESS_MASK Access, 
					 Rule::AefCommand &Command, Rule::RedirectStatus &Redirect);

	Rule::RuleResult MapSubject(PEPROCESS Subject, EntityAttributes &SubjectAttributes, 
                        PFILE_OBJECT Object, EntityAttributes &ObjectAttributes, 
                        Rule::AefCommand &Command, Rule::RedirectStatus &Redirect);

    Rule::RuleResult CreateSubject(PEPROCESS ParentSubject, EntityAttributes &ParentAttributes, 
                                   Rule::RedirectStatus ParentRedirect, ULONG ParentRuleId,
                                   PEPROCESS ChildSubject, EntityAttributes &ChildAttributes,
                                   Rule::RedirectStatus &ChildRedirect, ULONG &ChildRuleId,
                                   EntityAttributes &ObjectAttributes, PFILE_OBJECT FileObject,
								   Rule::AefCommand &Command);

    NTSTATUS Init(VOID);

};



#endif // __sxrule_h__