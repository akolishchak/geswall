//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __rule_h__
#define __rule_h__

namespace Rule {

	const ULONG GESWALL_MODIFY_ACCESS =	0x8000;

    enum RuleResult {
        rurBlockSubject,
        rurBlockAction,
        rurBlockModify,
        rurRedirect,
        rurAllowAction
    };

    enum AefCommand {
        aefNone,
        aefSaveSubjectInfo,
		aefSaveSubjectInfoPermanent,
        aefSaveObjectInfo,
        aefSaveAllInfo,
		aefSaveAllInfoPermanent
    };

    enum ObjectAccessType {
        acsUnknown,
        acsOpen,
		acsCreated,
		acsCreatedClose,
        acsRead,
        acsWrite,
        acsAci,
        acsMessage,
		acsLoad,
		acsSwitchSubject,
		acsIsolateOnStart
    };

    enum RedirectStatus {
        rdsUndefined = 0,
        rdsNone		 = 1,
        rdsKey		 = 2,
        rdsFile		 = 4,
        rdsAll		 = 6
    };

    typedef RuleResult
        (*MapSubjectCall)(PEPROCESS Subject, EntityAttributes &SubjectAttributes, 
                            PFILE_OBJECT Object, EntityAttributes &ObjectAttributes, 
                            ULONG &RuleId, AefCommand &Command, RedirectStatus &Redirect);

    typedef RuleResult
        (*CreateSubjectCall)(PEPROCESS ParentSubject, EntityAttributes &ParentAttributes, 
                             RedirectStatus ParentRedirect, ULONG ParentRuleId,
                             PEPROCESS ChildSubject, EntityAttributes &ChildAttributes, 
                             RedirectStatus &ChildRedirect, ULONG &ChildRuleId,
                             EntityAttributes &ObjectAttributes, PFILE_OBJECT FileObject,
							 AefCommand &Command);

    typedef RedirectStatus
        (*DeleteSubjectCall)(PEPROCESS Subject, EntityAttributes &Attributes, 
                             RedirectStatus Redirect, ULONG RuleId, AefCommand &Command);

	typedef RuleResult
        (*AccessObjectCall)(ObjectAccessType AccessType, 
                            PEPROCESS Subject, EntityAttributes &SubjectAttributes, ULONG RuleId, 
                            PVOID Object, EntityAttributes &ObjectAttributes, 
                            NtObjectType NtType, PVOID RelatedObject, ACCESS_MASK Access, 
							AefCommand &Command, RedirectStatus &Redirect);

    struct RuleInfo {
        CHAR Label[4];
        AccessObjectCall AccessObject;
        MapSubjectCall MapSubject;
        CreateSubjectCall CreateSubject;
		DeleteSubjectCall DeleteSubject;
        LIST_ENTRY Entry;
    };

    NTSTATUS Init(VOID);
    VOID Release(VOID);

    NTSTATUS Register(RuleInfo &Rule);
    NTSTATUS UnRegister(CHAR *Label);

    RuleResult AccessObject(ObjectAccessType AccessType, _EPROCESS *Subject, EntityAttributes &SubjectAttributes, 
							RedirectStatus Redirect, ULONG RuleId, PVOID Object,
                            PVOID RelatedObject, NtObjectType NtType, ACCESS_MASK &Access);

	bool NeedRuleCheck(_EPROCESS *Subject, EntityAttributes &SubjectAttributes, RedirectStatus &Redirect, ULONG &RuleId);
	bool NeedRuleCheck(EntityAttributes &SubjectAttributes, RedirectStatus &Redirect, ULONG &RuleId);

    inline RuleResult AccessObject(ObjectAccessType AccessType, _EPROCESS *Subject, PVOID Object,
									PVOID RelatedObject, NtObjectType NtType, ACCESS_MASK &Access)
	{
		RedirectStatus Redirect;
		ULONG RuleId;
        EntityAttributes SubjectAttributes;
		
		if ( NeedRuleCheck(Subject, SubjectAttributes, Redirect, RuleId) == false ) return rurAllowAction;

		return AccessObject(AccessType, Subject, SubjectAttributes, Redirect, RuleId, Object, RelatedObject, NtType, Access);
	}

    RuleResult MapSubject(PEPROCESS Subject, PFILE_OBJECT Object);
    RuleResult CreateSubject(PEPROCESS ParentSubject, PEPROCESS ChildSubject, PFILE_OBJECT FileObject);
	RedirectStatus DeleteSubject(PEPROCESS Subject);

    NtObjectType MapNtObjectType(POBJECT_TYPE ObjType, PVOID Object);
    ACCESS_MASK GetModifyAccess(NtObjectType Type);
	bool ResolveMaximumAllowed(PVOID Object, KPROCESSOR_MODE AccessMode, ACCESS_MASK *Access);
    WCHAR *GetResultString(RuleResult Result);
	PUNICODE_STRING GetObjectName(PVOID Object, PVOID RelatedObject, NtObjectType NtType);
};

#endif // __rule_h__