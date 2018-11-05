//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "rule.h"
#include "lock.h"
#include "aci.h"
#include "tools.h"
#include "fsfilter.h"
#include "ntrulemap.h"
#include "netfilter.h"

namespace Rule {
    LIST_ENTRY RuleList;
    CEResource Syn;

	RuleInfo *LookupRule(CHAR *Label);
	BOOLEAN bInited = FALSE;
};

_EPROCESS *__Object = NULL;
ACCESS_MASK __Access = 0;


Rule::RuleResult Rule::AccessObject(ObjectAccessType AccessType, _EPROCESS *Subject, EntityAttributes &SubjectAttributes,
									RedirectStatus Redirect, ULONG RuleId, PVOID Object, 
									PVOID RelatedObject, NtObjectType NtType, ACCESS_MASK &Access)
{
    RuleResult Result = rurAllowAction;
	//
	// Hack for performance optimization
	//
	if ( ( ( 1<<NtType ) & NtRuleMap::TypesMask ) || NtRuleMap::PolicyOptions & GesRule::ploIsolatedOnlyJailed ) return Result;

	//

#if DBG
    CHAR Name[NT_PROCNAMELEN];
    GetProcessNameByPointer(PsGetCurrentProcess(), Name);
    PUNICODE_STRING ObjectName = NULL;
	switch ( NtType ) {
		case nttNetwork:
			NetFilter::GetObjectName((PFILE_OBJECT)Object, RelatedObject, &ObjectName);
			break;

		case nttSystemObject:
			ObjectName = CopyUnicodeString((PUNICODE_STRING)RelatedObject);
			break;

		case nttFile:
			if ( RelatedObject != NULL )
				FsFilter::GetFileName((PFILE_OBJECT)Object, (PDEVICE_OBJECT)RelatedObject, &ObjectName);
			else
				GetObjectName((PFILE_OBJECT)Object, &ObjectName);
			break;

		case nttKey:
			if ( RelatedObject != NULL )
				GetRegistryObjectName(Object, (PUNICODE_STRING)RelatedObject, &ObjectName);
			else
				GetObjectName(Object, &ObjectName);
			break;

		default:
			GetObjectName(Object, &ObjectName);
			break;
	}
    ACCESS_MASK Prev = Access;
#endif

	if ( Access & MAXIMUM_ALLOWED ) {
		if ( NtType == nttFile || NtType == nttKey ) {
			ERR(0);
		}
		ResolveMaximumAllowed(Object, KeGetPreviousMode(), &Access);
	}

    //
    // No synchro for performance resons. Rule must be registered in DriverEntry
    // and unregistered in OnUnload
    //
    //Syn.Share();
    EntityAttributes ObjectAttributes;
	PLIST_ENTRY pEntry = RuleList.Flink;
	while (pEntry != &RuleList) {

		RuleInfo *pNode = CONTAINING_RECORD(pEntry, RuleInfo, Entry);

        //
        // Get info
        //
        AefCommand Command;
        Aci::GetObjectInfo(pNode->Label, Object, RelatedObject, NtType, ObjectAttributes, RuleId);

        RuleResult PrevResult = Result;
#if DBG
        EntityAttributes PrevObjectAttributes = ObjectAttributes;
#endif
        EntityAttributes PrevSubjectAttributes = SubjectAttributes;
        //
        // Apply rule
        //
        if ( pNode->AccessObject != NULL ) {
            Result = pNode->AccessObject(AccessType, Subject, SubjectAttributes, RuleId, Object, 
                                         ObjectAttributes, NtType, RelatedObject, Access, Command, Redirect);
            Result = min(Result, PrevResult);
        }

#if DBG
        if ( Command == aefSaveSubjectInfo || Command == aefSaveAllInfo )
            trace(P"%c%c%c%c has changed subject %s Attributes (%x,%x,%x,%x,%x,%x)=>(%x,%x,%x,%x,%x,%x)"
                  " while ACCESS %x %S object %wZ\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], Name, 
                PrevSubjectAttributes.Param[0], PrevSubjectAttributes.Param[1], PrevSubjectAttributes.Param[2],
				PrevSubjectAttributes.Param[3], PrevSubjectAttributes.Param[4], PrevSubjectAttributes.Param[5],
                SubjectAttributes.Param[0], SubjectAttributes.Param[1], SubjectAttributes.Param[2],
				SubjectAttributes.Param[3], SubjectAttributes.Param[4], SubjectAttributes.Param[5],
                Access, GetNtTypeString(NtType), ObjectName);

        if ( Command == aefSaveObjectInfo || Command == aefSaveAllInfo )
            trace(P"%c%c%c%c has changed %S object %wZ Attributes (%x,%x,%x,%x,%x,%x)=>(%x,%x,%x,%x,%x,%x)"
                  " while ACCESS %x by subject %s\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], 
                GetNtTypeString(NtType), ObjectName, 
                PrevObjectAttributes.Param[0], PrevObjectAttributes.Param[1], PrevObjectAttributes.Param[2],
				PrevObjectAttributes.Param[3], PrevObjectAttributes.Param[4], PrevObjectAttributes.Param[5],
                ObjectAttributes.Param[0], ObjectAttributes.Param[1], ObjectAttributes.Param[2],
				ObjectAttributes.Param[3], ObjectAttributes.Param[4], ObjectAttributes.Param[5],
                Access, Name);

        if ( PrevResult != Result )
            trace(P"%c%c%c%c decrease access %x of %s to %wZ (%x, %x, %x, %x, %x, %x) as %S\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], 
                Access, Name, ObjectName, 
                PrevObjectAttributes.Param[0], PrevObjectAttributes.Param[1], PrevObjectAttributes.Param[2],
				PrevObjectAttributes.Param[3], PrevObjectAttributes.Param[4], PrevObjectAttributes.Param[5],
                GetResultString(Result));
#endif
        //
        // Set info
        //
	    if ( Command == aefSaveSubjectInfo || Command == aefSaveAllInfo )
            Aci::SetSubjectInfo(pNode->Label, Subject, SubjectAttributes, Redirect, RuleId);
	    if ( Command == aefSaveSubjectInfoPermanent || Command == aefSaveAllInfoPermanent )
            Aci::SetSubjectInfoPermanent(pNode->Label, Subject, SubjectAttributes);
        if ( Command == aefSaveObjectInfo || Command == aefSaveAllInfo )
		    Aci::SetObjectInfo(pNode->Label, Object, RelatedObject, NtType, ObjectAttributes);

        if ( Result == rurBlockSubject )
            break;

        pEntry = pEntry->Flink;
	}
    //Syn.Release();

    if ( Result == rurBlockModify ) {
        Access &= ~GetModifyAccess(NtType);
#if DBG
        trace(P"STILL OPEN!!! %S(%s) %x->%x %wZ\n", 
            GetNtTypeString(NtType), Name, Prev, Access, ObjectName);
#endif
    }

    if ( Result == rurRedirect ) {
#if DBG
        trace(P"REDIRECT!!! %S(%s) %x->%x %wZ\n", 
            GetNtTypeString(NtType), Name, Prev, Access, ObjectName);
#endif
    }

#if DBG
    if ( Result == rurBlockSubject )
        trace(P"BLOCK!!! subject %s\n", Name);
    delete[] ObjectName;
#endif

    return Result;
}

bool Rule::NeedRuleCheck(_EPROCESS *Subject, EntityAttributes &SubjectAttributes, RedirectStatus &Redirect, ULONG &RuleId)
{
	Aci::GetSubjectInfo((PCHAR)&GesRule::GswLabel, Subject, SubjectAttributes, Redirect, RuleId);
	//
	// Hack for performance optimization
	//
	if ( 
		 ( 
		    !( SubjectAttributes.Param[GesRule::attOptions] & GesRule::oboForceIsolation ) &&
			(
				( SubjectAttributes.Param[GesRule::attOptions] & GesRule::oboKeepTrusted && SubjectAttributes.Param[GesRule::attIntegrity] == GesRule::modTCB ) ||
				( NtRuleMap::PolicyOptions & GesRule::ploIsolateOnlyDefined && RuleId == 0 && 
					( SubjectAttributes.Param[GesRule::attIntegrity] == GesRule::modTCB || 
						( NtRuleMap::PolicyOptions & GesRule::ploTrustByDefault && SubjectAttributes.Param[GesRule::attIntegrity] == GesRule::modUndefined ) 
					) 
				)
			)
		 )
		 || ( NtRuleMap::PolicyOptions & GesRule::ploIsolatedOnlyJailed && SubjectAttributes.Param[GesRule::attIntegrity] != GesRule::modUntrusted )		
	   ) {
		return false;
	}

	return true;
}

bool Rule::NeedRuleCheck(EntityAttributes &SubjectAttributes, RedirectStatus &Redirect, ULONG &RuleId)
{
	if ( 
		 ( 
			!( SubjectAttributes.Param[GesRule::attOptions] & GesRule::oboForceIsolation ) &&
			(
				( SubjectAttributes.Param[GesRule::attOptions] & GesRule::oboKeepTrusted && SubjectAttributes.Param[GesRule::attIntegrity] == GesRule::modTCB ) ||
				( NtRuleMap::PolicyOptions & GesRule::ploIsolateOnlyDefined && RuleId == 0 && 
					( SubjectAttributes.Param[GesRule::attIntegrity] == GesRule::modTCB || 
						( NtRuleMap::PolicyOptions & GesRule::ploTrustByDefault && SubjectAttributes.Param[GesRule::attIntegrity] == GesRule::modUndefined ) 
					) 
				)
			)
		 )
		 || ( NtRuleMap::PolicyOptions & GesRule::ploIsolatedOnlyJailed && SubjectAttributes.Param[GesRule::attIntegrity] != GesRule::modUntrusted )
	   ) {
		return false;
	}

	return true;
}

Rule::RuleResult Rule::MapSubject(PEPROCESS Subject, PFILE_OBJECT Object)
{
    RuleResult Result = rurAllowAction;

#if DBG
    CHAR Name[NT_PROCNAMELEN];
    GetProcessNameByPointer(Subject, Name);
    PUNICODE_STRING ObjectName;
    GetObjectName(Object, &ObjectName);
#endif

    //Syn.Share();
	PLIST_ENTRY pEntry = RuleList.Flink;
	while (pEntry != &RuleList) {

		RuleInfo *pNode = CONTAINING_RECORD(pEntry, RuleInfo, Entry);
        //
        // Get info
        //
        EntityAttributes SubjectAttributes, ObjectAttributes;
        RedirectStatus Redirect;
		ULONG RuleId;
        Aci::GetSubjectInfo(pNode->Label, Subject, SubjectAttributes, Redirect, RuleId);
        Aci::GetObjectInfo(pNode->Label, Object, NULL, nttFile, ObjectAttributes, RuleId);
        AefCommand Command;
        RuleResult PrevResult = Result;

        EntityAttributes PrevSubjectAttributes = SubjectAttributes;
        EntityAttributes PrevObjectAttributes = ObjectAttributes;
        //
        // Call map rule
        //
        if ( pNode->MapSubject != NULL ) {
            Result = pNode->MapSubject(Subject, SubjectAttributes, Object, ObjectAttributes, 
									   RuleId, Command, Redirect);
            Result = min(Result, PrevResult);
        }
        
#if DBG
        if ( Command == aefSaveSubjectInfo || Command == aefSaveAllInfo )
            trace(P"%c%c%c%c has changed subject %s Attributes (%x,%x,%x,%x,%x,%x)=>(%x,%x,%x,%x,%x,%x)"
                  " while MAPPING %wZ to it\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], Name, 
                PrevSubjectAttributes.Param[0], PrevSubjectAttributes.Param[1], PrevSubjectAttributes.Param[2],
				PrevSubjectAttributes.Param[3], PrevSubjectAttributes.Param[4], PrevSubjectAttributes.Param[5],
                SubjectAttributes.Param[0], SubjectAttributes.Param[1], SubjectAttributes.Param[2],
				SubjectAttributes.Param[3], SubjectAttributes.Param[4], SubjectAttributes.Param[5],
                ObjectName);

        if ( Command == aefSaveObjectInfo || Command == aefSaveAllInfo )
            trace(P"%c%c%c%c has changed %wZ Attributes (%x,%x,%x,%x,%x,%x)=>(%x,%x,%x,%x,%x,%x)"
                  " while MAPPING it to subject %s\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], ObjectName, 
                PrevObjectAttributes.Param[0], PrevObjectAttributes.Param[1], PrevObjectAttributes.Param[2],
				PrevObjectAttributes.Param[3], PrevObjectAttributes.Param[4], PrevObjectAttributes.Param[5],
                ObjectAttributes.Param[0], ObjectAttributes.Param[1], ObjectAttributes.Param[2],
				ObjectAttributes.Param[3], ObjectAttributes.Param[4], ObjectAttributes.Param[5],
                Name);

        if ( PrevResult != Result )
            trace(P"%c%c%c%c deny MAPPING object %wZ to subject %s\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], 
                ObjectName, Name);
#endif
        if ( ( RtlCompareMemory(&PrevSubjectAttributes, &SubjectAttributes, sizeof SubjectAttributes) != 
			   sizeof SubjectAttributes ) && Log::IsAllowedLogLevel(Log::llvImportant) ) {
            CHAR Name[NT_PROCNAMELEN];
            GetProcessNameByPointer(PsGetCurrentProcess(), Name);
            PUNICODE_STRING ObjectName;
            GetObjectName(Object, &ObjectName);
			Log::Write(Log::llvImportant, L">>>:%S:%d:%d:%d:%d:%d:%d:%wZ:%d:%d:%d:%d:%d:%d\r\n", 
                       Name, SubjectAttributes.Param[0], SubjectAttributes.Param[1], 
                       SubjectAttributes.Param[2], SubjectAttributes.Param[3], 
					   SubjectAttributes.Param[4], SubjectAttributes.Param[5],
                       ObjectName, ObjectAttributes.Param[0], ObjectAttributes.Param[1], 
                       ObjectAttributes.Param[2], ObjectAttributes.Param[3],
					   ObjectAttributes.Param[4], ObjectAttributes.Param[5]);
            delete[] ObjectName;
        } else
        if ( Log::IsAllowedLogLevel(Log::llvDetails) ) {
            CHAR Name[NT_PROCNAMELEN];
            GetProcessNameByPointer(PsGetCurrentProcess(), Name);
            PUNICODE_STRING ObjectName;
            GetObjectName(Object, &ObjectName);
			Log::Write(Log::llvDetails, L">>>:%S:%d:%d:%d:%d:%d:%d:%wZ:%d:%d:%d:%d:%d:%d\r\n", 
                       Name, SubjectAttributes.Param[0], SubjectAttributes.Param[1], 
                       SubjectAttributes.Param[2], SubjectAttributes.Param[3],
					   SubjectAttributes.Param[4], SubjectAttributes.Param[5],
                       ObjectName, ObjectAttributes.Param[0], ObjectAttributes.Param[1], 
                       ObjectAttributes.Param[2], ObjectAttributes.Param[3],
					   ObjectAttributes.Param[4], ObjectAttributes.Param[5]);
            delete[] ObjectName;
        }

        //
        // Set info
        //
        if ( Command == aefSaveSubjectInfo || Command == aefSaveAllInfo )
            Aci::SetSubjectInfo(pNode->Label, Subject, SubjectAttributes, Redirect, RuleId);
       
        if ( Command == aefSaveObjectInfo || Command == aefSaveAllInfo )
		    Aci::SetObjectInfo(pNode->Label, Object, NULL, nttFile, ObjectAttributes);

        if ( Result != rurAllowAction )
            break;

        pEntry = pEntry->Flink;
	}
    //Syn.Release();

#if DBG
    delete[] ObjectName;
#endif
    return Result;
}

Rule::RuleResult Rule::CreateSubject(PEPROCESS ParentSubject, PEPROCESS ChildSubject, 
                                     PFILE_OBJECT FileObject)
{
    RuleResult Result = rurAllowAction;
#if DBG
    CHAR Name[NT_PROCNAMELEN];
    GetProcessNameByPointer(ParentSubject, Name);
#endif

    //Syn.Share();
	PLIST_ENTRY pEntry = RuleList.Flink;
	while (pEntry != &RuleList) {

		RuleInfo *pNode = CONTAINING_RECORD(pEntry, RuleInfo, Entry);
        //
        // Get info
        //
        EntityAttributes ParentAttributes, ChildAttributes, ObjectAttributes;
        RedirectStatus ParentRedirect, ChildRedirect;
		ULONG ParentRuleId, ChildRuleId;
        Aci::GetSubjectInfo(pNode->Label, ParentSubject, ParentAttributes, ParentRedirect, ParentRuleId);
        ChildAttributes = ParentAttributes;
        ChildRedirect = ParentRedirect;
		ChildRuleId = ParentRuleId;
        Aci::GetObjectInfo(pNode->Label, FileObject, NULL, nttFile, ObjectAttributes);
        RuleResult PrevResult = Result;
		AefCommand Command = aefNone;
        //
        // Call subject create rule
        //
        if ( pNode->CreateSubject != NULL ) {
            Result = pNode->CreateSubject(ParentSubject, ParentAttributes, ParentRedirect, ParentRuleId,
                                          ChildSubject, ChildAttributes, ChildRedirect, ChildRuleId,
                                          ObjectAttributes, FileObject, Command);
            Result = min(Result, PrevResult);
        }
#if DBG
        if ( RtlCompareMemory(&ParentAttributes, &ChildAttributes, sizeof ParentAttributes) !=
             sizeof ParentAttributes )
            trace(P"%c%c%c%c has changed inherited subject Attributes (%x,%x,%x,%x,%x,%x)=>(%x,%x,%x,%x,%x,%x)"
                  " while CREATING by %s\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], 
                ParentAttributes.Param[0], ParentAttributes.Param[1], ParentAttributes.Param[2],
				ParentAttributes.Param[3], ParentAttributes.Param[4], ParentAttributes.Param[5],
                ChildAttributes.Param[0], ChildAttributes.Param[1], ChildAttributes.Param[2],
				ChildAttributes.Param[3], ChildAttributes.Param[4], ChildAttributes.Param[5],
                Name);

        if ( PrevResult != Result )
            trace(P"%c%c%c%c deny CREATING new subject by %s\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], 
                Name);
#endif
        if ( Result != rurAllowAction )
            break;
        //
        // Set info
        //
        Aci::SetSubjectInfo(pNode->Label, ChildSubject, ChildAttributes, ChildRedirect, ChildRuleId);
		if ( Command == aefSaveObjectInfo || Command == aefSaveAllInfo )
			Aci::SetObjectInfo(pNode->Label, FileObject, NULL, nttFile, ObjectAttributes);

        pEntry = pEntry->Flink;
	}
    //Syn.Release();

    return Result;
}

Rule::RedirectStatus Rule::DeleteSubject(PEPROCESS Subject)
{
    RedirectStatus Status = rdsUndefined;
#if DBG
    CHAR Name[NT_PROCNAMELEN];
    GetProcessNameByPointer(Subject, Name);
#endif

    //Syn.Share();
	PLIST_ENTRY pEntry = RuleList.Flink;
	while (pEntry != &RuleList) {

		RuleInfo *pNode = CONTAINING_RECORD(pEntry, RuleInfo, Entry);
        //
        // Get info
        //
        EntityAttributes SubjectAttributes, ObjectAttributes;
		RedirectStatus Redirect;
		ULONG RuleId;
        Aci::GetSubjectInfo(pNode->Label, Subject, SubjectAttributes, Redirect, RuleId);
        RedirectStatus PrevStatus = Status;
		AefCommand Command = aefNone;
        //
        // Call subject create rule
        //
        if ( pNode->DeleteSubject != NULL ) {
            Status = pNode->DeleteSubject(Subject, SubjectAttributes, Redirect, RuleId, Command);
			Status = (RedirectStatus)( PrevStatus | Status );
        }
#if DBG
        if ( PrevStatus != Status )
            trace(P"%c%c%c%c changes redirect status to %x for %s\n", 
                pNode->Label[0], pNode->Label[1], pNode->Label[2], pNode->Label[3], 
                Status, Name);
#endif
		pEntry = pEntry->Flink;
	}
    //Syn.Release();

    return Status;
}

NTSTATUS Rule::Init(VOID)
{
    InitializeListHead(&RuleList);
    NTSTATUS rc = Syn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

	bInited = TRUE;
    return rc;
}

VOID Rule::Release(VOID)
{
    if ( !bInited ) return;

    Syn.Exclusive();
	while ( !IsListEmpty(&RuleList) ) {

        PLIST_ENTRY pEntry = RemoveTailList(&RuleList);
		RuleInfo *Info = CONTAINING_RECORD(pEntry, RuleInfo, Entry);
        delete Info;
	}
    Syn.Release();
    Syn.Destroy();
}

NTSTATUS Rule::Register(RuleInfo &Rule)
{
    NTSTATUS rc = STATUS_SUCCESS;

    //
    // Check if rule should be applied
    //
    ULONG EnableRule;
    ULONG Size = sizeof EnableRule;
    PVOID Buf = &EnableRule;
    WCHAR RuleName[sizeof Rule.Label + 1];
    for (ULONG i = 0; i < sizeof Rule.Label; i++) RuleName[i] = Rule.Label[i];
    RuleName[sizeof RuleName / sizeof RuleName[0] - 1] = 0;

    rc = RegReadValue(&usRegParamName, RuleName, &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) || EnableRule == 0 ) {
        trace(P"%S rule bypassed by registry settings\n", RuleName);
        return STATUS_SUCCESS;
    }

    Syn.Exclusive();
    RuleInfo *Info = LookupRule(Rule.Label);
    if ( Info != NULL ) {
        Syn.Release();
        rc = STATUS_UNSUCCESSFUL;
        ERR(rc);
        return rc;
    }

    Info = new(PagedPool) RuleInfo;
    if ( Info == NULL ) {
        Syn.Release();
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    *Info = Rule;
    InsertTailList(&RuleList, &Info->Entry);
    Syn.Release();

    return rc;
}

NTSTATUS Rule::UnRegister(CHAR *Label)
{
    NTSTATUS rc = STATUS_SUCCESS;

    Syn.Exclusive();
    RuleInfo *Info = LookupRule(Label);
    if ( Info == NULL ) {
        Syn.Release();
        rc = STATUS_UNSUCCESSFUL;
        ERR(rc);
        return rc;
    }

    RemoveEntryList(&Info->Entry);
    delete Info;

    Syn.Release();
    return rc;
}


Rule::RuleInfo *Rule::LookupRule(CHAR *Label)
{
	PLIST_ENTRY pEntry = RuleList.Flink;
	while (pEntry != &RuleList) {

		RuleInfo *pNode = CONTAINING_RECORD(pEntry, RuleInfo, Entry);
		if ( RtlCompareMemory(pNode->Label, Label, sizeof pNode->Label) == sizeof pNode->Label )
            return pNode;

        pEntry = pEntry->Flink;
	}

    return NULL;
}

NtObjectType Rule::MapNtObjectType(POBJECT_TYPE ObjType, PVOID Object)
{
    NtObjectType NtType = nttUnknown;
    if ( ObjType == NULL && Object != NULL )
        ObjType = AdApi::GetObjectType(Object);

    if ( ObjType == NULL || ObjType == *IoFileObjectType )
        if ( Object != NULL && 
             (
              ( 
                PFILE_OBJECT(Object)->Vpb == NULL && 
                !( PFILE_OBJECT(Object)->Flags & FO_NAMED_PIPE ) &&
                PFILE_OBJECT(Object)->DeviceObject->DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM
              ) ||
              PFILE_OBJECT(Object)->Flags & FO_DIRECT_DEVICE_OPEN ||
              PFILE_OBJECT(Object)->Flags & FO_VOLUME_OPEN
             )
           )
            NtType = nttDevice;
        else
            NtType = nttFile;
    else
    if ( ObjType == *ExEventObjectType )
        NtType = nttEvent;
    else
    if ( ObjType == *ExSemaphoreObjectType )
        NtType = nttSemaphore;
    else
    if ( ObjType == *PsThreadType )
        NtType = nttThread;
    else
    if ( ObjType == *PsProcessType )
        NtType = nttProcess;
    else
    if ( ObjType == *ExDesktopObjectType )
        NtType = nttDesktop;
    else
    if ( ObjType == *ExWindowStationObjectType )
        NtType = nttWindowStation;
    else
    if ( ObjType == *LpcPortObjectType )
        NtType = nttPort;
    else
    if ( ObjType == *MmSectionObjectType )
        NtType = nttSection;
    else
    if ( ObjType == *IoDeviceObjectType )
        NtType = nttDevice;
    else
    if ( ObjType == *IoDriverObjectType )
        NtType = nttDriver;
    else
    if ( ObjType == *PsJobType )
        NtType = nttJob;

    if ( NtType == nttUnknown ) {

        static struct NtObType { 
            UNICODE_STRING Name;
            PVOID ObjType;
            NtObjectType NtObjType;
        } UnexportedTypes[] = { 
            { { 32, 34, L"\\ObjectTypes\\Key"}, NULL, nttKey },
            { { 44, 46, L"\\ObjectTypes\\Directory"}, NULL, nttDirectory },
            { { 36, 38, L"\\ObjectTypes\\Token"}, NULL, nttToken } 
        };
        static const UnexportedTypesNum = sizeof UnexportedTypes / sizeof UnexportedTypes[0];
        ULONG i;
        BOOLEAN bAllFilled = TRUE;
        for ( i=0; i < UnexportedTypesNum; i++ )
            if ( UnexportedTypes[i].ObjType == ObjType ) {
                NtType = UnexportedTypes[i].NtObjType;
                bAllFilled = TRUE;
                break;
            } else 
            if ( UnexportedTypes[i].ObjType == NULL )
                bAllFilled = FALSE;

        if ( !bAllFilled ) {

	        static const ULONG size = 30*sizeof(WCHAR)+sizeof(UNICODE_STRING);
            UCHAR buf[size];
	        ULONG ActualLength;

	        PUNICODE_STRING pObjName = (PUNICODE_STRING) buf;

	        NTSTATUS rc = ObQueryNameString(ObjType, 
						                    (POBJECT_NAME_INFORMATION)pObjName,
						                    size,
						                    &ActualLength);
            if ( NT_SUCCESS(rc) ) {
                for ( i=0; i < UnexportedTypesNum; i++ )
                    if ( !RtlCompareUnicodeString(pObjName, &UnexportedTypes[i].Name, TRUE) ) {
                        UnexportedTypes[i].ObjType = ObjType;
                        NtType = UnexportedTypes[i].NtObjType;
                        break;
                    }
            }
        }
    }

    return NtType;
}


ACCESS_MASK Rule::GetModifyAccess(NtObjectType Type)
{
	ACCESS_MASK Access = GESWALL_MODIFY_ACCESS | GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY;

    switch ( Type ) {
    
        case nttFile:
            Access |= FILE_WRITE_ACCESS | FILE_APPEND_DATA | FILE_WRITE_EA | 
                      FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
            break;

        case nttDirectory:
            Access |= DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;
            break;

        case nttKey:
            Access |= KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK;
            break;

        case nttProcess:
            Access |= PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID |
                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_PROCESS | 
                      PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME |
                      PROCESS_DUP_HANDLE;
            break;

        case nttThread:
            Access |= THREAD_SET_INFORMATION | THREAD_TERMINATE | THREAD_SET_CONTEXT | 
                      THREAD_SET_THREAD_TOKEN | THREAD_SUSPEND_RESUME;
            break;
            
        case nttEvent:
        case nttKeyedEvent:
            Access |= EVENT_MODIFY_STATE;
            break;

        case nttIoCompletion:
            Access |= IO_COMPLETION_MODIFY_STATE | DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS;
            break;

        case nttJob:
            Access |= JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_SET_ATTRIBUTES | JOB_OBJECT_TERMINATE |
                      JOB_OBJECT_SET_SECURITY_ATTRIBUTES;
            break;

        case nttSection:
            Access |= SECTION_MAP_WRITE | SECTION_EXTEND_SIZE;
            break;

        case nttSemaphore:
            Access |= SEMAPHORE_MODIFY_STATE;
            break;

        case nttToken:
            Access |= TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS |
                      TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
            break;

        case nttTimer:
            Access |= TIMER_MODIFY_STATE;
            break;

        case nttWindowStation:
			Access |= WINSTA_WRITEATTRIBUTES | WINSTA_CREATEDESKTOP | WINSTA_EXITWINDOWS;// | WINSTA_ACCESSCLIPBOARD;
			break;

        case nttPort:
        case nttWaitablePort:
			Access |= PORT_CONNECT | DELETE;
			break;

        case nttDesktop:
			Access |= DESKTOP_WRITEOBJECTS;
			break;

        case nttSymbolicLink:
        case nttDebug:
        case nttMutant:
        case nttProfile:
			break;

        default:
            Access |= FILE_WRITE_ACCESS;
            break;
    }

    return Access;
}

bool Rule::ResolveMaximumAllowed(PVOID Object, KPROCESSOR_MODE AccessMode, ACCESS_MASK *Access)
{
	static GENERIC_MAPPING GenericMapping = { 0, GESWALL_MODIFY_ACCESS, 0, GESWALL_MODIFY_ACCESS };
	//
	// get sd
	//
    PSECURITY_DESCRIPTOR sd = NULL;
    BOOLEAN  bMemoryAllocated;
	NTSTATUS rc = ObGetObjectSecurity(Object, &sd, &bMemoryAllocated);
	if ( !NT_SUCCESS(rc) ) return false;

	ACCESS_MASK Granted;
	SECURITY_SUBJECT_CONTEXT sc;
	SeCaptureSubjectContext(&sc);
	SeAccessCheck(sd, &sc, FALSE, MAXIMUM_ALLOWED, 0, NULL, &GenericMapping, AccessMode, &Granted, &rc);
	SeReleaseSubjectContext(&sc);
	ObReleaseObjectSecurity(sd, bMemoryAllocated);

	*Access &= ~MAXIMUM_ALLOWED;
	*Access |= Granted;

	return true;
}


WCHAR *Rule::GetResultString(RuleResult Result)
{
    switch(Result) {
        case rurBlockSubject:
            return L"STOP";

        case rurBlockAction:
            return L"DENY";

        case rurBlockModify:
            return L"READONLY";

        case rurRedirect:
            return L"REDIRECT";

        case rurAllowAction:
            return L"GRANT";
    }

    return L"UnknownResult";
}
