//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "sxrule.h"
#include "tools.h"

using namespace Rule;

namespace SxRule {
    ActionType MapActionType(ACCESS_MASK Access, NtObjectType NtType);
    PEPROCESS SystemProcess = NULL;
};

RuleResult SxRule::AccessObject(ObjectAccessType AccessType, 
                     PEPROCESS Subject, EntityAttributes &SubjectAttributes, 
                     PVOID Object, EntityAttributes &ObjectAttributes, 
                     NtObjectType NtType, PVOID RelatedObject, 
					 ACCESS_MASK Access, Rule::AefCommand &Command, RedirectStatus &Redirect)
{
    RuleResult Result = rurAllowAction;
/*
    {
        BOOLEAN bTrack = FALSE;
        UNICODE_STRING usName;
        PUNICODE_STRING ObjectName = NULL;
		GetObjectName(Object, &ObjectName);
        RtlInitUnicodeString(&usName, L"\\Device\\HarddiskVolume1\\test\\test");
        if ( ObjectName != NULL && !RtlCompareUnicodeString(&usName, ObjectName, TRUE) ) {
            bTrack = TRUE;
            PFILE_OBJECT FileObject = (PFILE_OBJECT) Object;
            FILE_BASIC_INFORMATION BasicInfo;
            NTSTATUS rc = QueryFile(IoGetRelatedDeviceObject(FileObject), FileObject,
                   FileBasicInformation, &BasicInfo, sizeof BasicInfo);
            if ( !NT_SUCCESS(rc) ) {
                ERR(rc);
            }
        }

        if ( ObjectName != NULL ) delete[] ObjectName;
    }
*/
    //
    // Do not control token access
    //
    Command = aefNone;
    if ( NtType == nttToken )
        return rurAllowAction;

    if ( AccessType == acsOpen || 
        ( AccessType == acsWrite && SubjectAttributes.Param[2] == iglUntrusted &&
          SubjectAttributes.Param[0] == 0 ) ) {
        
        ActionType Action = AccessType == acsOpen ? MapActionType(Access, NtType) : actModify;

        IntegrityLevel ObjectIntegrity = (IntegrityLevel) ObjectAttributes.Param[2];
	    if ( ObjectIntegrity == iglUndefined )
            if ( NtType == nttProcess )
                //
                // Suppose not seen process as Trusted
                //
                ObjectIntegrity = iglTrusted;
            else
                ObjectIntegrity = iglUntrusted;

        IntegrityLevel SubjectIntegrity = (IntegrityLevel) SubjectAttributes.Param[2];
	    if ( SubjectIntegrity == iglUndefined )
            SubjectIntegrity = iglTrusted;

        ConfidentLevel SubjectLevel = (ConfidentLevel) SubjectAttributes.Param[1];
        ConfidentLevel ObjectLevel = (ConfidentLevel) ObjectAttributes.Param[1];

        //
        // Confidentiality model
        //
        Rule::RuleResult MC = Rule::rurBlockAction;
        bool bConfidentiality = ( ObjectLevel < cflClassified ) ||
                                ( ( ObjectLevel >= cflClassified ) && ( SubjectIntegrity == iglTrusted ) );

        if ( bConfidentiality ) {
            MC = Rule::rurAllowAction;
        }

        // 
        // Integrity model
        //
        Rule::RuleResult MI = Rule::rurBlockModify;
        bool bIntegrity = ( Action == actRead ) || 
/*
                          ( 
                            ( NtType != nttFile ) && ( NtType != nttKey ) && ( NtType != nttDevice ) &&
                            ( NtType != nttProcess ) && ( NtType != nttThread ) 
                          ) ||
*/
                          ( ObjectIntegrity <= iglUntrusted ) || 
                          ( ( ObjectIntegrity == iglTrusted ) && ( SubjectIntegrity == iglTrusted ) );

        if ( bConfidentiality && bIntegrity ) {
            MI = Rule::rurAllowAction;

            if ( Action == actModify && SubjectIntegrity == iglUntrusted && 
                 ObjectAttributes.Param[0] == 0 ) {
                ObjectIntegrity = iglUntrusted;
                Command = Rule::aefSaveObjectInfo;
            }
        }

        Result = min(MI, MC);

        if ( Subject == SystemProcess ) SubjectIntegrity = iglTrusted;
/*
        if ( ObjectAttributes.Param[0] != 0 && NtType == nttFile && 
             PFILE_OBJECT(Object)->Flags & FO_NAMED_PIPE )
            //
            // Always allow access to named pipes of known trusted subjects
            //
            Result = rurAllowAction;
*/

        if ( AccessType == acsOpen && NtType == nttKey && Action == actModify ) {

            if ( Result == rurAllowAction && Command == aefSaveObjectInfo ) {
                ObjectIntegrity = (IntegrityLevel) ObjectAttributes.Param[2];
                Command = aefNone;
            } 
            else
            if ( Result == rurBlockModify ) {
                Result = rurAllowAction;
            }
        }

        if ( AccessType == acsWrite && NtType == nttKey && Result == rurBlockModify )
            Result = rurRedirect;

		if ( AccessType == acsOpen && NtType == nttFile && 
			 PFILE_OBJECT(Object)->Vpb != NULL && Result == rurBlockModify )
			Result = rurRedirect;

        SubjectAttributes.Param[2] = SubjectIntegrity;
        ObjectAttributes.Param[2] = ObjectIntegrity;
        SubjectAttributes.Param[1] = SubjectLevel;
        ObjectAttributes.Param[1] = ObjectLevel;
    } 
    else
    if ( AccessType == acsAci ) {
        Result = rurBlockModify;
    }
    else 
    if ( AccessType == acsMessage && SubjectAttributes.Param[2] < ObjectAttributes.Param[2] ) {
        Result = rurBlockAction;
    }

    return Result;
}

RuleResult SxRule::MapSubject(PEPROCESS Subject, EntityAttributes &SubjectAttributes, 
                        PFILE_OBJECT Object, EntityAttributes &ObjectAttributes, 
                        Rule::AefCommand &Command, RedirectStatus &Redirect)
{
    RuleResult Result = rurAllowAction;

    if ( Subject == SystemProcess && ObjectAttributes.Param[2] != iglTrusted )
        //
        // Block loading non-TCB objects to kernel
        //
        return rurBlockAction;
    
    if ( SubjectAttributes.Param[2] == iglUndefined ) 
        SubjectAttributes.Param[2] = iglTrusted;

    if ( Object == NULL )
        SubjectAttributes.Param[2] = min(SubjectAttributes.Param[2], iglTrusted);
    else {

        if ( ObjectAttributes.Param[2] <= iglUntrusted && 
             SubjectAttributes.Param[2] == iglTrusted && SubjectAttributes.Param[0] != 0 )
            return rurBlockAction;

        if ( ObjectAttributes.Param[2] == iglUndefined )
            SubjectAttributes.Param[2] = min(SubjectAttributes.Param[2], iglUntrusted);
        else
            SubjectAttributes.Param[2] = min(SubjectAttributes.Param[2], ObjectAttributes.Param[2]);
    }

    if ( SubjectAttributes.Param[2] == iglUntrusted )
        Redirect = rdsAll;

    Command = aefSaveSubjectInfo;
    return Result;
}

Rule::RuleResult SxRule::CreateSubject(PEPROCESS ParentSubject, EntityAttributes &ParentAttributes,
                                   RedirectStatus ParentRedirect, ULONG ParentRuleId,
                                   PEPROCESS ChildSubject, EntityAttributes &ChildAttributes,
                                   RedirectStatus &ChildRedirect, ULONG &ChildRuleId,
                                   EntityAttributes &ObjectAttributes, PFILE_OBJECT FileObject,
								   AefCommand &Command)
{
    ChildAttributes.Param[0] = ObjectAttributes.Param[0];

    return rurAllowAction;
}

SxRule::ActionType SxRule::MapActionType(ACCESS_MASK Access, NtObjectType NtType)
{
    ActionType Action = actRead;

    if ( Access & GetModifyAccess(NtType) || Access == 0 )
        Action = actModify;

    return Action;

}

NTSTATUS SxRule::Init(VOID)
{
    SystemProcess = PsGetCurrentProcess();

    return STATUS_SUCCESS;
}
