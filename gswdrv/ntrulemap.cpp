//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "ntrulemap.h"
#include "gesrule.h"
#include "tools.h"
#include "lock.h"
#include "request.h"
#include "hook.h"
#include "acidyn.h"
#include "sysprocess.h"
#include "netfilter.h"


using namespace Rule;
using namespace GesRule;

namespace NtRuleMap {
    PEPROCESS SystemProcess = NULL;
	UNICODE_STRING usParamsKey;

	CEResource Syn;
	const ULONG AutoIdRange = 0x80000000;
	ULONG CurrentAutoId = AutoIdRange;
	ULONG GetAutoId(VOID);

	ULONG GetObjectOptions(ULONG SubjectId);
	NTSTATUS SetObjectOptions(ULONG SubjectId, ULONG Options);

	HANDLE hParamsKey;
	ULONG PolicyOptions = 0;
	ULONG TypesMask = 0;
	ULONG JailTypesMask = 0;
	ULONG MessagesMask = 0;
	LONGLONG LogRepeatInterval = 5 * LONGLONG(1000) * LONGLONG(10000);

	AccessLogLevel AccessLog = aclDisabled;
	NotificationLevel Notification = ntlDisabled;

	ULONG RedirectFilter = 0;

	CEResource LogSyn;
	LIST_ENTRY LogHistoryList;
	WCHAR *DefaultAccessLogDir = L"\\SystemRoot\\geswall\\logs";
	WCHAR *AccessLogDir = NULL;

	RedirectStatus GetAllowedRiderectStatus(const RedirectStatus Redirect, const ULONG SubjectOptions)
	{
		ULONG Status = 0;
		if ( !( SubjectOptions & oboDisableFileRedirect ) && ( Redirect & rdsFile ) ) Status |= rdsFile;
		if ( !( SubjectOptions & oboDisableKeyRedirect ) && ( Redirect & rdsKey ) ) Status |= rdsKey;
		return (RedirectStatus) Status;
	}

	bool IsRedirectAllowed(PFILE_OBJECT FileObject);
};

//
// Apply GeSWall policy rules
// 1. Phase1 - exclude non-protected subjects according to global policy settings
// 2. Phase2 - apply rules according to access type
//	2.1 Phase2.1 - apply rules for opening and creating
//		2.1.1 Adjust input parameters according policy defaults
//		2.1.2 Apply strict multilevel policy
//		2.1.3 Apply explicit rules
//		2.1.4 Apply access decision mitigation policy
//		2.1.5 Post processing, adjusting subjects/objects parameters according to resulting access
//	2.2 Phase2.2 - apply rules for ACI access
//	2.3 Phase2.3 - apply rules for subject's windows access by messages
// 3. Phase3 - audit logging
//
RuleResult NtRuleMap::AccessObject(ObjectAccessType AccessType, 
                     PEPROCESS Subject, EntityAttributes &SubjectAttributes, ULONG RuleId,
                     PVOID Object, EntityAttributes &ObjectAttributes,
                     NtObjectType NtType, PVOID RelatedObject, ACCESS_MASK Access, 
					 AefCommand &Command, RedirectStatus &Redirect)
{
    RuleResult Result = rurAllowAction;
    Command = aefNone;
	//
	// 1. Phase1 - exclude non-protected subjects according to global policy settings
	//
    // Do not control access to specified object types
    //
/*======== Moved to Rule namespace, for optimization ======================
	if ( ( 1<<NtType ) & TypesMask ) return rurAllowAction;
	//
	// if ploIsolatedOnlyJailed or ploIsolateOnlyDefined options are enabled
	// then grant access for all irrelevant cases
	//
	if ( ( PolicyOptions & ploIsolatedOnlyJailed && SubjectAttributes.Param[attIntegrity] > modUntrusted ) ||
		 ( PolicyOptions & ploIsolateOnlyDefined && RuleId == 0 &&
		   ( !( SubjectAttributes.Param[attOptions] & oboTracked ) || SubjectAttributes.Param[attIntegrity] == modTCB ) ) )
		return rurAllowAction;
===========================================================================*/
	// 2. Phase2 - apply rules according to access type
	//
    if ( AccessType == acsOpen || AccessType == acsCreated ||
        ( AccessType == acsWrite && SubjectAttributes.Param[attIntegrity] <= modThreatPoint ) ) {
		//	2.1 Phase2.1 - apply rules for opening and creating
		// 
		//		2.1.1 Adjust input parameters according policy defaults
		// Get acction type, model's settings and options
		//
        ActionType Action = AccessType == acsOpen ? MapActionType(Access, NtType) : actModify;
		//
		// Identify object model
		//
        ModelType ObjectModel = (ModelType) ObjectAttributes.Param[attIntegrity];
	    if ( ObjectModel == modUndefined )
            if ( NtType == nttProcess ||
				 ( ( PolicyOptions & ploTrustByDefault ) && ( NtType == nttFile || NtType == nttKey ) ) )
                //
                // Consider non-seen process as TCB
                //
                ObjectModel = modTCB;
            else
                ObjectModel = modUntrusted;
		//
		// Identify subject model
		//
        ModelType SubjectModel = (ModelType)SubjectAttributes.Param[attIntegrity];
	    if ( SubjectModel == modUndefined )
			if ( Subject == SystemProcess )
				SubjectModel = modTCB;
			else
				SubjectModel = modUntrusted;

        ConfidentLevel SubjectLevel = (ConfidentLevel) SubjectAttributes.Param[attConfident];
		if ( SubjectLevel == cflUndefined ) {
			if ( SubjectModel == modThreatPoint )
				SubjectLevel = cflClassified;
			else
			if ( SubjectModel == modTrusted )
				SubjectLevel = cflSecret;
			else
			if ( SubjectModel == modTCB )
				SubjectLevel = cflSecret;
		}
        ConfidentLevel ObjectLevel = (ConfidentLevel) ObjectAttributes.Param[attConfident];

		if ( ObjectLevel == cflUndefined ) {
			//
			// set classified by default to disable default read access in jail mode
			//
			if ( !( ( 1<<NtType ) & JailTypesMask ) ) ObjectLevel = cflClassified;
			//
			// prevent read access for geswall objects
			//
			if ( ObjectAttributes.Param[attOptions] & oboGeSWall ) ObjectLevel = cflSecret;
		}
		//
		// Options
		//
		ULONG ObjectOptions = ObjectAttributes.Param[attOptions];
		ULONG SubjectOptions = SubjectAttributes.Param[attOptions];
		ObjectType GesType = MapObjectType(NtType);
		//
		//		2.1.2 Apply strict multilevel policy
		//
        Result = GesRule::Apply(
						        SubjectAttributes.Param[attSubjectId],
                                SubjectModel,
                                SubjectLevel,
                                ObjectAttributes.Param[attObjectId],
                                ObjectModel,
                                ObjectLevel,
                                GesType,
                                Action,
                                Command
                                );
		//
		if ( AccessType == acsCreated ) {
			//
			// Resource creation is allowed by default
			//
			Result = rurAllowAction;
		}
		//
		// system process settings are exclusion from policy
		//
        if ( Subject == SystemProcess ) {
			SubjectModel = modTCB;
			SubjectLevel = cflSecret;
			if ( Command == aefSaveSubjectInfo ) Command = aefNone;
		}

		if ( Result == rurAllowAction && Command == Rule::aefSaveSubjectInfo && 
			( SubjectModel == modThreatPoint || SubjectLevel == cflClassified ) ) {
			//
			// !( PolicyOptions & ploNoPopups ) is checked in gswserv
			//
			// Request user if we really must switch application to modThreatPoint
			//
			if ( NeedRuleCheck(SubjectAttributes, Redirect, RuleId) ) {
				ThreatPointSubjectReq *Req = new(PagedPool) ThreatPointSubjectReq;
				if ( Req != NULL ) {
					Req->ProcessId = PsGetCurrentProcessId();
					Req->Attr = SubjectAttributes;
					Req->RuleId = RuleId;
					Req->FileName[0] = 0;
					PUNICODE_STRING usName = Hook::GetProcessFileName(Subject);
					ULONG Length;
					if ( usName != NULL ) {
						Length = min(usName->Length, sizeof Req->FileName -  sizeof WCHAR);
						RtlCopyMemory(Req->FileName, usName->Buffer, Length);
						Req->FileName[Length / sizeof WCHAR] = 0;
						delete[] usName;
						usName = NULL;
					}
					Req->ResourceType = NtType;
					if ( NtType == nttFile )
						GetObjectName((PFILE_OBJECT)Object, &usName);
					else
						GetObjectName(Object, &usName);
					if ( usName != NULL ) {
						Length = min(usName->Length, sizeof Req->ResourceName -  sizeof WCHAR);
						RtlCopyMemory(Req->ResourceName, usName->Buffer, Length);
						Req->ResourceName[Length / sizeof WCHAR] = 0;
						delete[] usName;
						usName = NULL;
					}
					ULONG RequestResult = tpsKeepTrusted;
					if ( !( SubjectOptions & oboKeepTrusted ) ) RequestResult = Request::UserCall(Req, NULL, NULL);
					if ( SubjectOptions & oboKeepTrusted || RequestResult == tpsKeepTrusted || RequestResult == tpsOnceTrusted ) {
						if ( SubjectModel == modThreatPoint ) SubjectModel = modTCB;
						if ( SubjectLevel == cflClassified ) SubjectLevel = cflSecret;
						if ( !(SubjectOptions & oboKeepTrusted) && RequestResult == tpsKeepTrusted )
							SubjectOptions |= oboKeepTrusted;
						else
							Command = aefNone;
					} else {
						Redirect = GetAllowedRiderectStatus(rdsAll, SubjectOptions);
					}
					delete Req;

					if ( SubjectModel == modThreatPoint ) {
						//
						// Log switching
						//
						Log(acsSwitchSubject, Subject, SubjectAttributes, RuleId, Object, NtType, RelatedObject, NULL, Access, Result);
					}
				}
			} else {
				if ( SubjectModel == modThreatPoint ) SubjectModel = modTCB;
				if ( SubjectLevel == cflClassified ) SubjectLevel = cflSecret;
				Command = aefNone;
			}
		}
		//
		// Check for creation policy restrictions
		//
		if ( AccessType == acsCreated ) {
			if ( ObjectAttributes.Param[attObjectId] == 0 ) {
				//
				// to let strict rights go
				ObjectAttributes.Param[attObjectId] = SubjectAttributes.Param[attSubjectId];
			}

			if ( SubjectModel <= modThreatPoint ) {
				//
				if ( ObjectOptions & oboDenyAccess ) {
					//
					// Excplicit deny access
					//
					Result = rurBlockAction;
				} else
				if ( ( SubjectOptions & oboDisableFileCreate && NtType == nttFile ) ||
					( SubjectOptions & oboDisableKeyCreate && NtType == nttKey ) ) {
					//
					// instead of deny set blockmodify, so it can be mitigated to redirect later
					//
					Result = rurBlockModify;
				}
			}
		}
		//
		// Check confinement options
		//
		if ( SubjectModel <= modThreatPoint && PolicyOptions & ploConfineIsolated && 
			 Action == actModify && Result == rurAllowAction && 
			( ( GesType == obtStorage && SubjectAttributes.Param[attSubjectId] != ObjectAttributes.Param[attObjectId] ) ||
			  ( GesType == obtProcess && SubjectAttributes.Param[attSubjectId] != ObjectAttributes.Param[attSubjectId] )
			  // TODO: Compare RuleIds for processes
			)
		   ) {
			 Result = rurBlockModify;
		}
	    //
		//		2.1.3 Apply explicit rules
	    // explicit allow, deny or redirect access, regardless model behaviours.
	    // For non-TCB subjects and above TCB objects only!
	    //
		if ( ( SubjectModel < modTCB || ObjectModel > modTCB ) && SubjectAttributes.Param[attSubjectId] == ObjectAttributes.Param[attObjectId] ) {
			if ( ObjectOptions & oboGrantAccess ) Result = rurAllowAction;
			else 
			if ( ObjectOptions & oboDenyRedirectAccess ) Result = Action == actRead ? rurAllowAction : rurBlockModify;
			else
			if ( ObjectOptions & oboRedirectAccess ) Result = Action == actRead ? rurAllowAction : rurRedirect;
			else
			if ( ObjectOptions & oboDenyAccess ) Result = rurBlockAction;
			//else
			//if ( ObjectOptions & oboTracked ) Result = rurAllowAction;
			// If file is created by non-isolated application, then it should
			// not be modified by application in isolated mode, unless explicitely
			// permited,
			// TODO: check "Isolate Network Applications" mode behaviour in that case
			//
		}
		//
		//		2.1.4 Apply access decision mitigation policy
		//
		if ( Result == rurBlockAction && SubjectLevel == cflClassified && ObjectLevel == cflSecret && 
			 NtType == nttFile && !( ( PolicyOptions & ploNoPopups ) || ( SubjectOptions & oboNoPopups ) ) && IsInteractiveContext() ) {
			//
			// Request user for deny access to confidential resource
			//
			AccessSecretFileReq *Req = new(PagedPool) AccessSecretFileReq;
			if ( Req != NULL ) {
				Req->ProcessId = PsGetCurrentProcessId();
				Req->ProcAttr = SubjectAttributes;
				Req->FileAttr = ObjectAttributes;
				Req->RuleId = RuleId;
				Req->ProcFileName[0] = 0;
				PUNICODE_STRING usFileName = Hook::GetProcessFileName(Subject);
				if ( usFileName != NULL ) {
					ULONG Length = min(usFileName->Length, sizeof Req->ProcFileName -  sizeof WCHAR);
					RtlCopyMemory(Req->ProcFileName, usFileName->Buffer, Length);
					Req->ProcFileName[Length / sizeof WCHAR] = 0;
					delete[] usFileName;
				}
				usFileName = NULL;
				GetObjectName((PFILE_OBJECT)Object, &usFileName);
				if ( usFileName != NULL ) {
					ULONG Length = min(usFileName->Length, sizeof Req->FileName -  sizeof WCHAR);
					RtlCopyMemory(Req->FileName, usFileName->Buffer, Length);
					Req->FileName[Length / sizeof WCHAR] = 0;
					delete[] usFileName;
				}
				if ( Request::UserCall(Req, NULL, NULL) ) {
					Result = rurBlockModify;
				}
				delete Req;
			}
		}
		//
		// Mitigate farther
		//
        if ( ObjectOptions & oboSystem && SubjectModel > modUntrusted )
            //
            // Always allow access to named pipes of known trusted subjects, system pipes
            //
            Result = rurAllowAction;


		if ( Result == rurBlockModify && AccessType == acsOpen && NtType == nttKey ) {
			//
			// let open a key, the access will be blocked on SetValue
			//
			Result = rurAllowAction;
		}

        if ( Result == rurBlockModify && AccessType == acsWrite && NtType == nttKey &&
			 !( ObjectOptions & oboDenyRedirectAccess ) && !( SubjectOptions & oboDisableKeyRedirect ) ) {
			//
			// replace readonly by redirect for registry
			//
            Result = rurRedirect;
        }

        if ( Result == rurBlockModify && NtType == nttFile && PFILE_OBJECT(Object)->Vpb != NULL &&
			 SubjectModel > modUntrusted && Access & ( FILE_WRITE_ACCESS | FILE_APPEND_DATA | GENERIC_WRITE ) &&
			 !( ObjectOptions & oboDenyRedirectAccess ) && !( SubjectOptions & oboDisableFileRedirect ) && IsRedirectAllowed((PFILE_OBJECT)Object) ) {
			//
			// replace readonly by redirect for file
			//
            Result = rurRedirect;
        }
		//
		// allow reading attributes on confidential devices
		//
		if ( Result == rurBlockAction && NtType == nttDevice ) {
			if ( Action == actRead && ( Access & ~( FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE ) ) == 0 ) Result = rurAllowAction;
			else
			if ( Action == actModify && ( Access & ~( FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE ) ) == 0 ) Result = rurBlockModify;
		}
		//
		// Prevent access to geswall objects
		//
		if ( Result == rurAllowAction && Action == actModify && ObjectOptions & oboGeSWall &&
			!( SubjectOptions & ( oboGeSWall | oboKeepTrusted | oboSetup ) ) ) {
			Result = rurBlockModify;
		}
		//
		//		2.1.5 Post processing, adjusting subjects/objects parameters according to resulting access
		//
		// Mark every subject written by below TCB subject or just created
		//
		if ( Result == rurAllowAction && 
			( SubjectModel < modTCB && NtType == nttFile && PFILE_OBJECT(Object)->Vpb != NULL &&
			  ( ( Access & ( FILE_WRITE_ACCESS | FILE_APPEND_DATA | GENERIC_WRITE ) ) || AccessType == acsCreated )
			)
		   ) {
			if ( AccessType == acsCreated ) {
				//ObjectAttributes.Param[attObjectId] = SubjectAttributes.Param[attSubjectId];
				//
				// TODO: Check what to do for confidential level, there should be max
				//
				//ObjectLevel = 
				//	min(SubjectAttributes.Param[attConfident], ObjectAttributes.Param[attConfident]);
			}
			ObjectOptions |= oboTracked;
			ObjectModel = min(SubjectModel, ObjectModel);

			if ( Command == Rule::aefSaveSubjectInfo || Command == Rule::aefSaveAllInfo )
				Command = Rule::aefSaveAllInfo;
			else
				Command = Rule::aefSaveObjectInfo;
		}

		SubjectAttributes.Param[attIntegrity] = SubjectModel;
        ObjectAttributes.Param[attIntegrity] = ObjectModel;
        SubjectAttributes.Param[attConfident] = SubjectLevel;
        ObjectAttributes.Param[attConfident] = ObjectLevel;
        SubjectAttributes.Param[attOptions] = SubjectOptions;
        ObjectAttributes.Param[attOptions] = ObjectOptions;
    } 
	else
	//	2.2 Phase2.2 - apply rules for ACI access
    if ( AccessType == acsAci && SubjectAttributes.Param[attIntegrity] < modTCB ) {
        Result = rurBlockModify;
    }
	else
	//	2.3 Phase2.3 - apply rules for subject's windows access by messages
	if ( AccessType == acsMessage && 
		 ( ( ObjectAttributes.Param[attIntegrity] > SubjectAttributes.Param[attIntegrity] ) //||
		  // ( PolicyOptions & ploConfineIsolated && SubjectAttributes.Param[attSubjectId] != ObjectAttributes.Param[attSubjectId] )
  		   // TODO: Compare RuleIds
		 ) &&
		 !( Access == 0x3e4 || Access == 0x3e0 || Access == 0x3e1 || ( Access & MessagesMask && RuleId != 0 ) ||
		    ( ObjectAttributes.Param[attOptions] & oboSystemMessage && Access == 0x4a )
		  )
	   ) {
        Result = rurBlockAction;
	}
	//
	// Exlusions
	//
	if ( Result != rurAllowAction ) {
		if ( ObjectAttributes.Param[attOptions] & oboRelaxedAccess && NtType == nttProcess && Access == PROCESS_DUP_HANDLE )
			Result = rurAllowAction;
	}
	//
	// 3. Phase3 - audit logging
	//
	if ( Result != rurAllowAction ) {
		if ( NtType != nttFile && NtType != nttKey ) {
			// access for files is logged within FsFilter
			Log(AccessType, Subject, SubjectAttributes, RuleId, Object, NtType, RelatedObject, NULL, Access, Result);
		}
		if ( PolicyOptions & ploUnRestrincted ) Result = rurAllowAction;
	}

    return Result;
}

Rule::RuleResult NtRuleMap::MapSubject(PEPROCESS Subject, EntityAttributes &SubjectAttributes, 
                                 PFILE_OBJECT Object, EntityAttributes &ObjectAttributes, 
                                 ULONG &RuleId, AefCommand &Command, RedirectStatus &Redirect)
{
    if ( SubjectAttributes.Param[attIntegrity] == modUndefined && Subject == SystemProcess )
		SubjectAttributes.Param[attIntegrity] = modTCB;

	if ( ObjectAttributes.Param[attIntegrity] == modUndefined ) {
		if ( PolicyOptions & ploTrustByDefault ) 
			ObjectAttributes.Param[attIntegrity] = modTCB;
		else
			ObjectAttributes.Param[attIntegrity] = modUntrusted;
	}
	if ( Object == NULL )
		ObjectAttributes.Param[attIntegrity] = modTCB;

	if ( NtRuleMap::PolicyOptions & GesRule::ploIsolatedOnlyJailed && ObjectAttributes.Param[GesRule::attIntegrity] != GesRule::modUntrusted ) {
	    return rurAllowAction;
	}
	
	if ( 
	 	 SubjectAttributes.Param[attIntegrity] > ObjectAttributes.Param[attIntegrity] &&
		 ( ( SubjectAttributes.Param[attIntegrity] == modTCB && ObjectAttributes.Param[attIntegrity] != modTrusted ) 
		   ||
		   ( ( ObjectAttributes.Param[attOptions] & oboTracked ) && !( SubjectAttributes.Param[attOptions] & oboTracked ) &&
		     ( PolicyOptions & ploDenyTrackedDlls )
		   )
		 )
	   ) {
        //
        // Block loading
        //
		if ( AccessLog >= aclEnabled ) Log(acsLoad, Subject, SubjectAttributes, RuleId, Object, nttFile, NULL, NULL, 0, rurBlockAction);
		if ( PolicyOptions & ploUnRestrincted ) return rurAllowAction;

        return rurBlockAction;
	}

	if ( ObjectAttributes.Param[attOptions] & oboAppDLL ) {
		return CreateSubject(Subject, SubjectAttributes, Redirect, 0, 
							Subject, SubjectAttributes, Redirect, 
							RuleId, ObjectAttributes, Object, Command);
	}
    
    SubjectAttributes.Param[attIntegrity] = min(SubjectAttributes.Param[attIntegrity], ObjectAttributes.Param[attIntegrity]);

    if ( SubjectAttributes.Param[attIntegrity] == modThreatPoint )
        Redirect = GetAllowedRiderectStatus(rdsAll, SubjectAttributes.Param[attOptions]);

    if ( SubjectAttributes.Param[attIntegrity] == modUntrusted )
        Redirect = GetAllowedRiderectStatus(rdsKey, SubjectAttributes.Param[attOptions]);

    Command = aefSaveSubjectInfo;
    return rurAllowAction;
}

RuleResult NtRuleMap::CreateSubject(PEPROCESS ParentSubject, EntityAttributes &ParentAttributes,
              RedirectStatus ParentRedirect, ULONG ParentRuleId,
              PEPROCESS ChildSubject, EntityAttributes &ChildAttributes, 
			  RedirectStatus &ChildRedirect, ULONG &ChildRuleId,
              EntityAttributes &ObjectAttributes, PFILE_OBJECT FileObject, AefCommand &Command)
{
    Command = aefSaveSubjectInfo;

//	if ( ParentAttributes.Param[attIntegrity] == modUndefined && ParentSubject == SystemProcess )
//		ParentAttributes.Param[attIntegrity] = modTCB;
	if ( ParentAttributes.Param[attIntegrity] == modUndefined ) {
		if ( ParentSubject == SystemProcess || PolicyOptions & ploTrustByDefault )
			ParentAttributes.Param[attIntegrity] = modTCB;
		else
			ParentAttributes.Param[attIntegrity] = modUntrusted;
	}
	if ( ObjectAttributes.Param[attIntegrity] == modUndefined ) {
		if ( PolicyOptions & ploTrustByDefault )
			ObjectAttributes.Param[attIntegrity] = modTCB;
		else
			ObjectAttributes.Param[attIntegrity] = modUntrusted;
	}

	ChildAttributes.Param[attOptions] = 0;
	ULONG RuleId = 0;
	if ( ParentAttributes.Param[attIntegrity] > modThreatPoint || ParentRuleId != 0 ) {
		AciDyn::LoadSubjectRules(ChildSubject, &ObjectAttributes, &RuleId);
	}

    ChildAttributes.Param[attIntegrity] = min(ParentAttributes.Param[attIntegrity], ObjectAttributes.Param[attIntegrity]);
	if ( ChildAttributes.Param[attIntegrity] == modUndefined )
		ChildAttributes.Param[attIntegrity] = modUntrusted;

	if ( ObjectAttributes.Param[attSubjectId] != 0 ) {
		ChildAttributes.Param[attSubjectId] = ObjectAttributes.Param[attSubjectId];
	}
    if ( RuleId != 0 || ParentAttributes.Param[attIntegrity] > modThreatPoint ) {
		ChildRuleId = RuleId;
	} else {
		//
		// Load rules by parent ruleid, otherwise rules with given ruleid unloaded
		// when child apps terminates, as reference count reach zero. That leads to
		// loosing rules for parent app. Zero ruleid is not acceptable 
		// because then no way to set rules for child apps
		//
		AciDyn::LoadSubjectRules(ChildRuleId);
	}

	ChildAttributes.Param[attOptions] |= ObjectAttributes.Param[attOptions];

	if ( NtRuleMap::PolicyOptions & GesRule::ploIsolatedOnlyJailed && ChildAttributes.Param[GesRule::attIntegrity] != GesRule::modUntrusted ) {
		ChildAttributes.Param[attIntegrity] = modTCB;
	}
	else
	if ( ParentAttributes.Param[attIntegrity] >= modTCB && ParentAttributes.Param[attOptions] & oboKeepTrusted && ParentAttributes.Param[attOptions] & oboPropogateTrusted &&
 		 ParentAttributes.Param[attSubjectId] == ChildAttributes.Param[attSubjectId] ) {
		//
		// and propogate oboAutoIsolate then
		//
		ChildAttributes.Param[attOptions] |= oboKeepTrusted | oboPropogateTrusted;
		ChildAttributes.Param[attOptions] &= ~oboAutoIsolate;
	}
	else
	if ( ChildAttributes.Param[attOptions] & oboAutoIsolate )
		ChildAttributes.Param[attIntegrity] = modThreatPoint;
	else 
	if ( ChildAttributes.Param[attOptions] & oboTracked && ChildAttributes.Param[attIntegrity] == modThreatPoint &&
		 ParentAttributes.Param[attIntegrity] > modThreatPoint && IsInteractiveContext() ) {
		//
		// !( PolicyOptions & ploNoPopups ) is checked in gswserv
		//
		NotIsolateTrackedReq *Req = new(PagedPool) NotIsolateTrackedReq;
		if ( Req != NULL ) {
			Req->ProcessId = PsGetCurrentProcessId();
			Req->Attr = ChildAttributes;
			Req->RuleId = ChildRuleId;
			Req->ParentProcessId = Hook::GetProcessId(ParentSubject);
			Req->FileName[0] = 0;
			PUNICODE_STRING usFileName;
			GetObjectName(FileObject, &usFileName);
			if ( usFileName != NULL ) {
				ULONG Length = min(usFileName->Length, sizeof Req->FileName -  sizeof WCHAR);
				RtlCopyMemory(Req->FileName, usFileName->Buffer, Length);
				Req->FileName[Length / sizeof WCHAR] = 0;
				delete[] usFileName;
			}
			if ( Request::UserCall(Req, NULL, NULL) ) {
				ChildAttributes.Param[attIntegrity] = modTCB;
				ChildAttributes.Param[attOptions] |= oboKeepTrusted;
			}
			delete Req;
		}
	}
	else 
	if ( ChildAttributes.Param[attOptions] & oboIsolateOnStart && !( ChildAttributes.Param[attOptions] & oboKeepTrusted ) && 
		 ChildAttributes.Param[attIntegrity] == modTCB && IsInteractiveContext() ) {
		//
		// Isolate on start
		//
		if ( ParentAttributes.Param[attOptions] & oboKeepTrusted && ParentAttributes.Param[attSubjectId] == ChildAttributes.Param[attSubjectId] ) {
			//
			// Parent with the same AppId has oboKeepTrusted, so just propogate it to avoid dup dialogs
			//
			ChildAttributes.Param[attOptions] |= oboKeepTrusted;
		} else {
			//
			// User isolation request
			//
			ThreatPointSubjectReq *Req = new(PagedPool) ThreatPointSubjectReq;
			if ( Req != NULL ) {
				Req->ProcessId = Hook::GetProcessId(ChildSubject);
				Req->Attr = ChildAttributes;
				Req->RuleId = ChildRuleId;
				Req->FileName[0] = 0;
				PUNICODE_STRING usFileName;
				GetObjectName(FileObject, &usFileName);
				if ( usFileName != NULL ) {
					ULONG Length = min(usFileName->Length, sizeof Req->FileName -  sizeof WCHAR);
					RtlCopyMemory(Req->FileName, usFileName->Buffer, Length);
					Req->FileName[Length / sizeof WCHAR] = 0;
					delete[] usFileName;
				}
				Req->ResourceType = nttNetwork;
				Req->ResourceName[0] = 0;
				ULONG RequestResult = Request::UserCall(Req, NULL, NULL);
				if ( RequestResult == tpsKeepTrusted || RequestResult == tpsOnceTrusted ) {
					if ( RequestResult == tpsKeepTrusted )
						ChildAttributes.Param[attOptions] |= oboKeepTrusted;
				} else {
					ChildAttributes.Param[attIntegrity] = modThreatPoint;
					ChildAttributes.Param[attConfident] = cflClassified;
				}
				delete Req;
			}
		}
	}

	if ( ChildAttributes.Param[attIntegrity] < modTCB ) {
		//
		// Log isolation on start
		//
		Log(acsIsolateOnStart, ChildSubject, ChildAttributes, ChildRuleId, ParentSubject, nttProcess, NULL, NULL, 0, rurAllowAction);
	}
	if ( ! ( ChildAttributes.Param[attOptions] & oboOverridePolicy ) ) {
		//
		// no override enabled, set global policy settings over application specific one's
		//
		ChildAttributes.Param[attOptions] = ( ChildAttributes.Param[attOptions] & (~PolicyOverrideMask) ) |
											( PolicyOptions & PolicyOverrideMask );
	}

    if ( ChildAttributes.Param[attIntegrity] == modThreatPoint )
        ChildRedirect = GetAllowedRiderectStatus(rdsAll, ChildAttributes.Param[attOptions]);

    if ( ChildAttributes.Param[attIntegrity] == modUntrusted )
		ChildRedirect = GetAllowedRiderectStatus(rdsKey, ChildAttributes.Param[attOptions]);

	return rurAllowAction;
}

RedirectStatus NtRuleMap::DeleteSubject(PEPROCESS Subject, EntityAttributes &Attributes, 
                             RedirectStatus Redirect, ULONG RuleId, AefCommand &Command)
{
    Command = aefNone;

	AciDyn::UnloadSubjectRules(RuleId);

	ULONG Status = 0;
	if ( Attributes.Param[attOptions] & oboCleanupRedirect ) {
		if ( Redirect & rdsFile ) Status |= rdsFile;
		if ( Redirect & rdsKey ) Status |= rdsKey;
	}
	return (RedirectStatus) Status;
}


ObjectType NtRuleMap::MapObjectType(NtObjectType Type)
{
    ObjectType ObType = obtUnknown;

    switch ( Type ) {
    
        case nttFile:
        case nttKey:
            ObType = obtStorage;
            break;

        case nttProcess:
        case nttThread:
            ObType = obtProcess;
            break;

        case nttDevice:
        case nttPort:
        case nttWaitablePort:
		case nttNetwork:
            ObType = obtIO;
            break;

        case nttDirectory:
        case nttDebug:
        case nttDesktop:
        case nttEvent:
        case nttIoCompletion:
        case nttJob:
        case nttKeyedEvent:
        case nttMutant:
        case nttProfile:
        case nttSection:
        case nttSemaphore:
        case nttSymbolicLink:
        case nttToken:
        case nttTimer:
        case nttWindowStation:
            ObType = obtState;
            break;
    }

    return ObType;
}

ActionType NtRuleMap::MapActionType(ACCESS_MASK Access, NtObjectType NtType)
{
    ActionType Action = actRead;

    if ( Access & GetModifyAccess(NtType) || Access == 0 )
        Action = actModify;

    return Action;

}

NTSTATUS NtRuleMap::Init(VOID)
{
    SystemProcess = PsGetCurrentProcess();

    NTSTATUS rc = Syn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

	InitializeListHead(&LogHistoryList);
    rc = LogSyn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }
	//
	// Get current AutoId
	//
    ULONG AutoId;
    ULONG Size = sizeof AutoId;
    PVOID Buf = &AutoId;
    rc = RegReadValue(&usRegParamName, L"CurrentAutoId", (PVOID *) &Buf, &Size, NULL);
    if ( NT_SUCCESS(rc) ) CurrentAutoId = AutoId;
	rc = STATUS_SUCCESS;

	usParamsKey.Length = 0;
	usParamsKey.MaximumLength = usRegParamName.Length + 100 * sizeof WCHAR;
	usParamsKey.Buffer = new WCHAR[usParamsKey.MaximumLength / sizeof WCHAR];
	if ( usParamsKey.Buffer == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}
	RtlAppendUnicodeStringToString(&usParamsKey, &usRegParamName);
	RtlAppendUnicodeToString(&usParamsKey, L"\\GSWL");
    
	ULONG Disposition;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &usParamsKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	rc = ZwCreateKey(&hParamsKey, KEY_QUERY_VALUE | KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	GetSettings();

	if ( AccessLogDir != DefaultAccessLogDir && AccessLogDir != NULL ) delete[] AccessLogDir;
    Size = 0;
    ULONG Type = REG_SZ;
    rc = RegReadValue(&usParamsKey, L"AccessLogDir", (PVOID *) &AccessLogDir, &Size, &Type);
    if ( !NT_SUCCESS(rc) ) AccessLogDir = DefaultAccessLogDir;

	rc = AciDyn::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

    return rc;
}

namespace NtRuleMap {

NTSTATUS SaveAutoId(SysProcessInfo *Info)
{
	NTSTATUS rc = RegSaveValue(&usRegParamName, L"CurrentAutoId", &CurrentAutoId, 
								sizeof CurrentAutoId, REG_DWORD);
	if ( !NT_SUCCESS(rc) )
		ERR(rc);

	delete Info;
	return rc;
}

}; // namespace NtRuleMap {

ULONG NtRuleMap::GetAutoId(VOID)
{
	ULONG AutoId;

	Syn.Exclusive();

	AutoId = CurrentAutoId++;
	//
	// Save current AutoId
	//
	SysProcessInfo *Info = new(NonPagedPool) SysProcessInfo;
	if ( Info != NULL ) {
		SysProcess::Post(Info, (_SysProc) SaveAutoId);
	}

	Syn.Release();

	return AutoId;
}

ULONG NtRuleMap::GetObjectOptions(ULONG SubjectId)
{	
	ULONG Options = oboNone;

	WCHAR wcValueName[sizeof SubjectId * 2 + 1];
	BinToHex((PUCHAR)&SubjectId, sizeof SubjectId, wcValueName, sizeof wcValueName / sizeof wcValueName[0]);

    UNICODE_STRING usValueName;
    RtlInitUnicodeString(&usValueName, wcValueName);
    static const ULONG Size = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof ULONG;
	UCHAR Buf[Size];
	PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) Buf;

	ULONG Returned;
    NTSTATUS rc = ZwQueryValueKey(hParamsKey, &usValueName, KeyValuePartialInformation, PartialInfo, Size, &Returned);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return Options;
    }

    if ( PartialInfo->Type != REG_DWORD || PartialInfo->DataLength < sizeof ULONG ) {
        rc = STATUS_UNSUCCESSFUL;
        ERR(rc);
        return Options;
    }

    Options = *(ULONG *)PartialInfo->Data;
	return Options;
}

NTSTATUS NtRuleMap::SetObjectOptions(ULONG SubjectId, ULONG Options)
{
	Options |= GetObjectOptions(SubjectId);

	WCHAR wcValueName[sizeof SubjectId * 2 + 1];
	BinToHex((PUCHAR)&SubjectId, sizeof SubjectId, wcValueName, sizeof wcValueName / sizeof wcValueName[0]);

    UNICODE_STRING usValueName;
    RtlInitUnicodeString(&usValueName, wcValueName);
	NTSTATUS rc = ZwSetValueKey(hParamsKey, &usValueName, 0, REG_DWORD, &Options, sizeof Options);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	return rc;
}

NTSTATUS NtRuleMap::GetSettings(VOID)
{
	NTSTATUS rc;

    ULONG Size = sizeof PolicyOptions;
    PVOID Buf = &PolicyOptions;
    rc = RegReadValue(&usParamsKey, L"PolicyOptions", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) PolicyOptions = oboDisableKeyCreate;

    Size = sizeof TypesMask;
    Buf = &TypesMask;
    rc = RegReadValue(&usParamsKey, L"TypesMask", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) TypesMask = 0;

    Size = sizeof JailTypesMask;
    Buf = &JailTypesMask;
    rc = RegReadValue(&usParamsKey, L"JailTypesMask", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) JailTypesMask = 0;

    Size = sizeof MessagesMask;
    Buf = &MessagesMask;
    rc = RegReadValue(&usParamsKey, L"MessagesMask", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) MessagesMask = 0xfffffc00;

	GesRule::SecurityLevel Level;
    Size = sizeof Level;
    Buf = &Level;
    rc = RegReadValue(&usParamsKey, L"SecurityLevel", (PVOID *) &Buf, &Size, NULL);
	if ( !NT_SUCCESS(rc) ) Level = GesRule::secUndefined;
	PolicyOptions |= TranslateSecurityLevel(Level);

    Size = sizeof AccessLog;
    Buf = &AccessLog;
    rc = RegReadValue(&usParamsKey, L"AccessLog", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) AccessLog = aclDisabled;

    Size = sizeof Notification;
    Buf = &Notification;
    rc = RegReadValue(&usParamsKey, L"Notification", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) Notification = ntlDisabled;

	Size = sizeof LogRepeatInterval;
    Buf = &LogRepeatInterval;
    rc = RegReadValue(&usParamsKey, L"LogRepeatInterval", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) LogRepeatInterval = 5 * LONGLONG(1000) * LONGLONG(10000);

	Size = sizeof RedirectFilter;
    Buf = &RedirectFilter;
    rc = RegReadValue(&usParamsKey, L"RedirectFilter", (PVOID *) &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) RedirectFilter = 0;

	return STATUS_SUCCESS;
}

struct LogRecordInfo {
	Rule::ObjectAccessType AccessType;
	NtObjectType NtType;
	ULONG_PTR ObjectContext;
	Rule::RuleResult Result;
	LARGE_INTEGER SysTime;
	_EPROCESS *Subject;
	CHAR ProcName[NT_PROCNAMELEN];
	PUNICODE_STRING ObjectName;
	LIST_ENTRY Entry;
};

NTSTATUS NtRuleMap::Log(Rule::ObjectAccessType AccessType, _EPROCESS *Subject, EntityAttributes &SubjectAttributes, ULONG RuleId,
						PVOID Object, NtObjectType NtType, PVOID RelatedObject, PUNICODE_STRING _ObjectName, ULONG_PTR ObjectContext, Rule::RuleResult Result)
{
	if ( AccessLog < aclEnabled || 
		( AccessType == acsMessage && ( ObjectContext == 1 || ObjectContext == 4 ) ) ||
		( ( ( NtType == nttProcess && ObjectContext == PROCESS_DUP_HANDLE ) ||
			( NtType == nttDevice && ExGetPreviousMode() == KernelMode && ( ( ObjectContext & ~( FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE ) ) == 0 ) )
		  )
		  && AccessLog == aclReduced 
		)
		) return STATUS_SUCCESS;
	//
	// Get time
	//
	LARGE_INTEGER SysTime, Time;
	KeQuerySystemTime(&SysTime);
	ExSystemTimeToLocalTime(&SysTime, &Time);
	TIME_FIELDS TimeFields;
	RtlTimeToTimeFields(&Time, &TimeFields);
	//
	// Get subject name
	//
    CHAR ProcName[NT_PROCNAMELEN];
    GetProcessNameByPointer(Subject, ProcName);
	//
	// Get object name
	//
	NTSTATUS rc;
	PUNICODE_STRING ObjectName = NULL;
	if ( _ObjectName != NULL ) ObjectName = CopyUnicodeString(_ObjectName);
	if ( ObjectName == NULL ) {
		switch ( NtType ) {
			case nttFile:
				POBJECT_NAME_INFORMATION NameInfo;
				rc = AdApi::IoQueryFileDosDeviceName((PFILE_OBJECT)Object, &NameInfo);
				if ( NT_SUCCESS(rc) ) ObjectName = (PUNICODE_STRING)NameInfo;
				break;

			case nttThread:
				Object = IoThreadToProcess((PETHREAD)Object);
			case nttProcess:
				ObjectName = (PUNICODE_STRING) new(PagedPool) CHAR[sizeof UNICODE_STRING + NT_PROCNAMELEN * sizeof WCHAR];
				if ( ObjectName != NULL ) {
					WCHAR *Buffer = (WCHAR *) ( (PUCHAR)ObjectName + sizeof UNICODE_STRING );
					GetProcessNameByPointer((PEPROCESS)Object, Buffer);
					RtlInitUnicodeString(ObjectName, Buffer);
				}
				break;

			case nttKey:
				if ( RelatedObject != NULL )
					GetRegistryObjectName(Object, (PUNICODE_STRING)RelatedObject, &ObjectName);
				else
					GetObjectName(Object, &ObjectName);
				if ( ObjectName != NULL ) {
					//
					// replace \Registry\xxx by user mode equivalents
					//
					TranslateToUserRegistryName(ObjectName);
				}
				break;

			case nttNetwork:
				NetFilter::GetObjectName(Object, RelatedObject, &ObjectName);
				break;

			case nttSystemObject:
				// RelatedObject is pointer to unicode string, copy this string
				ObjectName = CopyUnicodeString((PUNICODE_STRING)RelatedObject);
				break;

			case nttDevice:
				if ( ((PFILE_OBJECT)Object)->DeviceObject != NULL )
					GetObjectName(((PFILE_OBJECT)Object)->DeviceObject, &ObjectName);
				else
					GetObjectName(Object, &ObjectName);

			default:
				GetObjectName(Object, &ObjectName);
				break;
		}
	}
	//
	// Check if such record is repeatative
	//
	bool Repeatative = false;
	LogSyn.Exclusive();
	PLIST_ENTRY Entry = LogHistoryList.Flink;
	while ( Entry != &LogHistoryList ) {

		LogRecordInfo *Info = CONTAINING_RECORD(Entry, LogRecordInfo, Entry);
		if ( SysTime.QuadPart - Info->SysTime.QuadPart <= LogRepeatInterval ) {
			if ( 
				 (
					!Repeatative && !strcmp(Info->ProcName, ProcName) &&
					Info->AccessType == AccessType && Info->Result == Result &&
					(
						(
							Info->ObjectContext == ObjectContext &&
							Info->NtType == NtType &&
							( Info->ObjectName == ObjectName ||
								( Info->ObjectName != NULL && ObjectName != NULL && 
									RtlCompareUnicodeString(Info->ObjectName, ObjectName, TRUE) == 0
								) 
							)
						) ||
						( AccessType == acsSwitchSubject && Info->Subject == Subject )
					)
				 )
			   ) {
				//
				// the same log record in repeatative interval found
				//
				Repeatative = true;
			}
			Entry = Entry->Flink;
		} else {
			//
			// record exceeded repeatative interval - remove it
			//
			RemoveEntryList(Entry);
			if ( Info->ObjectName != NULL ) delete Info->ObjectName;
			delete Info;
			Entry = LogHistoryList.Flink;
		}
	}
	LogSyn.Release();
	//
	// Do not log repeatative messages
	//
	if ( Repeatative == true ) {
		if ( ObjectName != NULL ) delete ObjectName;
		return STATUS_SUCCESS;
	}

	if ( AccessType == acsMessage ) {
		rc = Log::AccessRecord(Subject, &SubjectAttributes, RuleId, L"%4d.%02d.%02d %02d:%02d:%02d %S DENY %X message to %wZ (%s)\r\n", 
						TimeFields.Year,  TimeFields.Month, TimeFields.Day,
						TimeFields.Hour, TimeFields.Minute, TimeFields.Second, 
						ProcName, ObjectContext, ObjectName, GetNtTypeString(NtType));
	} else
	if ( AccessType == acsLoad ) {
		rc = Log::AccessRecord(Subject, &SubjectAttributes, RuleId, L"%4d.%02d.%02d %02d:%02d:%02d %S DENY load %wZ (%s)\r\n", 
						TimeFields.Year,  TimeFields.Month, TimeFields.Day,
						TimeFields.Hour, TimeFields.Minute, TimeFields.Second, 
						ProcName, ObjectName, GetNtTypeString(NtType));
	} else
	if ( AccessType == acsSwitchSubject ) {
		rc = Log::AccessRecord(Subject, &SubjectAttributes, RuleId, L"%4d.%02d.%02d %02d:%02d:%02d %S ISOLATE on access to %wZ (%s)\r\n", 
						TimeFields.Year,  TimeFields.Month, TimeFields.Day,
						TimeFields.Hour, TimeFields.Minute, TimeFields.Second, 
						ProcName, ObjectName, GetNtTypeString(NtType));
	} else
	if ( AccessType == acsIsolateOnStart ) {
		rc = Log::AccessRecord(Subject, &SubjectAttributes, RuleId, L"%4d.%02d.%02d %02d:%02d:%02d %S ISOLATE on start from %wZ\r\n", 
						TimeFields.Year,  TimeFields.Month, TimeFields.Day,
						TimeFields.Hour, TimeFields.Minute, TimeFields.Second, 
						ProcName, ObjectName);
	} else {
		rc = Log::AccessRecord(Subject, &SubjectAttributes, RuleId, L"%4d.%02d.%02d %02d:%02d:%02d %S %s access to %wZ (%s)\r\n", 
						TimeFields.Year,  TimeFields.Month, TimeFields.Day,
						TimeFields.Hour, TimeFields.Minute, TimeFields.Second, 
						ProcName, GetResultString(Result), ObjectName, GetNtTypeString(NtType));
	}

	//
	// insert in to history list
	//
	LogRecordInfo *Info = new(PagedPool) LogRecordInfo;
	if ( Info == NULL ) {
		ERR(STATUS_INSUFFICIENT_RESOURCES);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	Info->SysTime = SysTime;
	Info->AccessType = AccessType;
	Info->NtType = NtType;
	Info->ObjectContext = ObjectContext;
	Info->Result = Result;
	Info->Subject = Subject;
	strncpy(Info->ProcName, ProcName, sizeof Info->ProcName / sizeof Info->ProcName[0] - 1);
	Info->ObjectName = ObjectName;
	LogSyn.Exclusive();
	InsertTailList(&LogHistoryList, &Info->Entry);
	LogSyn.Release();

	return rc;
}

bool NtRuleMap::IsRedirectAllowed(PFILE_OBJECT FileObject)
{
	if ( RedirectFilter == 0 || FileObject == NULL || FileObject->FileName.Length == 0 || FileObject->FileName.Buffer == NULL ) return true;

	//
	// approach to extension
	//
	WCHAR Ext[10] = { 0 };
	SIZE_T ExtSize = 0;
	WCHAR *Str = FileObject->FileName.Buffer + ( FileObject->FileName.Length / sizeof WCHAR - 1 );
	while ( Str > FileObject->FileName.Buffer && *Str != '.' && ExtSize < ( sizeof Ext / sizeof Ext[0] - 1 ) ) {
		Str--;
		ExtSize++;
	}
	if ( *Str != '.' ) return true;

	Str++;
	SIZE_T i;
	for ( i = 0; i < ( sizeof Ext / sizeof Ext[0] - 1 ) && i < ExtSize; i++ ) Ext[i] = *Str++;
	_wcslwr(Ext);

	static const WCHAR *FileExt[] = {
		L"acm", L"ade", L"adp", L"app", L"asa", L"asp", L"aspx", L"bas", L"bat", L"bin",
		L"cer", L"chm", L"clb", L"cmd", L"cnt", L"cnv", L"com", L"cpl", L"cpx", L"crt",
		L"csh", L"dll", L"drv", L"dtd", L"exe", L"fon", L"fxp", L"grp", L"hlp", L"hls",
		L"hta", L"ime", L"inf", L"ins", L"isp", L"its", L"jse", L"ksh", L"lnk", L"mad",
		L"maf", L"mag", L"mam", L"man", L"maq", L"mar", L"mas", L"mat", L"mau", L"mav",
		L"maw", L"mda", L"mdb", L"mde", L"mdt", L"mdw", L"mdz", L"msc", L"msi", L"msp",
		L"mst", L"mui", L"nls", L"ocx", L"ops", L"pal", L"pcd", L"pif", L"prf", L"prg",
		L"pst", L"reg", L"scf", L"scr", L"sct", L"shb", L"shs", L"sys", L"tlb", L"tsp",
		L"url", L"vbe", L"vbs", L"vsmacros", L"vss", L"vst", L"vsw", L"wsc", L"wsf", L"wsh",
		L"xsd", L"xsl"
	};

	for ( i = 0; i < sizeof FileExt / sizeof FileExt[0]; i++ ) {
		int Res = wcscmp(Ext, FileExt[i]);
		if ( Res == 0 ) return false;
		if ( Res < 0 ) break;
	}

	return true;
}