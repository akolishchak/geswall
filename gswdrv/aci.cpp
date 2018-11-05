//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "aci.h"
#include "lock.h"
#include "tools.h"
#include "fsfilter.h"
#include "acidef.h"
#include "netfilter.h"
#include "gesruledef.h"

using namespace Rule;

namespace Aci {

    struct ObjectRecord {
        CHAR Label[4];
		ULONG RuleId;
        EntityAttributes Attr;
        NtObjectType Type;
        BufferType BufType;
		SIZE_T Size;
        LIST_ENTRY Entry;
    };

    struct NameRecord : ObjectRecord {
		UNICODE_STRING usName;
        WCHAR Name[1];
    };

    struct OwnerSidRecord : ObjectRecord {
        PUCHAR Sid[1];
    };

	struct IP4AddressRecord : ObjectRecord {
		IP4Address Addr;
	};

    struct DeferContext {
        CHAR Label[4];
        PVOID Object;
        PVOID RelatedObject;
        NtObjectType NtType;
        EntityAttributes Attributes;
        WORK_QUEUE_ITEM WorkItem;
        LIST_ENTRY Entry;
    };

    VOID DeferWorkItem(PVOID _Context);

	NTSTATUS AddRulesNoLock(RulePack *Pack, SIZE_T PackLength);
	bool IsValidRulePack(RulePack *Pack, SIZE_T PackLength);

	LIST_ENTRY RecordsList;
    LIST_ENTRY DeferList;
    CEResource Syn;
    CEResource DeferSyn;
	BOOLEAN bInited = FALSE;
};


NTSTATUS Aci::GetObjectInfo(CHAR *Label, PVOID Object, PVOID RelatedObject,
                            NtObjectType NtType, EntityAttributes &Attributes, ULONG RuleId)
{
    RedirectStatus Redirect;
    if ( NtType == nttProcess || NtType == nttThread ) {
        return Hook::GetProcessInfo(Label, (PEPROCESS)Object, Attributes, Redirect, RuleId);
    }

    BOOLEAN bAssigned = FALSE;
	RtlZeroMemory(Attributes.Param, sizeof Attributes.Param);
    if ( Object == NULL ) return STATUS_SUCCESS;
    NTSTATUS rc;

    BOOLEAN bTrack = FALSE;

/*    
    if ( RelatedObject == NULL ) {

        UNICODE_STRING usName;
        PUNICODE_STRING ObjectName = NULL;
		GetObjectName(Object, &ObjectName);
        RtlInitUnicodeString(&usName, L"\\Device\\NetBT");
        if ( ObjectName != NULL && CompareNames(ObjectName, &usName) ) {
            ERR(0);
        }

        if ( ObjectName != NULL ) delete[] ObjectName;
    }

	if ( RelatedObject != NULL ) {

        UNICODE_STRING usName;
        PUNICODE_STRING ObjectName = NULL;
		FsFilter::GetFileName((PFILE_OBJECT)Object, (PDEVICE_OBJECT)RelatedObject, &ObjectName);
        trace(P"%wZ\n", ObjectName);
        RtlInitUnicodeString(&usName, L"\\Device\\HarddiskVolume1\\Documents and Settings\\andr\\My Documents\\");
        if ( ObjectName != NULL && CompareNames(ObjectName, &usName) ) {
            ERR(0);
        }

        if ( ObjectName != NULL ) delete[] ObjectName;
    }
*/
    if ( NtType == nttKey ) {
        //
        // Try to look at defer list first
        //
        DeferSyn.Share();
		PLIST_ENTRY pEntry = DeferList.Flink;
		while (pEntry != &DeferList) {
			DeferContext *Context = CONTAINING_RECORD(pEntry, DeferContext, Entry);
            if ( Context->Object == Object ) {
                Attributes = Context->Attributes;
                DeferSyn.Release();
                if ( bTrack ) {
                    trace(P"TRACKED=============================================================\n");
                    ERR(0);
                }
                return STATUS_SUCCESS;
            }
			pEntry = pEntry->Flink;
		}
        DeferSyn.Release();
    }
    //
    // Get model type
    //
    PSECURITY_DESCRIPTOR sd = NULL;
    BOOLEAN  bMemoryAllocated;
	BOOLEAN bReleaseObjectSecurity = FALSE;
	//
	// Do not query devices for security, leads to problem with buggy drivers
	//
	if ( NtType == nttDevice ) goto cleanup;
	//
	if ( RelatedObject == NULL || NtType != nttFile ) {
		if ( NtType == nttFile ) {
			rc = GetFileSecurity((PFILE_OBJECT)Object, &sd);
		} else {
			rc = ObGetObjectSecurity(Object, &sd, &bMemoryAllocated);
			if ( NT_SUCCESS(rc) ) bReleaseObjectSecurity = TRUE;
		}
	} else {
		rc = FsFilter::GetFileSecurity((PFILE_OBJECT)Object, (PDEVICE_OBJECT)RelatedObject, &sd);
	}
    if ( !NT_SUCCESS(rc) || sd == NULL ) {
        //ERR(rc);
        sd = NULL;
        goto cleanup;
    }
    //
    // Get info from labels
    //
    PACL Acl;
    BOOLEAN SaclPresent;
    BOOLEAN Defaulted;
    rc = RtlGetSaclSecurityDescriptor(sd, &SaclPresent, &Acl, &Defaulted);
    if ( !NT_SUCCESS(rc) || !SaclPresent || Acl == NULL ) {
        //ERR(rc);
        rc = STATUS_SUCCESS;
        goto cleanup;
    }

	SYSTEM_AUDIT_ACE *Ace = (SYSTEM_AUDIT_ACE *) ((PUCHAR) Acl + sizeof(ACL));
	for (ULONG i=0;i < Acl->AceCount; i++) {

        Sid *InfoSid = (Sid *)&Ace->SidStart;
		if ( RtlCompareMemory(InfoSid, &BasicSid, FIELD_OFFSET(Sid, SubAuthority[1])) ==
             FIELD_OFFSET(Sid, SubAuthority[1]) && InfoSid->SubAuthority[1] == *(PULONG)Label ) {

                if ( bTrack ) {
                    trace(P"TRACKED=============================================================\n");
                    ERR(0);
                }

			RtlCopyMemory(Attributes.Param, &InfoSid->SubAuthority[2], sizeof Attributes.Param);
            bAssigned = TRUE;
            break;
		}

		Ace = (SYSTEM_AUDIT_ACE *)((PCHAR)Ace + Ace->Header.AceSize);
    }

cleanup:
    if ( 1 || !bAssigned ) {
        //
        // Check rules descriptions
        //
		// Get object name
		// Get object owner
		//
		PUNICODE_STRING ObjectName = NULL;
		switch ( NtType ) {
			case nttSystemObject:
				{
					ULONG ObjectRuleId;
					Hook::GetProcessInfo(Label, (PEPROCESS)Object, Attributes, Redirect, ObjectRuleId);
					ObjectName = CopyUnicodeString((PUNICODE_STRING)RelatedObject);
				}
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
		PSID Owner = NULL;
        if ( sd != NULL ) {
		    rc = RtlGetOwnerSecurityDescriptor(sd, &Owner, &Defaulted);
		    if ( !NT_SUCCESS(rc) )
			    Owner = NULL;
        }
		//
		// Confidential files identified only by rules, SACL labels are ignored
		//
		Attributes.Param[GesRule::attConfident] = 0;

		Syn.Share();
		PLIST_ENTRY pEntry = RecordsList.Flink;
		while (pEntry != &RecordsList) {

			ObjectRecord *Record = CONTAINING_RECORD(pEntry, ObjectRecord, Entry);
            ULONG *Param = Record->Attr.Param;
			if ( //*(PULONG)Record->Label == *(PULONG)Label && -- remove for performance
				 ( Record->RuleId == 0 || Record->RuleId == RuleId ) &&
                ( Record->Type == nttAny || Record->Type == NtType ) &&
                ( 
                    ( Param[0] != 0 && Attributes.Param[0] == 0 ) ||
                    ( Param[1] != 0 ) ||
                    ( Param[2] != 0 && Attributes.Param[2] == 0 ) ||
					( Param[3] != 0 && Attributes.Param[3] == 0 ) ||
					( Param[4] != 0 && Attributes.Param[4] == 0 ) ||
					( Param[5] != 0 ) 
                ) &&
				( 
				  ( Record->BufType == bufOwnerSid && Owner != NULL &&
						RtlEqualSid(((OwnerSidRecord *)Record)->Sid, Owner) ) ||

				  ( Record->BufType == bufObjectName && ObjectName != NULL &&
                   CompareNames(ObjectName, &((NameRecord *)Record)->usName) ) ||

				  ( Record->BufType == bufIP4Address && ObjectName != NULL &&
				  NetFilter::CompareIP4(RelatedObject, &((IP4AddressRecord *)Record)->Addr) )
				)
			   ) {

                if ( Attributes.Param[0] == 0 ) Attributes.Param[0] = Param[0];
                //if ( Attributes.Param[1] == 0 ) Attributes.Param[1] = Param[1];
				if ( Param[1] != 0 ) Attributes.Param[1] = Param[1];
                if ( Attributes.Param[2] == 0 ) Attributes.Param[2] = Param[2];
                if ( Attributes.Param[3] == 0 ) Attributes.Param[3] = Param[3];
                if ( Attributes.Param[4] == 0 ) Attributes.Param[4] = Param[4];
                //if ( Attributes.Param[5] == 0 ) Attributes.Param[5] = Param[5];
				Attributes.Param[5] |= Param[5];
			}
			pEntry = pEntry->Flink;
		}
		Syn.Release();

        if ( ObjectName != NULL ) delete[] ObjectName;
    }

    if ( sd != NULL ) {
        if ( bReleaseObjectSecurity )
            ObReleaseObjectSecurity(sd, bMemoryAllocated);
        else
            delete[] sd;
    }
    return rc;
}


NTSTATUS Aci::SetObjectInfo(CHAR *Label, PVOID Object, PVOID RelatedObject,
                            NtObjectType NtType, EntityAttributes &Attributes, BOOLEAN WorkerItem)
{
	if ( Object == NULL ) return STATUS_UNSUCCESSFUL;
    NTSTATUS rc = STATUS_SUCCESS;

    if ( NtType == nttProcess || NtType == nttThread ) {
        return Hook::SetProcessInfo(Label, (PEPROCESS)Object, Attributes, rdsUndefined, 0, asfNone);
    }

    PSECURITY_DESCRIPTOR sd = NULL;
    BOOLEAN  bMemoryAllocated;
    BOOLEAN bAllocateAcl = FALSE;
    PACL NewAcl = NULL;

    if ( NtType == nttKey && !WorkerItem ) {
        //
        // Create worker item, to avoid CmpRegistryLock deadlock
        // 
        DeferContext *Context = new(NonPagedPool) DeferContext;
        if ( Context == NULL ) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
            ERR(rc);
            return rc;
        }

        *(PULONG) Context->Label = *(PULONG)Label;
        ObReferenceObject(Object);
        Context->Object = Object;
        Context->RelatedObject = RelatedObject;
        Context->Attributes = Attributes;
        Context->NtType = NtType;
        ExInitializeWorkItem(&Context->WorkItem, DeferWorkItem, Context);

        DeferSyn.Exclusive();
        InsertTailList(&DeferList, &Context->Entry);
        DeferSyn.Release();

        ExQueueWorkItem(&Context->WorkItem, CriticalWorkQueue);
        return rc;
    }

    if ( RelatedObject == NULL || NtType != nttFile )
        rc = ObGetObjectSecurity(Object, &sd, &bMemoryAllocated);
    else
        rc = FsFilter::GetFileSecurity((PFILE_OBJECT)Object, (PDEVICE_OBJECT)RelatedObject, &sd);
    if ( !NT_SUCCESS(rc) || sd == NULL ) {
        ERR(rc);
        sd = NULL;
        goto cleanup;
    }
    //
    // Get info from labels
    //
    PACL Acl;
    BOOLEAN SaclPresent;
    BOOLEAN Defaulted;
    USHORT Size;
    rc = RtlGetSaclSecurityDescriptor(sd, &SaclPresent, &Acl, &Defaulted);
    if ( !NT_SUCCESS(rc) || !SaclPresent || Acl == NULL ) {
        //
        // There are no Sacl, create it
        //
        Size = sizeof ACL;
        Acl = (PACL) new (PagedPool) UCHAR[Size];
        if ( Acl == NULL ) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
            ERR(rc);
            goto cleanup;
        }
        bAllocateAcl = TRUE;

        rc = RtlCreateAcl(Acl, Size, ACL_REVISION);
        if (!NT_SUCCESS(rc)) {
           ERR(rc);
           goto cleanup;
        }
    }

    //
    // Check if our sid already exist
    //
    BOOLEAN bSidPresent = FALSE;
	SYSTEM_AUDIT_ACE *Ace = (SYSTEM_AUDIT_ACE *) ((PUCHAR) Acl + sizeof(ACL));
	for (ULONG i=0;i < Acl->AceCount; i++) {

        Sid *InfoSid = (Sid *)&Ace->SidStart;
		if ( RtlCompareMemory(InfoSid, &BasicSid, FIELD_OFFSET(Sid, SubAuthority[1])) ==
             FIELD_OFFSET(Sid, SubAuthority[1]) && InfoSid->SubAuthority[1] == *(PULONG)Label ) {

            bSidPresent = TRUE;
            break;
		}
		Ace = (SYSTEM_AUDIT_ACE *)((PCHAR)Ace + Ace->Header.AceSize);
    }

    if ( bSidPresent )
        Size = Acl->AclSize;
    else {
        //
        // Check for too big SACL (used in ms io stress)
        //
        if ( (LONG)Acl->AclSize + sizeof SYSTEM_AUDIT_ACE - sizeof ULONG + sizeof BasicSid > 0xffff ) {
            rc = STATUS_UNSUCCESSFUL;
            ERR(rc);
            goto cleanup;
        }

        Size = Acl->AclSize + sizeof SYSTEM_AUDIT_ACE - sizeof ULONG + sizeof BasicSid;
    }

    NewAcl = (PACL) new (PagedPool) CHAR[Size];
    if ( NewAcl == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        goto cleanup;
    }

    RtlCopyMemory(NewAcl, Acl, Acl->AclSize);
    Ace = (SYSTEM_AUDIT_ACE *) ((PUCHAR)NewAcl + ( (PUCHAR)Ace - (PUCHAR)Acl ) ); 

    if ( !bSidPresent ) {
        //
        // We have to add our sid
        //
        Ace->Header.AceType = SYSTEM_AUDIT_ACE_TYPE;
        Ace->Header.AceFlags = FAILED_ACCESS_ACE_FLAG;
        Ace->Header.AceSize = sizeof SYSTEM_AUDIT_ACE - sizeof ULONG + sizeof BasicSid;
        Ace->Mask = GENERIC_ALL;
        RtlCopyMemory(&Ace->SidStart, &BasicSid, sizeof BasicSid);
        ((Sid *)&Ace->SidStart)->SubAuthority[1] = *(PULONG)Label;
        NewAcl->AclSize = Size;
        NewAcl->AceCount++;
    }

	RtlCopyMemory(&((Sid *)&Ace->SidStart)->SubAuthority[2], Attributes.Param, sizeof Attributes.Param);

	if ( RelatedObject == NULL || NtType != nttFile )
		ObReleaseObjectSecurity(sd, bMemoryAllocated);
	else
		delete[] sd;
    sd = NULL;

    SECURITY_DESCRIPTOR NewSd;
    rc = RtlCreateSecurityDescriptor(&NewSd, SECURITY_DESCRIPTOR_REVISION);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        goto cleanup;
    }

    rc = RtlSetSaclSecurityDescriptor(&NewSd, TRUE, NewAcl, FALSE);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        goto cleanup;
    }

	if ( RelatedObject == NULL || NtType != nttFile )
		rc = AdApi::ObSetSecurityObjectByPointer(Object, SACL_SECURITY_INFORMATION, &NewSd);
    else
		rc = FsFilter::SetSecurityFile((PFILE_OBJECT)Object, (PDEVICE_OBJECT)RelatedObject, SACL_SECURITY_INFORMATION, &NewSd);
    if ( !NT_SUCCESS(rc) ) {
		//
		// it may fail without ACCESS_SYSTEM_SECURITY privilige, if so we will try to repeat the same
		// in system context
		//
        ERR(rc);
        goto cleanup;
    }

cleanup:
    if ( sd != NULL ) {
        if ( RelatedObject == NULL || NtType != nttFile )
            ObReleaseObjectSecurity(sd, bMemoryAllocated);
        else
            delete[] sd;
    }
    if ( bAllocateAcl ) delete[] Acl;
    if ( NewAcl != NULL ) delete[] NewAcl;

    return rc;
}

VOID Aci::DeferWorkItem(PVOID _Context)
{
    DeferContext *Context = (DeferContext *) _Context;
    SetObjectInfo(Context->Label, Context->Object, Context->RelatedObject, Context->NtType, 
                  Context->Attributes, TRUE);
    
    DeferSyn.Exclusive();
    RemoveEntryList(&Context->Entry);
    DeferSyn.Release();

    ObDereferenceObject(Context->Object);
    delete Context;
}

NTSTATUS Aci::SetObjectInfo(CHAR *Label, HANDLE hObject, NtObjectType NtType, EntityAttributes &Attributes)
{
	PVOID Object;
    NTSTATUS rc = ObReferenceObjectByHandle(hObject, FILE_GENERIC_READ | FILE_GENERIC_WRITE, *IoFileObjectType,
											UserMode, (PVOID *) &Object, NULL);
    if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
        return rc;
    }

	rc = SetObjectInfo(Label, Object, NULL, NtType, Attributes);
	ObDereferenceObject(Object);
    if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
        return rc;
    }

	return rc;
}


NTSTATUS Aci::GetSubjectInfo(CHAR *Label, PVOID Object, EntityAttributes &Attributes, 
                             Rule::RedirectStatus &Redirect, ULONG &RuleId)
{
    return Hook::GetProcessInfo(Label, (PEPROCESS)Object, Attributes, Redirect, RuleId);
}

NTSTATUS Aci::SetSubjectInfo(CHAR *Label, PVOID Object, EntityAttributes &Attributes,
                             Rule::RedirectStatus Redirect, ULONG RuleId)
{
    return Hook::SetProcessInfo(Label, (PEPROCESS)Object, Attributes, Redirect, RuleId, asfNone);
}

NTSTATUS Aci::OrSubjectInfo(CHAR *Label, PVOID Object, EntityAttributes &Attributes,
                             Rule::RedirectStatus Redirect, ULONG RuleId)
{
    return Hook::SetProcessInfo(Label, (PEPROCESS)Object, Attributes, Redirect, RuleId, asfOr);
}

NTSTATUS Aci::SetSubjectInfoPermanent(CHAR *Label, PVOID Object, EntityAttributes &Attributes)
{
	NTSTATUS rc = STATUS_UNSUCCESSFUL;
	PFILE_OBJECT FileObject = Hook::GetProcessFileObject((PEPROCESS)Object);
	if ( FileObject != NULL ) {
		rc = SetObjectInfo(Label, FileObject, NULL, nttFile, Attributes);
		ObDereferenceObject(FileObject);
	}

	return rc;
}

NTSTATUS Aci::Init(VOID)
{
    NTSTATUS rc;

    InitializeListHead(&RecordsList);
    InitializeListHead(&DeferList);
    rc = Syn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    rc = DeferSyn.Init();
    if ( !NT_SUCCESS(rc) ) {
        Syn.Destroy();
        ERR(rc);
        return rc;
    }

    rc = Refresh();
    if ( !NT_SUCCESS(rc) ) {
        Syn.Destroy();
        DeferSyn.Destroy();
        ERR(rc);
        return rc;
    }

	bInited = TRUE;
    return rc;
}

VOID Aci::Release(VOID)
{
    if ( !bInited ) return;

    Syn.Exclusive();
	while ( !IsListEmpty(&RecordsList) ) {

        PLIST_ENTRY pEntry = RemoveTailList(&RecordsList);
		ObjectRecord *Record = CONTAINING_RECORD(pEntry, ObjectRecord, Entry);
        delete Record;
	}
    Syn.Release();
    Syn.Destroy();

    DeferSyn.Exclusive();
	while ( !IsListEmpty(&DeferList) ) {

        PLIST_ENTRY pEntry = RemoveTailList(&DeferList);
		DeferContext *Context = CONTAINING_RECORD(pEntry, DeferContext, Entry);
        ObDereferenceObject(Context->Object);
        delete Context;
	}
    DeferSyn.Release();
    DeferSyn.Destroy();
}

NTSTATUS Aci::AddRuleRecord(RuleRecord *Record)
{
    NTSTATUS rc = STATUS_SUCCESS;

    ObjectRecord *ObjectRec;
    ULONG Size;
    
    switch ( Record->BufType ) {
        case bufObjectName:
            {
                Size = FIELD_OFFSET(NameRecord, Name) + Record->BufSize;
                NameRecord *NameRec = (NameRecord *) new UCHAR[Size];
                if ( NameRec == NULL ) {
                    rc = STATUS_INSUFFICIENT_RESOURCES;
                    ERR(rc);
                    return rc;
                }
                RtlCopyMemory(NameRec->Name, Record->Buf, Record->BufSize);
				RtlInitUnicodeString(&NameRec->usName, NameRec->Name);

                ObjectRec = NameRec;
            }
            break;

        case bufOwnerSid:
            {
                Size = FIELD_OFFSET(OwnerSidRecord, Sid) + Record->BufSize;
                OwnerSidRecord *OwnerSidRec = (OwnerSidRecord *) new UCHAR[Size];
                if ( OwnerSidRec == NULL ) {
                    rc = STATUS_INSUFFICIENT_RESOURCES;
                    ERR(rc);
                    return rc;
                }
                RtlCopyMemory(OwnerSidRec->Sid, Record->Buf, Record->BufSize);

                ObjectRec = OwnerSidRec;
            }
            break;

		case bufIP4Address:
			{
				if ( Record->BufSize < sizeof IP4Address ) {
                    rc = STATUS_INVALID_PARAMETER;
                    ERR(rc);
                    return rc;
				}

				Size = sizeof IP4AddressRecord;
				IP4AddressRecord *IP4AddressRec = (IP4AddressRecord *) new UCHAR[Size];
                if ( IP4AddressRec == NULL ) {
                    rc = STATUS_INSUFFICIENT_RESOURCES;
                    ERR(rc);
                    return rc;
                }
                RtlCopyMemory(&IP4AddressRec->Addr, Record->Buf, Record->BufSize);

                ObjectRec = IP4AddressRec;
			}
			break;

        default:
            return STATUS_UNSUCCESSFUL;
    }

    *(PULONG)ObjectRec->Label = *(PULONG)Record->Label;
	ObjectRec->RuleId = Record->RuleId;
    ObjectRec->Attr = Record->Attr;
    ObjectRec->Type = Record->Type;
	ObjectRec->Size = Size;
    ObjectRec->BufType = Record->BufType;

    Syn.Exclusive();
	//
	// andr: Check if such rule already exist (?)
	//
	// resources inserted with low priority
	if ( ObjectRec->RuleId == 0 ) {
		InsertTailList(&RecordsList, &ObjectRec->Entry);
	} else {
		InsertHeadList(&RecordsList, &ObjectRec->Entry);
	}

    Syn.Release();

    return rc;
}

NTSTATUS Aci::AddRulesNoLock(RulePack *Pack, SIZE_T PackLength)
{
	NTSTATUS rc = STATUS_SUCCESS;
    //
    // Check validity of rules
    //
	if ( IsValidRulePack(Pack, PackLength) == false ) {
        rc = STATUS_UNSUCCESSFUL;
        ERR(rc);
        return rc;
	}
    //
    // Rules are valid, apply them now
    //
    RuleRecord *Record = Pack->Record;
    for ( ULONG i = 0; i < Pack->RulesNumber; i++ ) {

        rc = AddRuleRecord(Record);
        if ( !NT_SUCCESS(rc) ) {
            ERR(rc);
            return rc;
        }

        Record = (RuleRecord *)((PUCHAR)Record + FIELD_OFFSET(RuleRecord, Buf) + Record->BufSize);
    }

	return rc;
}

NTSTATUS Aci::Refresh(VOID)
{
    NTSTATUS rc = STATUS_SUCCESS;

    //
    // Get Sid revision
    //
    ULONG SidRevision;
    ULONG Size = sizeof SidRevision;
    PVOID Buf = &SidRevision;
    rc = RegReadValue(&usRegParamName, L"SidRevision", (PVOID *) &Buf, &Size, NULL);
    if ( NT_SUCCESS(rc) ) {
        InterlockedExchange((PLONG)&BasicSid.SubAuthority[0], SidRevision);
        trace(P"SidRevision = %d\n", SidRevision);
    }
    else
        ERR(rc);

    //
    // Read rule records from registry
    //
    RulePack *Pack;
    ULONG PackLength = 0;
    ULONG Type = REG_BINARY;
    rc = RegReadValue(&usRegParamName, L"RuleRecords", (PVOID *) &Pack, &PackLength, &Type);
    if ( !NT_SUCCESS(rc) ) {
		Syn.Release();
        ERR(rc);
        return STATUS_SUCCESS;
    }

    Syn.Exclusive();
    //
    // Clear existing list, TODO: do not touch ruleid != 0
    //
	PLIST_ENTRY Entry = RecordsList.Flink;
	while ( Entry != &RecordsList ) {
		ObjectRecord *Record = CONTAINING_RECORD(Entry, ObjectRecord, Entry);
		if ( Record->RuleId == 0 ) {
			RemoveEntryList(&Record->Entry);
			delete Record;
			Entry = RecordsList.Flink;
		} else {
			Entry = Entry->Flink;
		}
	}

	rc = AddRulesNoLock(Pack, PackLength);
    delete[] Pack;

    Syn.Release();
    return rc;
}

NTSTATUS Aci::LoadRules(RulePack *Pack, SIZE_T PackLength)
{
	NTSTATUS rc;

	rc = AddRulesNoLock(Pack, PackLength);

	return rc;
}

NTSTATUS Aci::UnloadRules(ULONG RuleId)
{
    Syn.Exclusive();

	PLIST_ENTRY Entry = RecordsList.Flink;
	while ( Entry != &RecordsList ) {
		ObjectRecord *Record = CONTAINING_RECORD(Entry, ObjectRecord, Entry);
		if ( Record->RuleId == RuleId ) {
			RemoveEntryList(&Record->Entry);
			delete Record;
			Entry = RecordsList.Flink;
		}
		Entry = Entry->Flink;
	}
	
	Syn.Release();

	return STATUS_SUCCESS;
}

bool Aci::IsValidRulePack(RulePack *Pack, SIZE_T PackLength)
{
    //
    // Check validity of rules
    //
	if ( PackLength < sizeof RulePack ) {
        ERR(STATUS_UNSUCCESSFUL);
        return false;
	}

    ULONG i;
    RuleRecord *Record = Pack->Record;
    SIZE_T Size = FIELD_OFFSET(RulePack, Record);
    for ( i=0; i < Pack->RulesNumber; i++ ) {
        if ( Size + sizeof RuleRecord > PackLength ) {
            Size += sizeof RuleRecord;
            break;
        }

        ULONG Len = FIELD_OFFSET(RuleRecord, Buf) + Record->BufSize;
        Record = (RuleRecord *)((PUCHAR)Record + Len);
        Size += Len;
    }

    if ( Size != PackLength || Pack->PackVersion != PACK_VERSION ) {
        ERR(STATUS_UNSUCCESSFUL);
        return false;
    }

	return true;
}
