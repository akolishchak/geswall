//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "acidyn.h"
#include "gesrule.h"
#include "lock.h"
#include "hook.h"
#include "request.h"
#include "aci.h"
#include "tools.h"

namespace AciDyn {

struct RuleItem {
	LONG Counter;
	ULONG RuleId;
	PTOKEN_USER User;
	ULONG SubjectId;
	LIST_ENTRY Entry;
};

ULONG RuleCounter = 0;
LIST_ENTRY RulesList;
CEResource Syn;

RuleItem *LookupRuleItem(ULONG SubjectId, PTOKEN_USER User);


NTSTATUS LoadSubjectRules(PEPROCESS Process, EntityAttributes *Attributes, ULONG *RuleId)
{
	NTSTATUS rc;
	ULONG NewRuleId = 0;
	*RuleId = 0;
	//
	// Get/search rule sid
	//
	SECURITY_SUBJECT_CONTEXT  sc;
	SeCaptureSubjectContext(&sc);

	PTOKEN_USER User = NULL;
	rc = SeQueryInformationToken(SeQuerySubjectContextToken(&sc), TokenUser, (PVOID *) &User);
	SeReleaseSubjectContext(&sc);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	NewRuleId = InterlockedIncrement((PLONG)&RuleCounter);
	//
	// Send request to gswserv
	//
	ProcExecReq *Req = new(PagedPool) ProcExecReq;
	if ( Req == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}
	Req->RuleId = NewRuleId;
	Req->ThreadId = PsGetCurrentThreadId();
	RtlCopyMemory(Req->Label, &GesRule::GswLabel, sizeof Req->Label);
	Req->ProcessId = PsGetCurrentProcessId();
	Req->Process = Process;
	Req->FileName[0] = 0;
	Req->Attr = *Attributes;
	PUNICODE_STRING usFileName = Hook::GetProcessFileName(Process);
	if ( usFileName != NULL ) {
		ULONG Length = min(usFileName->Length, sizeof Req->FileName - sizeof WCHAR);
		RtlCopyMemory(Req->FileName, usFileName->Buffer, Length);
		Req->FileName[Length / sizeof WCHAR] = 0;
		delete[] usFileName;
	}

	ProcExecReply *Reply = NULL;
	SIZE_T ReplySize = 0;
	if ( !Request::UserCall(Req, (PVOID *)&Reply, &ReplySize) || 
		  ReplySize < FIELD_OFFSET(ProcExecReply, Pack.Record) ) {
	    if ( Reply != NULL ) delete Reply;
		delete Req;
		delete User;
		rc = STATUS_UNSUCCESSFUL;
		ERR(rc);
		return rc;
	}

	*Attributes = Reply->Attr;

	if ( Reply->Attr.Param[GesRule::attSubjectId] != 0 ) {
		//
		// Cache reply
		//
		RuleItem *Item = new(PagedPool) RuleItem;
		if ( Item == NULL ) {
			delete Reply;
			delete Req;
			delete User;
			rc = STATUS_INSUFFICIENT_RESOURCES;
			ERR(rc);
			return rc;
		}
		Item->Counter = 1;
		Item->SubjectId = Attributes->Param[GesRule::attSubjectId];
		Item->User = User;
		Item->RuleId = NewRuleId;
		*RuleId = NewRuleId;

		Syn.Exclusive();
		RuleItem *SameItem = LookupRuleItem(Attributes->Param[GesRule::attSubjectId], User);
		//
		// andr: TODO: let updates rules on the process, even though other still present
		//
		if ( SameItem == NULL ) {
			InsertTailList(&RulesList, &Item->Entry);
			rc = Aci::LoadRules(&Reply->Pack, ReplySize - FIELD_OFFSET(ProcExecReply, Pack));
			if ( !NT_SUCCESS(rc) ) {
				ERR(rc);
			}
		} else {
			SameItem->Counter++;
			*RuleId = SameItem->RuleId;
			delete User;
			delete Item;
		}
		Syn.Release();
	}

    delete Reply;
	delete Req;

	return STATUS_SUCCESS;
}

NTSTATUS UnloadSubjectRules(ULONG RuleId)
{
	if ( RuleId == 0 ) return STATUS_SUCCESS;

	Syn.Exclusive();
	RuleItem *Item = NULL;
	PLIST_ENTRY Entry = RulesList.Flink;
	while ( Entry != &RulesList ) {

		Item = CONTAINING_RECORD(Entry, RuleItem, Entry);
		if ( Item->RuleId == RuleId ) break;

		Entry = Entry->Flink;
	}
	if ( Item != NULL && --Item->Counter <= 0 ) {
		Aci::UnloadRules(RuleId);
		RemoveEntryList(&Item->Entry);
		delete Item->User;
		delete Item;
	}
	Syn.Release();

	return STATUS_SUCCESS;
}

NTSTATUS LoadSubjectRules(ULONG RuleId)
{
	if ( RuleId == 0 ) return STATUS_SUCCESS;

	Syn.Exclusive();
	PLIST_ENTRY Entry = RulesList.Flink;
	while ( Entry != &RulesList ) {
		RuleItem *Item = CONTAINING_RECORD(Entry, RuleItem, Entry);
		if ( Item->RuleId == RuleId ) {
			Item->Counter++;
			break;
		}
		Entry = Entry->Flink;
	}
	Syn.Release();

	return STATUS_SUCCESS;
}

NTSTATUS DisableRedirect(PEPROCESS Subject)
{
	EntityAttributes Attributes;
	Rule::RedirectStatus Redirect;
	ULONG RuleId;
	NTSTATUS rc = Aci::GetSubjectInfo((CHAR *)&GesRule::GswLabel, Subject, Attributes, Redirect, RuleId);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}
	if ( Redirect == Rule::rdsUndefined || Redirect == Rule::rdsNone ) {
		rc = STATUS_UNSUCCESSFUL;
		ERR(rc);
		return rc;
	}
	RtlZeroMemory(&Attributes, sizeof Attributes);
	Attributes.Param[GesRule::attOptions] = GesRule::oboDisableFileRedirect | GesRule::oboDisableKeyRedirect;
	return Aci::OrSubjectInfo((CHAR *)&GesRule::GswLabel, Subject, Attributes, Rule::rdsNone, 0);
}

NTSTATUS Init(VOID)
{
	InitializeListHead(&RulesList);

    NTSTATUS rc = Syn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

	return rc;
}

RuleItem *LookupRuleItem(ULONG SubjectId, PTOKEN_USER User)
{
	RuleItem *Item = NULL;
	PLIST_ENTRY Entry = RulesList.Flink;
	while ( Entry != &RulesList ) {

		Item = CONTAINING_RECORD(Entry, RuleItem, Entry);
		if ( Item->SubjectId == SubjectId && RtlEqualSid(User->User.Sid, Item->User->User.Sid) ) return Item;

		Entry = Entry->Flink;
	}
	return NULL;
}

}; // namespace AciDyn {