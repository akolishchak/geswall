//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "sysprocess.h"

namespace SysProcess {

KEVENT RequestEvent;
LIST_ENTRY ProcessList;
KSPIN_LOCK ListLock;
PVOID ProcessThreadPoniter = NULL;

void ProcessThread(PVOID Context);

} // namespace SysProcess {


NTSTATUS SysProcess::Init(void)
{
    NTSTATUS rc;

    KeInitializeEvent(&RequestEvent, SynchronizationEvent, FALSE);
    InitializeListHead(&ProcessList);
    KeInitializeSpinLock(&ListLock);

    HANDLE hProcessThread;
    rc = PsCreateSystemThread( &hProcessThread, THREAD_ALL_ACCESS,
                              NULL, NULL, NULL, ProcessThread, NULL);

	if (NT_SUCCESS(rc)) {
		ObReferenceObjectByHandle(hProcessThread, 0, NULL, KernelMode, &ProcessThreadPoniter, NULL);
        ZwClose(hProcessThread);
	}

    return rc;
}

PVOID SysProcess::GetProcessThread(VOID)
{
	return ProcessThreadPoniter;
}

VOID SysProcess::Post(SysProcessInfo *pInfo, _SysProc SysProc, BOOLEAN bPost)
{
    KeInitializeEvent(&pInfo->Event, SynchronizationEvent, FALSE);

    pInfo->SysProc = SysProc;
    pInfo->bPost = bPost;

    KIRQL OldIrql;
    KeAcquireSpinLock(&ListLock, &OldIrql);
    InsertTailList(&ProcessList, &pInfo->Entry);
    KeReleaseSpinLock(&ListLock, OldIrql);

    KeSetEvent(&RequestEvent, 0, FALSE);

    return;
}

VOID FastPostWorkItem(PVOID Context)
{
    SysProcessInfo *pInfo = (SysProcessInfo *) Context;

    NTSTATUS rc;
    if ( pInfo->bPost ) {
        rc = pInfo->SysProc(pInfo);
    } else {
        pInfo->rc = pInfo->SysProc(pInfo);
        KeSetEvent(&pInfo->Event, 0, FALSE);
    }
}


VOID SysProcess::FastPost(SysProcessInfo *pInfo, _SysProc SysProc, BOOLEAN bPost)
{
    KeInitializeEvent(&pInfo->Event, SynchronizationEvent, FALSE);

    pInfo->SysProc = SysProc;
    pInfo->bPost = bPost;

    ExInitializeWorkItem(&pInfo->WorkItem, FastPostWorkItem, pInfo);
	ExQueueWorkItem(&pInfo->WorkItem, DelayedWorkQueue);

    return;
}


NTSTATUS SysProcess::Run(SysProcessInfo *pInfo, _SysProc SysProc)
{
    Post(pInfo, SysProc, FALSE);
    KeWaitForSingleObject(&pInfo->Event, Executive, KernelMode, FALSE, NULL);

    return pInfo->rc;
}

void SysProcess::ProcessThread(PVOID Context)
{
   NTSTATUS rc;
   PLIST_ENTRY  request;

   PVOID events[] = { &RequestEvent };

    while (TRUE) {

        rc = KeWaitForMultipleObjects(1, events, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
      
        //if (rc == STATUS_WAIT_0)
        //    break;

        while (TRUE) {

            KIRQL OldIrql;
            KeAcquireSpinLock(&ListLock, &OldIrql);

            if (IsListEmpty(&ProcessList)) {
                
                KeReleaseSpinLock(&ListLock, OldIrql);
                break;
            }

            request = RemoveHeadList(&ProcessList);
            KeReleaseSpinLock(&ListLock, OldIrql);

            SysProcessInfo *pInfo = CONTAINING_RECORD(request, SysProcessInfo, Entry);

            if ( pInfo->bPost ) {
                rc = pInfo->SysProc(pInfo);
            } else {
                pInfo->rc = pInfo->SysProc(pInfo);
                KeSetEvent(&pInfo->Event, 0, FALSE);
            }
        }
    }

   PsTerminateSystemThread(STATUS_SUCCESS);
}
