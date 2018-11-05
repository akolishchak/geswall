//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "request.h"
#include "tools.h"
#include "lock.h"

namespace Request {
//
// Internal structure to track requests 
//
struct RequestInfo {
	RequestInfo(void)
	{
		Data = NULL;
	}
	~RequestInfo()
	{
		if ( !( Data->Flags & reqWaitReply ) && Data != NULL ) delete Data;
	}
	PVOID Id;						// Request Id
	RequestData *Data;				// Request content
	PVOID ResponseBuf;				// Response buffer
	SIZE_T ResponseBufSize;			// Response buffer size
	KEVENT CompleteEvent;           // Event that signed when responce received
	ULONG Result;					// Result status
	ULONG SessionId;				// request's session id
	LARGE_INTEGER Time;				// request's time
	LIST_ENTRY Entry;               // Entry for requests list
};

struct PeekInfo {
	PFILE_OBJECT FileObject;
	RequestInfo *Request;
};

LIST_ENTRY RequestList;
//
// to support many requests handling threads
//
LIST_ENTRY ServiceList;
//
// Have common synchro for both because of way they are used to avoid deadlocks
// No need share access and raising to APC accepted, so use mutex.
CEResource RequestSyn;


LIST_ENTRY ProcessList;
CEResource ProcessSyn;

struct HandlerInfo {
	PFILE_OBJECT FileObject;
	LIST_ENTRY Entry;
};

LIST_ENTRY HandlerList;

LONG HandlersNumber;
BOOLEAN bGotHandlers;
BOOLEAN bGotStopped;

PEPROCESS ServiceProcess = NULL;

const LONGLONG WaitPeriodUnit = - LONGLONG(1000) * LONGLONG(10000);
LARGE_INTEGER WaitPeriod;

KEVENT DestructorEvent;

NTSTATUS QueueRequest(RequestInfo *pRequestInfo, PIRP Irp);
VOID CleanRequestList(VOID);
RequestInfo *GetRequest(const PIRP Irp);

//
// Cancel safe stuff
//
IO_CSQ CancelSafeQueue;
NTSTATUS CsqInsertIrpEx(PIO_CSQ Csq, PIRP Irp, PVOID InsertContext);
VOID CsqRemoveIrp(PIO_CSQ Csq, PIRP Irp);
PIRP CsqPeekNextIrp(PIO_CSQ Csq, PIRP _Irp, PVOID PeekContext);
VOID CsqAcquireLock(PIO_CSQ Csq, PKIRQL Irql);
VOID CsqReleaseLock(PIO_CSQ Csq, KIRQL Irql);
VOID CsqCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp);


NTSTATUS Init(VOID)
{
	InitializeListHead(&RequestList);
	InitializeListHead(&ServiceList);
	InitializeListHead(&ProcessList);
	InitializeListHead(&HandlerList);

	NTSTATUS rc = RequestSyn.Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	rc = ProcessSyn.Init();
	if ( !NT_SUCCESS(rc) ) {
		RequestSyn.Destroy();
		ERR(rc);
		return rc;
	}

	rc = IoCsqInitializeEx(&CancelSafeQueue, CsqInsertIrpEx, CsqRemoveIrp, CsqPeekNextIrp,
							CsqAcquireLock, CsqReleaseLock, CsqCompleteCanceledIrp);
	if ( !NT_SUCCESS(rc) ) {
		ProcessSyn.Destroy();
		RequestSyn.Destroy();
		ERR(rc);
		return rc;
	}

    HandlersNumber = 0;
    bGotHandlers = FALSE;
    bGotStopped = FALSE;

	KeInitializeEvent(&DestructorEvent, NotificationEvent, FALSE);

	ULONG ResponceWaitSecs;
    ULONG Size = sizeof ResponceWaitSecs;
    PVOID Buf = &ResponceWaitSecs;
    rc = RegReadValue(&usRegParamName, L"ResponceWaitSecs", (PVOID *) &Buf, &Size, NULL);
    if ( NT_SUCCESS(rc) ) 
		WaitPeriod.QuadPart = ResponceWaitSecs * WaitPeriodUnit;
	else
		WaitPeriod.QuadPart = 30 * WaitPeriodUnit;

	return STATUS_SUCCESS;
}

BOOLEAN UserCall(RequestData *Data, PVOID *Response, SIZE_T *ResponseSize)
{
	//
	// Ignore requests within service process
	//
	if ( PsGetCurrentProcess() == ServiceProcess )
		return FALSE;

	NTSTATUS rc = STATUS_UNSUCCESSFUL;
    //
    // Check if there are registered handlers.
    // If not then return corresponding status
    //
    HandlerStatus Status = GetHandlerStatus();
    if ( Status != hstAvailable )
        return FALSE;
    //
    // User app may handle request, so go further
    //
	RequestInfo *pRequest = (RequestInfo *) new(NonPagedPool) RequestInfo;
	if ( pRequest == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return FALSE;
	}
	//
	// Init request header
	//
	pRequest->Id = pRequest; 
	pRequest->Data = Data;
	if ( !( Data->Flags & reqWaitReply ) ) {
		pRequest->Data = (RequestData *) new(PagedPool) UCHAR[Data->Size];
		if ( pRequest->Data == NULL ) {
			delete pRequest;
			rc = STATUS_INSUFFICIENT_RESOURCES;
			ERR(rc);
			return FALSE;
		}
		RtlCopyMemory(pRequest->Data, Data, Data->Size);
	}
	pRequest->ResponseBuf = NULL;
	pRequest->ResponseBufSize = 0;
	pRequest->Result = FALSE;
	KeQuerySystemTime(&pRequest->Time);
	pRequest->SessionId = 0;
	if ( Data->Flags & reqMatchSession ) {
		SECURITY_SUBJECT_CONTEXT  sc;
		SeCaptureSubjectContext(&sc);
		SeQuerySessionIdToken(SeQuerySubjectContextToken(&sc), &pRequest->SessionId);
		SeReleaseSubjectContext(&sc);
	}

	KeInitializeEvent(&pRequest->CompleteEvent, NotificationEvent, FALSE);

	//
	// Check if there are free waiting for handling GET_REQUEST IOCTL's IRPs 
	//
	PeekInfo Peek = { NULL, pRequest };
	RequestSyn.Exclusive();
	CleanRequestList();
	PIRP Irp = IoCsqRemoveNextIrp(&CancelSafeQueue, &Peek);
	if ( Irp == NULL ) {
		//
		//  nothing free, put request to queue
		//
		InsertTailList(&RequestList, &pRequest->Entry);
	} else {
		//
		// put request to service IRP and insert it to ProcessList
		//
		QueueRequest(pRequest, Irp);
	}

	RequestSyn.Release();

	ULONG Res = FALSE;
	if ( Data->Flags & reqWaitReply ) {
		//
		// Blocking wait for complete
		//
		PVOID Objects[] = { &DestructorEvent, &pRequest->CompleteEvent };
		rc = KeWaitForMultipleObjects(sizeof Objects / sizeof Objects[0], Objects, WaitAny, 
									Executive, KernelMode, FALSE, NULL, NULL);

		if ( rc != STATUS_WAIT_1 ) {
			delete pRequest;
			return FALSE;
		}
		Res = pRequest->Result;
		if ( Response != NULL ) *Response = pRequest->ResponseBuf;
		if ( ResponseSize != NULL ) *ResponseSize = pRequest->ResponseBufSize;
		//
		// Release memory
		delete pRequest;
	}

	return Res;
}

NTSTATUS QueueRequest(RequestInfo *pRequest, PIRP Irp)
{
	//
	// Check capasity of buf size
	//
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG OutBufLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if ( OutBufLength < pRequest->Data->Size ) {
		KeSetEvent(&pRequest->CompleteEvent, 0, FALSE);
		ERR(STATUS_INVALID_PARAMETER);
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	//
	//
    RequestData *Data = (RequestData *) Irp->AssociatedIrp.SystemBuffer;
	// fill out buf
	pRequest->Data->Id = pRequest->Id;
	RtlCopyMemory(Data, pRequest->Data, pRequest->Data->Size);
	//
	// Insert in process list
	if ( Data->Flags & reqWaitReply ) {
		ProcessSyn.Exclusive();
		InsertTailList(&ProcessList, &pRequest->Entry);
		ProcessSyn.Release();
	} else {
		delete pRequest;
	}

	//
	// Complete service IRP
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = Data->Size;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ServiceOffer(PIRP Irp)
{
	NTSTATUS rc;
	//
	// Service IRP sanity check
	//
	Irp->Tail.Overlay.DriverContext[0] = 0;
	SECURITY_SUBJECT_CONTEXT  sc;
	SeCaptureSubjectContext(&sc);
	SeQuerySessionIdToken(SeQuerySubjectContextToken(&sc), (PULONG)&Irp->Tail.Overlay.DriverContext[0]);
	SeReleaseSubjectContext(&sc);

	PIO_STACK_LOCATION CurrentIrpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG OutBufLength = CurrentIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	if ( OutBufLength < sizeof RequestData ) {
		rc = STATUS_INVALID_PARAMETER;
		ERR(rc);
	    Irp->IoStatus.Status = rc;
	    Irp->IoStatus.Information = 0;
	    IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return rc;
	}

	// Check if there are waiting requests
	// 
	RequestSyn.Exclusive();
	RequestInfo *pRequest = GetRequest(Irp);
	if ( pRequest == NULL ) {
		//
		//  no requests, put service IRP in to queue, and pend it
		//
	    // Note: IoCsqInsertIrp marks the IRP pending.
		//
		IoCsqInsertIrp(&CancelSafeQueue, Irp, NULL);
		rc = STATUS_PENDING;
	} else {
		//
		// Remove the request from RequestList and 
		// handle request by this service offer
		//
		RemoveEntryList(&pRequest->Entry);
		rc = QueueRequest(pRequest, Irp);
	}

	RequestSyn.Release();

	return rc;
}

NTSTATUS ApplyResponse(PIRP Irp)
{
	NTSTATUS rc = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	ResponseData *Response = (ResponseData *) Irp->AssociatedIrp.SystemBuffer;
    ULONG InBufLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

	//
	// Buffer sanity check
	if ( InBufLength < sizeof ResponseData || Response->Size > InBufLength ) {
		rc = STATUS_INVALID_PARAMETER;
		ERR(rc);
	    Irp->IoStatus.Status = rc;
	    Irp->IoStatus.Information = 0;
	    IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return rc;
	}

	//
	// Find waiting request in ProcessList by request id
	//
	ProcessSyn.Exclusive();
	PLIST_ENTRY pEntry = ProcessList.Flink;
	RequestInfo *pRequest;
	while (pEntry != &ProcessList) {

		pRequest = CONTAINING_RECORD(pEntry, RequestInfo, Entry);
		if ( pRequest->Id == Response->Id ) {
			//
			// Found, remove from list, set output buffer
			//
			if ( Response->Result ) {
				SIZE_T ResponseSize = Response->Size - sizeof ResponseData;
				if ( ResponseSize > 0 ) {
					pRequest->ResponseBuf = new(PagedPool) UCHAR[ResponseSize];
					if ( pRequest->ResponseBuf == NULL ) {
						//KeSetEvent(&pRequest->CompleteEvent, 0, FALSE);
						rc = STATUS_INSUFFICIENT_RESOURCES;
						ERR(rc);
						break;
					}
					pRequest->ResponseBufSize = ResponseSize;
					RtlCopyMemory(pRequest->ResponseBuf, (PUCHAR)Response + sizeof ResponseData, ResponseSize);
				}
			}
			pRequest->Result = Response->Result;
			RemoveEntryList(pEntry);
			rc = STATUS_SUCCESS;
			break;
		}
		pEntry = pEntry->Flink;
	}
	ProcessSyn.Release();

	// if found sign event
	if ( NT_SUCCESS(rc) ) {
		KeSetEvent(&pRequest->CompleteEvent, 0, FALSE);
		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == GESWALL_IOCTL_REPLY_REQUEST)
			return ServiceOffer(Irp);
	}

	Irp->IoStatus.Status = rc;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return rc;
}

NTSTATUS RemoveService(PIRP Irp)
{
    PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	// Check if there are waiting requests
	// 
	PeekInfo Peek = { pFileObject, NULL };
	RequestSyn.Exclusive();
	PLIST_ENTRY pEntry = ServiceList.Flink;
	PIRP ServiceIrp = IoCsqRemoveNextIrp(&CancelSafeQueue, &Peek);
	while ( ServiceIrp != NULL ) {
	    //
        // Complete IRP
	    ServiceIrp->IoStatus.Status = STATUS_CANCELLED;
	    ServiceIrp->IoStatus.Information = 0;
	    IoCompleteRequest(ServiceIrp, IO_NO_INCREMENT);

		ServiceIrp = IoCsqRemoveNextIrp(&CancelSafeQueue, &Peek);
	}

	RequestSyn.Release();
	//
	// decrement handlers counter
    RemoveHandler(pFileObject);

    return STATUS_SUCCESS;
}

NTSTATUS InformStop(PIRP Irp)
{
    //
    // Don't use synchro because it's not critical
    //
    bGotStopped = TRUE;
    //
    // Complete IRP
    NTSTATUS rc = STATUS_SUCCESS;
    Irp->IoStatus.Status = rc;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return rc;
}

NTSTATUS AddHandler(PFILE_OBJECT FileObject)
{
	NTSTATUS rc = STATUS_SUCCESS;

	HandlerInfo *Handler = (HandlerInfo *)ExAllocatePoolWithQuotaTag(PagedPool, sizeof HandlerInfo, 'QRWG');
	if ( Handler == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}
	Handler->FileObject = FileObject;

	RequestSyn.Exclusive();
	InsertTailList(&HandlerList, &Handler->Entry);

    InterlockedIncrement(&HandlersNumber);
    bGotHandlers = TRUE;
    bGotStopped = FALSE;

	if ( ServiceProcess == NULL )
		ServiceProcess = PsGetCurrentProcess();

	RequestSyn.Release();

    return STATUS_SUCCESS;
}

NTSTATUS RemoveHandler(PFILE_OBJECT FileObject)
{
	NTSTATUS rc = STATUS_UNSUCCESSFUL;
	RequestSyn.Exclusive();

	PLIST_ENTRY Entry = HandlerList.Flink;
	while ( Entry != &HandlerList ) {

		HandlerInfo *Handler = CONTAINING_RECORD(Entry, HandlerInfo, Entry);
		if ( Handler->FileObject == FileObject ) {
			RemoveEntryList(&Handler->Entry);
			delete Handler;
			rc = STATUS_SUCCESS;
			break;
		}
		Entry = Entry->Flink;
	}

	if ( NT_SUCCESS(rc) && InterlockedDecrement(&HandlersNumber) == 0 ) {
        //
        // If no more handlers then dequeue all pended requests
        //
		ProcessSyn.Exclusive();
	    
		while (!IsListEmpty(&ProcessList)) {

	        PLIST_ENTRY pEntry = RemoveHeadList(&ProcessList);
		    RequestInfo *pRequest = CONTAINING_RECORD(pEntry, RequestInfo, Entry);
            KeSetEvent(&pRequest->CompleteEvent, 0, FALSE);
	    }
		
		ServiceProcess = NULL;

		ProcessSyn.Release();
    }

	RequestSyn.Release();

    return STATUS_SUCCESS;
}


HandlerStatus GetHandlerStatus(void)
{
    if (HandlersNumber > 0)
        return hstAvailable;
    //
    // When app stopped all file handlers are closed. 
    // So, zero value of HandlersNumber means stopped app.
    //
    if (bGotHandlers)
        if (bGotStopped)
            return hstStopped;
        else
            return hstSuddenlyStopped;

    return hstNeverAppear;
}

VOID CleanRequestList(VOID)
{
	LARGE_INTEGER Time;
	KeQuerySystemTime(&Time);
    PLIST_ENTRY Entry = RequestList.Flink;
	while ( Entry != &RequestList ) {
		RequestInfo *Request = CONTAINING_RECORD(Entry, RequestInfo, Entry);
		if ( !( Request->Data->Flags & reqWaitReply ) && ( Time.QuadPart - Request->Time.QuadPart > Request->Data->Timeout.QuadPart ) ) {
			//
			// Request has been expired, dismiss it
			//
			RemoveEntryList(&Request->Entry);
			delete Request;
			Entry = RequestList.Flink;
		} else {
			Entry = Entry->Flink;
		}
	}
}

RequestInfo *GetRequest(const PIRP Irp)
{
	ULONG IoControlCode = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;
	LARGE_INTEGER Time;
	KeQuerySystemTime(&Time);
    PLIST_ENTRY Entry = RequestList.Flink;
	while ( Entry != &RequestList ) {
		RequestInfo *Request = CONTAINING_RECORD(Entry, RequestInfo, Entry);
		if ( Request->Data->Code == IoControlCode && ( Time.QuadPart - Request->Time.QuadPart <= Request->Data->Timeout.QuadPart )
			 && ( !( Request->Data->Flags & reqMatchSession ) || Request->SessionId == (ULONG_PTR)Irp->Tail.Overlay.DriverContext[0] )
		   ) {
			// Request found and return
			return Request;
		}
		Entry = Entry->Flink;
	}
	return NULL;
}

NTSTATUS CsqInsertIrpEx(PIO_CSQ Csq, PIRP Irp, PVOID InsertContext)
{
	InsertTailList(&ServiceList, &Irp->Tail.Overlay.ListEntry);
	return STATUS_SUCCESS;
}

VOID CsqRemoveIrp(PIO_CSQ Csq, PIRP Irp)
{
	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

PIRP CsqPeekNextIrp(PIO_CSQ Csq, PIRP _Irp, PVOID PeekContext)
{
	const PeekInfo *Info = (PeekInfo *) PeekContext;

	PLIST_ENTRY Entry;
	if ( _Irp == NULL ) {
		Entry = ServiceList.Flink;
	} else {
		Entry = _Irp->Tail.Overlay.ListEntry.Flink;
	}

	while ( Entry != &ServiceList ) {
		PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

		if ( Info == NULL ) return Irp;
		if ( ( Info->FileObject != NULL && IoGetCurrentIrpStackLocation(Irp)->FileObject == Info->FileObject ) || 
			 ( Info->Request != NULL && Info->Request->Data->Code == IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode 
			   && ( !( Info->Request->Data->Flags & reqMatchSession ) || Info->Request->SessionId == (ULONG_PTR)Irp->Tail.Overlay.DriverContext[0] ) 
			 ) ) {
			return Irp;
		}

		Entry = Entry->Flink;
	}

	return NULL;
}

VOID CsqAcquireLock(PIO_CSQ Csq, PKIRQL Irql)
{
	if ( !RequestSyn.IsExclusiveAcquired() ) {
		RequestSyn.Exclusive();
		*Irql = TRUE;
	} else {
		*Irql = FALSE;
	}
}

VOID CsqReleaseLock(PIO_CSQ Csq, KIRQL Irql)
{
	if ( Irql == TRUE ) RequestSyn.Release();
}

VOID CsqCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

} // namespace Request