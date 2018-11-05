//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "reqhandle.h"
#include <process.h>


CReqHandle::CReqHandle(_HandleProc Proc)
{
    HandleProc = Proc;
    hDevice = INVALID_HANDLE_VALUE;
    hThread = INVALID_HANDLE_VALUE;

	hDevice = CreateFile(GESWALL_USER_DEVICE_NAME, GENERIC_WRITE, 
                         FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

	hDestroyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

CReqHandle::~CReqHandle()
{
    Stop();
}

// 
// Start handling in current thread
//
bool CReqHandle::Start(void)
{
	bool Result = false;
    if (hDevice == INVALID_HANDLE_VALUE)
        return false;

    BOOL rc;
	BYTE InBuf[MaxReqDataSize], OutBuf[MaxReqDataSize];
    DWORD BytesReturned;
    OVERLAPPED Overlapped;

    memset(&Overlapped, 0, sizeof Overlapped);
    Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	HANDLE Events[] = { Overlapped.hEvent, hDestroyEvent };
    
    if (Overlapped.hEvent == INVALID_HANDLE_VALUE)
        return false;
	//
	// register opened handle as a request handler
	//
	rc = DeviceIoControl(hDevice, GESWALL_IOCTL_REGISTER_HANDLER, NULL, 0, NULL,  0, &BytesReturned, &Overlapped);
	if ( rc == FALSE && GetLastError() != ERROR_IO_PENDING ) throw GetLastError();
	rc = GetOverlappedResult(hDevice, &Overlapped, &BytesReturned, TRUE);
	if ( rc == FALSE ) throw GetLastError();

    try {

        while (true) {
			//
			// send service offer
			//
            ResetEvent(Overlapped.hEvent);
			rc = DeviceIoControl(hDevice, GESWALL_IOCTL_GET_REQUEST, NULL, 0, InBuf, 
								sizeof InBuf, &BytesReturned, &Overlapped);

			if ( rc == FALSE && GetLastError() != ERROR_IO_PENDING )
				throw GetLastError();

			rc = WaitForMultipleObjects(sizeof Events / sizeof Events[0], Events, FALSE, INFINITE);
			if ( rc != WAIT_OBJECT_0 ) {
				Result = true;
				break;
			}

			rc = GetOverlappedResult(hDevice, &Overlapped, &BytesReturned, TRUE);
			if ( rc == FALSE )
				throw GetLastError();
            //
            // Prepare response
            //
			RequestData *Request = (RequestData *) InBuf;
			PVOID ResponseBuf = NULL;
			SIZE_T ResponseSize = 0;
			ULONG ResponseResult = FALSE;
			if ( HandleProc != NULL ) {
				try {
					ResponseResult = HandleProc(Request, &ResponseBuf, &ResponseSize);
				} catch ( ... ) { }
			}

			ResponseData *Response;
			if ( ResponseBuf != NULL )
				Response = GetResponseData(ResponseBuf);
			else
				Response = (ResponseData *)OutBuf;

			Response->Id = Request->Id;
			Response->Result = ResponseResult;
			Response->Size = ResponseSize + sizeof ResponseData;

            //
            // Send response
            //
            ResetEvent(Overlapped.hEvent);
            rc = DeviceIoControl(hDevice, GESWALL_IOCTL_POST_REPLY, 
                                 Response, (DWORD)Response->Size, 
                                 NULL, 0, &BytesReturned, &Overlapped);
			if ( ResponseBuf != NULL ) FreeResponse(ResponseBuf);
			if ( rc == FALSE && GetLastError() != ERROR_IO_PENDING )
				throw GetLastError();

			rc = GetOverlappedResult(hDevice, &Overlapped, &BytesReturned, TRUE);
			if ( rc == FALSE )
				throw GetLastError();
        }
    } 
    catch ( DWORD &Error ) {
        if ( Error == ERROR_OPERATION_ABORTED ) Result = true;
    }

	CancelIo(hDevice);
    return Result;
}

//
// Handling thread 
//
DWORD WINAPI ProcessThread(void *Context)
{
    CReqHandle *pReqHandle = (CReqHandle *) Context;
	try {
		pReqHandle->Start();
	} catch ( ... ) {
	}

	return 0;
}

// 
// Start handling in backround thread
//
bool CReqHandle::StartBackground(void)
{
    if (hDevice == INVALID_HANDLE_VALUE)
        return false;

	DWORD ThreadId;
    hThread = CreateThread(NULL, 0, ProcessThread, this, 0, &ThreadId);
    if (hThread == INVALID_HANDLE_VALUE)
        return false;

    return true;
}

//
// Normal stop of handling
//
void CReqHandle::Stop(void)
{
    if (hDevice != INVALID_HANDLE_VALUE) {

		SetEvent(hDestroyEvent);
    }

    if (hThread != INVALID_HANDLE_VALUE) {
        //
        // Wait for thread completing
        //
        WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
        hThread = INVALID_HANDLE_VALUE;
    }

    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        hDevice = INVALID_HANDLE_VALUE;
        bFirstHandle = true;
    }
}

// 
// Stop of handling with authorization
//
void CReqHandle::AuthorizedStop(void)
{
	if ( hDevice == INVALID_HANDLE_VALUE ) return;

    DWORD BytesReturned;
    OVERLAPPED Overlapped;
    memset(&Overlapped, 0, sizeof Overlapped);
    Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    if (Overlapped.hEvent == INVALID_HANDLE_VALUE)
        return;
    //
    // Send service stop message
    //
    DeviceIoControl(hDevice, GESWALL_IOCTL_STOP_HANDLING, NULL, 0, NULL, 0, 
                    &BytesReturned, &Overlapped);

    GetOverlappedResult(hDevice, &Overlapped, &BytesReturned, TRUE);
    //
    // Call ordinal stop
    //
    Stop();
}
