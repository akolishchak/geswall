//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __request_h__
#define __request_h__


namespace Request {

//
// Define status of user app availability to handle requests
//
enum HandlerStatus {
    hstNeverAppear,         // user app never started yet
    hstAvailable,           // user app strted and may handle requests
    hstSuddenlyStopped,     // user app was started but is not available now,
                            // probably stopped
    hstStopped              // app was correctly stopped by authorized user

};

BOOLEAN UserCall(RequestData *Data, PVOID *Response, SIZE_T *ResponseSize);

NTSTATUS Init(VOID);
NTSTATUS ServiceOffer(PIRP Irp);
NTSTATUS ApplyResponse(PIRP Irp);
NTSTATUS RemoveService(PIRP Irp);
NTSTATUS InformStop(PIRP Irp);
//
// User app handlers info
//
NTSTATUS AddHandler(PFILE_OBJECT FileObject);
NTSTATUS RemoveHandler(PFILE_OBJECT FileObject);

HandlerStatus GetHandlerStatus(void);

}

#endif // __request_h__