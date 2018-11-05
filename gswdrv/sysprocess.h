//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __sysprocess_h__
#define __sysprocess_h__

struct SysProcessInfo; 
typedef NTSTATUS ( *_SysProc) (SysProcessInfo *pInfo);

struct SysProcessInfo {
    KEVENT Event;
    LIST_ENTRY Entry;
    WORK_QUEUE_ITEM WorkItem;
    NTSTATUS rc;
    _SysProc SysProc;
    BOOLEAN bPost;
};


namespace SysProcess {

NTSTATUS Init(void);
VOID Post(SysProcessInfo *pInfo, _SysProc SysProc, BOOLEAN bPost=TRUE);
VOID FastPost(SysProcessInfo *pInfo, _SysProc SysProc, BOOLEAN bPost=TRUE);
NTSTATUS Run(SysProcessInfo *pInfo, _SysProc SysProc);
PVOID GetProcessThread(VOID);

}


#endif