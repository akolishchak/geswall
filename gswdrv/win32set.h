//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __win32set_h__
#define __win32set_h__

namespace Win32Set {
    NTSTATUS Init(VOID);
    NTSTATUS Release(VOID);
    NTSTATUS Sync(W32HooksetSyncParams *Params);
    bool hookWholeW32 ();
    bool unhookWholeW32 ();
};


#endif //__win32set_h__