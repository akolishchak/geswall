//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __fastio_h__
#define __fastio_h__

namespace FastIo {
    NTSTATUS Init(PFAST_IO_DISPATCH *pFastIoDispatch);
};

#endif // __fastio_h__