//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __tdiio_h__
#define __tdiio_h__

namespace TdiIo {

NTSTATUS ControlDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

}; // namespace TdiIo {

#endif // __tdiio_h__