//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __fssetinfo_h__
#define __fssetinfo_h__

namespace FsFilter {

namespace SetInfo {

NTSTATUS Rename(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

}; // namespace Rename {

}; // namespace FsFilter {

#endif // __fssetinfo_h__