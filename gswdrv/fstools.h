//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __fstools_h__
#define __fstools_h__

namespace FsFilter {

NTSTATUS ComposeFileName(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, PUNICODE_STRING FileName);

NTSTATUS GetFileName(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, PUNICODE_STRING *FileName);
NTSTATUS GetFileSecurity(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, PSECURITY_DESCRIPTOR *sd);
NTSTATUS GetFileSD(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, PSECURITY_DESCRIPTOR *sd, 
				   SECURITY_INFORMATION SecurityInformation);
NTSTATUS SetSecurityFile(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject,
                         SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR sd);
NTSTATUS SendFsControl(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, ULONG FsControlCode,
					   PVOID InBuf, ULONG InSize, PVOID OutBuf, ULONG &OutSize);
NTSTATUS GetLongName(PDEVICE_OBJECT DeviceObject, PUNICODE_STRING *FileName);
NTSTATUS DeleteDirFiles(PUNICODE_STRING DirName);


}; // namespace FsFilter {


#endif // __fstools_h__