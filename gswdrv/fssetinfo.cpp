//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdfs.h"
#include "fsfilter.h"
#include "adapi.h"
#include "hook.h"
#include "ntrulemap.h"
#include "aci.h"

using namespace Rule;

namespace FsFilter {

namespace SetInfo {

NTSTATUS GetTargetName(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject,
						PFILE_OBJECT TargetFileObject, PFILE_RENAME_INFORMATION Info, 
						PUNICODE_STRING NewName);

NTSTATUS Rename(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	EntityAttributes ObjectAttributes;
	_EPROCESS *Subject = Hook::GetCurrentProcess();
	if ( NeedRuleCheck(Subject, SubjectAttributes, Redirect, RuleId) == false ) {
		return GswDispatch::PassThrough(DeviceObject, Irp);
	}

	PFILE_RENAME_INFORMATION Info = (PFILE_RENAME_INFORMATION) Irp->AssociatedIrp.SystemBuffer;
	if ( // NTFS stream rename
		 ( Info->FileNameLength >= sizeof WCHAR && Info->FileName[0] == L':' ) 
	   ) return GswDispatch::PassThrough(DeviceObject, Irp);

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PDEVICE_OBJECT AttachedTo = ((Extension *)DeviceObject->DeviceExtension)->AttachedTo;
    NTSTATUS rc = STATUS_SUCCESS;
	UNICODE_STRING usNewName = { 0, 0, NULL };
	//
	// Get new name
	//
	// Simple Rename: SetFile.FileObject is NULL. 
	// Fully Qualified Rename: SetFile.FileObject is non-NULL and FILE_RENAME_INFORMATION .RootDir is NULL. 
	// Relative Rename: SetFile.FileObject and FILE_RENAME_INFORMATION.RootDir are both non-NULL. 
	//
	rc = GetTargetName(DeviceObject, IrpSp->FileObject, IrpSp->Parameters.SetFile.FileObject, Info, &usNewName);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		//
		// failed to get new name, just pass throug
		return GswDispatch::PassThrough(DeviceObject, Irp);
	}

	trace(P"Rename file to %wZ\n", &usNewName);

	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ios;
	HANDLE hFile;
	InitializeObjectAttributes(&oa, &usNewName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hFile, SYNCHRONIZE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
						NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, AttachedTo);
	bool bCreate = false;
	if ( !NT_SUCCESS(rc) ) {
		//
		// suppose file doesn't exist, it means create operation
		// try to create a file with the same name in order to see if is enabled by policy
		//
		rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hFile, SYNCHRONIZE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, 
						FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
						NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, AttachedTo);
		bCreate = true;
	}

	if ( !NT_SUCCESS(rc) ) {
		if ( usNewName.Buffer != NULL ) delete[] usNewName.Buffer;
		ERR(rc);
		return GswDispatch::PassThrough(DeviceObject, Irp);
	}
	if ( Info->ReplaceIfExists == FALSE && bCreate == false ) {
		// file exists but replace is not allowed, let system handle it
		if ( usNewName.Buffer != NULL ) delete[] usNewName.Buffer;
		ZwClose(hFile);
		return GswDispatch::PassThrough(DeviceObject, Irp);
	}	

	PFILE_OBJECT FileObject;
	rc = ObReferenceObjectByHandle(hFile, SYNCHRONIZE, NULL, KernelMode, (PVOID *) &FileObject, NULL);
	if ( !NT_SUCCESS(rc) ) {
		if ( usNewName.Buffer != NULL ) delete[] usNewName.Buffer;
		ZwClose(hFile);
		ERR(rc);
		return GswDispatch::PassThrough(DeviceObject, Irp);
	}

	ACCESS_MASK DesiredAccess = FILE_WRITE_DATA;
	RuleResult Result = Rule::AccessObject(bCreate ? acsCreated : acsOpen, Subject, SubjectAttributes, Redirect, RuleId,
											FileObject, DeviceObject, nttFile, DesiredAccess);
	if ( Result != rurAllowAction ) {
		NtRuleMap::Log(bCreate ? acsCreated : acsOpen, Subject, SubjectAttributes, RuleId, FileObject, nttFile, DeviceObject, NULL, DesiredAccess, Result);
	}

	if ( Result == rurAllowAction && bCreate == true ) {
		// copy params before file is deleted
		Aci::GetObjectInfo((PCHAR)&GesRule::GswLabel, FileObject, DeviceObject, nttFile, ObjectAttributes, RuleId);
	}

	ObDereferenceObject(FileObject);
	ZwClose(hFile); // if file was creted, it's deleted on close

	if ( Result != rurAllowAction ) {
		if ( usNewName.Buffer != NULL ) delete[] usNewName.Buffer;
		return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
	}

	rc = GswDispatch::PassThrough(DeviceObject, Irp);

	if ( NT_SUCCESS(rc) && Result == rurAllowAction && bCreate == true ) {
		// set object attributes
		NTSTATUS lrc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hFile, SYNCHRONIZE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
						NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, AttachedTo);
		if ( NT_SUCCESS(lrc) ) {
			lrc = ObReferenceObjectByHandle(hFile, SYNCHRONIZE, NULL, KernelMode, (PVOID *) &FileObject, NULL);
			if ( NT_SUCCESS(lrc) ) {
				Aci::SetObjectInfo((PCHAR)&GesRule::GswLabel, FileObject, DeviceObject, nttFile, ObjectAttributes);
				ObDereferenceObject(FileObject);
			}
			ZwClose(hFile);
		}
	}

	if ( usNewName.Buffer != NULL ) delete[] usNewName.Buffer;

	return rc;
}

NTSTATUS GetTargetName(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject,
						PFILE_OBJECT TargetFileObject, PFILE_RENAME_INFORMATION Info, 
						PUNICODE_STRING NewName)
{
	NTSTATUS rc;
	// get prefix name
	PUNICODE_STRING PrefixName = NULL;

	if ( TargetFileObject == NULL ) {
		// Easy just copy the pathname component of the fully qualified source filename and 
		// append the target filename. The target filename is the WCHAR string at FILE_RENAME_INFORMATION.FileName. 
		rc = GetFileName(FileObject, DeviceObject, &PrefixName);
		if ( !NT_SUCCESS(rc) ) {
			ERR(rc);
			return rc;
		}
		//
		// find the last pathname component of the source file
		//
		LONG i = PrefixName->Length / sizeof WCHAR - 1; 
		while ( i >= 0 && PrefixName->Buffer[i] != '\\' ) i--;
		if ( i < 0 ) {
			//
			// the file system will fail too
			//
			rc = STATUS_UNSUCCESSFUL;
			ERR(rc);
			return rc;
		}
		PrefixName->Length = (USHORT) ( i * sizeof WCHAR );
	} else {
		//
		// Get path directory name if present
		//
		if ( Info->RootDirectory != NULL ) {
			PFILE_OBJECT FileObject;
			rc = ObReferenceObjectByHandle(Info->RootDirectory, STANDARD_RIGHTS_REQUIRED,
											NULL, KernelMode, (PVOID *)&FileObject, NULL);
			if ( !NT_SUCCESS(rc) ) {
				ERR(rc);
				return rc;
			}

			NTSTATUS rc = GetFileName(FileObject, DeviceObject, &PrefixName);
			ObDereferenceObject(FileObject);
			if ( !NT_SUCCESS(rc) ) {
				ERR(rc);
				return rc;
			}
		}
	}
	//
	// NewName = Prefix + FILE_RENAME_INFORMATION.FileName
	//
	UNICODE_STRING usTargetName = { (USHORT)Info->FileNameLength, (USHORT)Info->FileNameLength, Info->FileName };
	USHORT Length = (USHORT) ( ( PrefixName != NULL ? PrefixName->Length + sizeof WCHAR : 0 ) + usTargetName.Length );
	NewName->Buffer = new(PagedPool) WCHAR[Length / sizeof WCHAR];
	if ( NewName->Buffer == NULL ) {
		delete PrefixName;
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}
	NewName->MaximumLength = Length;
	NewName->Length = 0;

	if ( PrefixName != NULL ) {
		rc = RtlAppendUnicodeStringToString(NewName, PrefixName);
		delete PrefixName;
		if ( NT_SUCCESS(rc) ) {
			rc = RtlAppendUnicodeToString(NewName, L"\\");
		}
		if ( !NT_SUCCESS(rc) ) {
			delete[] NewName->Buffer;
			NewName->Buffer = NULL;
			NewName->Length = 0;
			NewName->MaximumLength = 0;
			ERR(rc);
			return rc;
		}
	}

	rc = RtlAppendUnicodeStringToString(NewName, &usTargetName);
	if ( !NT_SUCCESS(rc) ) {
		delete[] NewName->Buffer;
		NewName->Buffer = NULL;
		NewName->Length = 0;
		NewName->MaximumLength = 0;
		ERR(rc);
		return rc;
	}

	return rc;
}

}; // namespace SetInfo {

}; // namespace FsFilter {