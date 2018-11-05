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
#include "fstools.h"
#include "tools.h"
#include "adapi.h"

namespace FsFilter {

extern PDEVICE_OBJECT BootVdo;

NTSTATUS GetFileName(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject,
                     PUNICODE_STRING *FileName)
{
    NTSTATUS rc;
    Extension *DevExt = (Extension *) DeviceObject->DeviceExtension;
    PFILE_NAME_INFORMATION FileNameInfo = NULL;
    USHORT Length = 256 * sizeof WCHAR + sizeof UNICODE_STRING;

    do {
        Length *= 2;
        if ( FileNameInfo != NULL ) {
            delete[] FileNameInfo;
            FileNameInfo = NULL;
        }

        FileNameInfo = (PFILE_NAME_INFORMATION) new(PagedPool) UCHAR[Length];
        if ( FileNameInfo == NULL ) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
            ERR(rc);
            return rc;
        }

        rc = QueryFile(DevExt->AttachedTo, FileObject, FileNameInformation, 
                       FileNameInfo, Length);

    } while ( rc == STATUS_INFO_LENGTH_MISMATCH || rc == STATUS_BUFFER_OVERFLOW );

    if ( !NT_SUCCESS(rc) ) {
         delete[] FileNameInfo;
         FileNameInfo = NULL;
         //ERR(rc);
         return rc;
    }
    //
	// Copy full name to unicode_string
	//
    Length = DevExt->DeviceName->Length + (USHORT)FileNameInfo->FileNameLength + sizeof UNICODE_STRING;
    PVOID Buf = new(PagedPool) UCHAR[Length];
    if ( Buf == NULL ) {
        delete[] FileNameInfo;
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    *FileName = (PUNICODE_STRING) Buf;
    (*FileName)->Length = Length - sizeof UNICODE_STRING;
    (*FileName)->MaximumLength = (*FileName)->Length;
    (*FileName)->Buffer = (WCHAR *) ( (UCHAR *)*FileName + sizeof UNICODE_STRING );
    RtlCopyMemory((*FileName)->Buffer, DevExt->DeviceName->Buffer, DevExt->DeviceName->Length);
    RtlCopyMemory((*FileName)->Buffer + DevExt->DeviceName->Length / sizeof WCHAR, 
		FileNameInfo->FileName, FileNameInfo->FileNameLength);
    delete[] FileNameInfo;

	//
	// get long name
	//
	rc = GetLongName(DevExt->AttachedTo, FileName);
    if ( !NT_SUCCESS(rc) ) {
         ERR(rc);
         return rc;
    }

	return rc;
}

NTSTATUS GetFileSecurity(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, 
                                   PSECURITY_DESCRIPTOR *sd)
{
    Extension *DevExt = (Extension *) DeviceObject->DeviceExtension;
    //
    // Do not get sacl for network files
    //
    SECURITY_INFORMATION SecurityInformation = 
        DevExt->AttachedTo->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ?
        OWNER_SECURITY_INFORMATION : OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

	return GetFileSD(FileObject, DevExt->AttachedTo, sd, SecurityInformation);
}

NTSTATUS GetFileSD(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, 
                             PSECURITY_DESCRIPTOR *sd, SECURITY_INFORMATION SecurityInformation)
{
    NTSTATUS rc;
    ULONG Length = 0;
    *sd = NULL;
    
    rc = QuerySecurityFile(FileObject, DeviceObject, SecurityInformation, *sd, &Length);
    if ( Length == 0 ) {
        //	ERR(rc);
        return rc;
    }

    *sd = new(PagedPool) UCHAR[Length];
    if ( *sd == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    rc = QuerySecurityFile(FileObject, DeviceObject, SecurityInformation, *sd, &Length);

    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        delete[] *sd;
        *sd = NULL;
    }

    return rc;
}

NTSTATUS SetSecurityFile(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject,
                         SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR sd)
{
    Extension *DevExt = (Extension *) DeviceObject->DeviceExtension;
	return ::SetSecurityFile(FileObject, DevExt->AttachedTo, SecurityInformation, sd);
}

NTSTATUS ComposeFileName(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, PUNICODE_STRING FileName)
{
	NTSTATUS rc = STATUS_SUCCESS;
	//
    // get file name from file object
	//
	if ( FileObject->RelatedFileObject != NULL ) {
		//
		// Get related file name
		//
		PUNICODE_STRING RelatedName = NULL;
		rc = GetFileName(FileObject->RelatedFileObject, DeviceObject, &RelatedName);
		if ( !NT_SUCCESS(rc) ) {
			ERR(rc);
			return rc;
		}
		FileName->Buffer = 
			new(PagedPool) WCHAR[ ( FileObject->FileName.Length + RelatedName->Length ) / sizeof WCHAR ];
		if ( FileName->Buffer == NULL ) {
			delete[] RelatedName;
			rc = STATUS_INSUFFICIENT_RESOURCES;
			ERR(rc);
			return rc;
		}
		FileName->Length = 0;
		FileName->MaximumLength = (USHORT) ( FileObject->FileName.Length + RelatedName->Length );
		RtlDowncaseUnicodeString(FileName, RelatedName, FALSE);
		delete[] RelatedName;
	} else {
		//
		// Append volume name
		//
		PUNICODE_STRING DeviceName = ((Extension *)DeviceObject->DeviceExtension)->DeviceName;
		FileName->Buffer = 
			new(PagedPool) WCHAR[ ( FileObject->FileName.Length + DeviceName->Length ) / sizeof WCHAR ];
		if ( FileName->Buffer == NULL ) {
			rc = STATUS_INSUFFICIENT_RESOURCES;
			ERR(rc);
			return rc;
		}
		FileName->Length = 0;
		FileName->MaximumLength = (USHORT) ( FileObject->FileName.Length + DeviceName->Length );
		RtlDowncaseUnicodeString(FileName, DeviceName, FALSE);
	}
	//
	// Append file name
	//
	UNICODE_STRING Temp = { 0, FileName->MaximumLength - FileName->Length, 
							FileName->Buffer + FileName->Length / sizeof WCHAR };
	RtlDowncaseUnicodeString(&Temp, &FileObject->FileName, FALSE);
	FileName->Length = FileName->MaximumLength;

	return rc;
}

NTSTATUS SendFsControl(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject, 
					   ULONG FsControlCode, PVOID InBuf, ULONG InSize, PVOID OutBuf, ULONG &OutSize)
{
	if ( DeviceObject == NULL )
		DeviceObject = IoGetRelatedDeviceObject(FileObject);

	NTSTATUS rc;
	IO_STATUS_BLOCK IoStatusBlock;
	KEVENT Event;
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	PIRP Irp = IoBuildDeviceIoControlRequest(FsControlCode, DeviceObject,
											 InBuf, InSize, OutBuf, OutSize,
											 TRUE, &Event, &IoStatusBlock);
	if ( Irp == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}

	PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
    IrpSp->MinorFunction = IRP_MN_KERNEL_CALL;
    IrpSp->Parameters.FileSystemControl.FsControlCode = FsControlCode;
    IrpSp->Parameters.FileSystemControl.InputBufferLength = InSize;
    IrpSp->Parameters.FileSystemControl.OutputBufferLength = OutSize;
	IrpSp->FileObject = FileObject;
    Irp->RequestorMode = KernelMode;

	rc = IoCallDriver(DeviceObject, Irp);

	if ( rc == STATUS_PENDING )
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

	if ( NT_SUCCESS(rc) ) {
        rc = IoStatusBlock.Status;
		OutSize = (ULONG)IoStatusBlock.Information;
	}

	return rc;
}

NTSTATUS QueryDirectoryFile(
	IN PDEVICE_OBJECT DeviceObject, 
	IN PFILE_OBJECT FileObject, 
	OUT PVOID FileInformation, 
	IN ULONG Length, 
	IN FILE_INFORMATION_CLASS FileInformationClass, 
    IN BOOLEAN ReturnSingleEntry,
    IN PUNICODE_STRING FileName OPTIONAL,
    IN BOOLEAN RestartScan
    )
{
	if ( DeviceObject == NULL )
		DeviceObject = IoGetRelatedDeviceObject(FileObject);

	NTSTATUS rc;
	IO_STATUS_BLOCK IoStatusBlock;
	KEVENT Event;
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	//
	// HACK: Convert destination device flags to iocontrol code.
	//
	ULONG Code = METHOD_NEITHER;
	if ( DeviceObject->Flags & DO_BUFFERED_IO ) Code = METHOD_BUFFERED;
	else
	if ( DeviceObject->Flags & DO_DIRECT_IO ) Code = METHOD_OUT_DIRECT;
	//
	// allocate Irp
	//
	PIRP Irp = IoBuildDeviceIoControlRequest(0, DeviceObject,
											 NULL, 0, FileInformation, Length,
											 TRUE, &Event, &IoStatusBlock);
	if ( Irp == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}

	PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    IrpSp->MinorFunction = IRP_MN_QUERY_DIRECTORY;
	IrpSp->Parameters.QueryDirectory.FileInformationClass = FileInformationClass;
	IrpSp->Parameters.QueryDirectory.FileName = FileName;
	IrpSp->Parameters.QueryDirectory.Length = Length;
	IrpSp->Parameters.QueryDirectory.FileIndex = 0;
	IrpSp->FileObject = FileObject;
    if ( RestartScan ) IrpSp->Flags |= SL_RESTART_SCAN;
    if ( ReturnSingleEntry ) IrpSp->Flags |= SL_RETURN_SINGLE_ENTRY;
    Irp->RequestorMode = KernelMode;

    Irp->Flags |= IRP_DEFER_IO_COMPLETION;

	rc = IoCallDriver(DeviceObject, Irp);

	if ( rc == STATUS_PENDING )
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

	if ( NT_SUCCESS(rc) ) {
        rc = IoStatusBlock.Status;
	}

	return rc;
}


NTSTATUS GetLongName(PDEVICE_OBJECT DeviceObject, PUNICODE_STRING *FileName)
{
	//
	// we don't care about all cases, just check for ~
	// optimize for long names
	//
	NTSTATUS rc = STATUS_SUCCESS;
	SIZE_T Current = 0;
	PFILE_FULL_DIR_INFORMATION DirInfo = NULL;
	SIZE_T DirInfoSize = 1024;
	while ( true ) {
		WCHAR *Buffer = (*FileName)->Buffer + Current;
		WCHAR *End = (WCHAR *)( (PUCHAR)(*FileName)->Buffer + (*FileName)->Length );
		while ( true ) {
			if ( Buffer >= End ) {
				//
				// String handled, no more conversions required
				//
				goto cleanup;
			}
			if ( *Buffer == '~' ) break;
			Buffer++;
		}
		//
		// short name fragment discovered, extend it
		//

		//
		// 1. Get directory name
		//
		WCHAR *DirEnd;
		for ( DirEnd = Buffer; DirEnd > (*FileName)->Buffer && *DirEnd != '\\'; DirEnd-- );
		SIZE_T DirLength = (PUCHAR)DirEnd - (PUCHAR)(*FileName)->Buffer + sizeof WCHAR;
		UNICODE_STRING usDirName = { (USHORT)DirLength, (USHORT)DirLength, (*FileName)->Buffer };
		//
		// 2. Open directory
		//
		NTSTATUS rc;
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK ios;
		HANDLE hDir;
		InitializeObjectAttributes(&oa, &usDirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hDir, SYNCHRONIZE | FILE_LIST_DIRECTORY, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 
							FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
							NULL, 0, CreateFileTypeNone, NULL, 
							IO_NO_PARAMETER_CHECKING /* | IO_IGNORE_SHARE_ACCESS_CHECK */, DeviceObject);
		if ( !NT_SUCCESS(rc) ) {
			ERR(rc);
			goto cleanup;
		}
		//
		// 3. QueryDirectory information for long name
		//
		UNICODE_STRING usFileName;
		WCHAR *FileEnd;
		usFileName.Buffer = &(*FileName)->Buffer[DirLength / sizeof WCHAR];
		for ( FileEnd = usFileName.Buffer; FileEnd < End && *FileEnd != '\\'; FileEnd++ );
		usFileName.Length = (USHORT)((PUCHAR)FileEnd - (PUCHAR)usFileName.Buffer);
		usFileName.MaximumLength = usFileName.Length;

		while ( true ) {
			if ( DirInfo == NULL ) {
				DirInfo = (PFILE_FULL_DIR_INFORMATION) ExAllocatePoolWithQuotaTag(PagedPool, DirInfoSize, 'MNLG');
				if ( DirInfo == NULL ) {
					ZwClose(hDir);
					rc = STATUS_INSUFFICIENT_RESOURCES;
					ERR(rc);
					return rc;
				}
			}
			rc = ZwQueryDirectoryFile(hDir, NULL, NULL, NULL, &ios, DirInfo, (ULONG)DirInfoSize, FileFullDirectoryInformation,
									TRUE, &usFileName, TRUE);
			if ( rc == STATUS_BUFFER_OVERFLOW ) {
				//
				// bigger buffer required, just double the size
				//
				ExFreePool(DirInfo);
				DirInfo = NULL;
				DirInfoSize *= 2;
				continue;
			}
			ZwClose(hDir);
			if ( !NT_SUCCESS(rc) ) {
				ERR(rc);
				goto cleanup;
			}
			break;
		}
		//
		// 4. Extend the name with received long name fragment
		//

		// allocate new buffer
		SIZE_T NewLength = (*FileName)->Length - usFileName.Length + DirInfo->FileNameLength;
		PUNICODE_STRING NewFileName = 
			(PUNICODE_STRING) ExAllocatePoolWithQuotaTag(PagedPool, NewLength + sizeof UNICODE_STRING, 'MNLG');
		if ( NewFileName == NULL ) {
			rc = STATUS_INSUFFICIENT_RESOURCES;
			ERR(rc);
			goto cleanup;
		}
		NewFileName->Buffer = (WCHAR *) ( (PUCHAR)NewFileName + sizeof UNICODE_STRING );
		NewFileName->Length = (USHORT)NewLength;
		NewFileName->MaximumLength = (USHORT)NewLength;
		Buffer = NewFileName->Buffer;
		// copy prefix
		SIZE_T CopyLength = DirLength;
		RtlCopyMemory(Buffer, (*FileName)->Buffer, CopyLength);
		// copy new file name
		RtlCopyMemory((PUCHAR)Buffer + CopyLength, DirInfo->FileName, DirInfo->FileNameLength);
		// copy suffix
		CopyLength += DirInfo->FileNameLength;
		RtlCopyMemory((PUCHAR)Buffer + CopyLength, FileEnd, (PUCHAR)End - (PUCHAR)FileEnd);
		//
		// 5. Assign new buffer
		//
		Current = ( (PUCHAR)usFileName.Buffer - (PUCHAR)(*FileName)->Buffer + DirInfo->FileNameLength ) / sizeof WCHAR;
		delete *FileName;
		*FileName = NewFileName;
	}

cleanup:
	if ( DirInfo != NULL ) ExFreePool(DirInfo);
	return rc;
}

NTSTATUS DeleteDirFiles(PUNICODE_STRING DirName)
{
	if ( BootVdo == NULL ) return STATUS_UNSUCCESSFUL;

	NTSTATUS rc;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ios;
	HANDLE hDir;
	InitializeObjectAttributes(&oa, DirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hDir, SYNCHRONIZE | FILE_LIST_DIRECTORY, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 
							FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
							NULL, 0, CreateFileTypeNone, NULL, 
							IO_NO_PARAMETER_CHECKING /* | IO_IGNORE_SHARE_ACCESS_CHECK */, 
							((Extension *)BootVdo->DeviceExtension)->AttachedTo);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	static const SIZE_T BufferSize = 2048;
	PVOID Buffer = new(PagedPool) UCHAR[BufferSize];
	if ( Buffer == NULL ) {
		ZwClose(hDir);
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}

	BOOLEAN Restart = TRUE;
	while ( true ) {
		rc = ZwQueryDirectoryFile(hDir, NULL, NULL, NULL, &ios, Buffer, BufferSize, FileDirectoryInformation,
								FALSE, NULL, Restart);
		if ( rc != STATUS_SUCCESS ) break;
		Restart = FALSE;
		PFILE_DIRECTORY_INFORMATION DirInfo = (PFILE_DIRECTORY_INFORMATION) Buffer;
		
		while ( true ) {
			if ( !( DirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY ) ) {
				UNICODE_STRING usFileName = { (USHORT)DirInfo->FileNameLength, (USHORT)DirInfo->FileNameLength, DirInfo->FileName };
				InitializeObjectAttributes(&oa, &usFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hDir, NULL);
				HANDLE hFile;
				rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hFile, SYNCHRONIZE | DELETE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
										0, FILE_OPEN, 
										FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
										NULL, 0, CreateFileTypeNone, NULL, 
										IO_NO_PARAMETER_CHECKING /* | IO_IGNORE_SHARE_ACCESS_CHECK */, 
										((Extension *)BootVdo->DeviceExtension)->AttachedTo);
				if ( NT_SUCCESS(rc) ) {
					//
					// Delete on close
					//
					ZwClose(hFile);
				} else
					ERR(rc);
			}
			if ( DirInfo->NextEntryOffset == 0 ) break;
			DirInfo = (PFILE_DIRECTORY_INFORMATION) ( (PUCHAR)DirInfo + DirInfo->NextEntryOffset );
		}
	}

	delete Buffer;
	ZwClose(hDir);
	return rc;
}

} // namespace FsFilter