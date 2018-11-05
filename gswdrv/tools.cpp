//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "tools.h"
#include "fstools.h"

// Process name offset in KPEB
ULONG gProcessNameOffset;


//
//  GetProcessNameOffset - Scan the KPEB looking for the "System" process name - because 
//                   DriverEntry is called in that context.  This offset becomes a 
//                   reference for later. Set global variable gProcessNameOffset.
//
// Parameters:
//    none
//
//  IRQL_PASSIVE_LEVEL
//
//  return: none
//
VOID GetProcessNameOffset(VOID)
{
    gProcessNameOffset = 0;

    PEPROCESS curproc = PsGetCurrentProcess();
    for (ULONG i = 0; i < 3*PAGE_SIZE; i++ )
        if ( !strncmp( "System", (PCHAR) curproc + i, 6 )) {

            gProcessNameOffset = i;
			break;
        }
}


//
//  GetProcessNameByPointer - Get the name of the current process. 
//				gProcessNameOffset has to be set before first call of this function.
//
// Parameters:
//	  [in] curproc - EPROCESS pointer
//    [out] theName - buffer for name. NT_PROCNAMELEN defines maximum length of the buffer.
//
//  IRQL_PASSIVE_LEVEL
//
//  return:
//    process name
//
BOOLEAN GetProcessNameByPointer(_EPROCESS *curproc, PCHAR theName)
{
	if ( curproc != NULL ) {
		if( gProcessNameOffset ) {
			PCHAR nameptr = (PCHAR) curproc + gProcessNameOffset;
			strncpy( theName, nameptr, NT_PROCNAMELEN-2 );
			theName[NT_PROCNAMELEN-1] = 0; /* NULL at end */
			return TRUE;
		} 
	} else {
		strncpy( theName, "System", NT_PROCNAMELEN-2 );
	}

	return FALSE;
}

SIZE_T GetProcessNameByPointer(_EPROCESS *curproc, WCHAR *theName)
{
	if ( curproc != NULL ) {
		if( gProcessNameOffset ) {
			PCHAR nameptr = (PCHAR) curproc + gProcessNameOffset;
			SIZE_T i;
			for ( i = 0; *nameptr && i < NT_PROCNAMELEN-2; i++, nameptr++ )
				theName[i] = (WCHAR)*nameptr;

			theName[i] = 0; /* NULL at end */
			return i;
		} 
	} else {
		wcsncpy( theName, L"System", NT_PROCNAMELEN-2 );
	}

	return 0;
}


HANDLE GetProcessIdByProcess(PEPROCESS Process)
{
	HANDLE hProcess;
    NTSTATUS rc = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 
                                    0, *PsProcessType, KernelMode, &hProcess);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return NULL;
	}

	PROCESS_BASIC_INFORMATION Info;
	rc = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &Info, sizeof Info, NULL);
	ZwClose(hProcess);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return NULL;
	}

	return LongToHandle(Info.UniqueProcessId);
}

NTSTATUS GetObjectName(PFILE_OBJECT FileObject, PUNICODE_STRING *FileName)
{
    *FileName = NULL;
    if ( FileObject == NULL ) return STATUS_UNSUCCESSFUL;
	PDEVICE_OBJECT RelatedObject = IoGetRelatedDeviceObject(FileObject);
	if ( RelatedObject == NULL ) return STATUS_UNSUCCESSFUL;

	PDEVICE_OBJECT RealDeviceObject;
	if ( FileObject->Vpb != NULL && FileObject->Vpb->RealDevice != NULL )
		RealDeviceObject = FileObject->Vpb->RealDevice;
	else
	if ( FileObject->DeviceObject->Vpb != NULL && FileObject->DeviceObject->Vpb->RealDevice != NULL )
		RealDeviceObject = FileObject->DeviceObject->Vpb->RealDevice;
	else
		return STATUS_UNSUCCESSFUL;

	NTSTATUS rc;
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

        rc = QueryFile(RelatedObject, FileObject, FileNameInformation, 
                       FileNameInfo, Length);

    } while ( rc == STATUS_INFO_LENGTH_MISMATCH || rc == STATUS_BUFFER_OVERFLOW );

    if ( !NT_SUCCESS(rc) ) {
         delete[] FileNameInfo;
         FileNameInfo = NULL;
         //ERR(rc);
         return rc;
    }
	//
	// Get Device Name
	//
	PUNICODE_STRING DeviceName;
	rc = GetObjectName(RealDeviceObject, &DeviceName);
	if ( !NT_SUCCESS(rc) ) {
		delete[] FileNameInfo;
		ERR(rc);
		return rc;
	}
    //
	// Copy full name to unicode_string
	//
    Length = DeviceName->Length + (USHORT)FileNameInfo->FileNameLength + sizeof UNICODE_STRING;
    PVOID Buf = new(PagedPool) UCHAR[Length];
    if ( Buf == NULL ) {
        delete[] FileNameInfo;
		delete DeviceName;
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    *FileName = (PUNICODE_STRING) Buf;
    (*FileName)->Length = Length - sizeof UNICODE_STRING;
    (*FileName)->MaximumLength = (*FileName)->Length;
    (*FileName)->Buffer = (WCHAR *) ( (UCHAR *)*FileName + sizeof UNICODE_STRING );
    RtlCopyMemory((*FileName)->Buffer, DeviceName->Buffer, DeviceName->Length);
    RtlCopyMemory((*FileName)->Buffer + DeviceName->Length / sizeof WCHAR, 
		FileNameInfo->FileName, FileNameInfo->FileNameLength);
    delete[] FileNameInfo;
	delete DeviceName;

	return rc;
}

NTSTATUS GetObjectName(PVOID Object, PUNICODE_STRING *ObjectName)
{
    *ObjectName = NULL;
    if ( Object == NULL ) return STATUS_UNSUCCESSFUL;

	NTSTATUS rc;
	ULONG ActualLength;
    ULONG size = 256*sizeof(WCHAR)+sizeof(UNICODE_STRING);

    do {
        size *= 2;
        if (*ObjectName != NULL) {
            delete[] *ObjectName;
            *ObjectName = NULL;
        }

        *ObjectName = (PUNICODE_STRING) new(PagedPool) UCHAR[size];

        if ( *ObjectName == NULL ) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
            ERR(rc);
            return rc;
        }

        rc = ObQueryNameString(Object, 
						  (POBJECT_NAME_INFORMATION)*ObjectName,
						  size,
						  &ActualLength);

    } while ( rc == STATUS_INFO_LENGTH_MISMATCH || rc == STATUS_BUFFER_OVERFLOW );


    if (!NT_SUCCESS(rc)) {
         delete[] *ObjectName;
         *ObjectName = NULL;
         //ERR(rc);
         return rc;
    }

    return rc;
}

NTSTATUS GetRegistryObjectName(PVOID Object, PUNICODE_STRING ValueName, PUNICODE_STRING *ObjectName)
{
    *ObjectName = NULL;
    if ( Object == NULL ) return STATUS_UNSUCCESSFUL;

	NTSTATUS rc;
	ULONG ActualLength;
	ULONG PostFixSize = ValueName->Length + sizeof WCHAR;
	ULONG size = 256*sizeof(WCHAR) + PostFixSize + sizeof(UNICODE_STRING);

    do {
        size *= 2;
        if (*ObjectName != NULL) {
            delete[] *ObjectName;
            *ObjectName = NULL;
        }

        *ObjectName = (PUNICODE_STRING) new(PagedPool) UCHAR[size];

        if ( *ObjectName == NULL ) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
            ERR(rc);
            return rc;
        }

        rc = ObQueryNameString(Object, 
						  (POBJECT_NAME_INFORMATION)*ObjectName,
						  size - PostFixSize,
						  &ActualLength);

    } while ( rc == STATUS_INFO_LENGTH_MISMATCH || rc == STATUS_BUFFER_OVERFLOW );


    if (!NT_SUCCESS(rc)) {
         delete[] *ObjectName;
         *ObjectName = NULL;
         //ERR(rc);
         return rc;
    }
	//
	// Add value name
	//
	// assume buffer comes after unicode_string
	(*ObjectName)->MaximumLength = (PUCHAR)*ObjectName + size - (PUCHAR)(*ObjectName)->Buffer;
	RtlAppendUnicodeToString(*ObjectName, L"\\");
	RtlAppendUnicodeStringToString(*ObjectName, ValueName);

    return rc;
}

NTSTATUS RegReadValue(HANDLE hKey, PUNICODE_STRING usValue, PVOID *Buf, ULONG *BufSize, ULONG *Type OPTIONAL)
{
    ULONG Size = 0;
	NTSTATUS rc;
    rc = ZwQueryValueKey(hKey, usValue, KeyValuePartialInformation, NULL, 0, &Size);
    if ( rc != STATUS_BUFFER_OVERFLOW && rc != STATUS_BUFFER_TOO_SMALL &&
         rc != STATUS_INVALID_PARAMETER || Size == 0 ) {
        ERR(rc);
        return rc;
    }

    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) new(PagedPool) UCHAR[Size];
    if ( PartialInfo == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    rc = ZwQueryValueKey(hKey, usValue, KeyValuePartialInformation, PartialInfo, Size, &Size);
    if ( !NT_SUCCESS(rc) ) {
        delete[] PartialInfo;
        ERR(rc);
        return rc;
    }

    if ( Type != NULL && *Type != REG_NONE && PartialInfo->Type != *Type ) {
        delete[] PartialInfo;
        rc = STATUS_UNSUCCESSFUL;
        ERR(rc);
        return rc;
    }

    if ( *BufSize != 0 && *BufSize < PartialInfo->DataLength ) {
        *BufSize = PartialInfo->DataLength;
        delete[] PartialInfo;
        rc = STATUS_BUFFER_TOO_SMALL;
        ERR(rc);
        return rc;
    }

    if ( *BufSize == 0 ) {
        *Buf = new(PagedPool) UCHAR[PartialInfo->DataLength];
        if ( *Buf == NULL ) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
            ERR(rc);
            return rc;
        }
    }

    RtlCopyMemory(*Buf, PartialInfo->Data, PartialInfo->DataLength);
    if ( BufSize != NULL ) *BufSize = PartialInfo->DataLength;
    if ( Type != NULL ) *Type = PartialInfo->Type;
    delete[] PartialInfo;
	
	return rc;
}

NTSTATUS RegReadValue(HANDLE hKey, WCHAR *ValueName, PVOID *Buf, ULONG *BufSize, ULONG *Type OPTIONAL)
{
    UNICODE_STRING usValue;
    RtlInitUnicodeString(&usValue, ValueName);
	return RegReadValue(hKey, &usValue, Buf, BufSize, Type);
}

NTSTATUS RegReadValue(PUNICODE_STRING usKeyName, WCHAR *ValueName, PVOID *Buf, ULONG *BufSize, ULONG *Type OPTIONAL)
{
    NTSTATUS rc;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, usKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey;
    rc = ZwOpenKey(&hKey, KEY_READ, &oa);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

	rc = RegReadValue(hKey, ValueName, Buf, BufSize, Type);

	ZwClose(hKey);
    return rc;
}

NTSTATUS RegSaveValue(PUNICODE_STRING usKeyName, WCHAR *ValueName, PVOID Buf, ULONG BufSize, ULONG Type)
{
    NTSTATUS rc;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, usKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey;
    rc = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    UNICODE_STRING usValue;
    RtlInitUnicodeString(&usValue, ValueName);
    ULONG Size = 0;
    rc = ZwSetValueKey(hKey, &usValue, 0, Type, Buf, BufSize);
    ZwClose(hKey);

    return rc;
}


NTSTATUS Completion (IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context )
{
    ASSERT(Context != NULL);

    *Irp->UserIosb = Irp->IoStatus;

    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);

    IoFreeIrp(Irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS QueryFile(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject,
                   FILE_INFORMATION_CLASS FileInformationClass, PVOID FileQueryBuffer,
                   ULONG FileQueryBufferLength)
{
    NTSTATUS rc;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION IoStackLocation;

    //
    // Allocate an irp for this request.  This could also come from a 
    // private pool, for instance.
    //
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if(!Irp) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    //
    // Build the IRP's main body
    //  
    Irp->AssociatedIrp.SystemBuffer = FileQueryBuffer;
    Irp->UserIosb = &IoStatusBlock;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    //Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->RequestorMode = KernelMode;
    Irp->Flags = IRP_SYNCHRONOUS_API;

    //
    // Set up the I/O stack location.
    //
    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    IoStackLocation->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    IoStackLocation->DeviceObject = DeviceObject;
    IoStackLocation->FileObject = FileObject;
    IoStackLocation->Parameters.QueryFile.Length = FileQueryBufferLength;
    IoStackLocation->Parameters.QueryFile.FileInformationClass = FileInformationClass;

    //
    //  Initialize our completion routine
    //
    KEVENT WaitEvent;
    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

    IoSetCompletionRoutine(Irp, Completion, &WaitEvent, TRUE, TRUE, TRUE);

    //
    // Send it to the FSD
    //
    rc = IoCallDriver(DeviceObject, Irp);

    //
    //  Wait for the completion routine to be called.  
    //  Note:  Once we get to this point we can no longer fail this operation.
    //
    if ( rc == STATUS_PENDING ) {

      NTSTATUS localStatus = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
      ASSERT(STATUS_SUCCESS == localStatus);
    }

    //
    // Done! Note that since our completion routine frees the IRP we cannot 
    // touch the IRP now.
    //
    return IoStatusBlock.Status;
}

NTSTATUS SetFile(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject, FILE_INFORMATION_CLASS FileInformationClass,
				   PVOID FileQueryBuffer, ULONG FileQueryBufferLength)
{
    NTSTATUS rc;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION IoStackLocation;
	if ( DeviceObject == NULL ) DeviceObject = IoGetRelatedDeviceObject(FileObject);

    //
    // Allocate an irp for this request.  This could also come from a 
    // private pool, for instance.
    //
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if(!Irp) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    //
    // Build the IRP's main body
    //  
    Irp->AssociatedIrp.SystemBuffer = FileQueryBuffer;
    Irp->UserIosb = &IoStatusBlock;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    //Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->RequestorMode = KernelMode;
    Irp->Flags = IRP_SYNCHRONOUS_API;

    //
    // Set up the I/O stack location.
    //
    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    IoStackLocation->MajorFunction = IRP_MJ_SET_INFORMATION;
    IoStackLocation->DeviceObject = DeviceObject;
    IoStackLocation->FileObject = FileObject;
    IoStackLocation->Parameters.SetFile.Length = FileQueryBufferLength;
    IoStackLocation->Parameters.SetFile.FileInformationClass = FileInformationClass;

    //
    //  Initialize our completion routine
    //
    KEVENT WaitEvent;
    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

    IoSetCompletionRoutine(Irp, Completion, &WaitEvent, TRUE, TRUE, TRUE);

    //
    // Send it to the FSD
    //
    rc = IoCallDriver(DeviceObject, Irp);

    //
    //  Wait for the completion routine to be called.  
    //  Note:  Once we get to this point we can no longer fail this operation.
    //
    if ( rc == STATUS_PENDING ) {

      NTSTATUS localStatus = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
      ASSERT(STATUS_SUCCESS == localStatus);
    }

    //
    // Done! Note that since our completion routine frees the IRP we cannot 
    // touch the IRP now.
    //
	if ( NT_SUCCESS(rc) ) {
		rc = IoStatusBlock.Status;
	}
    return rc;
}

NTSTATUS QuerySecurityFile(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject,
                           SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR sd, ULONG *Length)
{
    NTSTATUS rc;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION IoStackLocation;

    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if ( Irp == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }
    //
    // Build the IRP's main body
    //  
    Irp->UserBuffer = sd;
    Irp->UserIosb = &IoStatusBlock;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    //Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->RequestorMode = KernelMode;
    Irp->Flags = IRP_SYNCHRONOUS_API;

    //
    // Set up the I/O stack location.
    //
    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    IoStackLocation->MajorFunction = IRP_MJ_QUERY_SECURITY;
    IoStackLocation->DeviceObject = DeviceObject;
    IoStackLocation->FileObject = FileObject;
    IoStackLocation->Parameters.QuerySecurity.Length = *Length;
    IoStackLocation->Parameters.QuerySecurity.SecurityInformation = SecurityInformation;

    //
    //  Initialize our completion routine
    //
    KEVENT WaitEvent;
    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

    IoSetCompletionRoutine(Irp, Completion, &WaitEvent, TRUE, TRUE, TRUE);

    //
    // Send it to the FSD
    //
    rc = IoCallDriver(DeviceObject, Irp);
    if ( rc == STATUS_PENDING ) {

      NTSTATUS lrc = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
    }

    *Length = IoStatusBlock.Information;
    return IoStatusBlock.Status;
}


NTSTATUS SetSecurityFile(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject,
                         SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR sd)
{
    NTSTATUS rc;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION IoStackLocation;

    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if ( Irp == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }
    //
    // Build the IRP's main body
    //  
    Irp->UserIosb = &IoStatusBlock;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    //Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->RequestorMode = KernelMode;
    Irp->Flags = IRP_SYNCHRONOUS_API;

    //
    // Set up the I/O stack location.
    //
    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    IoStackLocation->MajorFunction = IRP_MJ_SET_SECURITY;
    IoStackLocation->DeviceObject = DeviceObject;
    IoStackLocation->FileObject = FileObject;
    IoStackLocation->Parameters.SetSecurity.SecurityDescriptor = sd;
    IoStackLocation->Parameters.SetSecurity.SecurityInformation = SecurityInformation;

    //
    //  Initialize our completion routine
    //
    KEVENT WaitEvent;
    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

    IoSetCompletionRoutine(Irp, Completion, &WaitEvent, TRUE, TRUE, TRUE);

    //
    // Send it to the FSD
    //
    rc = IoCallDriver(DeviceObject, Irp);
    if ( rc == STATUS_PENDING ) {

      NTSTATUS lrc = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
    }

    return IoStatusBlock.Status;
}

USHORT BinToHex(UCHAR *Bin, LONG BinLength, WCHAR *Str, LONG StrLength)
{
    if ( StrLength < BinLength*2+1 )
        return 0;

    static WCHAR HexMap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                             '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    WCHAR *p =  Str;
    for (LONG i=0; i < BinLength; i++)  {
        *p++ = HexMap[Bin[i] >> 4]; 
        *p++ = HexMap[Bin[i] & 0xf];
    }
    *p = 0;

    return p - Str;
}


NTSTATUS BufferRequest(ULONG MajorFunction, PFILE_OBJECT FileObject, PVOID Buf, 
					   ULONG &Size, PLARGE_INTEGER pOffset)
{
    NTSTATUS rc;
    IO_STATUS_BLOCK ios;
    KEVENT Event;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    PDEVICE_OBJECT pDeviceObject = IoGetRelatedDeviceObject(FileObject);

    PIRP Irp = IoBuildSynchronousFsdRequest(MajorFunction, 
                                            pDeviceObject, 
                                            Buf, 
                                            Size, 
                                            pOffset, 
                                            &Event,
                                            &ios);
    if (Irp == NULL) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->FileObject = FileObject;
    Irp->RequestorMode = KernelMode;

    rc = IoCallDriver(pDeviceObject, Irp);

    if (rc == STATUS_PENDING) {
        rc = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    }

    if (NT_SUCCESS(rc)) {
        rc = ios.Status;
		Size = ios.Information;
	}

    return rc;
}

NTSTATUS CopyFile(HANDLE hSource, HANDLE hDest)
{
	NTSTATUS rc;
	static const Length = 256 * 1024;
	PUCHAR Buf = new (PagedPool) UCHAR[Length];
	if ( Buf == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}

	IO_STATUS_BLOCK ios;
	LARGE_INTEGER Offset = {0, 0};
	do {
		rc = ZwReadFile(hSource, NULL, NULL, NULL, &ios, Buf, Length, &Offset, NULL);
		if ( !NT_SUCCESS(rc) ) {
			ERR(rc);
			if ( rc == STATUS_END_OF_FILE ) rc = STATUS_SUCCESS;
			break;
		}

		ULONG Read = ios.Information;
		rc = ZwWriteFile(hDest, NULL, NULL, NULL, &ios, Buf, Read, &Offset, NULL);
		if ( !NT_SUCCESS(rc) || Read != ios.Information ) {
			ERR(rc);
			break;
		}
		Offset.QuadPart += ios.Information;
	} while ( ios.Information == Length );

	delete[] Buf;
	return rc;
}

NTSTATUS SendControl(PDEVICE_OBJECT DeviceObject, ULONG IoControlCode, PVOID InBuf, 
					 ULONG InSize, PVOID OutBuf, ULONG &OutSize)
{
	NTSTATUS rc = STATUS_UNSUCCESSFUL;

	if (DeviceObject == NULL) {
		ERR(rc);
		return rc;
	}

	KEVENT Event;
	IO_STATUS_BLOCK IoStatusBlock;
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	PIRP Irp = IoBuildDeviceIoControlRequest(IoControlCode, DeviceObject,
											  InBuf, InSize, OutBuf, OutSize,
											  TRUE, &Event, &IoStatusBlock);
	if (Irp == NULL) {
		ERR(STATUS_INSUFFICIENT_RESOURCES);
		rc = STATUS_INSUFFICIENT_RESOURCES;
	}

	rc = IoCallDriver(DeviceObject, Irp);
	if (rc == STATUS_PENDING)
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

	if ( NT_SUCCESS(rc) ) {
        rc = IoStatusBlock.Status;
		OutSize = IoStatusBlock.Information;
	}

	return rc;
}

BOOLEAN GetMD5(PVOID Buf, ULONG Length, md5_hash hash)
{
    crypt::hash_state md;
    crypt::md5_init(&md);
    crypt::md5_process(&md, (unsigned char *)Buf, Length);
    crypt::md5_done(&md, hash);

    return TRUE;
}

NTSTATUS ResolveSymLink(WCHAR *SymLink, PUNICODE_STRING ResolvedName)
{
	HANDLE hSymLink;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING usSymLink;
	RtlInitUnicodeString(&usSymLink, SymLink);
	InitializeObjectAttributes(&oa, &usSymLink, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS rc = ZwOpenSymbolicLinkObject(&hSymLink, SYMBOLIC_LINK_QUERY, &oa);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	rc = ZwQuerySymbolicLinkObject(hSymLink, ResolvedName, NULL);
	ZwClose(hSymLink);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	return rc;
}

NTSTATUS TranslateToUserRegistryName(PUNICODE_STRING RegName)
{
	static struct PrefixInfo {
		WCHAR *Name;
		WCHAR *UserName;
		SIZE_T NameSize;
		SIZE_T UserNameSize;
		SIZE_T Diff;
	} Prefix[] = {
		{ L"\\Registry\\Machine", L"HKLM", 0, 0, 0 },
		{ L"\\Registry\\User", L"HKU", 0, 0, 0 },
		{ L"\\Registry\\Machine\\Software\\CLASSES", L"HKCR", 0, 0, 0 },
		{ L"\\Registry\\User\\.Default", L"HKCU", 0, 0, 0 }
	};
	static bool Inited = false;
	if ( Inited == false ) {
		for ( SIZE_T i = 0; i < sizeof Prefix / sizeof Prefix[0]; i++ ) {
			Prefix[i].NameSize = wcslen(Prefix[i].Name) * sizeof WCHAR;
			Prefix[i].UserNameSize = wcslen(Prefix[i].UserName) * sizeof WCHAR;
			Prefix[i].Diff = Prefix[i].NameSize - Prefix[i].UserNameSize;
		}
		Inited = true;
	}

	for ( SIZE_T i = 0; i < sizeof Prefix / sizeof Prefix[0]; i++ ) {
		if ( RegName->Length >= Prefix[i].NameSize &&
			_wcsnicmp(RegName->Buffer, Prefix[i].Name, Prefix[i].NameSize / sizeof WCHAR) == 0 ) {

			RtlCopyMemory(RegName->Buffer, Prefix[i].UserName, Prefix[i].UserNameSize);
			RtlMoveMemory((PUCHAR)RegName->Buffer + Prefix[i].UserNameSize,
						  (PUCHAR)RegName->Buffer + Prefix[i].NameSize,
						  RegName->Length - Prefix[i].NameSize);
			RegName->Length -= Prefix[i].Diff;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

VOID SleepEx(LONG Milliseconds, BOOLEAN bAlertable)
{
	KEVENT wait_event;
	KeInitializeEvent(&wait_event, NotificationEvent, FALSE);

	LARGE_INTEGER timeout;
	timeout.QuadPart = -(Milliseconds * 10000);
	KeWaitForSingleObject(&wait_event, Executive, KernelMode, bAlertable, &timeout);
}

NTSTATUS DeleteSubKeys(PUNICODE_STRING KeyName)
{
	HANDLE hKey;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	NTSTATUS rc = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	static const SIZE_T BufferSize = 1024;
	PKEY_BASIC_INFORMATION KeyInfo = (PKEY_BASIC_INFORMATION) new(PagedPool) UCHAR[BufferSize];
	if ( KeyInfo == NULL ) {
		ZwClose(hKey);
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}

	while ( true ) {
		ULONG Length;
		rc = ZwEnumerateKey(hKey, 0, KeyBasicInformation, KeyInfo, BufferSize, &Length);
		if ( rc != STATUS_SUCCESS ) break;

		HANDLE hSubKey;
		UNICODE_STRING usSubKeyName = { KeyInfo->NameLength, KeyInfo->NameLength, KeyInfo->Name };
		InitializeObjectAttributes(&oa, &usSubKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hKey, NULL);
		rc = ZwOpenKey(&hSubKey, DELETE, &oa);
		if ( !NT_SUCCESS(rc) ) {
			ERR(rc);
			continue;
		}
		rc = ZwDeleteKey(hSubKey);
		ZwClose(hSubKey);
		if ( !NT_SUCCESS(rc) ) {
			ERR(rc);
		}
	}

	delete KeyInfo;
	ZwClose(hKey);
	return rc;
}

NTSTATUS GetFileSecurity(PFILE_OBJECT FileObject, PSECURITY_DESCRIPTOR *sd)
{
	if ( FileObject == NULL ) return STATUS_UNSUCCESSFUL;
	PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(FileObject);
	if ( DeviceObject == NULL ) return STATUS_UNSUCCESSFUL;
    //
    // Do not get sacl for network files
    //
    SECURITY_INFORMATION SecurityInformation = 
        DeviceObject->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ?
        OWNER_SECURITY_INFORMATION : OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

	return FsFilter::GetFileSD(FileObject, DeviceObject, sd, SecurityInformation);
}

BOOLEAN IsInteractiveContext(VOID)
{
	return TRUE;

	SECURITY_SUBJECT_CONTEXT  sc;
	SeCaptureSubjectContext(&sc);

	PTOKEN_GROUPS Groups = NULL;
	NTSTATUS rc = SeQueryInformationToken(SeQuerySubjectContextToken(&sc), TokenGroups, (PVOID *) &Groups);
	SeReleaseSubjectContext(&sc);
	if ( !NT_SUCCESS(rc) ) return FALSE;

	static const unsigned char InteractiveSid[] = {
		1,                           // rev
		1,                           // subauthcount
		0, 0, 0, 0, 0, 5,            // sia
		4, 0, 0, 0
	};

	for ( ULONG i = 0; i < Groups->GroupCount; i++ ) {
		if ( RtlEqualSid(Groups->Groups[i].Sid, (PSID)InteractiveSid) ) {
			ExFreePool(Groups);
			return TRUE;
		}
	}

	ExFreePool(Groups);
	return FALSE;
}

PUNICODE_STRING CopyUnicodeString(PUNICODE_STRING Src)
{
	PUNICODE_STRING Dest = (PUNICODE_STRING) new(PagedPool) UCHAR[Src->Length + sizeof UNICODE_STRING];
	if ( Dest == NULL ) {
		ERR(STATUS_INSUFFICIENT_RESOURCES);
		return NULL;
	}

	Dest->Buffer = (WCHAR *)((PUCHAR)Dest + sizeof UNICODE_STRING);
	RtlCopyMemory(Dest->Buffer, Src->Buffer, Src->Length);
	Dest->Length = Src->Length;
	Dest->MaximumLength = Src->Length;

	return Dest;
}


PUNICODE_STRING GetProcessImageName(PEPROCESS Process)
{
    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process
	PUNICODE_STRING imageName = NULL;

	KAPC_STATE ApcState;
	bool DettachRequired = false;
	if ( Process != PsGetCurrentProcess() ) {
		KeStackAttachProcess(Process, &ApcState);
		DettachRequired = true;
	}
    //
    // get the size we need
    //
    ULONG returnedLength;
    NTSTATUS rc = ZwQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)ProcessImageFileName, NULL, 0, &returnedLength);
	if ( rc == STATUS_INFO_LENGTH_MISMATCH ) {
		imageName = (PUNICODE_STRING) new(PagedPool) UCHAR[returnedLength];
		if ( imageName != NULL ) {
			rc = ZwQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)ProcessImageFileName, imageName, returnedLength, &returnedLength);
			if ( !NT_SUCCESS(rc) ) {
				delete imageName;
				imageName = NULL;
				ERR(rc);
			}
		} else {
			ERR(STATUS_INSUFFICIENT_RESOURCES);
		}
	} else
	if ( rc == STATUS_INVALID_INFO_CLASS ) {

		PROCESS_BASIC_INFORMATION BasicInfo;
		rc = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &BasicInfo, sizeof PROCESS_BASIC_INFORMATION, &returnedLength);
		if ( NT_SUCCESS(rc) && BasicInfo.PebBaseAddress != NULL ) {
			if ( BasicInfo.PebBaseAddress) {
				PPEB Peb = (PPEB) BasicInfo.PebBaseAddress;
				__try {
					WCHAR *Buffer = Peb->ProcessParameters->ImagePathName.Buffer;
					if ( (PCHAR)Buffer < (PCHAR)Peb->ProcessParameters ) Buffer = (WCHAR *)( (PCHAR)Peb->ProcessParameters + (ULONG_PTR)Buffer );
					USHORT Length = Peb->ProcessParameters->ImagePathName.Length;
					SIZE_T Size = sizeof UNICODE_STRING + Length;
					static const WCHAR Prefix[] = L"\\??\\";
					SIZE_T PrefixLength = 0;
					if ( *Buffer != '\\' ) {
						PrefixLength = sizeof Prefix - sizeof Prefix[0];
						Size += PrefixLength;
					}

					imageName = (PUNICODE_STRING) new(PagedPool) UCHAR[Size];
					if ( imageName != NULL ) {
						imageName->Buffer = (WCHAR *) ( (PCHAR)imageName + sizeof UNICODE_STRING );
						if ( PrefixLength != 0 ) {
							RtlCopyMemory(imageName->Buffer, Prefix, PrefixLength);
						}
						RtlCopyMemory((PCHAR)imageName->Buffer + PrefixLength, Buffer, Length);
						imageName->Length = PrefixLength + Length;
						imageName->MaximumLength = imageName->Length;
					}
				} __except ( EXCEPTION_EXECUTE_HANDLER ) {
					if ( imageName != NULL ) delete imageName;
					imageName = NULL;
					ERR(GetExceptionCode());
				}
			}
		}
	} else {
		ERR(rc);
	}

	if ( DettachRequired ) KeUnstackDetachProcess(&ApcState);

	return imageName;
}

