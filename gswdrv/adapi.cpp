//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "adapi.h"
#include "tools.h"

PKE_SERVICE_DESCRIPTOR_TABLE_ENTRY KeServiceDescriptorTableShadow = NULL;

namespace AdApi {

	_ObSetSecurityObjectByPointer ObSetSecurityObjectByPointer = NULL;
	_ZwOpenProcessTokenEx ZwOpenProcessTokenEx = NULL;
	_IoAttachDeviceToDeviceStackSafe IoAttachDeviceToDeviceStackSafe = NULL;
	_IoCreateFileSpecifyDeviceObjectHint IoCreateFileSpecifyDeviceObjectHint = NULL;
	_IoQueryFileDosDeviceName IoQueryFileDosDeviceName = NULL;
	_IoGetLowerDeviceObject IoGetLowerDeviceObject = NULL;
	_PsIsThreadImpersonating PsIsThreadImpersonating = NULL;

    KPROCESSOR_MODE __PsGetCurrentThreadPreviousMode(VOID);

	NTSTATUS NTAPI __ObSetSecurityObjectByPointer(
		IN PVOID Object,
		IN SECURITY_INFORMATION SecurityInformation,
		IN PSECURITY_DESCRIPTOR SecurityDescriptor
		);

    NTSTATUS NTAPI __ZwOpenProcessTokenEx(
        IN HANDLE       ProcessHandle,
        IN ACCESS_MASK  DesiredAccess,
        IN ULONG        HandleAttributes,
        OUT PHANDLE     TokenHandle
        );

    NTSTATUS __IoAttachDeviceToDeviceStackSafe(
        IN PDEVICE_OBJECT  SourceDevice,
        IN PDEVICE_OBJECT  TargetDevice,
        IN OUT PDEVICE_OBJECT  *AttachedToDeviceObject 
        );

	NTSTATUS __IoCreateFileSpecifyDeviceObjectHint(
		OUT PHANDLE  FileHandle,
		IN ACCESS_MASK  DesiredAccess,
		IN POBJECT_ATTRIBUTES  ObjectAttributes,
		OUT PIO_STATUS_BLOCK  IoStatusBlock,
		IN PLARGE_INTEGER  AllocationSize OPTIONAL,
		IN ULONG  FileAttributes,
		IN ULONG  ShareAccess,
		IN ULONG  Disposition,
		IN ULONG  CreateOptions,
		IN PVOID  EaBuffer OPTIONAL,
		IN ULONG  EaLength,
		IN CREATE_FILE_TYPE  CreateFileType,
		IN PVOID  ExtraCreateParameters OPTIONAL,
		IN ULONG  Options,
		IN PVOID  DeviceObject
		);

	NTSTATUS __IoQueryFileDosDeviceName(
		IN PFILE_OBJECT FileObject,
		OUT POBJECT_NAME_INFORMATION *ObjectNameInformation
		);

	BOOLEAN __PsIsThreadImpersonating(IN PETHREAD Thread); 

    ULONG ServiceTableOffset = 0;
	ULONG NtVer = 0;

	POBJECT_TYPE *ObTypeIndexTable = NULL;
}


NTSTATUS AdApi::Init(VOID)
{
    UNICODE_STRING usName;
    ULONG NtMajor, NtMinor;
    PsGetVersion(&NtMajor, &NtMinor, NULL, NULL);
    NtVer = NtMajor << 16 | NtMinor;

    RtlInitUnicodeString(&usName, L"ObSetSecurityObjectByPointer");
    PVOID SysRoutine = MmGetSystemRoutineAddress(&usName);
    if ( SysRoutine == NULL )
		ObSetSecurityObjectByPointer = __ObSetSecurityObjectByPointer;
	else
		ObSetSecurityObjectByPointer = (_ObSetSecurityObjectByPointer) SysRoutine;

    RtlInitUnicodeString(&usName, L"ZwOpenProcessTokenEx");
    SysRoutine = MmGetSystemRoutineAddress(&usName);
    if ( SysRoutine == NULL )
		ZwOpenProcessTokenEx = __ZwOpenProcessTokenEx;
	else
		ZwOpenProcessTokenEx = (_ZwOpenProcessTokenEx) SysRoutine;

    RtlInitUnicodeString(&usName, L"IoAttachDeviceToDeviceStackSafe");
    SysRoutine = MmGetSystemRoutineAddress(&usName);
    if ( SysRoutine == NULL )
		IoAttachDeviceToDeviceStackSafe = __IoAttachDeviceToDeviceStackSafe;
	else
		IoAttachDeviceToDeviceStackSafe = (_IoAttachDeviceToDeviceStackSafe) SysRoutine;

    RtlInitUnicodeString(&usName, L"IoCreateFileSpecifyDeviceObjectHint");
    SysRoutine = MmGetSystemRoutineAddress(&usName);
    if ( SysRoutine == NULL )
		IoCreateFileSpecifyDeviceObjectHint = __IoCreateFileSpecifyDeviceObjectHint;
	else
		IoCreateFileSpecifyDeviceObjectHint = (_IoCreateFileSpecifyDeviceObjectHint) SysRoutine;

    RtlInitUnicodeString(&usName, L"IoQueryFileDosDeviceName");
    SysRoutine = MmGetSystemRoutineAddress(&usName);
    if ( SysRoutine == NULL )
		IoQueryFileDosDeviceName = __IoQueryFileDosDeviceName;
	else
		IoQueryFileDosDeviceName = (_IoQueryFileDosDeviceName) SysRoutine;

    RtlInitUnicodeString(&usName, L"IoGetLowerDeviceObject");
    SysRoutine = MmGetSystemRoutineAddress(&usName);
	IoGetLowerDeviceObject = (_IoGetLowerDeviceObject) SysRoutine;

    RtlInitUnicodeString(&usName, L"PsIsThreadImpersonating");
    SysRoutine = MmGetSystemRoutineAddress(&usName);
    if ( SysRoutine == NULL )
		PsIsThreadImpersonating = __PsIsThreadImpersonating;
	else
		PsIsThreadImpersonating = (_PsIsThreadImpersonating) SysRoutine;

    //
    // Get ServiceTable offset in PETHREAD structure
    //
    PETHREAD Thread = PsGetCurrentThread();
    for (ULONG i=0; i<PAGE_SIZE; i++)
        if ( *(PKE_SERVICE_DESCRIPTOR_TABLE_ENTRY *)((PCHAR)Thread + i) == KeServiceDescriptorTable ) {
            ServiceTableOffset = i;
            break;
        }

	if ( NtVer >= 0x00060001 ) {
		//
		// Get ObTypeIndexTable
		//
		static const UCHAR Stamp[] = { 0x8b, 0x04, 0x85 };
	    
		RtlInitUnicodeString(&usName, L"NtQuerySecurityObject");
		SysRoutine = MmGetSystemRoutineAddress(&usName);
		if ( SysRoutine != NULL ) {

			PCHAR Cur = (PCHAR) SysRoutine;
			POBJECT_TYPE *Temp;

			for ( ULONG i=0; i < 512; i++ )
				if ( RtlCompareMemory(Cur, Stamp, sizeof Stamp) == sizeof Stamp ) {
					Temp = (POBJECT_TYPE *)( *PLONG_PTR(Cur+3) );
					//
					// validate with driver object type
					//
					UCHAR Index = *PUCHAR(PUCHAR(gDriverObject) - 0x0c);
					if ( Temp[Index] == *IoDriverObjectType ) {
						ObTypeIndexTable = Temp;
					}
					break;
				} 
				else
					Cur++;
		}

		if ( ObTypeIndexTable == NULL ) {
			ERR(STATUS_UNSUCCESSFUL);
			return STATUS_UNSUCCESSFUL;
		}

	}

    return STATUS_SUCCESS;
}


BOOLEAN AdApi::InitShadowTable(VOID)
{
    if ( KeServiceDescriptorTableShadow != NULL || ServiceTableOffset == 0 ) 
        return FALSE;

    PETHREAD Thread = PsGetCurrentThread();
    PKE_SERVICE_DESCRIPTOR_TABLE_ENTRY ServiceTable = 
        *(PKE_SERVICE_DESCRIPTOR_TABLE_ENTRY *)((PCHAR)Thread + ServiceTableOffset);

    if ( ServiceTable != KeServiceDescriptorTable ) {
        if ( InterlockedCompareExchangePointer((PVOID *)&KeServiceDescriptorTableShadow, ServiceTable, NULL) == NULL ) {
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS NTAPI AdApi::__ObSetSecurityObjectByPointer(
	IN PVOID Object,
	IN SECURITY_INFORMATION SecurityInformation,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor
	)
{
    POBJECT_HEADER ObjectHeader = GetObjectHeader(Object);
    POBJECT_TYPE ObjectType = ObjectHeader->ObjectType;

    return ObjectType->ObjectTypeInitializer.SecurityProcedure(
                        Object,
                        NULL,
                        &SecurityInformation,
                        SecurityDescriptor,
                        NULL,
                        &ObjectHeader->SecurityDescriptor,
                        ObjectType->ObjectTypeInitializer.PagedPool,
                        &ObjectType->ObjectTypeInitializer.GenericMapping);
}

NTSTATUS NTAPI AdApi::__ZwOpenProcessTokenEx(
    IN HANDLE       ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN ULONG        HandleAttributes,
    OUT PHANDLE     TokenHandle
    )
{
    NTSTATUS rc;

    HANDLE hToken;
    rc = ZwOpenProcessToken(ProcessHandle, TOKEN_QUERY, &hToken);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    PVOID Token;
    rc = ObReferenceObjectByHandle(hToken, 0, 0, KernelMode, &Token, NULL);
    if ( !NT_SUCCESS(rc) ) {
        ZwClose(hToken);
        ERR(rc);
        return rc;
    }

    HANDLE hProcess;
    rc = ObOpenObjectByPointer(Token, OBJ_KERNEL_HANDLE, 0, DesiredAccess, 
                               0, KernelMode, TokenHandle);
    ZwClose(hToken);
    ObDereferenceObject(Token);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    return rc;
}


NTSTATUS AdApi::__IoAttachDeviceToDeviceStackSafe(
    IN PDEVICE_OBJECT  SourceDevice,
    IN PDEVICE_OBJECT  TargetDevice,
    IN OUT PDEVICE_OBJECT  *AttachedToDeviceObject 
    )
{
    *AttachedToDeviceObject = TargetDevice;
    *AttachedToDeviceObject = IoAttachDeviceToDeviceStack(SourceDevice, TargetDevice);
    if (*AttachedToDeviceObject == NULL) {
        return STATUS_NO_SUCH_DEVICE;
    }

    return STATUS_SUCCESS;
}

NTSTATUS AdApi::__IoCreateFileSpecifyDeviceObjectHint(
    OUT PHANDLE  FileHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN PLARGE_INTEGER  AllocationSize OPTIONAL,
    IN ULONG  FileAttributes,
    IN ULONG  ShareAccess,
    IN ULONG  Disposition,
    IN ULONG  CreateOptions,
    IN PVOID  EaBuffer OPTIONAL,
    IN ULONG  EaLength,
    IN CREATE_FILE_TYPE  CreateFileType,
    IN PVOID  ExtraCreateParameters OPTIONAL,
    IN ULONG  Options,
    IN PVOID  DeviceObject
    )
{
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS AdApi::__IoQueryFileDosDeviceName(
	IN PFILE_OBJECT FileObject,
	OUT POBJECT_NAME_INFORMATION *ObjectNameInformation
	)
{
	PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(FileObject);
	if ( DeviceObject == NULL ) return STATUS_UNSUCCESSFUL;

	PDEVICE_OBJECT RealDeviceObject;
	if ( FileObject->Vpb != NULL && FileObject->Vpb->RealDevice != NULL )
		RealDeviceObject = FileObject->Vpb->RealDevice;
	else
	if ( FileObject->DeviceObject->Vpb != NULL && FileObject->DeviceObject->Vpb->RealDevice != NULL )
		RealDeviceObject = FileObject->DeviceObject->Vpb->RealDevice;
	else {
		return GetObjectName((PVOID)FileObject, (PUNICODE_STRING *)ObjectNameInformation);
	}
	//
	// Get file name
	//
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

        rc = QueryFile(DeviceObject, FileObject, FileNameInformation, FileNameInfo, Length);

    } while ( rc == STATUS_INFO_LENGTH_MISMATCH || rc == STATUS_BUFFER_OVERFLOW );

    if ( !NT_SUCCESS(rc) ) {
         delete[] FileNameInfo;
         FileNameInfo = NULL;
         //ERR(rc);
         return rc;
    }

	UNICODE_STRING DosName;
	rc = RtlVolumeDeviceToDosName(RealDeviceObject, &DosName);
    if ( !NT_SUCCESS(rc) ) {
         delete[] FileNameInfo;
         FileNameInfo = NULL;
         //ERR(rc);
         return rc;
    }

	*ObjectNameInformation = (POBJECT_NAME_INFORMATION) 
		new UCHAR[sizeof OBJECT_NAME_INFORMATION + FileNameInfo->FileNameLength + DosName.Length];
	if ( *ObjectNameInformation == NULL ) {
		delete DosName.Buffer;
		delete[] FileNameInfo;
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}

	(*ObjectNameInformation)->Name.Buffer = (WCHAR *) ( (PUCHAR)*ObjectNameInformation + sizeof OBJECT_NAME_INFORMATION );
	(*ObjectNameInformation)->Name.Length = FileNameInfo->FileNameLength + DosName.Length;
	(*ObjectNameInformation)->Name.MaximumLength = (*ObjectNameInformation)->Name.Length;

	RtlCopyMemory((*ObjectNameInformation)->Name.Buffer, DosName.Buffer, DosName.Length);
	RtlCopyMemory((*ObjectNameInformation)->Name.Buffer + DosName.Length / sizeof WCHAR, FileNameInfo->FileName, FileNameInfo->FileNameLength);

	return STATUS_SUCCESS;
}

BOOLEAN AdApi::__PsIsThreadImpersonating(IN PETHREAD Thread)
{
	BOOLEAN CopyOnOpen;
	BOOLEAN EffectiveOnly;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;

	PACCESS_TOKEN Token = PsReferenceImpersonationToken(Thread, &CopyOnOpen, &EffectiveOnly, &ImpersonationLevel);
	if ( Token != NULL ) {
		PsDereferenceImpersonationToken(Token);
		return TRUE;
	}

	return FALSE;
}

POBJECT_TYPE AdApi::GetObjectType(PVOID Object)
{
	if ( NtVer < 0x00060001 ) {
		return GetObjectHeader(Object)->ObjectType;
	} else {
		UCHAR Index = *PUCHAR(PUCHAR(gDriverObject) - 0x0c);
		return ObTypeIndexTable[Index];
	}
}