//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "netfilter.h"
#include "tdiio.h"
#include "tools.h"

namespace NetFilter {

PDRIVER_DISPATCH Dispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
VOID DefferedInit(PVOID context);
PEPROCESS SystemProcess = NULL;

NTSTATUS GetObjectName(PVOID FileObject, PVOID RelatedObject, PUNICODE_STRING *ObjectName)
{
	if ( RelatedObject == NULL ) {
		*ObjectName = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS rc = STATUS_SUCCESS;

	const SIZE_T NameLength = 25 * sizeof(WCHAR);
	*ObjectName = (PUNICODE_STRING) new(PagedPool) UCHAR[sizeof UNICODE_STRING + NameLength];
	if ( *ObjectName == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}

	(*ObjectName)->Buffer = (WCHAR *)( (PUCHAR)*ObjectName + sizeof UNICODE_STRING );
	(*ObjectName)->MaximumLength = NameLength;

	Ip4_Address *Dest = (Ip4_Address *) RelatedObject;

	WCHAR Buf[25];
	rc = RtlStringCbPrintfW((*ObjectName)->Buffer, NameLength, L"%d.%d.%d.%d:%d", Dest->addr[0], Dest->addr[1], Dest->addr[2], Dest->addr[3], ntohs(Dest->sin_port));
	if ( !NT_SUCCESS(rc) ) {
		delete *ObjectName;
		*ObjectName = NULL;
		ERR(rc);
		return rc;
	}

	(*ObjectName)->Length = wcslen((*ObjectName)->Buffer) * sizeof(WCHAR);

	return rc;
}

bool CompareIP4(PVOID RelatedObject, IP4Address *Addr)
{
	if ( Addr->Ip == 0 )
		return TRUE;

	Ip4_Address *Dest = (Ip4_Address *) RelatedObject;

	// if address is not identified, then match it
	//if ( Dest->in_addr == 0 )
	//	return TRUE;

	bool Result = ( Dest->in_addr & Addr->Mask ) == Addr->Ip;
	if ( Result && Addr->Port != 0 )
		Result = Dest->sin_port == Addr->Port;

	return Result;
}

NTSTATUS AttachTdi(VOID)
{
    NTSTATUS rc = STATUS_SUCCESS;

    static const struct {
        TargetDeviceType Type;
        WCHAR *Name;
    } TcpipDevice[] =  {
        { tdtTcp, L"\\Device\\Tcp" },
        { tdtUdp, L"\\Device\\Udp" },
        { tdtRawIp, L"\\Device\\RawIp" },
        { tdtMulticast, L"\\Device\\IPMULTICAST" },
        { tdtIp, L"\\Device\\Ip" } };

    static const TcpipDevicesNumber = sizeof TcpipDevice / sizeof TcpipDevice[0];

    for ( SIZE_T i = 0; i < TcpipDevicesNumber; i++ ) {

        UNICODE_STRING usDeviceName;
        RtlInitUnicodeString(&usDeviceName, TcpipDevice[i].Name);

        PFILE_OBJECT FileObject;
        PDEVICE_OBJECT DeviceObject;
        rc = IoGetDeviceObjectPointer(&usDeviceName, FILE_READ_DATA, &FileObject, &DeviceObject);
        if (!NT_SUCCESS(rc)) {
            ERR(rc);
			SleepEx(100, FALSE);
            continue;
        }

        ObReferenceObject(DeviceObject);
        ObDereferenceObject(FileObject);

		PDEVICE_OBJECT NewDeviceObject;
		rc = IoCreateDevice(gDriverObject, sizeof Extension,  NULL, DeviceObject->DeviceType, 0,  FALSE, &NewDeviceObject);
		if (!NT_SUCCESS(rc)) {
			ERR(rc);
			continue;
		}    
	  
		Extension *DevExt = (Extension *) NewDeviceObject->DeviceExtension;
		//
		// Initialize extension
		//
		DevExt->TargetType = TcpipDevice[i].Type;
		DevExt->Dispatch = Dispatch;

		for ( int j = 0; j < 100; j++ ) {
			rc = GswDispatch::AttachDevice(DeviceObject, NewDeviceObject);
			if ( NT_SUCCESS(rc) ) break;
			SleepEx(100, FALSE);
		}
        ObDereferenceObject(DeviceObject);
        if (!NT_SUCCESS(rc)) {
			IoDeleteDevice(NewDeviceObject);
            ERR(rc);
        }
    }
	
	return rc;
}

VOID DefferedInit(PVOID context)
{
    NTSTATUS rc;

	PFILE_OBJECT FileObject;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING usDevName;
	RtlInitUnicodeString(&usDevName, L"\\Device\\Tcp");

	for ( ULONG i = 0; i < 100; i++ ) {
		rc = IoGetDeviceObjectPointer(&usDevName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
		if ( NT_SUCCESS(rc) ) break;
		SleepEx(2000, FALSE);
	}

	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

	ObDereferenceObject(FileObject);

	rc = AttachTdi();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

cleanup:
	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS Init(VOID)
{
    NTSTATUS rc = STATUS_SUCCESS;

	SystemProcess = PsGetCurrentProcess();

    RtlZeroMemory(Dispatch, sizeof Dispatch);
	Dispatch[IRP_MJ_DEVICE_CONTROL] = TdiIo::ControlDispatch;
    Dispatch[IRP_MJ_INTERNAL_DEVICE_CONTROL] = TdiIo::ControlDispatch;

	HANDLE hDefferedInit;
	rc = PsCreateSystemThread(&hDefferedInit, THREAD_ALL_ACCESS, NULL, NULL, NULL, DefferedInit, NULL);
	if ( NT_SUCCESS(rc) ) {
		ZwClose(hDefferedInit);
	}

	return rc;
}

VOID Release(VOID)
{
}

} // namespace NetFilter {
