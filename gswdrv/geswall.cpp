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
#include "hook.h"
#include "aci.h"
#include "ntrulemap.h"
#include "sxrule.h"
#include "fsfilter.h"
#include "request.h"
#include "sysprocess.h"
#include "netfilter.h"


PDEVICE_OBJECT gControlDevice = NULL;
PDRIVER_OBJECT gDriverObject = NULL;
ULONG NtVer;

// {DA439DC5-B2A1-4b07-8988-F8F5981201D0}
DEFINE_GUID(GUID_SD_GESWALL_CONTROL_OBJECT, 
0xda439dc5, 0xb2a1, 0x4b07, 0x89, 0x88, 0xf8, 0xf5, 0x98, 0x12, 0x1, 0xd0);

VOID OnUnload(IN PDRIVER_OBJECT DriverObject);

extern "C" NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath );
UNICODE_STRING usRegParamName;

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
	NTSTATUS rc = STATUS_SUCCESS;
    ULONG i;

    gDriverObject = DriverObject;

    //KdBreakPoint();
    ULONG NtMajor, NtMinor;
    PsGetVersion(&NtMajor, &NtMinor, NULL, NULL);
    NtVer = NtMajor << 16 | NtMinor;

    rc = AdApi::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

	//---------------------------------------------------------------
	// Create dispatch points for all routines that must be handled
	//
#if DBG
	DriverObject->DriverUnload  = OnUnload;
#endif

	rc = GswDispatch::Init(DriverObject);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

    //
	// Get process name offset
	GetProcessNameOffset();

    //
    // Build param reg key name
    //
    UNICODE_STRING usSubParam;
    RtlInitUnicodeString(&usSubParam, L"\\Parameters");

    ULONG Size = usSubParam.Length +  RegistryPath->Length;
    usRegParamName.Buffer = (WCHAR *) new(PagedPool) UCHAR[Size];
    if ( usRegParamName.Buffer == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
        return rc;
    }

    RtlCopyMemory(usRegParamName.Buffer, RegistryPath->Buffer, RegistryPath->Length);
    RtlCopyMemory((PUCHAR)usRegParamName.Buffer + RegistryPath->Length, usSubParam.Buffer, usSubParam.Length);
    usRegParamName.Length = (USHORT)Size;
    usRegParamName.MaximumLength = usRegParamName.Length;

    rc = Log::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

	trace("\n\n\n============ Starting %s ============\n", P);

    rc = SysProcess::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

    rc = Request::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}
	rc = Rule::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

    rc = NtRuleMap::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

    rc = SxRule::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}


    Rule::RuleInfo RuleInfo;
    *(PULONG)RuleInfo.Label = 'LWSG';
    RuleInfo.AccessObject = NtRuleMap::AccessObject;
    RuleInfo.MapSubject = NtRuleMap::MapSubject;
    RuleInfo.CreateSubject = NtRuleMap::CreateSubject;
	RuleInfo.DeleteSubject = NtRuleMap::DeleteSubject;

    rc = Rule::Register(RuleInfo);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}
/*
    *(PULONG)RuleInfo.Label = 'EXES';
    RuleInfo.AccessObject = SxRule::AccessObject;
    RuleInfo.MapSubject = SxRule::MapSubject;
    RuleInfo.CreateSubject = SxRule::CreateSubject;

    rc = Rule::Register(RuleInfo);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}
*/
    rc = Aci::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

	rc = Hook::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

    rc = FsFilter::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

    rc = NetFilter::Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}
    //    
    // Setup the control device
    //    
    UNICODE_STRING usDeviceName;
    RtlInitUnicodeString(&usDeviceName, L"\\Device\\"DEVICE_NAME);

	UNICODE_STRING SddlString;
	RtlInitUnicodeString(&SddlString, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)");

    rc = IoCreateDeviceSecure(DriverObject,
                        0,
                        &usDeviceName,
                        FILE_DEVICE_GESWALL,
                        FILE_DEVICE_SECURE_OPEN,
                        FALSE,
						&SddlString,
						(LPCGUID)&GUID_SD_GESWALL_CONTROL_OBJECT,
                        &gControlDevice);

    if (!NT_SUCCESS(rc)) {
		ERR(rc);
        trace(P"IoCreateDeviceSecure failed\n");
		goto cleanup;
	}
	gControlDevice->DeviceExtension = NULL;

    //
	// Create a symbolic link
    //
    UNICODE_STRING usDeviceSymLink;
    RtlInitUnicodeString(&usDeviceSymLink, L"\\DosDevices\\"DEVICE_NAME);
    rc = IoCreateSymbolicLink(&usDeviceSymLink, &usDeviceName);
    if (!NT_SUCCESS(rc)) {
		ERR(rc);
        trace(P"IoCreateSymbolicLink failed\n");
		goto cleanup;
    }

	//
	// set rules attributes on control device and registry
	//
	EntityAttributes Attributes;
	RtlZeroMemory(&Attributes, sizeof Attributes);
	Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
	Attributes.Param[GesRule::attOptions] = GesRule::oboGeSWall;
	Aci::SetObjectInfo((PCHAR)&GesRule::GswLabel, gControlDevice, NULL, nttDevice, Attributes);

cleanup:
    if (!NT_SUCCESS(rc))
        OnUnload(DriverObject);
    else
	    trace(P"successfuly started\n");

	return rc;
}

//
// Driver is not unloadable
//
VOID OnUnload( IN PDRIVER_OBJECT DriverObject )
{
	NTSTATUS		rc = STATUS_UNSUCCESSFUL;
	UNICODE_STRING	usDeviceSymLink;

	trace(P"unloading...\n");

	Hook::Release();
    Aci::Release();
    Rule::Release();
    Log::Release();

	//
	// Delete the symbolic link 
	//
	RtlInitUnicodeString(&usDeviceSymLink, L"\\DosDevices\\"DEVICE_NAME);
	IoDeleteSymbolicLink(&usDeviceSymLink);
	if (gControlDevice != NULL) IoDeleteDevice(gControlDevice);

    if ( usRegParamName.Buffer != NULL ) delete[] usRegParamName.Buffer;
}
