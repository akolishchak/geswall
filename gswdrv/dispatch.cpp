//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "lock.h"
#include "dispatch.h"
#include "aci.h"
#include "win32set.h"
#include "request.h"
#include "ntrulemap.h"
#include "acidyn.h"
#include "tools.h"

namespace GswDispatch {

PDRIVER_OBJECT DriverObject = NULL;

bool IsDeviceAttached(PDEVICE_OBJECT TargetDevice);

LIST_ENTRY DeviceList;
CEResource Syn;

NTSTATUS CommonDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Extension *DevExt = (Extension *) DeviceObject->DeviceExtension;
    if ( DevExt != NULL ) {
        PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
        PDRIVER_DISPATCH Dispatch = *(DevExt->Dispatch)[IrpSp->MajorFunction];

        if ( Dispatch != NULL ) 
            return Dispatch(DeviceObject, Irp);
        //
        // Pass through
        //
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(DevExt->AttachedTo, Irp);
    }

    NTSTATUS rc = STATUS_UNSUCCESSFUL;
	EntityAttributes Attributes;
	Rule::RedirectStatus Redirect;
	ULONG RuleId;

	Irp->IoStatus.Information = 0;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	if ( IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL ) {

	    ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
		//
		// access check
		//
		if ( ( ( IoControlCode>>14 & 3 ) & FILE_WRITE_ACCESS ) && IoControlCode != GESWALL_IOCTL_REFRESH_SETTINGS ) {
			//
			// TODO:
			//
			rc = Aci::GetSubjectInfo((CHAR *)&GesRule::GswLabel, Hook::GetCurrentProcess(), Attributes, Redirect, RuleId);
			if ( NT_SUCCESS(rc) ) {
				if ( !( Attributes.Param[GesRule::attIntegrity] == GesRule::modTCB && 
					    ( IoControlCode == GESWALL_IOCTL_SET_ATTRIBUTES || ( Attributes.Param[GesRule::attOptions] & ( GesRule::oboGeSWall | GesRule::oboSetup ) ) )
					  )
				   ) {
				    rc = STATUS_ACCESS_DENIED;
					Irp->IoStatus.Status = rc;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return rc;
				}
			}
		}
		//
		// call appropriate handler
		//
		PVOID InBuf = Irp->AssociatedIrp.SystemBuffer;
        ULONG InBufLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	    PVOID OutBuf = Irp->AssociatedIrp.SystemBuffer;
		ULONG OutBufLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
		switch ( IoControlCode ) {
            case GESWALL_IOCTL_REFRESH_RULES:
                rc = Aci::Refresh();
                break;

			case GESWALL_IOCTL_ADD_RULES:
				rc = Aci::LoadRules((RulePack *)InBuf, InBufLength);
				break;

			case GESWALL_IOCTL_W32HOOKSET_INIT:
				rc = Win32Set::Init();
				break;

			case GESWALL_IOCTL_W32HOOKSET_RELEASE:
				rc = Win32Set::Release();
				break;

			case GESWALL_IOCTL_W32HOOKSET_SYNC:
				if ( InBufLength < sizeof W32HooksetSyncParams ) {
					rc = STATUS_INVALID_PARAMETER;
					ERR(rc);
					break;
				}
				rc = Win32Set::Sync((W32HooksetSyncParams *)InBuf);
				break;

			case GESWALL_IOCTL_GET_REQUEST:
			case GESWALL_IOCTL_GET_NOTIFICATION:
				return Request::ServiceOffer(Irp);
				 
			case GESWALL_IOCTL_POST_REPLY:	
			case GESWALL_IOCTL_REPLY_REQUEST:
				return Request::ApplyResponse(Irp);
				 
			case GESWALL_IOCTL_STOP_HANDLING:	
				return Request::InformStop(Irp);

			case GESWALL_IOCTL_REGISTER_HANDLER:
				rc = Request::AddHandler(IrpSp->FileObject);
				break;

			case GESWALL_IOCTL_SET_ATTRIBUTES:
				{
					if ( InBufLength < sizeof SetAttributesInfo ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}
					SetAttributesInfo *Info = (SetAttributesInfo *)InBuf;
					rc = Aci::SetObjectInfo(Info->Label, Info->hObject, Info->ResType, Info->Attr);
				}
				break;

			case GESWALL_IOCTL_GET_SUBJ_ATTRIBUTES:
				{
					if ( InBufLength < sizeof GetSubjAttributesInfo ||
						 OutBufLength < sizeof SubjAttributesInfo ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}

					GetSubjAttributesInfo *Info = (GetSubjAttributesInfo *)InBuf;
					PEPROCESS Process;
					rc = PsLookupProcessByProcessId(Info->ProcessId, &Process);
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
						break;
					}

					rc = Aci::GetSubjectInfo(Info->Label, Process, Attributes, Redirect, RuleId);
					ObDereferenceObject(Process);
					if ( NT_SUCCESS(rc) ) {
						SubjAttributesInfo *SubjInfo = (SubjAttributesInfo *) OutBuf;
						SubjInfo->Attr = Attributes;
						// patch if required
						if ( NtRuleMap::PolicyOptions & GesRule::ploIsolatedOnlyJailed && Attributes.Param[GesRule::attIntegrity] != GesRule::modUntrusted ) {
							SubjInfo->Attr.Param[GesRule::attIntegrity] = GesRule::modTCB;
						}
						SubjInfo->RuleId = RuleId;
						Irp->IoStatus.Information = sizeof SubjAttributesInfo;
					}
				}
				break;

			case GESWALL_IOCTL_GET_CURRENT_SUBJ_ATTRIBUTES:
				{
					if ( OutBufLength < sizeof SubjAttributesInfo ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}

					rc = Aci::GetSubjectInfo((CHAR *)&GesRule::GswLabel, Hook::GetCurrentProcess(), Attributes, Redirect, RuleId);
					if ( NT_SUCCESS(rc) ) {
						SubjAttributesInfo *SubjInfo = (SubjAttributesInfo *) OutBuf;
						SubjInfo->Attr = Attributes;
						// patch if required
						if ( NtRuleMap::PolicyOptions & GesRule::ploIsolatedOnlyJailed && Attributes.Param[GesRule::attIntegrity] != GesRule::modUntrusted ) {
							SubjInfo->Attr.Param[GesRule::attIntegrity] = GesRule::modTCB;
						}
						SubjInfo->RuleId = RuleId;
						Irp->IoStatus.Information = sizeof SubjAttributesInfo;
					}
				}
				break;

			case GESWALL_IOCTL_REFRESH_SETTINGS:
				rc = NtRuleMap::GetSettings();
				break;

			case GESWALL_IOCTL_GET_PROCESSID:
				{
                	if ( InBufLength < sizeof PVOID || OutBufLength < sizeof HANDLE ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}
					*(HANDLE *)OutBuf = Hook::GetProcessId(*(PEPROCESS *)InBuf);
					Irp->IoStatus.Information = sizeof HANDLE;
					rc = STATUS_SUCCESS;
				}
				break;

			case GESWALL_IOCTL_GET_PROCESS_EXECNAME:
				{
					if ( InBufLength < sizeof HANDLE ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}

					PEPROCESS Process;
					rc = PsLookupProcessByProcessId(*(HANDLE *)InBuf, &Process);
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
						break;
					}

					PUNICODE_STRING FileName = Hook::GetProcessFileName(Process);
					ObDereferenceObject(Process);
					if ( FileName == NULL ) {
						rc = STATUS_UNSUCCESSFUL;
						ERR(rc);
						break;
					}

					if ( OutBufLength < ( FileName->Length + sizeof WCHAR ) ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}

					RtlCopyMemory(OutBuf, FileName->Buffer, FileName->Length);
					((WCHAR *)OutBuf)[FileName->Length / sizeof WCHAR] = 0;
					Irp->IoStatus.Information = FileName->Length + sizeof WCHAR;
					rc = STATUS_SUCCESS;
				}
				break;

			case GESWALL_IOCTL_GET_OBJ_ATTRIBUTES:
				{
					if ( InBufLength < sizeof GetObjectAttributesInfo ||
						 OutBufLength < sizeof ObjectAttributesInfo ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}

					GetObjectAttributesInfo *Info = (GetObjectAttributesInfo *)InBuf;
					if ( Info->Type != nttFile ) {
						// only files are supported
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}

					KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
					PVOID Object;
					rc = ObReferenceObjectByHandle(Info->hObject, FILE_READ_ATTRIBUTES, *IoFileObjectType, KeGetPreviousMode(), &Object, NULL);
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
						break;
					}

					rc = Aci::GetObjectInfo(Info->Label, Object, NULL, Info->Type, Attributes, Info->RuleId);
					ObDereferenceObject(Object);
					if ( NT_SUCCESS(rc) ) {
						ObjectAttributesInfo *ObjInfo = (ObjectAttributesInfo *) OutBuf;
						ObjInfo->Attr = Attributes;
						Irp->IoStatus.Information = sizeof ObjectAttributesInfo;
					}
				}
				break;

			case GESWALL_IOCTL_GET_RELEASE_ID:
				{
					if ( OutBufLength < sizeof LONG ) {
						rc = STATUS_INVALID_PARAMETER;
						ERR(rc);
						break;
					}
					*(LONG *)OutBuf = RELEASE_ID;
					Irp->IoStatus.Information = sizeof LONG;
					rc = STATUS_SUCCESS;
				}
				break;

			//case GESWALL_IOCTL_DISABLE_REDIRECT:
			//	rc = AciDyn::DisableRedirect(PsGetCurrentProcess());
			//	break;

			default:
			    rc = STATUS_INVALID_DEVICE_REQUEST;
				break;
		}
    } else 
    if ( IrpSp->MajorFunction == IRP_MJ_CREATE ) {
		rc = STATUS_SUCCESS;

    } else 
    if ( IrpSp->MajorFunction == IRP_MJ_CLEANUP || 
	     IrpSp->MajorFunction == IRP_MJ_CLOSE ) {

        if ( IrpSp->MajorFunction == IRP_MJ_CLEANUP ) {
			Request::RemoveService(Irp);
		}

	    rc = STATUS_SUCCESS;
	}

	Irp->IoStatus.Status = rc;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return rc;
}

NTSTATUS BlockedCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
    )
{
    ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));
    ASSERT(Context != NULL);

    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS BlockedCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    KEVENT WaitEvent;
    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, BlockedCompletion, &WaitEvent, TRUE, TRUE, TRUE);

    NTSTATUS rc = IoCallDriver(DeviceObject, Irp);
    if ( rc == STATUS_PENDING ) {
        rc = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
        ASSERT( STATUS_SUCCESS == rc );
        rc = Irp->IoStatus.Status;
    }

	return rc;
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS rc, ULONG_PTR Information)
{
	Irp->IoStatus.Status = rc;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return rc;
}

NTSTATUS AttachDevice(PDEVICE_OBJECT TargetDevice, PDEVICE_OBJECT SourceDevice)
{
    Extension *DevExt = (Extension *) SourceDevice->DeviceExtension;

	Syn.Exclusive();

	if ( IsDeviceAttached(TargetDevice) ) {
		Syn.Release();
		return STATUS_UNSUCCESSFUL;
	}

	DevExt->TargetDevice = TargetDevice;
	InsertTailList(&DeviceList, &DevExt->ExtensionEntry);
    //
    //  Propagate flags from Device Object we are trying to attach to.
    //  Note that we do this before the actual attachment to make sure
    //  the flags are properly set once we are attached (since an IRP
    //  can come in immediately after attachment but before the flags would
    //  be set).
    //
	SourceDevice->Flags |= TargetDevice->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO | DO_POWER_PAGABLE);

	NTSTATUS rc = AdApi::IoAttachDeviceToDeviceStackSafe(SourceDevice, TargetDevice, &DevExt->AttachedTo);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		RemoveEntryList(&DevExt->ExtensionEntry);
	} else {
		SourceDevice->Flags |= DevExt->AttachedTo->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO | DO_POWER_PAGABLE);
		SourceDevice->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	Syn.Release();

	return rc;
}

VOID DetachDevice(PDEVICE_OBJECT SourceDevice)
{
    Extension *DevExt = (Extension *) SourceDevice->DeviceExtension;

	Syn.Exclusive();

	RemoveEntryList(&DevExt->ExtensionEntry);
	IoDetachDevice(DevExt->AttachedTo);

	Syn.Release();
}

bool IsDeviceAttached(PDEVICE_OBJECT TargetDevice)
{
    PDEVICE_OBJECT NextDevObj;
    PDEVICE_OBJECT CurrentDevObj = IoGetAttachedDeviceReference(TargetDevice);

#if (_WIN32_WINNT <= 0x0500)

	if ( AdApi::IoGetLowerDeviceObject == NULL ) {

		PLIST_ENTRY Entry = DeviceList.Flink;
		while ( Entry != &DeviceList ) {
			Extension *DevExt = CONTAINING_RECORD(Entry, Extension, ExtensionEntry);
			if ( DevExt->TargetDevice == TargetDevice ) {
				ObDereferenceObject(CurrentDevObj);
				return true;
			}
			Entry = Entry->Flink;
		}

		if ( IsMyDeviceObject(CurrentDevObj) ) {
			ObDereferenceObject(CurrentDevObj);
			return true;
		}

		return false;
	}
#endif // #if (_WIN32_WINNT <= 0x0500)

    //
    //  CurrentDevObj has the top of the attachment chain.  Scan
    //  down the list to find our device object.
    do {
        if ( IsMyDeviceObject(CurrentDevObj) ) {
            ObDereferenceObject(CurrentDevObj);
            return true;
        }
        //
        //  Get the next attached object.  This puts a reference on 
        //  the device object.
        //
		NextDevObj = AdApi::IoGetLowerDeviceObject(CurrentDevObj);
        //
        //  Dereference our current device object, before
        //  moving to the next one.
        //
        ObDereferenceObject(CurrentDevObj);
        CurrentDevObj = NextDevObj;
    } while ( NULL != CurrentDevObj );

	return false;
}

NTSTATUS Init(PDRIVER_OBJECT _DriverObject)
{
	InitializeListHead(&DeviceList);

	DriverObject = _DriverObject;
    for ( ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ ) {
        DriverObject->MajorFunction[i] = CommonDispatch;
    }

	NTSTATUS rc = Syn.Init();
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return rc;
	}

	return rc;
}

} // namespace GswDispatch {