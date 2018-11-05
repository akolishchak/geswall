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
#include "fssetinfo.h"
#include "fastio.h"
#include "tools.h"
#include "adapi.h"
#include "lock.h"
#include "hook.h"
#include "sysprocess.h"
#include "ntrulemap.h"

//
//  These macros are used to test, set and clear flags respectively
//
#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

using namespace Rule;

namespace FsFilter {
    VOID FsNotification(IN PDEVICE_OBJECT DeviceObject, IN BOOLEAN FsActive);
    NTSTATUS Create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS Write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS Close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
	NTSTATUS Cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    VOID CreateCompleteWorker(IN PVOID _Context);

    NTSTATUS FsControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS FsControlMountVolume(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS FsControlMountVolumeComplete(
        IN PDEVICE_OBJECT DeviceObject,
        IN PIRP Irp,
        IN PDEVICE_OBJECT NewDeviceObject
        );

    NTSTATUS FsControlLoadFileSystem(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS FsControlLoadFileSystemComplete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

    NTSTATUS AttachCdo(PDEVICE_OBJECT TargetDevice);
    VOID DetachCdo(PDEVICE_OBJECT DeviceObject);
    NTSTATUS AttachToDevice(PDEVICE_OBJECT TargetDevice, PDEVICE_OBJECT NewDeviceObject);
    BOOLEAN IsAttachedDevice(PDEVICE_OBJECT DeviceObject, PDEVICE_OBJECT *AttachedDeviceObject);
    VOID ReleaseExtension(PDEVICE_OBJECT DeviceObject);

    PDRIVER_DISPATCH Dispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
    FAST_MUTEX AttachMutex;

	VOID DefferedInit(PVOID context);

    struct FileInfo {
		FileInfo(PFILE_OBJECT _FileObject, PUNICODE_STRING _FileName, PDEVICE_OBJECT _DeviceObject, _EPROCESS *_Process, EntityAttributes &_Attributes, ULONG _RuleId)
		{
			FileObject = _FileObject;
			FileName = _FileName;
			DeviceObject = _DeviceObject;
			Process = _Process;
			if ( Process != NULL ) ObReferenceObject(Process);
			Attributes = _Attributes;
			RuleId = _RuleId;
		}
		~FileInfo()
		{
			if ( Process != NULL ) ObDereferenceObject(Process);
			if ( FileName != NULL ) delete FileName;
		}
        PFILE_OBJECT FileObject;
		PUNICODE_STRING FileName;
		PDEVICE_OBJECT DeviceObject;
		_EPROCESS *Process;
		EntityAttributes Attributes;
		ULONG RuleId;
        LIST_ENTRY Entry;
    };
    FileInfo *LookupFile(PLIST_ENTRY FileList, PFILE_OBJECT FileObject);

    LIST_ENTRY ReadOnlyList;
    CEResource ReadOnlySyn;

	VOID AcquireRedirContext(PFILE_OBJECT FileObject);
	VOID ReleaseRedirContext(PFILE_OBJECT FileObject);
	VOID CheckRedirContext(PFILE_OBJECT FileObject);

	CEResource RedirSyn;

	LIST_ENTRY CreateList;
	CEResource CreateSyn;

	PDEVICE_OBJECT BootVdo = NULL;

NTSTATUS Create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

    if ( ((Extension *)DeviceObject->DeviceExtension)->TargetType == tdtCdo &&
         ((Extension *)DeviceObject->DeviceExtension)->AttachedTo->DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM && 
		 ((Extension *)DeviceObject->DeviceExtension)->AttachedTo->DeviceType != FILE_DEVICE_NAMED_PIPE ) {
        //
        // Pass through
        //
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
    }

	if ( ((Extension *)DeviceObject->DeviceExtension)->AttachedTo->DeviceType == FILE_DEVICE_NAMED_PIPE ) {
		ERR(0);
	}

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if ( IrpSp->FileObject == NULL || IrpSp->FileObject->Flags & FO_STREAM_FILE ) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
    }

	RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	_EPROCESS *Process = Hook::GetCurrentProcess();
	if ( NeedRuleCheck(Process, SubjectAttributes, Redirect, RuleId) == false ) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
	}
	//
	// Get requested operation info
	//
    //PEPROCESS Process = IoGetRequestorProcess(Irp);
    //if ( Process == NULL )
    //    Process = IoGetCurrentProcess();
	PFILE_OBJECT FileObject = IrpSp->FileObject;
    ACCESS_MASK DesiredAccess = IrpSp->Parameters.Create.SecurityContext->DesiredAccess;

    ULONG Disposition = IrpSp->Parameters.Create.Options >> 24;
    ULONG CreateOptions = IrpSp->Parameters.Create.Options & 0x00ffffff;
	ULONG ShareAccess = IrpSp->Parameters.Create.ShareAccess;

    if ( Disposition != FILE_OPEN || CreateOptions & FILE_DELETE_ON_CLOSE )
        DesiredAccess |= FILE_WRITE_DATA;

	PDEVICE_OBJECT AttachedTo = ((Extension *)DeviceObject->DeviceExtension)->AttachedTo;
    NTSTATUS rc = STATUS_SUCCESS;

	PUNICODE_STRING ObjectName = NULL;
	UNICODE_STRING usFileName = { 0, 0, NULL };
	//
	// Check if file already redirected
	//
	if ( Hook::IsRedirectEnabled(Rule::rdsFile) && BootVdo != NULL && AttachedTo->DeviceType != FILE_DEVICE_NAMED_PIPE ) {
		rc = ComposeFileName(FileObject, DeviceObject, &usFileName);
		if ( NT_SUCCESS(rc) ) {
			//
			// exlcude re-entrance
			//
			if ( IsRedirectedFile(&usFileName) ) {
				ERR(0);
				delete[] usFileName.Buffer;
				IoSkipCurrentIrpStackLocation(Irp);
				return IoCallDriver(AttachedTo, Irp);
			}

			UNICODE_STRING RedirectName;
			if ( Hook::GetRedirectName(nttFile, &usFileName, &RedirectName) ) {
				RedirSyn.Exclusive();
				OBJECT_ATTRIBUTES oa;
				IO_STATUS_BLOCK ios;
				InitializeObjectAttributes(&oa, &RedirectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
				HANDLE hDest;
				rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hDest, SYNCHRONIZE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
										ShareAccess,
										FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
										NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING,
										((Extension *)BootVdo->DeviceExtension)->AttachedTo);
				if ( NT_SUCCESS(rc) || rc == STATUS_SHARING_VIOLATION ) {
					if ( NT_SUCCESS(rc) ) ZwClose(hDest);
					RedirSyn.Release();
					ERR(rc);
					trace("MESSAGE!!!  %wZ\n", &usFileName);
					delete[] usFileName.Buffer;
					if ( FileObject->FileName.Buffer != NULL ) delete[] FileObject->FileName.Buffer;
					FileObject->FileName = RedirectName;
					FileObject->RelatedFileObject = NULL;
					return GswDispatch::CompleteIrp(Irp, STATUS_REPARSE, IO_REPARSE);
				} else {
					RedirSyn.Release();
					delete[] RedirectName.Buffer;
					if ( rc != STATUS_OBJECT_NAME_NOT_FOUND ) {
						ERR(rc);
						trace("MESSAGE!!!  %wZ\n", &usFileName);
					}
				}
			} else {
				ERR(0);
			}
		} else {
			ERR(rc);
		}
	}

	rc = STATUS_SUCCESS;
	PFILE_OBJECT SwapFileObject = NULL;
	HANDLE hSwapFile = NULL;
    ULONG_PTR LowLimit, HighLimit;
    IoGetStackLimits(&LowLimit, &HighLimit);
	if ( Disposition == FILE_SUPERSEDE || Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF || 
		 ( LowLimit <= (ULONG_PTR)IrpSp->FileObject && (ULONG_PTR)IrpSp->FileObject <= HighLimit ) 
       ) {
        //
        // get file name from file object
		//
		if ( usFileName.Buffer == NULL ) {
			rc = ComposeFileName(FileObject, DeviceObject, &usFileName);
			if ( !NT_SUCCESS(rc) ) {
				ERR(rc);
				return GswDispatch::CompleteIrp(Irp, rc);
			}
		}
        //
        // Try to open file, if exists then check access rules
		//
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK ios;
		InitializeObjectAttributes(&oa, &usFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hSwapFile, DesiredAccess, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
							ShareAccess, FILE_OPEN, 
							IrpSp->Parameters.Create.Options & 0x00ffffff & ~FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT,
							NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, AttachedTo);
		if ( NT_SUCCESS(rc) ) {
			rc = ObReferenceObjectByHandle(hSwapFile, DesiredAccess, NULL, KernelMode, (PVOID *) &SwapFileObject, NULL);
			if ( !NT_SUCCESS(rc) ) {
				SwapFileObject = NULL;
				ZwClose(hSwapFile);
				ERR(rc);
			}
		} else {
			if ( rc == STATUS_SHARING_VIOLATION ) ERR(rc);
		}
	}

	BOOLEAN bFileCreate = FALSE;
	BOOLEAN bFileStream = FALSE;
	if ( SwapFileObject == NULL ) {
		if ( Disposition == FILE_OPEN || Disposition == FILE_OPEN_IF || rc == STATUS_SHARING_VIOLATION ) {
			rc = GswDispatch::BlockedCallDriver(AttachedTo, Irp);
			if ( rc == STATUS_SHARING_VIOLATION || rc == STATUS_OBJECT_NAME_COLLISION ) {
				ERR(rc);
			    CHAR Name[NT_PROCNAMELEN];
				GetProcessNameByPointer((_EPROCESS *)Process, Name);
				trace("MESSAGE!!!  %s:  %wZ\n", Name, &FileObject->FileName);
				trace("MESSAGE!!!  DesiredAccess = %x, ShareAccess = %d, CreateOptions = %x, Disposition = %d\n",
						DesiredAccess, ShareAccess, CreateOptions, Disposition);
				trace("MESSAGE!!!  ==================\n");
			}
			if ( !NT_SUCCESS(rc) || rc == STATUS_REPARSE ) {

				if ( usFileName.Buffer != NULL ) {
					delete[] usFileName.Buffer;
					usFileName.Buffer = NULL;
				}

				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return rc;
			}
			if ( Irp->IoStatus.Information == FILE_CREATED ) {
				bFileCreate = TRUE;
			} 
		} else {
			//
			// Track file creation
			//
			rc = GswDispatch::BlockedCallDriver(AttachedTo, Irp);
			if ( rc == STATUS_SHARING_VIOLATION ) ERR(rc);
			if ( !NT_SUCCESS(rc) || rc == STATUS_REPARSE ) {

				if ( usFileName.Buffer != NULL ) {
					delete[] usFileName.Buffer;
					usFileName.Buffer = NULL;
				}

				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return rc;
			}
			bFileCreate = TRUE;
		}

		if ( bFileCreate == TRUE && usFileName.Buffer != NULL ) {
			//
			// validate if file created is not a stream over existing file
			//
			USHORT i;
			for ( i = 0; i < usFileName.Length / sizeof WCHAR; i++ )
				if ( usFileName.Buffer[i] == ':' )
					break;
			if ( i < usFileName.Length / sizeof WCHAR ) {
				//
				// This a file stream
				//
				bFileStream = TRUE;
			}
			
		}
	}

	if ( usFileName.Buffer != NULL ) {
		delete[] usFileName.Buffer;
		usFileName.Buffer = NULL;
	}

	FILE_DISPOSITION_INFORMATION Disp;

	RuleResult Result = Rule::AccessObject(bFileCreate && !bFileStream ? acsCreated : acsOpen, (_EPROCESS *)Process,
											SubjectAttributes, Redirect, RuleId,
											SwapFileObject != NULL ? SwapFileObject : FileObject, 
											DeviceObject, FileObject->Flags & ( FO_VOLUME_OPEN | FO_DIRECT_DEVICE_OPEN ) ? nttDevice : nttFile, DesiredAccess);

	if ( Result == rurRedirect ) {
		//
		// check if it is not directory
		//
		FILE_STANDARD_INFORMATION StandardInfo;
		NTSTATUS lrc = QueryFile(AttachedTo, SwapFileObject != NULL ? SwapFileObject : FileObject, 
								FileStandardInformation, &StandardInfo, sizeof StandardInfo);
		if ( !NT_SUCCESS(lrc) || StandardInfo.Directory || BootVdo == NULL || AttachedTo->DeviceType == FILE_DEVICE_NAMED_PIPE )
			Result = rurBlockModify;
		//else
		//if ( bFileCreate && bFileStream )
		//	Result = rurBlockAction;
	} else
	if ( Result == rurBlockModify && bFileCreate ) {
		Result = rurBlockAction;
	}

	switch ( Result ) {
        case rurBlockSubject:
        case rurBlockAction:
            //
			// Log denied access
			//
			NtRuleMap::Log(Rule::acsWrite, Process, SubjectAttributes, RuleId, FileObject, FileObject->Flags & ( FO_VOLUME_OPEN | FO_DIRECT_DEVICE_OPEN ) ? nttDevice : nttFile, DeviceObject, NULL, DesiredAccess, Result);
			//
			if ( SwapFileObject != NULL ) {
				ObDereferenceObject(SwapFileObject);
				ZwClose(hSwapFile);
			} else {
				if ( bFileCreate ) {
					//
					// Delete the file
					//
					Disp.DeleteFile = TRUE;
					rc = SetFile(AttachedTo, FileObject, FileDispositionInformation, &Disp, sizeof Disp);
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
					}
				}
				IoCancelFileOpen(AttachedTo, FileObject);
			}
			return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);

        case rurBlockModify:
			{
				trace("MESSAGE!!! BlockModify, DesiredAccess = %x\n", 
					IrpSp->Parameters.Create.SecurityContext->DesiredAccess);

				if ( CreateOptions & FILE_DELETE_ON_CLOSE || Disposition == FILE_SUPERSEDE || 
					 Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF ) {
					//
					if ( SwapFileObject != NULL ) {
						ObDereferenceObject(SwapFileObject);
						ZwClose(hSwapFile);
					} else
						IoCancelFileOpen(AttachedTo, FileObject);
					return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
				}

				//
				// Get file name
				//
				if ( FileObject->Flags & ( FO_VOLUME_OPEN | FO_DIRECT_DEVICE_OPEN ) ) {
					if ( FileObject->DeviceObject != NULL )
						GetObjectName(FileObject->DeviceObject, &ObjectName);
					else
						GetObjectName(FileObject, &ObjectName);
				} else {
					AdApi::IoQueryFileDosDeviceName(FileObject, (POBJECT_NAME_INFORMATION *)&ObjectName);
				}
				// ignore error code
				FileInfo *Info = new(PagedPool) FileInfo(FileObject, ObjectName, DeviceObject, Process, SubjectAttributes, RuleId);
				if ( Info == NULL ) {
					if ( SwapFileObject != NULL ) {
						ObDereferenceObject(SwapFileObject);
						ZwClose(hSwapFile);
					} else
						IoCancelFileOpen(AttachedTo, FileObject);
					return GswDispatch::CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES);
				}

				ReadOnlySyn.Exclusive();
				InsertTailList(&ReadOnlyList, &Info->Entry);
				ReadOnlySyn.Release();
			}
            break;

		case rurAllowAction:
			break;

		case rurRedirect:
			{
				//
				// Log redirected access
				//
				NtRuleMap::Log(Rule::acsWrite, Process, SubjectAttributes, RuleId, FileObject, nttFile, DeviceObject, NULL, DesiredAccess, Result);
				//
				//
				// 1) Open redirected file
				// 2) If file doesn't exist then:
				//		a) get file name
				//      b) cancel current open
				//		c) open file again for read
				//		d) copy content of original one
				// 3) Prepare and return reparse
				//

				if ( bFileCreate ) {
					//
					// Delete the file
					//
					Disp.DeleteFile = TRUE;
					rc = SetFile(AttachedTo, FileObject, FileDispositionInformation, &Disp, sizeof Disp);
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
					}
				}
				//
				// get file name
				//
				ObjectName = NULL;
				rc = FsFilter::GetFileName(SwapFileObject != NULL ? SwapFileObject : FileObject, 
											DeviceObject, &ObjectName);
				if ( !NT_SUCCESS(rc) ) {
					ERR(rc);
					if ( SwapFileObject != NULL ) {
						ObDereferenceObject(SwapFileObject);
						ZwClose(hSwapFile);
					} else
						IoCancelFileOpen(AttachedTo, FileObject);
					return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
				}
				RtlDowncaseUnicodeString(ObjectName, ObjectName, FALSE);

				//
				// get redirected name
				//
				UNICODE_STRING usFile;
				if ( !Hook::GetRedirectName(nttFile, ObjectName, &usFile) ) {
					rc = STATUS_UNSUCCESSFUL;
					ERR(rc);
					delete ObjectName;
					if ( SwapFileObject != NULL ) {
						ObDereferenceObject(SwapFileObject);
						ZwClose(hSwapFile);
					} else
						IoCancelFileOpen(AttachedTo, FileObject);
					return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
				}

				//
				// get file security descriptor
				//
				PSECURITY_DESCRIPTOR sd = NULL;
				rc = GetFileSD(SwapFileObject != NULL ? SwapFileObject : FileObject, AttachedTo, &sd,
							   OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);
				if ( !NT_SUCCESS(rc) ) {
					sd = NULL;
				}

				RedirSyn.Exclusive();

				OBJECT_ATTRIBUTES oa;
				IO_STATUS_BLOCK ios;
				InitializeObjectAttributes(&oa, &usFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

				HANDLE hDest;
				rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hDest, FILE_GENERIC_WRITE | DELETE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
								ShareAccess,
								FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
								NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING,
								((Extension *)BootVdo->DeviceExtension)->AttachedTo);
				if ( !NT_SUCCESS(rc) ) hDest = NULL;

				if ( sd != NULL ) delete[] sd;
				
				if ( !NT_SUCCESS(rc) && rc != STATUS_SHARING_VIOLATION ) {
					ERR(rc);
					RedirSyn.Release();
					delete ObjectName;
					delete[] usFile.Buffer;
					if ( SwapFileObject != NULL ) {
						ObDereferenceObject(SwapFileObject);
						ZwClose(hSwapFile);
					} else
						IoCancelFileOpen(AttachedTo, FileObject);
					return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
				}

				if ( NT_SUCCESS(rc) && ios.Information == FILE_CREATED ) {
					//
					// If file was not exist, copy content from original one
					//
					if ( SwapFileObject != NULL ) {
						ObDereferenceObject(SwapFileObject);
						ZwClose(hSwapFile);
					} else
						IoCancelFileOpen(AttachedTo, FileObject);

					trace("MESSAGE!!! copy %wZ\n", ObjectName);
					InitializeObjectAttributes(&oa, ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
					HANDLE hSource;
					rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hSource, FILE_READ_DATA, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
									ShareAccess,
									FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | ( bFileCreate ? FILE_DELETE_ON_CLOSE : 0 ), 
									NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, AttachedTo);
			        delete[] ObjectName;
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
						ZwClose(hDest);
						RedirSyn.Release();
						delete[] usFile.Buffer;
						return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
					}

					rc = CopyFile(hSource, hDest);
					trace("MESSAGE!!! copy complted = %d\n", rc);
					if ( !NT_SUCCESS(rc) ) {
						//
						// delete dest
						//
						FILE_DISPOSITION_INFORMATION Disp;
						Disp.DeleteFile = TRUE;
						NTSTATUS lrc = ZwSetInformationFile(hDest, &ios, &Disp, sizeof Disp, FileDispositionInformation);
						if ( !NT_SUCCESS(lrc) ) ERR(lrc);
					}
					ZwClose(hSource);
					ZwClose(hDest);
					RedirSyn.Release();

					if ( !NT_SUCCESS(rc) ) {
						//
						// if copy fails then fail the request as well
						//
						ERR(rc);
						delete[] usFile.Buffer;
						return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
					}

				} else {
					delete ObjectName;
					if ( hDest != NULL ) ZwClose(hDest);
					if ( SwapFileObject != NULL ) {
						ObDereferenceObject(SwapFileObject);
						ZwClose(hSwapFile);
					} else
						IoCancelFileOpen(AttachedTo, FileObject);
					RedirSyn.Release();
				}
                
				if ( FileObject->FileName.Buffer != NULL ) delete[] FileObject->FileName.Buffer;
				FileObject->FileName = usFile;
				FileObject->RelatedFileObject = NULL;

				return GswDispatch::CompleteIrp(Irp, STATUS_REPARSE, IO_REPARSE);
			}
			break;
    }

	if ( SwapFileObject != NULL ) {
		ObDereferenceObject(SwapFileObject);
		ZwClose(hSwapFile);
		IoCopyCurrentIrpStackLocationToNext(Irp);
        rc = IoCallDriver(AttachedTo, Irp);
	} else
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return rc;
}

NTSTATUS Write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	if ( IrpSp->MajorFunction == IRP_MJ_SET_INFORMATION && IrpSp->Parameters.SetFile.FileInformationClass == FilePositionInformation ) {
		// FilePositionInformation no need to be restricted
		return GswDispatch::PassThrough(DeviceObject, Irp);
	}

	bool LoggingMode = EnableLogging;
	if ( IrpSp->MajorFunction == IRP_MJ_SET_INFORMATION && IrpSp->Parameters.SetFile.FileInformationClass == FileBasicInformation ) {
		LoggingMode = DisableLogging;
	}

    if ( IsFileReadOnly(IrpSp->FileObject, LoggingMode) ) {
		return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
    }
	//
	// Control renaming
	//
	if ( IrpSp->MajorFunction == IRP_MJ_SET_INFORMATION &&
		 ( IrpSp->Parameters.SetFile.FileInformationClass == FileLinkInformation ||
		   IrpSp->Parameters.SetFile.FileInformationClass == FileRenameInformation )
	   ) return SetInfo::Rename(DeviceObject, Irp);
    //
    // Pass through
    //
	return GswDispatch::PassThrough(DeviceObject, Irp);
}

NTSTATUS Close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    ReadOnlySyn.Exclusive();
    FileInfo *Info = LookupFile(&ReadOnlyList, IoGetCurrentIrpStackLocation(Irp)->FileObject);
    if ( Info != NULL ) {
        RemoveEntryList(&Info->Entry);
        delete Info;
    }
    ReadOnlySyn.Release();
    //
    // Pass through
    //
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
}

NTSTATUS Cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
/*
    CreateSyn.Exclusive();
    FileInfo *Info = LookupFile(&CreateList, IoGetCurrentIrpStackLocation(Irp)->FileObject);
    if ( Info != NULL ) {
		//
		//
		//
		_EPROCESS *Process = (_EPROCESS *)Info->Process;
		PFILE_OBJECT FileObject = Info->FileObject;
		ACCESS_MASK DesiredAccess = Info->DesiredAccess;
		
        RemoveEntryList(&Info->Entry);
        delete Info;
		CreateSyn.Release();

		RuleResult Result = Rule::AccessObject(acsCreatedClose, Process, 
												FileObject, DeviceObject, nttFile, DesiredAccess);

    } else
		CreateSyn.Release();
*/
    //
    // Pass through
    //
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
}


FsFilter::FileInfo *LookupFile(PLIST_ENTRY FileList, PFILE_OBJECT FileObject)
{
    PLIST_ENTRY pEntry = FileList->Flink;
    while ( pEntry != FileList ) {

        FileInfo *pNode = CONTAINING_RECORD(pEntry, FileInfo, Entry);
        if ( pNode->FileObject == FileObject )
            return pNode;
        pEntry = pEntry->Flink;
    }
    return NULL;
}

NTSTATUS Init(VOID)
{
    NTSTATUS rc = STATUS_SUCCESS;

    InitializeListHead(&ReadOnlyList);
    rc = ReadOnlySyn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    InitializeListHead(&CreateList);
    rc = CreateSyn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    rc = RedirSyn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    RtlZeroMemory(Dispatch, sizeof Dispatch);
    Dispatch[IRP_MJ_CREATE] = Create;
    //Dispatch[IRP_MJ_CREATE_NAMED_PIPE] = Create;
    //Dispatch[IRP_MJ_CREATE_MAILSLOT] = Create;
    Dispatch[IRP_MJ_FILE_SYSTEM_CONTROL] = FsControl;
    Dispatch[IRP_MJ_WRITE] = Write;
    Dispatch[IRP_MJ_SET_EA] = Write;
    Dispatch[IRP_MJ_SET_INFORMATION] = Write;
    Dispatch[IRP_MJ_SET_QUOTA] = Write;
    Dispatch[IRP_MJ_SET_SECURITY] = Write;
    Dispatch[IRP_MJ_SET_VOLUME_INFORMATION] = Write;
    Dispatch[IRP_MJ_CLOSE] = Close;
	Dispatch[IRP_MJ_CLEANUP] = Cleanup;

    rc = FastIo::Init(&gDriverObject->FastIoDispatch);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    ExInitializeFastMutex(&AttachMutex);

    //
    //  Register this driver for watching file systems coming and going.  This
    //  enumerates all existing file systems as well as new file systems as they
    //  come and go.
    //
    rc = IoRegisterFsRegistrationChange(gDriverObject, FsNotification);
    if (!NT_SUCCESS( rc )) {
        ERR(rc);
        return rc;
    }

    //
    //  Attempt to attach to the RAWDISK file system device object since this
    //  file system is not enumerated by IoRegisterFsRegistrationChange.
    //
    {
        PDEVICE_OBJECT RawDeviceObject;
        PFILE_OBJECT FileObject;
        UNICODE_STRING usName;

        RtlInitUnicodeString(&usName, L"\\Device\\RawDisk");

        rc = IoGetDeviceObjectPointer(
                    &usName,
                    FILE_READ_ATTRIBUTES,
                    &FileObject,
                    &RawDeviceObject );

        if (NT_SUCCESS( rc )) {

            FsNotification(RawDeviceObject, TRUE);
            ObDereferenceObject(FileObject);
        }
    }

	HANDLE hDefferedInit;
	rc = PsCreateSystemThread(&hDefferedInit, THREAD_ALL_ACCESS, NULL, NULL, NULL, DefferedInit, NULL);
	if ( NT_SUCCESS(rc) ) {
		ZwClose(hDefferedInit);
	}

    return rc;
}

VOID DefferedInit(PVOID context)
{
	NTSTATUS rc;
	//
	// Attach to \\Device\\NamedPipe
	//
	PFILE_OBJECT FileObject;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING usDevName;
	RtlInitUnicodeString(&usDevName, L"\\Device\\NamedPipe");

	for ( ULONG i = 0; i < 100; i++ ) {
		rc = IoGetDeviceObjectPointer(&usDevName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
		if ( NT_SUCCESS(rc) ) break;
		SleepEx(2000, FALSE);
	}

	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		goto cleanup;
	}

	rc = AttachCdo(DeviceObject);
	ObDereferenceObject(FileObject);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
	}

cleanup:
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID FsNotification(IN PDEVICE_OBJECT DeviceObject, IN BOOLEAN FsActive)
{
    PAGED_CODE();

    if ( FsActive ) {
        AttachCdo(DeviceObject);
    } else {
        DetachCdo(DeviceObject);
    }
}

NTSTATUS FsControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PAGED_CODE();

    ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));
    //
    //  Process the minor function code.
    //
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    switch ( IrpSp->MinorFunction ) {

        case IRP_MN_MOUNT_VOLUME:
            return FsControlMountVolume(DeviceObject, Irp);

        case IRP_MN_LOAD_FILE_SYSTEM:
            return FsControlLoadFileSystem(DeviceObject, Irp);

		case IRP_MN_USER_FS_REQUEST:
			{
				ULONG ControlCode = IrpSp->Parameters.FileSystemControl.FsControlCode;
				ULONG DeviceType = DEVICE_TYPE_FROM_CTL_CODE(ControlCode);
				if ( DeviceType != FILE_DEVICE_NAMED_PIPE ) {
					//
					// suppose that all fsctls are write access one's
					//
					bool Logging = EnableLogging;
					//
					// Exlude known prefetch actions
					//
					if ( ControlCode == FSCTL_CREATE_OR_GET_OBJECT_ID && ExGetPreviousMode() == KernelMode ) Logging = DisableLogging;

					if ( IsFileReadOnly(IrpSp->FileObject, Logging) ) {
						return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED);
					}
					//
					// 2. check particular fsctl's which have implicit files objects
					//
					return GswDispatch::PassThrough(DeviceObject, Irp);
				}

				if ( ControlCode != FSCTL_PIPE_IMPERSONATE ) break;
				FILE_PIPE_CLIENT_PROCESS_BUFFER ClientProcess;
				ULONG BufSize = sizeof ClientProcess;
				NTSTATUS rc = SendFsControl(IrpSp->FileObject, ((Extension *)DeviceObject->DeviceExtension)->AttachedTo, 
					   FSCTL_PIPE_QUERY_CLIENT_PROCESS, NULL, 0, &ClientProcess, BufSize);
				if ( NT_SUCCESS(rc) && ClientProcess.ClientSession == NULL ) {
					//
					// Note, we do _not_ handle remote access, when ClientProcess.ClientSession != NULL
					// In that case ClientProcess.ClientProcess contains PID on remote machine, 
					// which we have no idea how to resolve
					//
					//
					// Pass Irp down to get impersonated token
					//
					rc = GswDispatch::BlockedCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
					if ( !NT_SUCCESS(rc) ) {
						IoCompleteRequest(Irp, IO_NO_INCREMENT);
						return rc;
					}
					/*
					CHAR ServerName[NT_PROCNAMELEN];
					GetProcessNameByPointer((_EPROCESS *)PsGetCurrentProcess(), ServerName);
					CHAR ClientName[NT_PROCNAMELEN];
					GetProcessNameByPointer((_EPROCESS *)ClientProcess.ClientProcess, ClientName);

					trace(P"ZwImpersonateClientOfPipe: Client = %s:%d(%d), Server = %s:%d(%d)\n", 
						ClientName, 0, 0, 
						ServerName, PsGetCurrentProcessId(), PsGetCurrentThreadId());
					*/
					ACCESS_MASK _DesiredAccess = GENERIC_READ;
					//RuleResult Result = Rule::AccessObject(acsOpen, (_EPROCESS *)ClientProcess.ClientProcess, (_EPROCESS *)PsGetCurrentProcess(), NULL,
					//										nttProcess, _DesiredAccess);
					RuleResult Result = rurAllowAction;
					if ( Result == rurAllowAction ) {
						NTSTATUS lrc;
						_EPROCESS *Process;
						lrc = PsLookupProcessByProcessId(ClientProcess.ClientProcess, (PEPROCESS *) &Process);
						if ( NT_SUCCESS(lrc) ) {
							ObDereferenceObject(Process);
						} else {
							Process = (_EPROCESS *)ClientProcess.ClientProcess;
						}

						lrc = Hook::AddThreadMap((_ETHREAD *)PsGetCurrentThread(), Process);
						if ( !NT_SUCCESS(lrc) ) {
							ERR(lrc);
						}
					} else {
						HANDLE hToken = NULL;
						ZwSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof hToken);
						rc = STATUS_ACCESS_DENIED;
					}
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return rc;
				} else
					ERR(rc);
			}
			break;
    }        

    //
    // Pass through
    //
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
}

NTSTATUS FsControlCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
    )
{
    ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));
    ASSERT(Context != NULL);

    if ( NtVer >= 0x00050001 ) {
        //
        //  On Windows XP or later, the context passed in will be an event
        //  to signal.
        //
        KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);

    } else {
        //
        //  For Windows 2000, if we are not at passive level, we should 
        //  queue this work to a worker thread using the workitem that is in 
        //  Context.
        //
        if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
            //
            //  We are not at passive level, but we need to be to do our work,
            //  so queue off to the worker thread.
            //
            ExQueueWorkItem( (PWORK_QUEUE_ITEM) Context, DelayedWorkQueue );
            
        } else {

            PWORK_QUEUE_ITEM WorkItem = (PWORK_QUEUE_ITEM) Context;
            //
            //  We are already at passive level, so we will just call our 
            //  worker routine directly.
            //
            (WorkItem->WorkerRoutine)(WorkItem->Parameter);
        }
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

struct FsControlContext {
    WORK_QUEUE_ITEM WorkItem;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    PDEVICE_OBJECT NewDeviceObject;
};

VOID FsControlMountVolumeCompleteWorker(IN PVOID _Context)
{
    ASSERT( _Context != NULL );

    FsControlContext *Context = (FsControlContext *) _Context;

    FsFilter::FsControlMountVolumeComplete( Context->DeviceObject,
                                            Context->Irp,
                                            Context->NewDeviceObject);
    delete Context;

}


NTSTATUS FsControlMountVolume(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PAGED_CODE();

    ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
    ASSERT(IS_DESIRED_DEVICE_TYPE(DeviceObject->DeviceType));

    //
    //  Get the real device object (also known as the storage stack device
    //  object or the disk device object) pointed to by the vpb parameter
    //  because this vpb may be changed by the underlying file system.
    //  Both FAT and CDFS may change the VPB address if the volume being
    //  mounted is one they recognize from a previous mount.
    //
    NTSTATUS rc;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT StorageDevice = IrpSp->Parameters.MountVolume.Vpb->RealDevice;

    //
    //  This is a mount request.  Create a device object that can be
    //  attached to the file system's volume device object if this request
    //  is successful.  We allocate this memory now since we can not return
    //  an error in the completion routine.  
    //
    //  Since the device object we are going to attach to has not yet been
    //  created (it is created by the base file system) we are going to use
    //  the type of the file system control device object.  We are assuming
    //  that the file system control device object will have the same type
    //  as the volume device objects associated with it.
    //
    PDEVICE_OBJECT NewDeviceObject;

    rc = IoCreateDevice(gDriverObject,
                        sizeof VdoExtension,
                        NULL,
                        DeviceObject->DeviceType,
                        0,
                        FALSE,
                        &NewDeviceObject);

    if ( !NT_SUCCESS(rc) ) {
        //
        //  If we can not attach to the volume, then don't allow the volume
        //  to be mounted.
        //
        ERR(rc);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = rc;
        IoCompleteRequest( Irp, IO_NO_INCREMENT );
        return rc;
    }

    //
    //  We need to save the RealDevice object pointed to by the vpb
    //  parameter because this vpb may be changed by the underlying
    //  file system.  Both FAT and CDFS may change the VPB address if
    //  the volume being mounted is one they recognize from a previous
    //  mount.
    //
    VdoExtension *VdoDevExt = (VdoExtension *) NewDeviceObject->DeviceExtension;
    VdoDevExt->TargetType = tdtVdo;
    VdoDevExt->StorageDevice = StorageDevice;
    VdoDevExt->Cdo = DeviceObject;
    GetObjectName(StorageDevice, &VdoDevExt->DeviceName);

    //
    //  VERSION NOTE:
    //
    //  On Windows 2000, we cannot simply synchronize back to the dispatch
    //  routine to do our post-mount processing.  We need to do this work at
    //  passive level, so we will queue that work to a worker thread from
    //  the completion routine.
    //
    //  For Windows XP and later, we can safely synchronize back to the dispatch
    //  routine.  The code below shows both methods.  Admittedly, the code
    //  would be simplified if you chose to only use one method or the other, 
    //  but you should be able to easily adapt this for your needs.
    //
    if ( NtVer >= 0x00050001 ) {

        KEVENT WaitEvent;
        KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

        IoCopyCurrentIrpStackLocationToNext(Irp);

        IoSetCompletionRoutine( Irp,
                                FsControlCompletion,
                                &WaitEvent,     //context parameter
                                TRUE,
                                TRUE,
                                TRUE );

        rc = IoCallDriver(((CdoExtension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
        //
        //  Wait for the operation to complete
        //
        if ( rc == STATUS_PENDING ) {

            rc = KeWaitForSingleObject(&WaitEvent,
                                        Executive,
                                        KernelMode,
                                        FALSE,
                                        NULL);
            ASSERT( STATUS_SUCCESS == rc );
        }

        //
        //  Verify the IoCompleteRequest was called
        //
        ASSERT(KeReadStateEvent(&WaitEvent) || !NT_SUCCESS(Irp->IoStatus.Status));

        rc = FsControlMountVolumeComplete(DeviceObject, Irp, NewDeviceObject);

    } else {
        //
        //  Initialize our completion routine
        //
        FsControlContext * Context = new(NonPagedPool) FsControlContext;
        if ( Context == NULL ) {
            //
            //  If we cannot allocate our completion context, we will just pass 
            //  through the operation.  If your filter must be present for data
            //  access to this volume, you should consider failing the operation
            //  if memory cannot be allocated here.
            //
            ERR(STATUS_INSUFFICIENT_RESOURCES);
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(((CdoExtension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);

        } 
        
        Context->DeviceObject = DeviceObject;
        Context->Irp = Irp;
        Context->NewDeviceObject = NewDeviceObject;
        ExInitializeWorkItem(&Context->WorkItem, FsControlMountVolumeCompleteWorker, Context);

        IoCopyCurrentIrpStackLocationToNext(Irp);

        IoSetCompletionRoutine( Irp,
                                FsControlCompletion,
                                &Context->WorkItem, //context parameter
                                TRUE,
                                TRUE,
                                TRUE);
        //
        //  Call the driver
        //
        rc = IoCallDriver(((CdoExtension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
    }

    return rc;
}

NTSTATUS FsControlMountVolumeComplete(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PDEVICE_OBJECT NewDeviceObject
    )
{
    PAGED_CODE();

    NTSTATUS rc;
    VdoExtension *DevExt = (VdoExtension *) NewDeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    
    //
    //  Get the correct VPB from the real device object saved in our
    //  device extension.  We do this because the VPB in the IRP stack
    //  may not be the correct VPB when we get here.  The underlying
    //  file system may change VPBs if it detects a volume it has
    //  mounted previously.
    //
    PVPB Vpb = DevExt->StorageDevice->Vpb;

    //
    //  See if the mount was successful.
    //
    if ( NT_SUCCESS(Irp->IoStatus.Status) ) {
        //
        //  Acquire lock so we can atomically test if we area already attached
        //  and if not, then attach.  This prevents a double attach race
        //  condition.
        //
        ExAcquireFastMutex(&AttachMutex);

        rc = AttachToDevice(Vpb->DeviceObject, NewDeviceObject);
        if ( !NT_SUCCESS(rc) ) {
            ReleaseExtension(NewDeviceObject);
            IoDeleteDevice(NewDeviceObject);
		} else {
			//
			// save pointer on boot partition, needed for redirect
			//
			if ( DevExt->StorageDevice->Flags & DO_SYSTEM_BOOT_PARTITION || BootVdo == NULL ) {
				InterlockedExchangePointer((PVOID *)&BootVdo, NewDeviceObject);
			}
		}
        //
        //  Release the lock
        //
        ExReleaseFastMutex(&AttachMutex);
    } else {
        //
        //  The mount request failed, handle it.
        //
        ReleaseExtension(NewDeviceObject);
        IoDeleteDevice(NewDeviceObject);
    }
    //
    //  Complete the request.  
    //  NOTE:  We must save the status before completing because after
    //         completing the IRP we can not longer access it (it might be
    //         freed).
    //
    rc = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return rc;
}

VOID FsControlLoadFileSystemCompleteWorker(IN PVOID _Context)
{
    ASSERT( NULL != _Context );
    FsControlContext *Context = (FsControlContext *) _Context;

    FsFilter::FsControlLoadFileSystemComplete(Context->DeviceObject, Context->Irp);

    delete Context;
}


NTSTATUS FsControlLoadFileSystem(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PAGED_CODE();
    //
    //  This is a "load file system" request being sent to a file system
    //  recognizer device object.  This IRP_MN code is only sent to 
    //  file system recognizers.
    //
    //  NOTE:  Since we no longer are attaching to the standard Microsoft file
    //         system recognizers we will normally never execute this code.
    //         However, there might be 3rd party file systems which have their
    //         own recognizer which may still trigger this IRP.
    //
    //
    //  VERSION NOTE:
    //
    //  On Windows 2000, we cannot simply synchronize back to the dispatch
    //  routine to do our post-load filesystem processing.  We need to do 
    //  this work at passive level, so we will queue that work to a worker 
    //  thread from the completion routine.
    //
    //  For Windows XP and later, we can safely synchronize back to the dispatch
    //  routine.  
    //
    NTSTATUS rc;

    if ( NtVer >= 0x00050001 ) {

        KEVENT WaitEvent;
        KeInitializeEvent( &WaitEvent, 
                           NotificationEvent, 
                           FALSE );

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine( Irp,
                                FsControlCompletion,
                                &WaitEvent,     //context parameter
                                TRUE,
                                TRUE,
                                TRUE );

        rc = IoCallDriver( ((CdoExtension *)DeviceObject->DeviceExtension)->AttachedTo, Irp );

        //
        //  Wait for the operation to complete
        //
        if ( rc == STATUS_PENDING ) {

            rc = KeWaitForSingleObject( &WaitEvent,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL );
            ASSERT( STATUS_SUCCESS == rc );
        }

        //
        //  Verify the IoCompleteRequest was called
        //
        ASSERT(KeReadStateEvent(&WaitEvent) || !NT_SUCCESS(Irp->IoStatus.Status));

        rc = FsControlLoadFileSystemComplete(DeviceObject, Irp);

    } else {
        //
        //  Set a completion routine so we can delete the device object when
        //  the load is complete.
        //
        FsControlContext *Context = new(NonPagedPool) FsControlContext;
        if ( Context == NULL ) {
            //
            //  If we cannot allocate our completion context, we will just pass 
            //  through the operation.  If your filter must be present for data
            //  access to this volume, you should consider failing the operation
            //  if memory cannot be allocated here.
            //
            ERR(STATUS_INSUFFICIENT_RESOURCES);
            IoSkipCurrentIrpStackLocation( Irp );
            return IoCallDriver(((CdoExtension *)DeviceObject->DeviceExtension)->AttachedTo, Irp );
        } 

        Context->DeviceObject = DeviceObject;
        Context->Irp = Irp;
        Context->NewDeviceObject = NULL;
        ExInitializeWorkItem(&Context->WorkItem, FsControlLoadFileSystemCompleteWorker, Context);
              
        IoCopyCurrentIrpStackLocationToNext(Irp);

        IoSetCompletionRoutine( Irp,
                                FsControlCompletion,
                                Context,
                                TRUE,
                                TRUE,
                                TRUE);
        //
        //  Detach from the file system recognizer device object.
        //
        IoDetachDevice(((CdoExtension *)DeviceObject->DeviceExtension)->AttachedTo);
        //
        //  Call the driver
        //
        rc = IoCallDriver(((CdoExtension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
    }
    
    return rc;
}

NTSTATUS FsControlLoadFileSystemComplete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS rc;

    PAGED_CODE();

    CdoExtension *DevExt = (CdoExtension *) DeviceObject->DeviceExtension;
    //
    //  Check status of the operation
    //
    if ( !NT_SUCCESS( Irp->IoStatus.Status ) && 
         ( Irp->IoStatus.Status != STATUS_IMAGE_ALREADY_LOADED ) ) {
        //
        //  The load was not successful.  Simply reattach to the recognizer
        //  driver in case it ever figures out how to get the driver loaded
        //  on a subsequent call.  There is not a lot we can do if this
        //  reattach fails.
        //
		AdApi::IoAttachDeviceToDeviceStackSafe(DeviceObject, 
                                        DevExt->AttachedTo,
                                        &DevExt->AttachedTo);

        ASSERT(DevExt->AttachedTo != NULL);

    } else {
        //
        //  The load was successful, so cleanup this device and delete the 
        //  Device object
        //
        ReleaseExtension(DeviceObject);
        IoDeleteDevice(DeviceObject);
    }
    //
    //  Continue processing the operation
    //
    rc = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return rc;
}



NTSTATUS AttachCdo(PDEVICE_OBJECT TargetDevice)
{
    NTSTATUS rc;
    PDEVICE_OBJECT NewDeviceObject;

    PAGED_CODE();

    //
    //  See if this is a file system type we care about.  If not, return.
    //
    if ( !IS_DESIRED_DEVICE_TYPE(TargetDevice->DeviceType) ) {

        return STATUS_SUCCESS;
    }

    //
    //  always init NAME buffer
    //
    PUNICODE_STRING TempName;
    rc = GetObjectName(TargetDevice->DriverObject, &TempName);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
    }
    //
    //  See if this is one of the standard Microsoft file system recognizer
    //  devices (see if this device is in the FS_REC driver).  If so skip it.
    //  We no longer attach to file system recognizer devices, we simply wait
    //  for the real file system driver to load.
    //
    UNICODE_STRING FsrecName;
    RtlInitUnicodeString(&FsrecName, L"\\FileSystem\\Fs_Rec");
    if ( TempName != NULL && RtlCompareUnicodeString(TempName, &FsrecName, TRUE) == 0 ) {
        if ( TempName != NULL ) delete[] TempName;
        return STATUS_SUCCESS;
    }

    if ( TempName != NULL ) delete[] TempName;
    //
    //  We want to attach to this file system.  Create a new device object we
    //  can attach with.
    //
    rc = IoCreateDevice(gDriverObject,
                         sizeof CdoExtension,
                         NULL,
                         TargetDevice->DeviceType,
                         0,
                         FALSE,
                         &NewDeviceObject);

    if (!NT_SUCCESS( rc )) {
        ERR(rc);
        return rc;
    }
    //
    //  Do the attachment
    //
    CdoExtension *DevExt = (CdoExtension *) NewDeviceObject->DeviceExtension;
    DevExt->TargetType = tdtCdo;
    rc = GetObjectName(TargetDevice, &DevExt->DeviceName);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
    }

    rc = AttachToDevice(TargetDevice, NewDeviceObject);
    if ( !NT_SUCCESS(rc) ) {
        ReleaseExtension(NewDeviceObject);
        IoDeleteDevice(NewDeviceObject);
    }

    return rc;
}


VOID DetachCdo(PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_OBJECT OurAttachedDevice;

    PAGED_CODE();
    //
    //  Skip the base file system device object (since it can't be us)
    //
    OurAttachedDevice = DeviceObject->AttachedDevice;
    while (NULL != OurAttachedDevice) {

        if (IS_MY_DEVICE_OBJECT( OurAttachedDevice )) {

            CdoExtension *DevExt = (CdoExtension *) OurAttachedDevice->DeviceExtension;
            //
            //  Detach us from the object just below us
            //  Cleanup and delete the object
            //
            IoDetachDevice(DeviceObject);
            ReleaseExtension(OurAttachedDevice);
            IoDeleteDevice(OurAttachedDevice);
            return;
        }
        //
        //  Look at the next device up in the attachment chain
        //
        DeviceObject = OurAttachedDevice;
        OurAttachedDevice = OurAttachedDevice->AttachedDevice;
    }
}

VOID DetachVdo(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice)
{
    //
    //  Detach from the file system's volume device object.
    //
    IoDetachDevice(TargetDevice);
    ReleaseExtension(SourceDevice);
    IoDeleteDevice(SourceDevice);
}


NTSTATUS AttachToDevice(PDEVICE_OBJECT TargetDevice, PDEVICE_OBJECT NewDeviceObject)
{
    NTSTATUS rc;

    Extension *DevExt = (Extension *) NewDeviceObject->DeviceExtension;

    if (IsAttachedDevice ( TargetDevice, NULL )) {
        rc = STATUS_SUCCESS;
        ERR(rc);
        return rc;
    }

    //
    //  Propagate flags from Device Object we are trying to attach to.
    //  Note that we do this before the actual attachment to make sure
    //  the flags are properly set once we are attached (since an IRP
    //  can come in immediately after attachment but before the flags would
    //  be set).
    //
    if ( FlagOn( TargetDevice->Flags, DO_BUFFERED_IO )) {

        SetFlag( NewDeviceObject->Flags, DO_BUFFERED_IO );
    }

    if ( FlagOn( TargetDevice->Flags, DO_DIRECT_IO )) {

        SetFlag( NewDeviceObject->Flags, DO_DIRECT_IO );
    }

    if ( DevExt->TargetType == tdtCdo ) {
        if ( FlagOn( TargetDevice->Characteristics, FILE_DEVICE_SECURE_OPEN ) ) {

            SetFlag( NewDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN );
        }
    }

    DevExt->Dispatch = Dispatch;
    //
    //  Attach our device object to the given device object
    //  The only reason this can fail is if someone is trying to dismount
    //  this volume while we are attaching to it.
    //
    rc = AdApi::IoAttachDeviceToDeviceStackSafe(NewDeviceObject, TargetDevice, &DevExt->AttachedTo);
    if (!NT_SUCCESS( rc )) {
        ERR(rc);
        return rc;
    }
	//
    //  Finished all initialization of the new device object,  so clear the
    //  initializing flag now.
    //
    ClearFlag(NewDeviceObject->Flags, DO_DEVICE_INITIALIZING);

    return STATUS_SUCCESS;
}


BOOLEAN IsAttachedDevice(PDEVICE_OBJECT DeviceObject, PDEVICE_OBJECT *AttachedDeviceObject)
{
    PDEVICE_OBJECT CurrentDevObj;
    PDEVICE_OBJECT NextDevObj;

    CurrentDevObj = IoGetAttachedDeviceReference( DeviceObject );

#if (_WIN32_WINNT <= 0x0500)

    if (IS_MY_DEVICE_OBJECT( CurrentDevObj )) {

        //
        //  We have found that we are already attached.  If we are
        //  returning the device object we are attached to then leave the
        //  reference on it.  If not then remove the reference.
        //

        if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

            *AttachedDeviceObject = CurrentDevObj;
        }            

        ObDereferenceObject( CurrentDevObj );
        return TRUE;
    }

#else // #if (_WIN32_WINNT <= 0x0500)
    //
    //  CurrentDevObj has the top of the attachment chain.  Scan
    //  down the list to find our device object.
    do {
    
        if (IS_MY_DEVICE_OBJECT( CurrentDevObj )) {

            //
            //  We have found that we are already attached.  If we are
            //  returning the device object we are attached to then leave the
            //  reference on it.  If not then remove the reference.
            //

            if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

                *AttachedDeviceObject = CurrentDevObj;
            }            

            ObDereferenceObject( CurrentDevObj );
            return TRUE;
        }

        //
        //  Get the next attached object.  This puts a reference on 
        //  the device object.
        //

        NextDevObj = IoGetLowerDeviceObject( CurrentDevObj );

        //
        //  Dereference our current device object, before
        //  moving to the next one.
        //

        ObDereferenceObject( CurrentDevObj );

        CurrentDevObj = NextDevObj;
        
    } while (NULL != CurrentDevObj);
    
    if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

        *AttachedDeviceObject = NULL;
    }

#endif // #if (_WIN32_WINNT <= 0x0500)

    return FALSE;
}    


VOID ReleaseExtension(PDEVICE_OBJECT DeviceObject)
{
    if ( ((Extension *)DeviceObject->DeviceExtension)->TargetType == tdtCdo ) {
        CdoExtension *DevExt = (CdoExtension *) DeviceObject->DeviceExtension;
        if ( DevExt->DeviceName != NULL ) delete[] DevExt->DeviceName;
    } 
    else {
        VdoExtension *DevExt = (VdoExtension *) DeviceObject->DeviceExtension;
        if ( DevExt->DeviceName != NULL ) delete[] DevExt->DeviceName;
		//
		// zero pointer for boot partition
		//
		InterlockedCompareExchangePointer((PVOID *)&BootVdo, NULL, DeviceObject);
    }
}

struct AccessLogInfo : SysProcessInfo {
    PFILE_OBJECT FileObject;
	PUNICODE_STRING FileName;
	PDEVICE_OBJECT DeviceObject;
	_EPROCESS *Process;
	EntityAttributes Attributes;
	ULONG RuleId;
};

NTSTATUS AccessLog(AccessLogInfo *LogInfo)
{
	NtRuleMap::Log(Rule::acsWrite, LogInfo->Process, LogInfo->Attributes, LogInfo->RuleId, LogInfo->FileObject, LogInfo->FileObject->Flags & ( FO_VOLUME_OPEN | FO_DIRECT_DEVICE_OPEN ) ? nttDevice : nttFile, LogInfo->DeviceObject, LogInfo->FileName, FILE_WRITE_DATA, Rule::rurBlockModify);

	ObDereferenceObject(LogInfo->Process);
	ObDereferenceObject(LogInfo->FileObject);
	delete LogInfo->FileName;
	delete LogInfo;
	return STATUS_SUCCESS;
}

BOOLEAN IsFileReadOnly(PFILE_OBJECT FileObject, bool LoggingMode)
{
    ReadOnlySyn.Share();
    FileInfo *Info = LookupFile(&ReadOnlyList, FileObject);
    ReadOnlySyn.Release();

	if ( Info != NULL ) {
		if ( LoggingMode || NtRuleMap::AccessLog == GesRule::aclEnabled ) {
			//
			// Log
			//
			AccessLogInfo *LogInfo = new(NonPagedPool) AccessLogInfo;
			if ( LogInfo != NULL ) {
				LogInfo->FileObject = Info->FileObject;
				LogInfo->FileName = CopyUnicodeString(Info->FileName);
				ObReferenceObject(LogInfo->FileObject);
				LogInfo->DeviceObject = Info->DeviceObject;
				LogInfo->Process = Info->Process;
				ObReferenceObject(LogInfo->Process);
				LogInfo->Attributes = Info->Attributes;
				LogInfo->RuleId = Info->RuleId;
				SysProcess::Post(LogInfo, (_SysProc) AccessLog);
			}
		}

		return TRUE;
	}

	return FALSE;
}

BOOLEAN IsRedirectedFile(PUNICODE_STRING FileName)
{
	static PUNICODE_STRING RedirectDir = NULL;

	if ( RedirectDir == NULL && BootVdo != NULL ) {
		//
		// resolve symbolic redirect directory name
		//
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK ios;
		UNICODE_STRING DirName;
		RtlInitUnicodeString(&DirName, Hook::RedirectDir);
		InitializeObjectAttributes(&oa, &DirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE hDir;
		NTSTATUS rc = AdApi::IoCreateFileSpecifyDeviceObjectHint(&hDir, FILE_READ_ATTRIBUTES, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 
							FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
							NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING,
							((Extension *)BootVdo->DeviceExtension)->AttachedTo);
		if ( NT_SUCCESS(rc) ) {
			PFILE_OBJECT DirObject;
			rc = ObReferenceObjectByHandle(hDir, FILE_READ_ATTRIBUTES, NULL, KernelMode, (PVOID *) &DirObject, NULL);
			if ( NT_SUCCESS(rc) ) {
				PUNICODE_STRING ObjectName = NULL;
				rc = GetFileName(DirObject, BootVdo, &ObjectName);
				if ( NT_SUCCESS(rc) ) {
					RtlDowncaseUnicodeString(ObjectName, ObjectName, FALSE);
					ObjectName = (PUNICODE_STRING) InterlockedExchangePointer((PVOID *)&RedirectDir, ObjectName);
					if ( ObjectName != NULL ) delete[] ObjectName;
				}
				ObDereferenceObject(DirObject);
			}
			ZwClose(hDir);
		}
	}
	
	if ( RedirectDir != NULL ) {
		if ( FileName->Length < RedirectDir->Length ) return FALSE;
		UNICODE_STRING pr = *FileName;
		pr.Length = RedirectDir->Length;
		return !RtlCompareUnicodeString(&pr, RedirectDir, FALSE);
	}

	return FALSE;
}

} // namespace FsFilter {
