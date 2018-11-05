//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "hook.h"
#include "rule.h"
#include "aci.h"
#include "lock.h"
#include "tools.h"
#include "hin.h"
#include "win32hook.h"
#include "fsfilter.h"
#include "sysprocess.h"
#include "ntrulemap.h"

using namespace Rule;

#define NameHash        md5_hash        
#define GetNameHash     GetMD5

namespace Hook {

    typedef NTSTATUS (*_ObCreateHandle)(
        IN ULONG Action, 
        IN PVOID Object, 
        IN POBJECT_TYPE ObjectType,
        IN PACCESS_STATE AccessState, 
        IN ULONG Unknown1, 
        IN ULONG HandleAttributes,
        IN ULONG Unknown2, 
        IN KPROCESSOR_MODE AccessMode, 
        IN ULONG Unknown3,
        OUT PHANDLE Handle
        );

    NTSTATUS NewObCreateHandle(
        IN ULONG Action, 
        IN PVOID Object, 
        IN POBJECT_TYPE ObjectType,
        IN PACCESS_STATE AccessState, 
        IN ULONG Unknown1, 
        IN ULONG HandleAttributes,
        IN ULONG Unknown2, 
        IN KPROCESSOR_MODE AccessMode, 
        IN ULONG Unknown3,
        OUT PHANDLE Handle
        );
    _ObCreateHandle ObCreateHandle = NULL;
    _ObCreateHandle OldObCreateHandle = NULL;
	hin::HOOK_HANDLE hObCreateHandle;

    typedef NTSTATUS (__fastcall *_ObCreateHandle2)(
        IN PACCESS_STATE AccessState, 
        IN ULONG HandleAttributes,
        IN ULONG Action, 
        IN PVOID Object, 
        IN POBJECT_TYPE ObjectType,
        IN ULONG Unknown1, 
        IN ULONG Unknown2, 
        IN ULONG AccessMode, 
        IN ULONG Unknown3,
        OUT PHANDLE Handle
        );

    NTSTATUS __fastcall NewObCreateHandle2(
        IN PACCESS_STATE AccessState, 
        IN ULONG HandleAttributes,
        IN ULONG Action, 
        IN PVOID Object, 
        IN POBJECT_TYPE ObjectType,
        IN ULONG Unknown1, 
        IN ULONG Unknown2, 
        IN ULONG AccessMode, 
        IN ULONG Unknown3,
        OUT PHANDLE Handle
        );
    _ObCreateHandle2 ObCreateHandle2 = NULL;
    _ObCreateHandle2 OldObCreateHandle2 = NULL;
	hin::HOOK_HANDLE hObCreateHandle2;


    typedef NTSTATUS (*_ObCreateHandle3)(
        IN ULONG Action, 
        IN PVOID Object, 
        IN ACCESS_MASK DesiredAccess,
        IN PACCESS_STATE AccessState, 
        IN ULONG Unknown1, 
        IN ULONG HandleAttributes,
        IN ULONG AccessMode, 
        IN ULONG Unknown2, 
        IN ULONG Unknown3,
        OUT PHANDLE Handle
        );

    NTSTATUS NewObCreateHandle3(
        IN ULONG Action, 
        IN PVOID Object, 
        IN ACCESS_MASK DesiredAccess,
        IN PACCESS_STATE AccessState, 
        IN ULONG Unknown1, 
        IN ULONG HandleAttributes,
        IN ULONG AccessMode, 
        IN ULONG Unknown2, 
        IN ULONG Unknown3,
        OUT PHANDLE Handle
        );
    _ObCreateHandle3 ObCreateHandle3 = NULL;
    _ObCreateHandle3 OldObCreateHandle3 = NULL;
	hin::HOOK_HANDLE hObCreateHandle3;

	VOID CreateProcessNotify(
        IN HANDLE  ParentId,
        IN HANDLE  ProcessId,
        IN BOOLEAN  Create
        );

    struct ProcessAttrinutes {
        ULONG Label;
        EntityAttributes Attr;
        LIST_ENTRY Entry;
    };

    struct ProcessInfo {
        PEPROCESS ParentProcess;
        PEPROCESS Process;
		HANDLE ProcessId;
        PFILE_OBJECT FileObject;
        RedirectStatus Redirect;
		ULONG RuleId;
        WCHAR wcHash[sizeof NameHash * 2 + NT_PROCNAMELEN + 1];
		PUNICODE_STRING FileName;
        LIST_ENTRY AttrList;
        LIST_ENTRY Entry;
    };

	SIZE_T SetProcessName(PEPROCESS Process, WCHAR *Buf);
	ProcessAttrinutes *LookupAttributes(CHAR *Label, ProcessInfo *Info);
    ProcessInfo *LookupProcess(PEPROCESS Process);
	_EPROCESS *LookupProcessByToken(HANDLE hToken);
    SectionInfo *LookupSection(PSECTION_OBJECT Section, PUNICODE_STRING FileName, bool CleanList);
    PVOID GetObCreateHandle(VOID);
	PVOID GetObCreateHandle2(VOID);
	bool ObCreateHandleAccessCheck(ULONG Action, PVOID Object, POBJECT_TYPE ObjectType, PACCESS_STATE AccessState, ACCESS_MASK *Access, KPROCESSOR_MODE AccessMode);
	CEResource Syn;
    LIST_ENTRY ProcessList;

    LARGE_INTEGER RedirectIDBase = {0, 0};
    LONG RedirectIDSuffix = 0;
    CEResource RedirSyn;

	BOOLEAN bInited = FALSE;


	OB_PREOP_CALLBACK_STATUS ObPreCallback(__in PVOID RegistrationContext, __in  POB_PRE_OPERATION_INFORMATION OperationInformation);
	VOID ObPostCallback(__in  PVOID RegistrationContext, __in  POB_POST_OPERATION_INFORMATION OperationInformation);

	const OB_OPERATION_REGISTRATION ObCallbacks[] = {
		{	PsProcessType, 
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			ObPreCallback,
			ObPostCallback
		},
		{	PsThreadType, 
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			ObPreCallback,
			ObPostCallback
		}
	};

	const OB_CALLBACK_REGISTRATION ObCallbackReg = {
		OB_FLT_REGISTRATION_VERSION,
		sizeof ObCallbacks / sizeof ObCallbacks[0],
		{12, 14, L"429999"},
		NULL,
		ObCallbacks
	};

	PVOID ObRegHandle = NULL;

}

NTSTATUS Hook::Init(VOID)
{
    NTSTATUS rc;

    InitializeListHead(&ProcessList);

    rc = Syn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    rc = RedirSyn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    //
    // Get redirect id base
    //
    KeQuerySystemTime(&RedirectIDBase);

    //
    // Insert system process info
    //
    ProcessInfo *Info = new (PagedPool) ProcessInfo;
    if ( Info == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }
    Info->Process = PsGetCurrentProcess();
	Info->ProcessId = PsGetCurrentProcessId();
	ObReferenceObject(Info->Process);
    Info->ParentProcess = NULL;
    Info->FileObject = NULL;
    Info->wcHash[0] = 0;
    Info->Redirect = rdsNone;
	Info->RuleId = 0;
	Info->FileName = NULL;
    InitializeListHead(&Info->AttrList);
    InsertTailList(&ProcessList, &Info->Entry);

    //
    // Hook functions
    //
	PVOID Module = hin::GetModuleBase("ntoskrnl.exe");
	if ( AdApi::NtVer < 0x00060000 ) {
		ObCreateHandle = (_ObCreateHandle) GetObCreateHandle();
		hObCreateHandle = hin::HookCode(Module, ObCreateHandle, 
											NewObCreateHandle, (PVOID *) &OldObCreateHandle);
		if ( hObCreateHandle == NULL ) {
			OldObCreateHandle = NULL;
			Release();
			ERR(rc);
			return rc;
		}
	} else 
	if ( AdApi::NtVer < 0x00060001 ) {
		ObCreateHandle2 = (_ObCreateHandle2) GetObCreateHandle();
		hObCreateHandle2 = hin::HookCode(Module, ObCreateHandle2, 
											NewObCreateHandle2, (PVOID *) &OldObCreateHandle2);
		if ( hObCreateHandle2 == NULL ) {
			OldObCreateHandle2 = NULL;
			Release();
			ERR(rc);
			return rc;
		}
	} else {
		ObCreateHandle3 = (_ObCreateHandle3) GetObCreateHandle2();
		hObCreateHandle3 = hin::HookCode(Module, ObCreateHandle3, 
											NewObCreateHandle3, (PVOID *) &OldObCreateHandle3);
		if ( hObCreateHandle3 == NULL ) {
			OldObCreateHandle3 = NULL;
			Release();
			ERR(rc);
			return rc;
		}
	}
	//
    // Process start/termination tracking
    //
    rc = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }
	//
	// Object access tracking
	//
	rc = ObRegisterCallbacks(&ObCallbackReg, &ObRegHandle);
    if ( !NT_SUCCESS(rc) ) {
		PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
        ERR(rc);
        return rc;
    }

	bInited = TRUE;

    return rc;
}

VOID Hook::Release(VOID)
{
    if ( !bInited ) return;
	
	NTSTATUS rc;

    if ( OldObCreateHandle != NULL ) {
		hin::UnHook(hObCreateHandle);
    }

	rc = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
    }

	Syn.Exclusive();
    while ( !IsListEmpty(&ProcessList) ) {

        PLIST_ENTRY pEntry = RemoveTailList(&ProcessList);
        ProcessInfo *Info = CONTAINING_RECORD(pEntry, ProcessInfo, Entry);
        //
        // Delete attributes
        //
        while ( !IsListEmpty(&Info->AttrList) ) {

            PLIST_ENTRY pEntryAttr = RemoveTailList(&Info->AttrList);
			ProcessAttrinutes *AttrInfo = CONTAINING_RECORD(pEntryAttr, ProcessAttrinutes, Entry);
            delete AttrInfo;
        }
        delete Info;
    }

    Syn.Release();

    Syn.Destroy();
    RedirSyn.Destroy();
}

NTSTATUS Hook::NewObCreateHandle(
    IN ULONG Action, 
    IN PVOID Object, 
    IN POBJECT_TYPE ObjectType,
    IN PACCESS_STATE AccessState, 
    IN ULONG Unknown1, 
    IN ULONG HandleAttributes,
    IN ULONG Unknown2, 
    IN KPROCESSOR_MODE AccessMode, 
    IN ULONG Unknown3,
    OUT PHANDLE Handle)
{
	if ( !ObCreateHandleAccessCheck(Action, Object, ObjectType, AccessState, NULL, AccessMode) ) return STATUS_ACCESS_DENIED;

	return OldObCreateHandle(
                Action, 
                Object, 
                ObjectType,
                AccessState, 
                Unknown1, 
                HandleAttributes,
                Unknown2, 
                AccessMode, 
                Unknown3,
                Handle);
}

NTSTATUS __fastcall Hook::NewObCreateHandle2(
        IN PACCESS_STATE AccessState, 
        IN ULONG HandleAttributes,
        IN ULONG Action, 
        IN PVOID Object, 
        IN POBJECT_TYPE ObjectType,
        IN ULONG Unknown1, 
        IN ULONG Unknown2, 
        IN ULONG AccessMode, 
        IN ULONG Unknown3,
        OUT PHANDLE Handle)
{
	__asm mov HandleAttributes, eax;

	if ( !ObCreateHandleAccessCheck(Action, Object, ObjectType, AccessState, NULL, AccessMode) ) return STATUS_ACCESS_DENIED;

	NTSTATUS rc;
	__asm {
		push Handle
		push Unknown3
		push AccessMode
		push Unknown2
		push Unknown1
		push ObjectType
		push Object
		push Action
		mov eax, HandleAttributes
		mov ecx, AccessState
		call OldObCreateHandle2
		mov rc, eax
	}

	return rc;
}

NTSTATUS Hook::NewObCreateHandle3(
    IN ULONG Action, 
    IN PVOID Object, 
    IN ACCESS_MASK DesiredAccess,
    IN PACCESS_STATE AccessState, 
    IN ULONG Unknown1, 
    IN ULONG HandleAttributes,
    IN ULONG AccessMode, 
    IN ULONG Unknown2, 
    IN ULONG Unknown3,
    OUT PHANDLE Handle)
{
	if ( !ObCreateHandleAccessCheck(Action, Object, NULL, AccessState, &DesiredAccess, AccessMode) ) return STATUS_ACCESS_DENIED;

	return OldObCreateHandle3(
                Action, 
                Object, 
                DesiredAccess,
                AccessState, 
                Unknown1, 
                HandleAttributes,
                AccessMode, 
                Unknown2, 
                Unknown3,
                Handle);
}

namespace Hook {

OB_PREOP_CALLBACK_STATUS ObPreCallback(__in PVOID RegistrationContext, __in  POB_PRE_OPERATION_INFORMATION OperationInformation)
{
}

VOID ObPostCallback(__in  PVOID RegistrationContext, __in  POB_POST_OPERATION_INFORMATION OperationInformation)
{
}


struct CreateContainersInfo : SysProcessInfo {
	UCHAR *Hash;
	PEPROCESS Process;
};

NTSTATUS CreateRedirectContainers(CreateContainersInfo *Info)
{
	NTSTATUS rc = STATUS_SUCCESS;
	UCHAR *Hash = Info->Hash;	
	PEPROCESS Process = Info->Process;
	//
	// Create folder for files redirect if not here yet
	//
	UNICODE_STRING usName;

	static const NameLength = 256;
	usName.Buffer = new (PagedPool) WCHAR[NameLength];
	if ( usName.Buffer == NULL ) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}
	usName.Length = 0;
	usName.MaximumLength = NameLength * sizeof WCHAR;
	RtlAppendUnicodeToString(&usName, RedirectDir);
	usName.Length += sizeof WCHAR * SetProcessName(Process, usName.Buffer + usName.Length / sizeof WCHAR);

	usName.Length += sizeof WCHAR *
						BinToHex(Hash, sizeof NameHash, 
							usName.Buffer + usName.Length / sizeof WCHAR, 
							( usName.MaximumLength - usName.Length ) / sizeof WCHAR);

	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ios;
	HANDLE Handle;
	InitializeObjectAttributes(&oa, &usName, 
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
								NULL, NULL);

	rc = IoCreateFile(&Handle, 0, &oa, &ios, NULL, FILE_ATTRIBUTE_DIRECTORY,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
						NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if ( NT_SUCCESS(rc) )
		ZwClose(Handle);
	else
		ERR(rc);

	//
	// Create key for registry redirect
	//
	usName.Length = 0;
	RtlAppendUnicodeStringToString(&usName, &usRegParamName);
    RtlAppendUnicodeToString(&usName, L"\\redirect\\");
	usName.Length += sizeof WCHAR * SetProcessName(Process, usName.Buffer + usName.Length / sizeof WCHAR);
	usName.Length += sizeof WCHAR *
						BinToHex(Hash, sizeof NameHash, 
							usName.Buffer + usName.Length / sizeof WCHAR, 
							( usName.MaximumLength - usName.Length ) / sizeof WCHAR);

    ULONG Disposition;
    rc = ZwCreateKey(&Handle, KEY_SET_VALUE, &oa, 0, NULL, 
                        REG_OPTION_NON_VOLATILE, &Disposition);
    if ( NT_SUCCESS(rc) )
		ZwClose(Handle);
	else
        ERR(rc);

	delete[] usName.Buffer;

	return rc;
}

}; // namespace Hook {

VOID Hook::CreateProcessNotify(
    IN HANDLE  ParentId,
    IN HANDLE  ProcessId,
    IN BOOLEAN  Create
    )
{
    //
    // Get EPROCESS pointer
    //
    NTSTATUS rc;
    PEPROCESS Process;
    rc = PsLookupProcessByProcessId(ProcessId, &Process);
    if ( !NT_SUCCESS(rc) ) {
        if ( PsGetCurrentProcessId() != ProcessId ) {
            ERR(rc);
            return;
        }
		ERR(rc);

        Process = PsGetCurrentProcess();
        ObReferenceObject(Process); // simulate PsLookupProcessByProcessId reference
    }

	PEPROCESS RealParent = Hook::GetCurrentProcess();

	if ( Create ) {

		PEPROCESS ParentProcess;
		rc = PsLookupProcessByProcessId(ParentId, &ParentProcess);
		if ( !NT_SUCCESS(rc) ) {
			ObDereferenceObject(Process);
			ERR(rc);
			return;
		}

		PUNICODE_STRING FileName = GetProcessImageName(Process);
        PFILE_OBJECT FileObject = NULL;
		HANDLE hFile = NULL;

        Syn.Exclusive();

        SectionInfo *SectInfo = LookupSection(NULL, FileName, true);
        if ( SectInfo != NULL ) {
            FileObject = SectInfo->FileObject;
		} else {
			//
			// Get file object by opening file
			//
			Syn.Release();
			OBJECT_ATTRIBUTES oa;
			IO_STATUS_BLOCK ios;
			InitializeObjectAttributes(&oa, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			rc = IoCreateFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
								FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
								FILE_OPEN , FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
								NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
			if ( !NT_SUCCESS(rc) ) {
				ObDereferenceObject(ParentProcess);
				ObDereferenceObject(Process);
				ERR(0);
				return;
			}
			rc = ObReferenceObjectByHandle(hFile, FILE_EXECUTE | SYNCHRONIZE, *IoFileObjectType, KernelMode, (PVOID *) &FileObject, NULL);
			if ( !NT_SUCCESS(rc) ) {
				ZwClose(hFile);
				ObDereferenceObject(ParentProcess);
				ObDereferenceObject(Process);
				ERR(0);
				return;
			}

			Syn.Exclusive();
		}

        ProcessInfo *Info = LookupProcess(Process);
        if ( Info == NULL ) {
            //
            // Insert new process
            //
            Info = new (PagedPool) ProcessInfo;
            if ( Info == NULL ) {
                Syn.Release();
				if ( FileName != NULL ) delete FileName;
				if ( hFile != NULL ) {
					ObDereferenceObject(FileObject);
					ZwClose(hFile);
				}
				ObDereferenceObject(ParentProcess);
				ObDereferenceObject(Process);
                rc = STATUS_INSUFFICIENT_RESOURCES;
                ERR(rc);
                return;
            }

            Info->Process = Process;
			Info->ProcessId = ProcessId;
			ObReferenceObject(Info->Process);
            Info->ParentProcess = ParentProcess;
            Info->FileObject = FileObject;
			//
			// reference file object before releasing Syn lock
			ObReferenceObject(FileObject);
            Info->wcHash[0] = 0;
            Info->Redirect = rdsNone;
			Info->RuleId = 0;
			Info->FileName = FileName;
            InitializeListHead(&Info->AttrList);
            InsertTailList(&ProcessList, &Info->Entry);

			if ( Info->FileName != NULL ) {
				NameHash Hash;
				GetNameHash(Info->FileName->Buffer, Info->FileName->Length, Hash);
				if (Info != NULL) {
					BinToHex(Hash, sizeof Hash, Info->wcHash + SetProcessName(Process, Info->wcHash), sizeof Info->wcHash / sizeof WCHAR);
				}
				Syn.Release();

				//
				// Create folder for files redirect if not here yet
				//
				CreateContainersInfo *ContainersInfo = new(NonPagedPool) CreateContainersInfo;
				if ( Info != NULL ) {
					ContainersInfo->Hash = Hash;
					ContainersInfo->Process = Process;
					SysProcess::Run(ContainersInfo, (_SysProc) CreateRedirectContainers);
					delete ContainersInfo;
				} else
					ERR(STATUS_INSUFFICIENT_RESOURCES);
			} else {
				Syn.Release();
			}

			RuleResult Result = CreateSubject(ParentProcess, Process, FileObject);
			//
			// Dereferencing file object, it means ProcessInfo doesn't contain a valid FileObject
			// TODO: Check if that is necessary
			//
			ObDereferenceObject(FileObject);
		} else {
			Syn.Release();
			if ( FileName != NULL ) delete FileName;
		}

		if ( hFile != NULL ) {
			ObDereferenceObject(FileObject);
			ZwClose(hFile);
		}
		ObDereferenceObject(ParentProcess);
		ObDereferenceObject(Process);
		return;
	}

	RedirectStatus CleanupStatus = Rule::DeleteSubject(Process);

    Syn.Exclusive();

    ProcessInfo *Info = LookupProcess(Process);
    if (Info != NULL) {
        //
        // Delete process info
        //
        RemoveEntryList(&Info->Entry);
		ObDereferenceObject(Info->Process);
        //
        // Delete attributes
        //
       while ( !IsListEmpty(&Info->AttrList) ) {

            PLIST_ENTRY pEntry = RemoveTailList(&Info->AttrList);
			ProcessAttrinutes *AttrInfo = CONTAINING_RECORD(pEntry, ProcessAttrinutes, Entry);
            delete AttrInfo;
       }
	}
	//
	// Delete maps
	//
	PLIST_ENTRY Entry = ThreadMapList.Flink;
	while ( Entry != &ThreadMapList ) {
		ThreadMapItem *MapItem = CONTAINING_RECORD(Entry, ThreadMapItem, Entry);
		if ( MapItem->Process == Process ) {
			RemoveEntryList(&MapItem->Entry);
			delete MapItem;
			Entry = ThreadMapList.Flink;
		} else
			Entry = Entry->Flink;
	}
	Entry = TokenMapList.Flink;
	while ( Entry != &TokenMapList ) {
		TokenMapItem *MapItem = CONTAINING_RECORD(Entry, TokenMapItem, Entry);
		if ( MapItem->HostProcess == Process || MapItem->Process == Process ) {
			RemoveEntryList(&MapItem->Entry);
			delete MapItem;
			Entry = TokenMapList.Flink;
		} else
			Entry = Entry->Flink;
	}

	Syn.Release();

	//
	// Enforce cleanup policy
	//
	if ( Info != NULL ) {
		if ( CleanupStatus & rdsFile ) {
			UNICODE_STRING RootName = { 0, 0, NULL };
			static const NameLength = 256;
			RootName.Buffer = new (PagedPool) WCHAR[NameLength];
			if ( RootName.Buffer != NULL ) {
				RootName.MaximumLength = NameLength * sizeof WCHAR;

				RootName.Length = 0;
				if ( CleanupStatus & rdsFile ) {
					//
					// Delete redirected files
					//
					RtlAppendUnicodeToString(&RootName, RedirectDir);
					RtlAppendUnicodeToString(&RootName, Info->wcHash);
					rc = FsFilter::DeleteDirFiles(&RootName);
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
					}
				}
				RootName.Length = 0;
				if ( CleanupStatus & rdsKey ) {
					//
					// Delete redirected values
					//
					RtlAppendUnicodeStringToString(&RootName, &usRegParamName);
					RtlAppendUnicodeToString(&RootName, L"\\redirect\\");
					RtlAppendUnicodeToString(&RootName, Info->wcHash);
					rc = DeleteSubKeys(&RootName);
					if ( !NT_SUCCESS(rc) ) {
						ERR(rc);
					}
				}
				delete[] RootName.Buffer;
			} else
				ERR(STATUS_INSUFFICIENT_RESOURCES);
		}

  		if ( Info->FileName != NULL ) delete[] Info->FileName;
		delete Info;
	}

    ObDereferenceObject(Process); // dereference from PsLookupProcessByProcessId
}

NTSTATUS Hook::NewMmMapViewOfSection (
    IN PVOID                SectionObject,
    IN PEPROCESS            Process,
    IN OUT PVOID            *BaseAddress,
    IN ULONG                ZeroBits,
    IN ULONG                CommitSize,
    IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
    IN OUT PULONG           ViewSize,
    IN SECTION_INHERIT      InheritDisposition,
    IN ULONG                AllocationType,
    IN ULONG                Protect
    )
{ 
    NTSTATUS rc;
    BOOLEAN bTrack = FALSE;

    {
        HANDLE hSection;
        rc = ObOpenObjectByPointer(SectionObject, OBJ_KERNEL_HANDLE, NULL, 
                                    0, *MmSectionObjectType, KernelMode, &hSection);
        if ( NT_SUCCESS(rc) ) {
            SECTION_BASIC_INFORMATION SectInfo;
            rc = ZwQuerySection(hSection, SectionBasicInformation, &SectInfo, sizeof SectInfo, NULL);
            if ( NT_SUCCESS(rc) && SectInfo.Attributes & SEC_IMAGE )
                bTrack = TRUE;
            ZwClose(hSection);
        }
    }

    if ( bTrack ) {

        PSECTION_OBJECT Section = (PSECTION_OBJECT) SectionObject;
        PFILE_OBJECT FileObject = NULL;
		ProcessInfo *Info = NULL;

        Syn.Exclusive();

        SectionInfo *SectInfo = LookupSection(Section, NULL, true);
        if ( SectInfo != NULL ) {
            FileObject = SectInfo->FileObject; 
        }

        if ( FileObject != NULL ) Info = LookupProcess(Process);
        Syn.Release();

        if ( Info != NULL ) {
			RuleResult Result = MapSubject(Process, FileObject);
			if ( Result != rurAllowAction ) {
				rc = STATUS_ACCESS_DENIED;
				ERR(rc);
				return rc;
			}
		}
    }

    rc = OldMmMapViewOfSection(
                SectionObject,
                Process,
                BaseAddress,
                ZeroBits,
                CommitSize,
                SectionOffset,
                ViewSize,
                InheritDisposition,
                AllocationType,
                Protect);

    return rc;
}

NTSTATUS Hook::NewMmCreateSection (
    OUT PVOID               *SectionObject,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER       MaximumSize,
    IN ULONG                SectionPageProtection,
    IN ULONG                AllocationAttributes,
    IN HANDLE               FileHandle OPTIONAL,
    IN PFILE_OBJECT         FileObject OPTIONAL
    )
{
    NTSTATUS rc;

	ACCESS_MASK ModifyAccess = Rule::GetModifyAccess(nttSection);
	if ( ( DesiredAccess & ModifyAccess || DesiredAccess == 0 ) && 
		 ( FileObject != NULL || FileHandle != NULL ) ) {
		PFILE_OBJECT TempFileObject = FileObject;
        if ( TempFileObject == NULL && FileHandle != NULL ) {
            rc = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, 
                                           KernelMode, (PVOID *) &TempFileObject, NULL);
            if ( !NT_SUCCESS(rc) ) {
                ERR(rc);
                return rc;
            }
		} else
			ObReferenceObject(TempFileObject);

		bool LoggingMode = FsFilter::EnableLogging;
		if ( FileHandle == NULL || !( DesiredAccess & ( SECTION_MAP_WRITE | SECTION_EXTEND_SIZE | GENERIC_WRITE | GENERIC_ALL ) ) ) {
			LoggingMode = FsFilter::DisableLogging;
		}
		BOOLEAN bIsReadOnly = FsFilter::IsFileReadOnly(TempFileObject, LoggingMode);
		ObDereferenceObject(TempFileObject);
		if ( bIsReadOnly ) {
			DesiredAccess &= ~ModifyAccess;
			if ( DesiredAccess == 0 ) return STATUS_ACCESS_DENIED;
		}
	}

	//
	// Clean section list in advance
	//
	if ( AllocationAttributes & SEC_IMAGE ) {
        Syn.Exclusive();
        SectionInfo *SectInfo = LookupSection(NULL, NULL, true);
		Syn.Release();
	}

	rc = OldMmCreateSection(
                SectionObject,
                DesiredAccess,
                ObjectAttributes,
                MaximumSize,
                SectionPageProtection,
                AllocationAttributes,
                FileHandle,
                FileObject);

    if ( NT_SUCCESS(rc) && AllocationAttributes & SEC_IMAGE && 
		 SectionPageProtection & ( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) ) {

        if ( FileObject == NULL && FileHandle != NULL ) {
            rc = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, 
                                           KernelMode, (PVOID *) &FileObject, NULL);
            if ( !NT_SUCCESS(rc) ) {
                ObDereferenceObject(*SectionObject);
                ERR(rc);
                return rc;
            }
		} else {
			if ( FileObject != NULL )
				ObReferenceObject(FileObject);
			else
				return rc;
		}

        PSECTION_OBJECT Section = (PSECTION_OBJECT) *SectionObject;
        if ( Section->Segment->BaseAddress != 
             FileObject->SectionObjectPointer->ImageSectionObject ) {

            ObDereferenceObject(*SectionObject);
            ObDereferenceObject(FileObject);
            rc = STATUS_UNSUCCESSFUL;
            ERR(rc);
            return rc;
        }

        Syn.Exclusive();
        SectionInfo *SectInfo = LookupSection(Section, NULL, false);
        if ( SectInfo == NULL ) {
            //
            // Insert new Section
            //
            SectInfo = new (PagedPool) SectionInfo;
            if ( SectInfo == NULL ) {
                Syn.Release();
                rc = STATUS_INSUFFICIENT_RESOURCES;
                ERR(rc);
                return rc;
            }

            SectInfo->Section = Section;
            SectInfo->FileObject = FileObject;
            GetObjectName(FileObject, &SectInfo->FileName);

            ObReferenceObject(Section);
            InsertTailList(&SectionList, &SectInfo->Entry);
        }

        Syn.Release();
	}

    return rc;
}

NTSTATUS Hook::NewZwQueryValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    )
{
    NTSTATUS rc;
	if ( KeGetPreviousMode() == KernelMode )
		return OldZwQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    if ( IsRedirectEnabled(rdsKey) ) {

        PVOID Object;
        rc = ObReferenceObjectByHandle(KeyHandle, KEY_QUERY_VALUE, NULL, KeGetPreviousMode(), 
                                       (PVOID *) &Object, NULL);
        if ( !NT_SUCCESS(rc) ) {
            ERR(rc);
            return rc;
        }

	    PUNICODE_STRING ObjectName = NULL;
        rc = GetObjectName(Object, &ObjectName);
		if ( !NT_SUCCESS(rc) ) {
			ObDereferenceObject(Object);
			ERR(rc);
			return rc;
		}

        UNICODE_STRING usKey;
		if ( GetRedirectName(nttKey, ObjectName, &usKey) ) {
			delete[] ObjectName;
			ObDereferenceObject(Object);
            OBJECT_ATTRIBUTES oa;
            HANDLE hKey;
            InitializeObjectAttributes(&oa, &usKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
            rc = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
			delete[] usKey.Buffer;
            if ( NT_SUCCESS(rc) ) {
                rc = OldZwQueryValueKey(
                        hKey,
                        ValueName,
                        KeyValueInformationClass,
                        KeyValueInformation,
                        Length,
                        ResultLength);

                ZwClose(hKey);
                if ( NT_SUCCESS(rc) ) return rc;
            }
		} else {
			delete[] ObjectName;
			ObDereferenceObject(Object);
		}
    }

    rc = OldZwQueryValueKey(
            KeyHandle,
            ValueName,
            KeyValueInformationClass,
            KeyValueInformation,
            Length,
            ResultLength);

    return rc;
}


NTSTATUS Hook::NewZwQueryMultipleValueKey (
    IN HANDLE KeyHandle,
    IN OUT PKEY_VALUE_ENTRY ValueList,
    IN ULONG NumberOfValues,
    OUT PVOID Buffer,
    IN OUT PULONG Length,
    OUT PULONG ReturnLength
    )
{
    NTSTATUS rc;

    rc = OldZwQueryMultipleValueKey(
            KeyHandle,
            ValueList,
            NumberOfValues,
            Buffer,
            Length,
            ReturnLength);

    return rc;
}

NTSTATUS Hook::NewZwSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex OPTIONAL,
    IN ULONG Type,
    IN PVOID Data,
    IN ULONG DataSize
    )
{
	if ( KeGetPreviousMode() == KernelMode )
		return OldZwSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

	RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	_EPROCESS *Subject = Hook::GetCurrentProcess();
	if ( NeedRuleCheck(Subject, SubjectAttributes, Redirect, RuleId) == false ) {
		return OldZwSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
	}

	NTSTATUS rc;
    BOOLEAN bRedirect = FALSE;
    PVOID Object;
    rc = ObReferenceObjectByHandle(KeyHandle, KEY_SET_VALUE, NULL, KeGetPreviousMode(), 
                                   (PVOID *) &Object, NULL);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

	//
	// Copy Value Name
	//
	UNICODE_STRING CopiedValueName = { 0, 0, NULL };
	__try {
		ProbeForRead(ValueName, sizeof UNICODE_STRING, sizeof(ULONG));
		CopiedValueName.MaximumLength = ValueName->Length;
		ProbeForRead(ValueName->Buffer, CopiedValueName.MaximumLength, sizeof(ULONG));
		CopiedValueName.Buffer = (WCHAR *) new(PagedPool) UCHAR[CopiedValueName.MaximumLength];
		if ( CopiedValueName.Buffer != NULL ) RtlCopyMemory(CopiedValueName.Buffer, ValueName->Buffer, CopiedValueName.MaximumLength);
		CopiedValueName.Length = CopiedValueName.MaximumLength;
	} __except( EXCEPTION_EXECUTE_HANDLER ) {
		ERR(GetExceptionCode());
	}

	ACCESS_MASK DesiredAccess = 0;
    RuleResult Result = Rule::AccessObject(acsWrite, Subject, SubjectAttributes, Redirect, RuleId, 
											Object, &CopiedValueName, nttKey, DesiredAccess);
	if ( Result != rurAllowAction ) {

		bool LogIt = true;
		if ( NtRuleMap::AccessLog == GesRule::aclReduced ) {
			//
			// Read current value
			//
			ULONG Size = DataSize;
			PVOID Buf = new(PagedPool) UCHAR[Size];
			if ( Buf != NULL ) {
				rc = RegReadValue(KeyHandle, &CopiedValueName, (PVOID *) &Buf, &Size, NULL);
				if ( NT_SUCCESS(rc) && Size == DataSize ) {
					__try {
						ProbeForRead(Data, DataSize, sizeof(ULONG));
						if ( RtlCompareMemory(Buf, Data, Size) == Size ) LogIt = false;
					} __except( EXCEPTION_EXECUTE_HANDLER ) {
						ERR(GetExceptionCode());
					}
				}
				delete Buf;
			}
		}
		if ( LogIt ) {
			//
			// Log restricted access
			//
			NtRuleMap::Log(Rule::acsWrite, Subject, SubjectAttributes, RuleId, Object, nttKey, &CopiedValueName, NULL, DesiredAccess, Result);
		}
	}
	if ( CopiedValueName.Buffer != NULL ) delete CopiedValueName.Buffer;
    
    switch ( Result ) {
        case rurBlockSubject:
        case rurBlockAction:
        case rurBlockModify:
			ObDereferenceObject(Object);
            return STATUS_ACCESS_DENIED;

        case rurRedirect:
            {
				PUNICODE_STRING ObjectName = NULL;
				rc = GetObjectName(Object, &ObjectName);
				if ( !NT_SUCCESS(rc) ) {
					ObDereferenceObject(Object);
					ERR(rc);
					return rc;
				}

				UNICODE_STRING usKey;
				if ( !GetRedirectName(nttKey, ObjectName, &usKey) ) {
					delete[] ObjectName;
				    ObDereferenceObject(Object);
					rc = STATUS_UNSUCCESSFUL;
                    ERR(rc);
                    return rc;
				}
				delete[] ObjectName;
/*
				//
				// TODO: get object sd
				//
				PSECURITY_DESCRIPTOR sd = NULL;
			    BOOLEAN  bMemoryAllocated;
		        rc = ObGetObjectSecurity(Object, &sd, &bMemoryAllocated);
				if ( !NT_SUCCESS(rc) ) {
					sd = NULL;
				}
*/
				OBJECT_ATTRIBUTES oa;
                ULONG Disposition;
                //InitializeObjectAttributes(&oa, &usKey, OBJ_CASE_INSENSITIVE, NULL, sd);
				InitializeObjectAttributes(&oa, &usKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
                rc = ZwCreateKey(&KeyHandle, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition);

//				if ( sd != NULL ) ObReleaseObjectSecurity(sd, bMemoryAllocated);

				delete[] usKey.Buffer;
                if ( !NT_SUCCESS(rc) ) {
					ObDereferenceObject(Object);
                    ERR(rc);
                    return rc;
                }

                bRedirect = TRUE;
            }
            break;
    }

    ObDereferenceObject(Object);

    rc = OldZwSetValueKey(
            KeyHandle,
            ValueName,
            TitleIndex,
            Type,
            Data,
            DataSize);

    if ( bRedirect ) ZwClose(KeyHandle);

    return rc;
}

NTSTATUS Hook::NewZwDeleteValueKey(IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName)
{
	if ( KeGetPreviousMode() == KernelMode )
		return OldZwDeleteValueKey(KeyHandle, ValueName);

	RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	_EPROCESS *Subject = Hook::GetCurrentProcess();
	if ( NeedRuleCheck(Subject, SubjectAttributes, Redirect, RuleId) == false ) {
		return OldZwDeleteValueKey(KeyHandle, ValueName);
	}

	NTSTATUS rc;
    PVOID Object;
    rc = ObReferenceObjectByHandle(KeyHandle, KEY_SET_VALUE, NULL, KeGetPreviousMode(), 
                                   (PVOID *) &Object, NULL);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

	//
	// Copy Value Name
	//
	UNICODE_STRING CopiedValueName = { 0, 0, NULL };
	__try {
		ProbeForRead(ValueName, sizeof UNICODE_STRING, sizeof(ULONG));
		CopiedValueName.MaximumLength = ValueName->Length;
		ProbeForRead(ValueName->Buffer, CopiedValueName.MaximumLength, sizeof(ULONG));
		CopiedValueName.Buffer = (WCHAR *) new(PagedPool) UCHAR[CopiedValueName.MaximumLength];
		if ( CopiedValueName.Buffer != NULL ) RtlCopyMemory(CopiedValueName.Buffer, ValueName->Buffer, CopiedValueName.MaximumLength);
		CopiedValueName.Length = CopiedValueName.MaximumLength;
	} __except( EXCEPTION_EXECUTE_HANDLER ) {
		ERR(GetExceptionCode());
	}

	ACCESS_MASK DesiredAccess = 0;
    RuleResult Result = Rule::AccessObject(acsWrite, Subject, SubjectAttributes, Redirect, RuleId, 
										   Object, &CopiedValueName, nttKey, DesiredAccess);
	if ( Result != rurAllowAction ) {
		//
		// Log restricted access
		//
		NtRuleMap::Log(Rule::acsWrite, Subject, SubjectAttributes, RuleId, Object, nttKey, &CopiedValueName, NULL, DesiredAccess, Result);
	}
	if ( CopiedValueName.Buffer != NULL ) delete CopiedValueName.Buffer;
    ObDereferenceObject(Object);

    if ( Result != rurAllowAction ) {
        return STATUS_ACCESS_DENIED;
	}

	return OldZwDeleteValueKey(KeyHandle, ValueName);
}

NTSTATUS Hook::NewZwDeleteKey(IN HANDLE KeyHandle)
{
	if ( KeGetPreviousMode() == KernelMode )
		return OldZwDeleteKey(KeyHandle);

	RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	_EPROCESS *Subject = Hook::GetCurrentProcess();
	if ( NeedRuleCheck(Subject, SubjectAttributes, Redirect, RuleId) == false ) {
		return OldZwDeleteKey(KeyHandle);
	}

	NTSTATUS rc;
    PVOID Object;
    rc = ObReferenceObjectByHandle(KeyHandle, DELETE, NULL, KeGetPreviousMode(), (PVOID *) &Object, NULL);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    ACCESS_MASK DesiredAccess = 0;
    RuleResult Result = Rule::AccessObject(acsWrite, Subject, SubjectAttributes, Redirect, RuleId, 
										   Object, NULL, nttKey, DesiredAccess);
	if ( Result != rurAllowAction ) {
		//
		// Log restricted access
		//
		NtRuleMap::Log(Rule::acsWrite, Subject, SubjectAttributes, RuleId, Object, nttKey, NULL, NULL, DesiredAccess, Result);
	}
    ObDereferenceObject(Object);

    if ( Result != rurAllowAction ) {
        return STATUS_ACCESS_DENIED;
	}

	return OldZwDeleteKey(KeyHandle);
}

NTSTATUS Hook::NewZwRestoreKey(IN HANDLE KeyHandle, IN HANDLE FileHandle, IN ULONG Flags)
{
	if ( KeGetPreviousMode() == KernelMode )
		return OldZwRestoreKey(KeyHandle, FileHandle, Flags);

	RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	_EPROCESS *Subject = Hook::GetCurrentProcess();
	if ( NeedRuleCheck(Subject, SubjectAttributes, Redirect, RuleId) == false ) {
		return OldZwRestoreKey(KeyHandle, FileHandle, Flags);
	}

	NTSTATUS rc;
    PVOID Object;
    rc = ObReferenceObjectByHandle(KeyHandle, 0, NULL, KeGetPreviousMode(), (PVOID *) &Object, NULL);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    ACCESS_MASK DesiredAccess = 0;
    RuleResult Result = Rule::AccessObject(acsWrite, Subject, SubjectAttributes, Redirect, RuleId, 
										   Object, NULL, nttKey, DesiredAccess);
	if ( Result != rurAllowAction ) {
		//
		// Log restricted access
		//
		NtRuleMap::Log(Rule::acsWrite, Subject, SubjectAttributes, RuleId, Object, nttKey, NULL, NULL, DesiredAccess, Result);
	}
    ObDereferenceObject(Object);

    if ( Result != rurAllowAction ) {
        return STATUS_ACCESS_DENIED;
	}

	return OldZwRestoreKey(KeyHandle, FileHandle, Flags);
}

NTSTATUS Hook::NewZwReplaceKey(
	IN POBJECT_ATTRIBUTES   NewFileObjectAttributes,
	IN HANDLE               KeyHandle,
	IN POBJECT_ATTRIBUTES   OldFileObjectAttributes
	)
{
	if ( KeGetPreviousMode() == KernelMode )
		return OldZwReplaceKey(NewFileObjectAttributes, KeyHandle, OldFileObjectAttributes);

	RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	_EPROCESS *Subject = Hook::GetCurrentProcess();
	if ( NeedRuleCheck(Subject, SubjectAttributes, Redirect, RuleId) == false ) {
		return OldZwReplaceKey(NewFileObjectAttributes, KeyHandle, OldFileObjectAttributes);
	}

	NTSTATUS rc;
    PVOID Object;
    rc = ObReferenceObjectByHandle(KeyHandle, 0, NULL, KeGetPreviousMode(), (PVOID *) &Object, NULL);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    ACCESS_MASK DesiredAccess = 0;
    RuleResult Result = Rule::AccessObject(acsWrite, Subject, SubjectAttributes, Redirect, RuleId, 
										   Object, NULL, nttKey, DesiredAccess);
	if ( Result != rurAllowAction ) {
		//
		// Log restricted access
		//
		NtRuleMap::Log(Rule::acsWrite, Subject, SubjectAttributes, RuleId, Object, nttKey, NULL, NULL, DesiredAccess, Result);
	}
    ObDereferenceObject(Object);

    if ( Result != rurAllowAction ) {
        return STATUS_ACCESS_DENIED;
	}

	return OldZwReplaceKey(NewFileObjectAttributes, KeyHandle, OldFileObjectAttributes);
}

NTSTATUS Hook::NewZwClose(IN HANDLE Handle)
{
    NTSTATUS rc;

    rc = OldZwClose(Handle);
	if ( !NT_SUCCESS(rc) ) return rc;
	//
	// Clean token map list, not good to hook ZwClose, but no other way
	// TODO: fix it, when have a better idea
	//
	TokenSyn.Exclusive();
	TokenMapItem *MapItem = LookupTokenMap(Handle, PsGetCurrentProcess());
	if ( MapItem != NULL ) {
		RemoveEntryList(&MapItem->Entry);
		delete MapItem;
	}
	TokenSyn.Release();

    return rc;
}

NTSTATUS Hook::NewZwSetSecurityObject(
    IN HANDLE Handle,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor
    )
{
    NTSTATUS rc;

    if ( SecurityInformation & SACL_SECURITY_INFORMATION ) {

        PVOID Object;
        rc = ObReferenceObjectByHandle(Handle, ACCESS_SYSTEM_SECURITY, NULL, KeGetPreviousMode(), 
                                       (PVOID *) &Object, NULL);
        if ( !NT_SUCCESS(rc) ) {
            ERR(rc);
            return rc;
        }

        NtObjectType NtType = MapNtObjectType(NULL, Object);
        ACCESS_MASK Access = 0;
        RuleResult Result = AccessObject(acsAci, Hook::GetCurrentProcess(), Object, NULL,
										 NtType, Access);
        ObDereferenceObject(Object);

        switch ( Result ) {
            case rurBlockSubject:
            case rurBlockAction:
            case rurBlockModify:
            case rurRedirect:
                SecurityInformation &= ~SACL_SECURITY_INFORMATION;
        }
    }

    rc = OldZwSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor);

    return rc;
}

NTSTATUS Hook::GetProcessInfo(CHAR *Label, PEPROCESS Process, EntityAttributes &Attributes,
                              Rule::RedirectStatus &Redirect, ULONG &RuleId)
{
	NTSTATUS rc = STATUS_UNSUCCESSFUL;
    RtlZeroMemory(&Attributes, sizeof Attributes);
	Redirect = rdsNone;
	RuleId = 0;

    Syn.Share();
    ProcessInfo *Info = LookupProcess(Process);
    if ( Info != NULL ) {
        Redirect = Info->Redirect;
		RuleId = Info->RuleId;
        ProcessAttrinutes *Attr = LookupAttributes(Label, Info);
        if ( Attr != NULL ) {
            Attributes = Attr->Attr;
        }
		// check/set processid
		if ( Info->ProcessId == 0 && PsGetCurrentProcess() == Process ) {
			InterlockedExchangePointer(&Info->ProcessId, PsGetCurrentProcessId());
		}
		rc = STATUS_SUCCESS;
    }

    Syn.Release();
    return rc;
}

NTSTATUS Hook::SetProcessInfo(CHAR *Label, PEPROCESS Process, EntityAttributes &Attributes,
							  Rule::RedirectStatus Redirect, ULONG RuleId, AttrSetFunction Func)
{
    NTSTATUS rc = STATUS_SUCCESS;

    Syn.Exclusive();
    ProcessInfo *Info = LookupProcess(Process);
    if ( Info != NULL ) {
        if ( Redirect != rdsUndefined ) Info->Redirect = Redirect;
		if ( RuleId != 0 ) Info->RuleId = RuleId;
        ProcessAttrinutes *Attr = LookupAttributes(Label, Info);
        if ( Attr == NULL ) {
            Attr = new (PagedPool) ProcessAttrinutes;
            if ( Attr == NULL ) {
                Syn.Release();
                rc = STATUS_INSUFFICIENT_RESOURCES;
                ERR(rc);
                return rc;
            }
            Attr->Label = *(PULONG)Label;
            InsertTailList(&Info->AttrList, &Attr->Entry);
        }
		if ( Func == asfNone ) Attr->Attr = Attributes;
		else
		if ( Func == asfOr ) {
			for ( SIZE_T i = 0; i < AttrNum; i++ ) Attr->Attr.Param[i] |= Attributes.Param[i];
		}
    }

    Syn.Release();
    return rc;
}

PFILE_OBJECT Hook::GetProcessFileObject(PEPROCESS Process)
{
	PFILE_OBJECT FileObject = NULL;
    Syn.Share();
    ProcessInfo *Info = LookupProcess(Process);
    if ( Info != NULL ) {
		FileObject = Info->FileObject;
		ObReferenceObject(FileObject);
    }

    Syn.Release();
    return FileObject;
}

PUNICODE_STRING Hook::GetProcessFileName(PEPROCESS Process)
{
	PUNICODE_STRING FileName = NULL;
    Syn.Share();
    ProcessInfo *Info = LookupProcess(Process);
    if ( Info != NULL && Info->FileName != NULL ) {
		FileName = (PUNICODE_STRING) new(PagedPool) UCHAR[sizeof UNICODE_STRING + Info->FileName->Length];
		if ( FileName != NULL ) {
			FileName->Buffer = (WCHAR *)((PUCHAR)FileName + sizeof UNICODE_STRING);
			FileName->Length = Info->FileName->Length;
			FileName->MaximumLength = FileName->Length;
			RtlCopyMemory(FileName->Buffer, Info->FileName->Buffer, Info->FileName->Length);
		}
		else
			ERR(STATUS_INSUFFICIENT_RESOURCES);
    }

    Syn.Release();
    return FileName;
}

BOOLEAN Hook::IsRedirectEnabled(Rule::RedirectStatus Redirect)
{
	BOOLEAN bRedirect = FALSE;

	Syn.Share();
	ProcessInfo *Info = LookupProcess(PsGetCurrentProcess());
	if (Info != NULL && ( Info->Redirect == rdsAll || Info->Redirect == Redirect ) )
		bRedirect = TRUE;
	Syn.Release();

	return bRedirect;
}

BOOLEAN Hook::GetRedirectName(NtObjectType NtType, PUNICODE_STRING ObjectName, PUNICODE_STRING Name)
{
	Name->Buffer = NULL;

	static const NameLength = 256;
	Name->Buffer = new (PagedPool) WCHAR[NameLength];
	if ( Name->Buffer == NULL ) {
		ERR(STATUS_INSUFFICIENT_RESOURCES);
		return FALSE;
	}

	Name->Length = 0;
	Name->MaximumLength = NameLength * sizeof WCHAR;
	if ( NtType == nttFile )
		RtlAppendUnicodeToString(Name, RedirectDir);
	else {
        RtlAppendUnicodeStringToString(Name, &usRegParamName);
        RtlAppendUnicodeToString(Name, L"\\redirect\\");
	}

	Syn.Share();
	ProcessInfo *Info = LookupProcess(PsGetCurrentProcess());
	if (Info != NULL) {
		RtlAppendUnicodeToString(Name, Info->wcHash);
	}
	Syn.Release();

	RtlAppendUnicodeToString(Name, L"\\");
	//
	// copy part of name
	//
	static const SIZE_T MaxNameLength = 64;
	SIZE_T Length = min(ObjectName->Length / sizeof WCHAR, MaxNameLength-1);
	WCHAR *Dest = Name->Buffer + Name->Length / sizeof WCHAR;
	WCHAR *Src = ObjectName->Buffer + ObjectName->Length / sizeof WCHAR - Length;
	SIZE_T i;
	for ( i = 0; i < Length; i++ ) 
		if ( Src[i] == '\\' || Src[i] == '/' ) 
			Dest[i] = '#';
		else
			Dest[i] = Src[i];

	for ( i = Length; i < MaxNameLength; i ++ ) Dest[i] = '_';
	Name->Length += MaxNameLength * sizeof WCHAR;
	//
	// Copy hash
	//
    NameHash Hash;
    GetNameHash(ObjectName->Buffer, ObjectName->Length, Hash);
	Name->Length += sizeof WCHAR *
				  BinToHex(Hash, sizeof Hash, Name->Buffer + Name->Length / sizeof WCHAR, 
								( Name->MaximumLength - Name->Length ) / sizeof WCHAR);

	return TRUE;
}

SIZE_T Hook::SetProcessName(PEPROCESS Process, WCHAR *Buf)
{
	SIZE_T Length = GetProcessNameByPointer(Process, Buf);
	SIZE_T i;
	for ( i = Length; i < NT_PROCNAMELEN - 1; i ++ ) Buf[i] = '_';
	Buf[i] = 0;
	return i;
}

Hook::ProcessAttrinutes *Hook::LookupAttributes(CHAR *Label, ProcessInfo *Info)
{
   PLIST_ENTRY pEntry = Info->AttrList.Flink;
   while ( pEntry != &Info->AttrList ) {

      ProcessAttrinutes *pNode = CONTAINING_RECORD(pEntry, ProcessAttrinutes, Entry);
      if ( pNode->Label == *(PULONG)Label )
            return pNode;

        pEntry = pEntry->Flink;
   }
    return NULL;
}

Hook::ProcessInfo *Hook::LookupProcess(PEPROCESS Process)
{
   PLIST_ENTRY pEntry = ProcessList.Flink;
   while (pEntry != &ProcessList) {

      ProcessInfo *pNode = CONTAINING_RECORD(pEntry, ProcessInfo, Entry);
      if ( pNode->Process == Process )
            return pNode;

        pEntry = pEntry->Flink;
   }

    return NULL;
}

Hook::SectionInfo *Hook::LookupSection(PSECTION_OBJECT Section, PUNICODE_STRING FileName, bool CleanList)
{
   PLIST_ENTRY pEntry = SectionList.Flink;
   while (pEntry != &SectionList) {
		SectionInfo *pNode = CONTAINING_RECORD(pEntry, SectionInfo, Entry);
        //
        // Look for deleted sections
        //
		if ( ObGetObjectPointerCount(pNode->Section) == 1 && CleanList ) {
			RemoveEntryList(&pNode->Entry);
            ObDereferenceObject(pNode->FileObject);
            ObDereferenceObject(pNode->Section);
			if ( pNode->FileName != NULL ) delete pNode->FileName;
			delete pNode;

			pEntry = SectionList.Flink;
            continue;
		} 

		if ( ( Section != NULL && pNode->Section == Section ) ||
			 ( FileName != NULL && pNode->FileName != NULL && 0 == RtlCompareUnicodeString(pNode->FileName, FileName, FALSE) ) 
		   ) return pNode;

        pEntry = pEntry->Flink;
   }

    return NULL;
}

Hook::ThreadMapItem *Hook::LookupThreadMap(PETHREAD Thread)
{
	PLIST_ENTRY Entry = ThreadMapList.Flink;
	while ( Entry != &ThreadMapList ) {
		ThreadMapItem *Item = CONTAINING_RECORD(Entry, ThreadMapItem, Entry);
		if ( Item->Thread == Thread ) return Item;
        Entry = Entry->Flink;
	}
    return NULL;
}

NTSTATUS Hook::AddThreadMap(_ETHREAD *Thread, _EPROCESS *Process)
{
	NTSTATUS rc = STATUS_SUCCESS;

	TokenSyn.Exclusive();
	//
	// Check if such mapping already exist
	//
	ThreadMapItem *Item = LookupThreadMap(Thread);
	if ( Item != NULL ) {
		trace("AddThreadMap: BUGBUGBUG!!!!!!!!!!!!!!!!!!!!!!, %p -> %p\n", Item->Process, Process);
		ObDereferenceObject(Item->Process);
		Item->Process = Process;
		ObReferenceObject(Item->Process);
		TokenSyn.Release();
		rc = STATUS_UNSUCCESSFUL;
		ERR(rc);
		return rc;
	}

	Item = new(PagedPool) ThreadMapItem(Thread, Process);
	if ( Item == NULL ) {
		TokenSyn.Release();
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}
	InsertTailList(&ThreadMapList, &Item->Entry);

	TokenSyn.Release();
	return rc;
}

Hook::TokenMapItem *Hook::LookupTokenMap(HANDLE hToken, PEPROCESS HostProcess)
{
	PLIST_ENTRY Entry = TokenMapList.Flink;
	while ( Entry != &TokenMapList ) {
		TokenMapItem *Item = CONTAINING_RECORD(Entry, TokenMapItem, Entry);
		if ( Item->HostProcess == HostProcess && Item->hToken == hToken ) return Item;
        Entry = Entry->Flink;
	}
    return NULL;
}

NTSTATUS Hook::AddTokenMap(HANDLE hToken, PEPROCESS HostProcess, PEPROCESS Process)
{
	NTSTATUS rc = STATUS_SUCCESS;
	TokenSyn.Exclusive();
	//
	// Check if such mapping already exists
	TokenMapItem *Item = LookupTokenMap(hToken, HostProcess);
	if ( Item != NULL ) {
		TokenSyn.Release();
		trace("AddTokenMap: BUGBUGBUG!!!!!!!!!!!!!!!!!!!!!!\n");
		rc = STATUS_UNSUCCESSFUL;
		ERR(rc);
		return rc;
	}

	Item = new(PagedPool) TokenMapItem(hToken, HostProcess, Process);
	if ( Item == NULL ) {
		TokenSyn.Release();
		rc = STATUS_INSUFFICIENT_RESOURCES;
		ERR(rc);
		return rc;
	}
	InsertTailList(&TokenMapList, &Item->Entry);

	TokenSyn.Release();
	return rc;
}

_EPROCESS *Hook::GetCurrentProcess(VOID)
{
	PEPROCESS Result = PsGetCurrentProcess();
	if ( !AdApi::PsIsThreadImpersonating(PsGetCurrentThread()) ) return Result;

	TokenSyn.Share();
	ThreadMapItem *Item = LookupThreadMap(PsGetCurrentThread());
	if ( Item != NULL ) {
		Result = Item->Process;
	}
	TokenSyn.Release();
/*
    TokenSyn.Share();
    ProcessInfo *Info = LookupProcess(Result);
	if ( Info != NULL ) {
		ProcessAttrinutes *Attr = LookupAttributes((CHAR *)&GesRule::GswLabel, Info);
		if ( Attr->Attr.Param[GesRule::attIntegrity] == GesRule::modTCB ) {
			//
			// if thread is impersonated and current process is non-isolated then try to retrive the original
			//

			// First, get impersonation token info
			//
			BOOLEAN CopyOnOpen;
			BOOLEAN EffectiveOnly;
			SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
			PACCESS_TOKEN Token = PsReferenceImpersonationToken(PsGetCurrentThread(), &CopyOnOpen, &EffectiveOnly, &ImpersonationLevel);
			if ( Token != NULL ) {

				PTOKEN_STATISTICS ImpersonatedStatistics;
				NTSTATUS rc = SeQueryInformationToken(Token, TokenStatistics, (PVOID *) &ImpersonatedStatistics);
				if ( !NT_SUCCESS(rc) ) ImpersonatedStatistics = NULL;
				PsDereferenceImpersonationToken(Token);

				if ( ImpersonatedStatistics != NULL ) {
					PLIST_ENTRY pEntry = ProcessList.Flink;
					while (pEntry != &ProcessList) {
						Info = CONTAINING_RECORD(pEntry, ProcessInfo, Entry);

						Token = PsReferencePrimaryToken(Info->Process);
						PTOKEN_STATISTICS Statistics;
						NTSTATUS rc = SeQueryInformationToken(Token, TokenStatistics, (PVOID *) &Statistics);
						PsDereferencePrimaryToken(Token);
						if ( NT_SUCCESS(rc) ) {
							if ( RtlEqualLuid(&Statistics->ModifiedId, &ImpersonatedStatistics->ModifiedId) ) {
								Result = Info->Process;
								ExFreePool(Statistics);
								break;
							}
							ExFreePool(Statistics);
						}

						pEntry = pEntry->Flink;
					}

					ExFreePool(ImpersonatedStatistics);
				}
			}
		}
	}
	TokenSyn.Release();
*/
	return Result;
}

HANDLE Hook::GetProcessId(PEPROCESS Process)
{
	HANDLE ProcessId = 0;
    Syn.Share();
    ProcessInfo *Info = LookupProcess(Process);
	if ( Info != NULL ) ProcessId = Info->ProcessId;

    Syn.Release();
	return ProcessId;
}

_EPROCESS *Hook::LookupProcessByToken(HANDLE hToken)
{
	PACCESS_TOKEN *Token = NULL;
	NTSTATUS rc = ObReferenceObjectByHandle(hToken, TOKEN_QUERY, *SeTokenObjectType, ExGetPreviousMode(), (PVOID *)&Token, NULL);
	if ( !NT_SUCCESS(rc) ) {
		ERR(rc);
		return NULL;
	}
	
	_EPROCESS *Process = NULL;

	Syn.Share();

	PLIST_ENTRY Entry = ProcessList.Flink;
	while ( Entry != &ProcessList ) {

		ProcessInfo *Node = CONTAINING_RECORD(Entry, ProcessInfo, Entry);
		PACCESS_TOKEN ProcessToken = PsReferencePrimaryToken(Node->Process);
		if ( ProcessToken != NULL ) {
			if ( ProcessToken == Token ) {
				ObDereferenceObject(ProcessToken);
				Process = Node->Process;
				break;
			}
			ObDereferenceObject(ProcessToken);
		}

		Entry = Entry->Flink;
	}

	if ( Process != NULL )
		ObReferenceObject(Process);

	Syn.Release();

	ObDereferenceObject(Token);

	return Process;
}


PVOID Hook::GetObCreateHandle(VOID)
{
    static const UCHAR Stamp[] = { 0x6a, 0x01, 0xe8 };
    PVOID Func = NULL;
    
	PVOID Base = hin::GetModuleBase("ntoskrnl.exe");
	PCHAR Cur = (PCHAR) hin::GetExportedFunc(Base, "ObOpenObjectByPointer");

    for ( ULONG i=0; i < 512; i++ )
        if ( RtlCompareMemory(Cur, Stamp, sizeof Stamp) == sizeof Stamp ) {
            Func = ( *PLONG(Cur+sizeof Stamp) + Cur + sizeof Stamp + 4 );
            break;
        } 
        else
            Cur++;
    

    return Func;
}

PVOID Hook::GetObCreateHandle2(VOID)
{
    static const UCHAR Stamp[] = { 0x6a, 0x01, 0xe8 };
    PVOID Func = NULL;
    
	PVOID Base = hin::GetModuleBase("ntoskrnl.exe");
	PCHAR Cur = (PCHAR) hin::GetExportedFunc(Base, "ObOpenObjectByPointerWithTag");

    for ( ULONG i=0; i < 512; i++ )
        if ( RtlCompareMemory(Cur, Stamp, sizeof Stamp) == sizeof Stamp ) {
            Func = ( *PLONG(Cur+sizeof Stamp) + Cur + sizeof Stamp + 4 );
            break;
        } 
        else
            Cur++;
    

    return Func;
}
