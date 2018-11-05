//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2003-2011 GentleSecurity. All rights reserved.
//
//

#if (!_CONSOLE && !_WINDOWS) // kernel mode
 #include "stdafx.h"
#endif 

#include "hin.h"
#include "x86.h"

namespace commonlib {

namespace hin {

#if defined(_X86_) || defined(_AMD64_)
	const SIZE_T TrampolineSize = sizeof x86::_Trampoline;
#elif defined(_IA64_)
	#error no IA64 support yet
#endif

HOOK_HANDLE HookCode(PVOID Module, PBYTE Code, PBYTE NewCode, PVOID *PrevCode, PBYTE Trampoline)
{
	PVOID HookContext = NULL;

#if defined(_X86_)
	x86::InitParse(x86::cwt32);
	return x86::InjectCode(Module, Code, NewCode, PrevCode, (x86::_Trampoline *)Trampoline);
#elif defined(_AMD64_)
	x86::InitParse(x86::cwt64);
	return x86::InjectCode(Module, Code, NewCode, PrevCode,  (x86::_Trampoline *)Trampoline);
#elif defined(_IA64_)
	#error no IA64 support yet
	ia64::InitParse();
	return ia64::InjectCode(Module, Code, NewCode, PrevCode,  (ia64::_Trampoline *)Trampoline);
#endif

}

VOID UnHook(HOOK_HANDLE Handle)
{
	PBYTE Trampoline;
#if defined(_X86_) || defined(_AMD64_)
	Trampoline = (PBYTE) x86::RemoveInjection((x86::InjectContext *)Handle);
#elif defined(_IA64_)
	#error no IA64 support yet
	Trampoline = (PBYTE) ia64::RemoveInjection((ia64::InjectContext *)Handle);
#endif
	if ( Trampoline == NULL ) return;
	FreeTrampoline(Trampoline);
}

PVOID GetModuleBase(PCHAR Name)
{
#if defined(_NTDDK_) || defined(_NTIFS_)
    ULONG Size;
    PVOID Module = NULL;

    ZwQuerySystemInformation(SystemModuleInformation, &Size, 0, &Size);
    PCHAR Buf = new (PagedPool) CHAR[Size];
	if ( Buf == NULL ) {
		return NULL;
	}

    NTSTATUS rc = ZwQuerySystemInformation(SystemModuleInformation, Buf, Size, NULL);
	if ( !NT_SUCCESS(rc) ) {
		return NULL;
	}
	Size = *(PULONG) Buf;
	PSYSTEM_MODULE_INFORMATION ModuleInfo = (PSYSTEM_MODULE_INFORMATION) (Buf + sizeof ULONG);

    for (ULONG i=0; i < Size; i++) {
        if ( !_stricmp(ModuleInfo[i].ImageName + ModuleInfo[i].ModuleNameOffset, Name) ) {
            Module = ModuleInfo[i].Base;
            break;
        }
    }

    if ( Module == NULL && !strcmp(Name, "ntoskrnl.exe") ) {
        //
        // for ntoskrnl.exe take first record
        //
        Module = ModuleInfo[0].Base;
    }

    delete[] Buf;
    return Module;
#else
	return GetModuleHandleA(Name);
#endif
}

PVOID GetExportedFunc(PVOID Module, PCHAR Name)
{
	if ( Module == NULL ) return NULL;

#if defined(_NTDDK_) || defined(_NTIFS_)
    PVOID Func = NULL;

    __try {
        PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PCHAR)Module + PIMAGE_DOS_HEADER(Module)->e_lfanew);
        PIMAGE_DATA_DIRECTORY ExportDir = NtHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
        ULONG Size = ExportDir->Size;
        ULONG Addr = ExportDir->VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY Exports = (PIMAGE_EXPORT_DIRECTORY)((PCHAR)Module + Addr);
        PULONG Functions = (PULONG)((PCHAR)Module + Exports->AddressOfFunctions);
        PSHORT Ordinals = (PSHORT)((PCHAR)Module + Exports->AddressOfNameOrdinals);
        PULONG Names = (PULONG)((PCHAR)Module + Exports->AddressOfNames);
  
        for (ULONG i=0; i < Exports->NumberOfNames; i++) {
            ULONG Ord = Ordinals[i];
            if ( Functions[Ord] < Addr || Functions[Ord] >= (Addr+Size) ) {
                if (strcmp((PCHAR)Module + Names[i], Name)==0) {
                    Func = (PCHAR)Module + Functions[Ord];
                    break;
                }
            }
        }
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
		return NULL;
    }
    return Func;
#else
	return GetProcAddress((HMODULE)Module, Name);
#endif
}

PVOID GetImportedFunc(PVOID Module, PCHAR Name)
{
	if ( Module == NULL ) return NULL;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)Module + PIMAGE_DOS_HEADER(Module)->e_lfanew);
	PIMAGE_DATA_DIRECTORY ImportDir = NtHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
	ULONG Size = ImportDir->Size;
	ULONG Addr = ImportDir->VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR Imports = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)Module + Addr);

	while ( Imports->OriginalFirstThunk != NULL ) {

		PIMAGE_THUNK_DATA First = (PIMAGE_THUNK_DATA)((PBYTE)Module + Imports->OriginalFirstThunk);
		PIMAGE_THUNK_DATA Real = (PIMAGE_THUNK_DATA)((PBYTE)Module + Imports->FirstThunk);

		for (ULONG i=0; First[i].u1.AddressOfData != 0; i++) {

			PIMAGE_IMPORT_BY_NAME ImpName = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Module + First[i].u1.AddressOfData);
			if ( Name[0] == 0 || !strcmp((PCHAR)ImpName->Name, Name) )
				return &Real[i].u1.Function;
		}

		Imports++;
	}

	return NULL;
}

PVOID MapForWrite(MAPHANDLE *Handle, PVOID Mem, ULONG Length)
{
	*Handle = new MapHandle;
	if ( *Handle == NULL ) {
		return NULL;
	}

	(*Handle)->Length = Length;

#if defined(_NTDDK_) || defined(_NTIFS_)
	PMDL Mdl = IoAllocateMdl(Mem, Length, FALSE, FALSE, NULL);
	if ( Mdl == NULL ) return NULL;
	__try {
		MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(Mdl);
		return NULL;
	}

	PVOID vaddr = MmGetSystemAddressForMdlSafe(Mdl, HighPagePriority);
	if ( vaddr == NULL ) {
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
	}

	(*Handle)->Mdl = Mdl;
	(*Handle)->Mem = vaddr;
	return vaddr;
#else
	if ( !VirtualProtectEx(GetCurrentProcess(), Mem, Length, PAGE_EXECUTE_READWRITE, &(*Handle)->Protect) )
		return NULL;
	(*Handle)->Mem = Mem;

	return Mem;
#endif
}

VOID UnMap(MAPHANDLE Handle)
{
#if defined(_NTDDK_) || defined(_NTIFS_)
	MmUnmapLockedPages(Handle->Mem, Handle->Mdl);
	MmUnlockPages(Handle->Mdl);
	IoFreeMdl(Handle->Mdl);
#else
	VirtualProtectEx(GetCurrentProcess(), Handle->Mem, Handle->Length, Handle->Protect, &Handle->Protect);
#endif

	delete Handle;
}

const SIZE_T TrampPoolSize = 20;

enum TrampStatus {
	trmEmpty,
	trmFilled
};

TrampStatus TrampPoolStatus[TrampPoolSize];

#pragma code_seg()
	const BYTE TramPool[TrampPoolSize][TrampolineSize] = { 0 };
#pragma

PBYTE AllocateTrampoline(VOID)
{
	for (SIZE_T i=0; i < TrampPoolSize; i++)
		if ( TrampPoolStatus[i] == trmEmpty ) {
			TrampPoolStatus[i] = trmFilled;
			return (PBYTE) TramPool[i];
		}
	return NULL;
}

VOID FreeTrampoline(PBYTE Trampoline)
{
	SIZE_T Item = ( Trampoline - (PBYTE)TramPool ) / sizeof TramPool[0];
	if ( Item < TrampPoolSize ) TrampPoolStatus[Item] = trmEmpty;
}

#if defined(_NTDDK_) || defined(_NTIFS_)

#ifdef SYSTEMSERVICE
#undef SYSTEMSERVICE
#endif // #ifdef SYSTEMSERVICE

#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable[0].SSDT[GetServiceIndex(_function)].SysCallPtr
#define WIN32SERVICE(_function)   KeServiceDescriptorTableShadow[1].SSDT[GetServiceIndex(_function)].SysCallPtr

NTSTATUS HookService(WCHAR *wcServiceProc, ULONG Index, PVOID NewServiceProc, 
                     PVOID *OriginalServiceProc, ServiceType Type) 
{
    if ( Type == srvWin32 && KeServiceDescriptorTableShadow == NULL )
        return STATUS_UNSUCCESSFUL;

    PVOID virt_addr;
    PMDL pMdl;
    *OriginalServiceProc = NULL;
    PVOID ServiceProc = NULL;

    if ( wcServiceProc != NULL ) {
        UNICODE_STRING usName;
        RtlInitUnicodeString(&usName, wcServiceProc);
        ServiceProc = MmGetSystemRoutineAddress(&usName);
        if ( ServiceProc == NULL )
            return STATUS_UNSUCCESSFUL;
    }

    PVOID ServiceDescriptor;
    if ( ServiceProc != NULL )
        ServiceDescriptor = Type == srvSystem ? 
                            &SYSTEMSERVICE(ServiceProc) : &WIN32SERVICE(ServiceProc);
    else
        ServiceDescriptor = Type == srvSystem ? 
                            &KeServiceDescriptorTable[0].SSDT[Index].SysCallPtr :
                            &KeServiceDescriptorTableShadow[1].SSDT[Index-0x1000].SysCallPtr;

#if _WIN32_WINNT >= 0x0500
    pMdl = IoAllocateMdl(ServiceDescriptor, sizeof (PVOID), FALSE, FALSE, NULL);
    if (pMdl == NULL)
        return STATUS_UNSUCCESSFUL;
    __try {
        MmProbeAndLockPages(pMdl, KernelMode, IoModifyAccess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(pMdl);
        return GetExceptionCode();
    }

    virt_addr = MmGetSystemAddressForMdlSafe(pMdl, HighPagePriority);
    if (virt_addr == NULL) {
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return STATUS_UNSUCCESSFUL;
    }
    *OriginalServiceProc = InterlockedExchangePointer(virt_addr, NewServiceProc);

    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);
#else // #if _WIN32_WINNT >= 0x0500
    virt_addr = ServiceDescriptor;
    *OriginalServiceProc = (void *) InterlockedExchange((long *) virt_addr, (long) NewServiceProc);
#endif // #if _WIN32_WINNT >= 0x0500

    return STATUS_SUCCESS;
}

void UnHookService(WCHAR *wcServiceProc, ULONG Index, PVOID OriginalServiceProc, 
                   PVOID NewServiceProc, ServiceType Type)
{
    if ( Type == srvWin32 && KeServiceDescriptorTableShadow == NULL )
        return;

    PVOID virt_addr;
    PMDL pMdl;
    PVOID ServiceDescriptor;
    PVOID ServiceProc = NULL;

    if ( wcServiceProc != NULL ) {
        UNICODE_STRING usName;
        RtlInitUnicodeString(&usName, wcServiceProc);
        ServiceProc = MmGetSystemRoutineAddress(&usName);
        if ( ServiceProc == NULL )
            return;
    }

    if ( ServiceProc != NULL )
        ServiceDescriptor = Type == srvSystem ? 
                            &SYSTEMSERVICE(ServiceProc) : &WIN32SERVICE(ServiceProc);
    else
        ServiceDescriptor = Type == srvSystem ? 
                            &KeServiceDescriptorTable[0].SSDT[Index].SysCallPtr :
                            &KeServiceDescriptorTableShadow[1].SSDT[Index-0x1000].SysCallPtr;

    if (OriginalServiceProc != NULL) {
#if _WIN32_WINNT >= 0x0500
        pMdl = IoAllocateMdl(ServiceDescriptor, sizeof (PVOID), FALSE, FALSE, NULL);
        if (pMdl == NULL)
            return;
        __try {
            MmProbeAndLockPages(pMdl, KernelMode, IoModifyAccess);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(pMdl);
            return;
        }

        virt_addr = MmGetSystemAddressForMdlSafe(pMdl, HighPagePriority);
        if (virt_addr == NULL) {
            MmUnlockPages(pMdl);
            IoFreeMdl(pMdl);
            return;
        }
        InterlockedCompareExchangePointer(virt_addr, OriginalServiceProc, NewServiceProc);

       MmUnlockPages(pMdl);
       IoFreeMdl(pMdl);
#else // #if _WIN32_WINNT >= 0x0500       
        virt_addr = ServiceDescriptor;
        InterlockedCompareExchange((void **) virt_addr, OriginalServiceProc, NewServiceProc);
#endif // #if _WIN32_WINNT >= 0x0500
    }

    OriginalServiceProc = NULL;
    ServiceDescriptor = NULL;
}

#endif // #if defined(_NTDDK_) || defined(_NTIFS_)

} // namespace hin {

} // namespace commonlib {