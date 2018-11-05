//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "win32set.h"
#include "win32hook.h"
 
namespace Win32Set {

W32HooksetSyncParams CurrentParams;
BOOLEAN bInited = false;
BOOLEAN bWaitForCall = false;
PEPROCESS TrackedProcess = NULL;
PETHREAD TrackedThread = NULL;

static void* queryUnprotectMemory (void* address, int size, PMDL& mdl, void*& newPage);
static void  releaseUnprotectMemory (PMDL mdl, void* newPage);

#define SIZE_OF_STUB_0         32  

static void  hookerStubStep0 (void);
static void* hookerStubStep1 (ULONG indexOfService, unsigned long* parametersAddress);

static void* (*ptrToStep1) (ULONG, unsigned long*) = hookerStubStep1;

static unsigned char* createStubTable (ULONG numberOfServices);
static void           destroyStubTable (unsigned char* stubTable);

static unsigned char*  startStubTable           = NULL;
static void**          originalServiceAddresses = NULL;

static KE_SERVICE_DESCRIPTOR_TABLE_ENTRY serviceDescriptorTable;


bool isNeedHook (ULONG indexOfService, void* parametersAddress, ULONG sizeOfParamsFrame)
{
    // check parameters area and check hook needed
    if ( !bWaitForCall ||
         TrackedProcess != PsGetCurrentProcess() || TrackedThread != PsGetCurrentThread()
		 //||
         //CurrentParams.ParamSize != sizeOfParamsFrame ) {
		 ) {

       return false;
    }

	if ( CurrentParams.ParamSize != sizeOfParamsFrame )
		return false;

    for (ULONG i=0; i < CurrentParams.TestParamsNum; i++)
        if ( RtlCompareMemory(&CurrentParams.Param[i].Param, 
                             (PUCHAR)parametersAddress + CurrentParams.Param[i].Offset,
                             CurrentParams.Param[i].Size) != 
             CurrentParams.Param[i].Size 
            ) {
           return false;
        }

    bWaitForCall = false;
    Win32Hook::SetServiceIndex(CurrentParams.Func, indexOfService + 0x1000);

	// hack for WindowFromDCIndex
	if ( CurrentParams.Func == ntuCallOneParam ) {
		Win32Hook::WindowsFromDCIndex = *(PULONG)((PUCHAR)parametersAddress + sizeof PULONG_PTR);
	}

    return true;
} // isNeedHook


bool hookWholeW32 ()
{
  bool  result  = false;
  PMDL  mdl     = NULL;
  void* newPage = NULL;
  
  if (NULL == originalServiceAddresses)
  {
    originalServiceAddresses = static_cast <void**> (ExAllocatePool (NonPagedPool, sizeof (void*) * serviceDescriptorTable.NumberOfServices));
    if (NULL != originalServiceAddresses)
    {
      startStubTable = createStubTable (serviceDescriptorTable.NumberOfServices);
      if (NULL != startStubTable)
      {
        PSSDT addressesTable = (PSSDT) queryUnprotectMemory (serviceDescriptorTable.SSDT, sizeof (void*) * serviceDescriptorTable.NumberOfServices, mdl, newPage);
        if (NULL != addressesTable)
        {
          for (ULONG i=0; i<serviceDescriptorTable.NumberOfServices; ++i)
          {
            originalServiceAddresses [i] = InterlockedExchangePointer (&(addressesTable[i].SysCallPtr), (startStubTable + (i * SIZE_OF_STUB_0)));
          }
          releaseUnprotectMemory (mdl, newPage);
          result = true;
        } // if (NULL != addressesTable)
        else
        {
          destroyStubTable (startStubTable);
          startStubTable = NULL;
          ExFreePool (originalServiceAddresses);
          originalServiceAddresses = NULL;
        }
      } // if (NULL != startStubTable)
      else
      {
        ExFreePool (originalServiceAddresses);
        originalServiceAddresses = NULL;
      }
    } // if (NULL != originalServiceAddresses)
  }
  else
  {
    result = true;
  }
  
  return result;
} // hookWholeW32

bool unhookWholeW32 ()
{
  bool  result  = false;
  PMDL  mdl     = NULL;
  void* newPage = NULL;
  
  if (NULL != originalServiceAddresses)
  {
    PSSDT addressesTable = (PSSDT) queryUnprotectMemory (serviceDescriptorTable.SSDT, sizeof (void*) * serviceDescriptorTable.NumberOfServices, mdl, newPage);
    if (NULL != addressesTable)
    {
      for (ULONG i=0; i<serviceDescriptorTable.NumberOfServices; ++i)
      {
        if ( (startStubTable + (i * SIZE_OF_STUB_0) ) == addressesTable[i].SysCallPtr )
          InterlockedExchangePointer (&(addressesTable[i].SysCallPtr), originalServiceAddresses [i]);
      }  
      
      releaseUnprotectMemory (mdl, newPage);
      
      ExFreePool (originalServiceAddresses);
      originalServiceAddresses = NULL;
      result = true;
    }
    
    if (NULL != startStubTable)
    {
      destroyStubTable (startStubTable);
      startStubTable = NULL;
    }  
  }
  else
  {
    result = true;
  }
  
  return result;
} // unhookWholeW32

void* queryUnprotectMemory (void* address, int size, PMDL& mdl, void*& newPage)
{
  void* addressResult = NULL;

  mdl = IoAllocateMdl (address, size, FALSE, FALSE, NULL);
  if (NULL != mdl)
  {
    MmBuildMdlForNonPagedPool (mdl);
    newPage = static_cast <void*> (MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority));
    if (NULL != newPage)
    {
      //addressResult = static_cast <void*> (MmGetSystemAddressForMdlSafe (mdl, LowPagePriority));
      addressResult = reinterpret_cast <void*> ((((ULONG_PTR)PAGE_ALIGN(newPage))+MmGetMdlByteOffset(mdl)));
    } // if (NULL != newPage)
    else
    {
      IoFreeMdl (mdl);
    }
  } // if (NULL != pMdl)

  return addressResult;
} // queryUnprotectMemory

void releaseUnprotectMemory (PMDL mdl, void* newPage)
{
  MmUnmapLockedPages (newPage, mdl);
  IoFreeMdl (mdl);
} // releaseUnprotectMemory

unsigned char* createStubTable (ULONG numberOfServices)
{
  unsigned char* stubTable = static_cast <unsigned char*> (ExAllocatePool (NonPagedPool, SIZE_OF_STUB_0 * numberOfServices));
  
  if (NULL != stubTable)
  {
    unsigned char* ptr = stubTable;
    for (ULONG i=0; i<numberOfServices; ++i)
    {
      memmove (ptr, hookerStubStep0, SIZE_OF_STUB_0);
      ptr += SIZE_OF_STUB_0;
    }
  }
  
  return stubTable;
} // createStubTable

void destroyStubTable (unsigned char* stubTable)
{
  ExFreePool (stubTable);
} // destroyStubTable

void* hookerStubStep1 (ULONG indexOfService, unsigned long* parametersAddress)
{
  void*           originalServiceAddress = originalServiceAddresses [indexOfService];
  ULONG           sizeOfParamsFrame      = serviceDescriptorTable.SSPT [indexOfService].ParamBytes;
  bool            needHook               = isNeedHook (indexOfService, parametersAddress, sizeOfParamsFrame);

  return originalServiceAddress;
} // hookerStubStep1

__declspec(naked) void hookerStubStep0 (void)
{
  __asm
  {
    call   _get_current_addr
_get_current_addr:
    pop    eax  
      
    lea    ecx, [esp + 4]                   // parametersAddress
    push   ecx                              //
    
    sub    eax, dword ptr [startStubTable]  // index 
    shr    eax, 5                           // div (SIZE_OF_STUB_0 = 32)
    push   eax                              //
    
    call   dword ptr [ptrToStep1]
    jmp    eax
    nop
    nop
  }
} // hookerStubStep0

NTSTATUS Init(VOID)
{
    if ( !bInited ) {
        if ( !AdApi::InitShadowTable() ) return STATUS_UNSUCCESSFUL;
        serviceDescriptorTable = KeServiceDescriptorTableShadow[1];
        bInited = true;
        hookWholeW32();
        TrackedProcess = PsGetCurrentProcess();
        TrackedThread = PsGetCurrentThread();
        return STATUS_SUCCESS;
    } else
        return STATUS_UNSUCCESSFUL;
}

NTSTATUS Release(VOID)
{
    if ( !bInited ) return STATUS_UNSUCCESSFUL;

    unhookWholeW32();
    bInited = false;
    Win32Hook::Init();
    return STATUS_SUCCESS;
}

NTSTATUS Sync(W32HooksetSyncParams *Params)
{
    //
    // Sanity checks
    //
    if ( Params->Func >= ntuMax ||
        Params->TestParamsNum > sizeof Params->Param / sizeof Params->Param[0] ) {
        ERR(STATUS_UNSUCCESSFUL);
        return STATUS_UNSUCCESSFUL;
    }
    for (ULONG i=0; i < Params->TestParamsNum; i++)
        if ( ( Params->Param[i].Offset + Params->Param[i].Size ) > Params->ParamSize ) {
            ERR(STATUS_UNSUCCESSFUL);
            return STATUS_UNSUCCESSFUL;
        }

    CurrentParams = *Params;
    bWaitForCall = true;
    return STATUS_SUCCESS;
}


} // namespace Win32Set {