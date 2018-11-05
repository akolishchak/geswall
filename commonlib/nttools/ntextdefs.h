//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _NT_NATIVE_EXTDEFS_H_
 #define _NT_NATIVE_EXTDEFS_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _OBJECT_NAMETYPE_INFO 
{               
  UNICODE_STRING ObjectName;
  UNICODE_STRING ObjectType;
} OBJECT_NAMETYPE_INFO, *POBJECT_NAMETYPE_INFO;   

typedef enum _DIRECTORYINFOCLASS 
{
  ObjectArray,
  ObjectByOne
} DIRECTORYINFOCLASS, *PDIRECTORYINFOCLASS;
    
NTSYSAPI
NTSTATUS 
NTAPI
NtOpenDirectoryObject (
  PHANDLE DirectoryHandle, 
  ACCESS_MASK DesiredAccess, 
  POBJECT_ATTRIBUTES ObjectAttributes
  );

NTSYSAPI
NTSTATUS 
NTAPI
NtQueryDirectoryObject (
  HANDLE DirectoryObjectHandle, 
  PVOID ObjectInfoBuffer, 
  ULONG ObjectInfoBufferLength, 
  DIRECTORYINFOCLASS DirectoryInformationClass, 
  BOOLEAN First, 
  PULONG ObjectIndex, 
  PULONG LengthReturned
  );

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation, // 0 Y N
	ObjectNameInformation, // 1 Y N
	ObjectTypeInformation, // 2 Y N
	ObjectAllTypesInformation, // 3 Y N
	ObjectHandleInformation // 4 Y Y
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION { // Information Class 0
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
	ULONG Reserved[3];
	ULONG NameInformationLength;
	ULONG TypeInformationLength;
	ULONG SecurityDescriptorLength;
	LARGE_INTEGER CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
	IN HANDLE ObjectHandle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,              // 0        Y        N
    SystemProcessorInformation,          // 1        Y        N
    SystemPerformanceInformation,        // 2        Y        N
    SystemTimeOfDayInformation,          // 3        Y        N
    SystemNotImplemented1,               // 4        Y        N
    SystemProcessesAndThreadsInformation, // 5       Y        N
    SystemCallCounts,                    // 6        Y        N
    SystemConfigurationInformation,      // 7        Y        N
    SystemProcessorTimes,                // 8        Y        N
    SystemGlobalFlag,                    // 9        Y        Y
    SystemNotImplemented2,               // 10       Y        N
    SystemModuleInformation,             // 11       Y        N
    SystemLockInformation,               // 12       Y        N
    SystemNotImplemented3,               // 13       Y        N
    SystemNotImplemented4,               // 14       Y        N
    SystemNotImplemented5,               // 15       Y        N
    SystemHandleInformation,             // 16       Y        N
    SystemObjectInformation,             // 17       Y        N
    SystemPagefileInformation,           // 18       Y        N
    SystemInstructionEmulationCounts,    // 19       Y        N
    SystemInvalidInfoClass1,             // 20
    SystemCacheInformation,              // 21       Y        Y
    SystemPoolTagInformation,            // 22       Y        N
    SystemProcessorStatistics,           // 23       Y        N
    SystemDpcInformation,                // 24       Y        Y
    SystemNotImplemented6,               // 25       Y        N
    SystemLoadImage,                     // 26       N        Y
    SystemUnloadImage,                   // 27       N        Y
    SystemTimeAdjustment,                // 28       Y        Y
    SystemNotImplemented7,               // 29       Y        N
    SystemNotImplemented8,               // 30       Y        N
    SystemNotImplemented9,               // 31       Y        N
    SystemCrashDumpInformation,          // 32       Y        N
    SystemExceptionInformation,          // 33       Y        N
    SystemCrashDumpStateInformation,     // 34       Y        Y/N
    SystemKernelDebuggerInformation,     // 35       Y        N
    SystemContextSwitchInformation,      // 36       Y        N
    SystemRegistryQuotaInformation,      // 37       Y        Y
    SystemLoadAndCallImage,              // 38       N        Y
    SystemPrioritySeparation,            // 39       N        Y
    SystemNotImplemented10,              // 40       Y        N
    SystemNotImplemented11,              // 41       Y        N
    SystemInvalidInfoClass2,             // 42
    SystemInvalidInfoClass3,             // 43
    SystemTimeZoneInformation,           // 44       Y        N
    SystemLookasideInformation,          // 45       Y        N
    SystemSetTimeSlipEvent,              // 46       N        Y
    SystemCreateSession,                 // 47       N        Y
    SystemDeleteSession,                 // 48       N        Y
    SystemInvalidInfoClass4,             // 49
    SystemRangeStartInformation,         // 50       Y        N
    SystemVerifierInformation,           // 51       Y        Y
    SystemAddVerifier,                   // 52       N        Y
    SystemSessionProcessesInformation    // 53       Y        N
} SYSTEM_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

typedef struct _SYSTEM_HANDLE_INFORMATION { // Information Class 16
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;  // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_OBJECT_TYPE_INFORMATION { // Information Class 17
    ULONG NextEntryOffset;
    ULONG ObjectCount;
    ULONG HandleCount;
    ULONG TypeNumber;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ACCESS_MASK ValidAccessMask;
    POOL_TYPE PoolType;
    UCHAR Unknown;
    UNICODE_STRING Name;
} SYSTEM_OBJECT_TYPE_INFORMATION, *PSYSTEM_OBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION {
    ULONG NextEntryOffset;
    PVOID Object;
    ULONG CreatorProcessId;
    USHORT Unknown;
    USHORT Flags;
    ULONG PointerCount;
    ULONG HandleCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG ExclusiveProcessId;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    UNICODE_STRING Name;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
    IN HANDLE ObjectHandle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG Attributes,
    IN ULONG Options
    );

typedef struct _OBJECT_TYPE_INFORMATION { // Information Class 2
    UNICODE_STRING Name;
    ULONG ObjectCount;
    ULONG HandleCount;
    ULONG Reserved1[4];
    ULONG PeakObjectCount;
    ULONG PeakHandleCount;
    ULONG Reserved2[4];
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    UCHAR Unknown;
    BOOLEAN MaintainHandleDatabase;
    UCHAR Reserved3[2];
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationProcess (
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID            ProcessInformation,
    IN ULONG            ProcessInformationLength
);



#ifdef __cplusplus
} //extern "C"
#endif

#endif //_NT_NATIVE_EXTDEFS_H_
