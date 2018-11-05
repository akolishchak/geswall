//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __adapi_h__
#define __adapi_h__

extern "C" {


//
// service tables stuff
// 

/* number of entries in the service descriptor tables */
#define SSDT_MAX_ENTRIES 4

#pragma pack( push, 1 )

// System Service Dispatch Table
typedef struct _SSDT {
                PVOID   SysCallPtr;
} SSDT, *PSSDT;

// System Service Parameters Table
typedef struct _SSPT   {
                UCHAR   ParamBytes;
} SSPT, *PSSPT;

typedef struct _KeServiceDescriptorTableEntry {
                PSSDT            SSDT;
                PULONG           ServiceCounterTable;
                ULONG            NumberOfServices;
                PSSPT            SSPT;

} KE_SERVICE_DESCRIPTOR_TABLE_ENTRY, *PKE_SERVICE_DESCRIPTOR_TABLE_ENTRY,
  SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#pragma pack( pop )

extern "C" {
__declspec(dllimport) 
KE_SERVICE_DESCRIPTOR_TABLE_ENTRY
KeServiceDescriptorTable[SSDT_MAX_ENTRIES];

}
extern PKE_SERVICE_DESCRIPTOR_TABLE_ENTRY KeServiceDescriptorTableShadow;


//
// These undocumented structures are used only for NT4 implementation
// of IoGetRequestorProcessId, so using is safe becauce structures will never
// change
//

#ifndef _NTIFS_

typedef struct _KAPC_STATE {
    LIST_ENTRY  ApcListHead[MaximumMode];
    PEPROCESS   Process;
    BOOLEAN     KernelApcInProgress;
    BOOLEAN     KernelApcPending;
    BOOLEAN     UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

#endif // #ifndef _NTIFS_

typedef struct _KQUEUE                          *PKQUEUE;
typedef struct _KTRAP_FRAME                     *PKTRAP_FRAME;

typedef struct _KTHREAD {
    DISPATCHER_HEADER           Header;
    LIST_ENTRY                  MutantListHead;
    PVOID                       InitialStack;
    PVOID                       StackLimit;
    struct _TEB                 *Teb;
    PVOID                       TlsArray;
    PVOID                       KernelStack;
    BOOLEAN                     DebugActive;
    UCHAR                       State;
    USHORT                      Alerted;
    UCHAR                       Iopl;
    UCHAR                       NpxState;
    UCHAR                       Saturation;
    UCHAR                       Priority;
    KAPC_STATE                  ApcState;
    ULONG                       ContextSwitches;
    NTSTATUS                    WaitStatus;
    UCHAR                       WaitIrql;
    UCHAR                       WaitMode;
    UCHAR                       WaitNext;
    UCHAR                       WaitReason;
    PKWAIT_BLOCK                WaitBlockList;
    LIST_ENTRY                  WaitListEntry;
    ULONG                       WaitTime;
    UCHAR                       BasePriority;
    UCHAR                       DecrementCount;
    UCHAR                       PriorityDecrement;
    UCHAR                       Quantum;
    KWAIT_BLOCK                 WaitBlock[4];
    ULONG                       LegoData;
    ULONG                       KernelApcDisable;
    ULONG                       UserAffinity;
    BOOLEAN                     SystemAffinityActive;
#if (_WIN32_WINNT < 0x0500)
    UCHAR                       Pad[3];
#else // (_WIN32_WINNT >= 0x0500)
    UCHAR                       PowerState;
    UCHAR                       NpxIrql;
    UCHAR                       Pad[1];
#endif // (_WIN32_WINNT >= 0x0500)
    PSERVICE_DESCRIPTOR_TABLE   ServiceDescriptorTable;
    PKQUEUE                     Queue;
    KSPIN_LOCK                  ApcQueueLock;
    KTIMER                      Timer;
    LIST_ENTRY                  QueueListEntry;
    ULONG                       Affinity;
    BOOLEAN                     Preempted;
    BOOLEAN                     ProcessReadyQueue;
    BOOLEAN                     KernelStackResident;
    UCHAR                       NextProcessor;
    PVOID                       CallbackStack;
    PVOID                       Win32Thread;
    PKTRAP_FRAME                TrapFrame;
    PKAPC_STATE                 ApcStatePointer[2];
#if (_WIN32_WINNT >= 0x0500)
    UCHAR                       PreviousMode;
#endif // (_WIN32_WINNT >= 0x0500)
    BOOLEAN                     EnableStackSwap;
    BOOLEAN                     LargeStack;
    UCHAR                       ResourceIndex;
#if (_WIN32_WINNT < 0x0500)
    UCHAR                       PreviousMode;
#endif // (_WIN32_WINNT < 0x0500)
    ULONG                       KernelTime;
    ULONG                       UserTime;
    KAPC_STATE                  SavedApcState;
    BOOLEAN                     Alertable;
    UCHAR                       ApcStateIndex;
    BOOLEAN                     ApcQueueable;
    BOOLEAN                     AutoAlignment;
    PVOID                       StackBase;
    KAPC                        SuspendApc;
    KSEMAPHORE                  SuspendSemaphore;
    LIST_ENTRY                  ThreadListEntry;
    UCHAR                       FreezeCount;
    UCHAR                       SuspendCount;
    UCHAR                       IdealProcessor;
    BOOLEAN                     DisableBoost;
} KTHREAD, *PKTHREAD;

struct _ETHREAD {
    KTHREAD                         Tcb;
    LARGE_INTEGER                   CreateTime;
    union {
        LARGE_INTEGER               ExitTime;
        LIST_ENTRY                  LpcReplyChain;
    };
    union {
        NTSTATUS                    ExitStatus;
        PVOID                       OfsChain;
    };
    LIST_ENTRY                      PostBlockList;
    LIST_ENTRY                      TerminationPortList;
    KSPIN_LOCK                      ActiveTimerListLock;
    LIST_ENTRY                      ActiveTimerListHead;
    CLIENT_ID                       Cid;
};


typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation,
  SystemProcessorInformation,
  SystemPerformanceInformation,
  SystemTimeOfDayInformation,
  SystemNotImplemented1,
  SystemProcessesAndThreadsInformation,
  SystemCallCounts,
  SystemConfigurationInformation,
  SystemProcessorTimes,
  SystemGlobalFlag,
  SystemNotImplemented2,
  SystemModuleInformation,
  /* ... */
} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG Reserved[2];
  PVOID Base;
  ULONG Size;
  ULONG Flags;
  USHORT Index;
  USHORT Unknown;
  USHORT LoadCount;
  USHORT ModuleNameOffset;
  CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


typedef enum {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandBy,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;


typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD, *PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheretedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;


NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation (
			  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			  IN OUT PVOID SystemInformation,
			  IN ULONG SystemInformationLength,
			  OUT PULONG ReturnLength OPTIONAL
			  );

#ifndef _NTIFS_

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInfo,
    ObjectNameInfo,
    ObjectTypeInfo,
    ObjectAllTypesInfo,
    ObjectProtectionInfo
} OBJECT_INFORMATION_CLASS;

#endif //#ifndef _NTIFS_

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG           Attributes;
    ACCESS_MASK     GrantedAccess;
    ULONG           HandleCount;
    ULONG           ReferenceCount;
    ULONG           PagedPoolUsage;
    ULONG           NonPagedPoolUsage;
    ULONG           Reserved[3];
    ULONG           NameInformationLength;
    ULONG           TypeInformationLength;
    ULONG           SecurityDescriptorLength;
    LARGE_INTEGER   CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject (
    IN HANDLE ObjectHandle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG Length,
    OUT PULONG ResultLength OPTIONAL
);


NTKERNELAPI
NTSTATUS
ObQueryNameString(
    IN PVOID Object,
    OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
    IN ULONG Length,
    OUT PULONG ReturnLength
    );


extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *ExDesktopObjectType;
extern POBJECT_TYPE *ExWindowStationObjectType;
extern POBJECT_TYPE *IoAdapterObjectType;
extern POBJECT_TYPE *IoDeviceHandlerObjectType;
extern POBJECT_TYPE *IoDeviceObjectType;
extern POBJECT_TYPE *IoDriverObjectType;
extern POBJECT_TYPE *KeI386MachineType;
extern POBJECT_TYPE *LpcPortObjectType;
extern POBJECT_TYPE *MmSectionObjectType;
extern POBJECT_TYPE *PsJobType;
extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *SeTokenObjectType;

NTKERNELAPI                                                     
NTSTATUS                                                        
ObReferenceObjectByHandle(                                      
    IN HANDLE Handle,                                           
    IN ACCESS_MASK DesiredAccess,                               
    IN POBJECT_TYPE ObjectType OPTIONAL,                        
    IN KPROCESSOR_MODE AccessMode,                              
    OUT PVOID *Object,                                          
    OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL   
    );                                                          
NTKERNELAPI                                                     
NTSTATUS                                                        
ObOpenObjectByPointer(                                          
    IN PVOID Object,                                            
    IN ULONG HandleAttributes,                                  
    IN PACCESS_STATE PassedAccessState OPTIONAL,                
    IN ACCESS_MASK DesiredAccess OPTIONAL,                      
    IN POBJECT_TYPE ObjectType OPTIONAL,                        
    IN KPROCESSOR_MODE AccessMode,                              
    OUT PHANDLE Handle                                          
    );                                                          

NTSYSAPI
NTSTATUS NTAPI
ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN PVOID ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID *Object
    );

NTKERNELAPI
NTSTATUS
SeCreateAccessState (
    OUT PACCESS_STATE   AccessState,
    IN PVOID            AuxData,
    IN ACCESS_MASK      AccessMask,
    IN PGENERIC_MAPPING Mapping
);


NTKERNELAPI
VOID
SeDeleteAccessState (
    IN PACCESS_STATE AccessState
);

NTKERNELAPI
VOID
SeCaptureSubjectContext (
    OUT PSECURITY_SUBJECT_CONTEXT SubjectContext
    );

NTKERNELAPI
VOID
SeReleaseSubjectContext (
    IN PSECURITY_SUBJECT_CONTEXT SubjectContext
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwDuplicateObject(
   IN HANDLE SourceProcessHandle,
   IN HANDLE SourceHandle,
   IN HANDLE TargetProcessHandle,
   IN OUT PHANDLE TargetHandle OPTIONAL,
   IN ACCESS_MASK DesiredAccess,
   IN ULONG Attributes,
   IN ULONG Options
);

NTSYSAPI                                        
NTSTATUS                                        
NTAPI                                           
RtlGetOwnerSecurityDescriptor (                 
    PSECURITY_DESCRIPTOR SecurityDescriptor,    
    PSID *Owner,                                
    PBOOLEAN OwnerDefaulted                     
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetSaclSecurityDescriptor (
    IN  PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PBOOLEAN SaclPresent,
    OUT PACL *Sacl,
    OUT PBOOLEAN SaclDefaulted
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetSaclSecurityDescriptor (
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN SaclPresent,
    PACL Sacl,
    BOOLEAN SaclDefaulted
    );

NTSYSAPI                                        
NTSTATUS                                        
NTAPI                                           
RtlCreateAcl (                                  
    PACL Acl,                                   
    ULONG AclLength,                            
    ULONG AclRevision                           
    );                                          

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid(
    PSID Sid1,
    PSID Sid2
    );


NTSYSAPI
NTSTATUS
NTAPI
ZwSetSecurityObject(
    IN HANDLE Handle,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor
    );

typedef
NTSTATUS 
( *_ObSetSecurityObjectByPointer)(
    IN PVOID Object,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid(
    PSID Sid1,
    PSID Sid2
    );


NTSYSAPI
NTSTATUS
NTAPI
ZwCreateSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
    );

typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation,
    SectionImageInformation
} SECTION_INFORMATION_CLASS;

typedef struct _SECTION_BASIC_INFORMATION { // Information Class 0
    PVOID BaseAddress;
    ULONG Attributes;
    LARGE_INTEGER Size;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySection(
    IN HANDLE SectionHandle,
    IN SECTION_INFORMATION_CLASS SectionInformationClass,
    OUT PVOID SectionInformation,
    IN ULONG SectionInformationLength,
    OUT PULONG ResultLength OPTIONAL
);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    IN PVOID        ProcessId,
    OUT PEPROCESS   *Process
);

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId (
    IN PVOID        UniqueThreadId,
    OUT PETHREAD    *Thread
);

#ifndef _NTIFS_

NTKERNELAPI
NTSTATUS
PsLookupProcessThreadByCid (
    IN PCLIENT_ID   Cid,
    OUT PEPROCESS   *Process OPTIONAL,
    OUT PETHREAD    *Thread
);

#endif // #ifndef _NTIFS_

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);


typedef USHORT SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

#ifndef _NTIFS_

NTKERNELAPI
VOID
KeStackAttachProcess (
    IN PEPROCESS Process,
    OUT PKAPC_STATE ApcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess (
    IN PKAPC_STATE ApcState
    );

typedef struct _SECURITY_DESCRIPTOR {
   UCHAR Revision;
   UCHAR Sbz1;
   SECURITY_DESCRIPTOR_CONTROL Control;
   PSID Owner;
   PSID Group;
   PACL Sacl;
   PACL Dacl;
} SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;

#endif // #ifndef _NTIFS_

#define ACL_REVISION1   (1)

#ifndef _NTIFS_

typedef struct _ACE_HEADER {
    UCHAR AceType;
    UCHAR AceFlags;
    USHORT AceSize;
} ACE_HEADER;
typedef ACE_HEADER *PACE_HEADER;


#define ACCESS_ALLOWED_ACE_TYPE                 (0x0)
#define ACCESS_DENIED_ACE_TYPE                  (0x1)
#define SYSTEM_AUDIT_ACE_TYPE                   (0x2)
#define SYSTEM_ALARM_ACE_TYPE                   (0x3)

#define ACCESS_ALLOWED_OBJECT_ACE_TYPE          (0x5)
#define ACCESS_DENIED_OBJECT_ACE_TYPE           (0x6)
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE            (0x7)
#define SYSTEM_ALARM_OBJECT_ACE_TYPE            (0x8)

#define OBJECT_INHERIT_ACE                (0x1)
#define CONTAINER_INHERIT_ACE             (0x2)
#define NO_PROPAGATE_INHERIT_ACE          (0x4)
#define INHERIT_ONLY_ACE                  (0x8)
#define INHERITED_ACE                     (0x10)
#define SUCCESSFUL_ACCESS_ACE_FLAG       (0x40)
#define FAILED_ACCESS_ACE_FLAG           (0x80)

typedef struct _SYSTEM_AUDIT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG SidStart;
} SYSTEM_AUDIT_ACE;
typedef SYSTEM_AUDIT_ACE *PSYSTEM_AUDIT_ACE;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids
} TOKEN_INFORMATION_CLASS;



typedef struct _SID_AND_ATTRIBUTES {
    PSID    Sid;
    ULONG   Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;


typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_GROUPS {
    ULONG               GroupCount;
    SID_AND_ATTRIBUTES  Groups[1];
} TOKEN_GROUPS, *PTOKEN_GROUPS;

NTKERNELAPI
NTSTATUS
SeQueryInformationToken(
    IN PACCESS_TOKEN Token,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID *TokenInformation
);

NTKERNELAPI
BOOLEAN
SeTokenIsAdmin(
    IN PACCESS_TOKEN Token
);

#define SeQuerySubjectContextToken( SubjectContext )                \
    ( ARGUMENT_PRESENT(                                             \
        ((PSECURITY_SUBJECT_CONTEXT) SubjectContext)->ClientToken   \
        ) ?                                                         \
    ((PSECURITY_SUBJECT_CONTEXT) SubjectContext)->ClientToken :     \
    ((PSECURITY_SUBJECT_CONTEXT) SubjectContext)->PrimaryToken )

NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName
    );

#endif // #ifndef _NTIFS_


NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcessToken (
    IN HANDLE       ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    OUT PHANDLE     TokenHandle
);

typedef
NTSTATUS
( *_ZwOpenProcessTokenEx) (
    IN HANDLE       ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN ULONG        HandleAttributes,
    OUT PHANDLE     TokenHandle
);


NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationToken (
    IN HANDLE                   TokenHandle,
    IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
    OUT PVOID                   TokenInformation,
    IN ULONG                    TokenInformationLength,
    OUT PULONG                  ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationToken (
    IN HANDLE                   TokenHandle,
    IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
    IN PVOID                    TokenInformation,
    IN ULONG                    TokenInformationLength
);


NTKERNELAPI
KPROCESSOR_MODE
KeGetPreviousMode(VOID);

typedef unsigned short      WORD;
typedef unsigned long      DWORD;
typedef unsigned char      BYTE;


#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

struct SEGMENT;
typedef SEGMENT *PSEGMENT;
struct EVENT_COUNTER;
typedef EVENT_COUNTER *PEVENT_COUNTER;
struct SUBSECTION;
typedef SUBSECTION *PSUBSECTION;
struct LARGE_CONTROL_AREA;
typedef LARGE_CONTROL_AREA *PLARGE_CONTROL_AREA;
struct MMSECTION_FLAGS;
typedef MMSECTION_FLAGS *PMMSECTION_FLAGS;
struct MMSUBSECTION_FLAGS;
typedef MMSUBSECTION_FLAGS *PMMSUBSECTION_FLAGS;


typedef struct _CONTROL_AREA {
/*0x000*/ PSEGMENT Segment;
/*0x004*/ LIST_ENTRY DereferenceList;
/*0x00c*/ ULONG NumberOfSectionReferences;
/*0x010*/ ULONG NumberOfPfnReferences;
/*0x014*/ ULONG NumberOfMappedViews;
/*0x018*/ USHORT NumberOfSubsections;
/*0x01a*/ USHORT FlushInProgressCount;
/*0x01c*/ ULONG NumberOfUserReferences;
/*0x020*/ ULONG u;
/*0x024*/ PFILE_OBJECT FilePointer;
/*0x028*/ PEVENT_COUNTER WaitingForDeletion;
/*0x02c*/ USHORT ModifiedWriteCount;
/*0x02e*/ USHORT NumberOfSystemCacheViews;
} CONTROL_AREA, *PCONTROL_AREA;


typedef struct _SEGMENT_OBJECT {
/*0x000*/ PVOID BaseAddress;
/*0x004*/ ULONG TotalNumberOfPtes;
/*0x008*/ LARGE_INTEGER SizeOfSegment;
/*0x010*/ ULONG NonExtendedPtes;
/*0x014*/ ULONG ImageCommitment;
/*0x018*/ PCONTROL_AREA ControlArea;
/*0x01c*/ PSUBSECTION Subsection;
/*0x020*/ PLARGE_CONTROL_AREA LargeControlArea;
/*0x024*/ PMMSECTION_FLAGS MmSectionFlags;
/*0x028*/ PMMSUBSECTION_FLAGS MmSubSectionFlags;
} SEGMENT_OBJECT, *PSEGMENT_OBJECT;


typedef struct _SECTION_OBJECT {
/*0x000*/ PVOID StartingVa;
/*0x004*/ PVOID EndingVa;
/*0x008*/ PVOID Parent;
/*0x00c*/ PVOID LeftChild;
/*0x010*/ PVOID RightChild;
/*0x014*/ PSEGMENT_OBJECT Segment;
} SECTION_OBJECT, *PSECTION_OBJECT;


#define OB_FLAG_CREATE_INFO    0x01 // has OBJECT_CREATE_INFO
#define OB_FLAG_KERNEL_MODE    0x02 // created by kernel
#define OB_FLAG_CREATOR_INFO   0x04 // has OBJECT_CREATOR_INFO
#define OB_FLAG_EXCLUSIVE      0x08 // OBJ_EXCLUSIVE
#define OB_FLAG_PERMANENT      0x10 // OBJ_PERMANENT
#define OB_FLAG_SECURITY       0x20 // has security descriptor
#define OB_FLAG_SINGLE_PROCESS 0x40 // no HandleDBList

struct QUOTA_BLOCK;
typedef QUOTA_BLOCK *PQUOTA_BLOCK;
struct OBJECT_CREATE_INFO;
typedef OBJECT_CREATE_INFO *POBJECT_CREATE_INFO;

typedef struct _OBJECT_HEADER
        {
/*000*/ DWORD        PointerCount;       // number of references
/*004*/ DWORD        HandleCount;        // number of open handles
/*008*/ POBJECT_TYPE ObjectType;
/*00C*/ BYTE         NameOffset;         // -> OBJECT_NAME
/*00D*/ BYTE         HandleDBOffset;     // -> OBJECT_HANDLE_DB
/*00E*/ BYTE         QuotaChargesOffset; // -> OBJECT_QUOTA_CHARGES
/*00F*/ BYTE         ObjectFlags;        // OB_FLAG_*
/*010*/ union
            { // OB_FLAG_CREATE_INFO ? ObjectCreateInfo : QuotaBlock
/*010*/     PQUOTA_BLOCK        QuotaBlock;
/*010*/     POBJECT_CREATE_INFO ObjectCreateInfo;
/*014*/     };
/*014*/ PSECURITY_DESCRIPTOR SecurityDescriptor;
/*018*/ }
        OBJECT_HEADER,
     * POBJECT_HEADER,
    **PPOBJECT_HEADER;

typedef NTSTATUS (NTAPI *NTPROC) ();
typedef VOID (NTAPI *NTPROC_VOID) ();
typedef BOOLEAN (NTAPI *NTPROC_BOOLEAN) ();

typedef NTSTATUS (NTAPI *NTPROC_SECURITY) (
                        PVOID Object,
                        ULONG Unknown1,
                        PSECURITY_INFORMATION SecurityInformation,
                        PSECURITY_DESCRIPTOR SecurityDescriptor1,
                        ULONG Unknown2,
                        PSECURITY_DESCRIPTOR SecurityDescriptor2,
                        POOL_TYPE PagedPool,
                        PGENERIC_MAPPING GenericMapping                                           
                        );


typedef struct _OBJECT_TYPE_INITIALIZER
        {
/*000*/ WORD            Length;          //0x004C
/*002*/ BOOLEAN         UseDefaultObject;//OBJECT_TYPE.DefaultObject
/*003*/ BOOLEAN         Reserved1;
/*004*/ DWORD           InvalidAttributes;
/*008*/ GENERIC_MAPPING GenericMapping;
/*018*/ ACCESS_MASK     ValidAccessMask;
/*01C*/ BOOLEAN         SecurityRequired;
/*01D*/ BOOLEAN         MaintainHandleCount; // OBJECT_HANDLE_DB
/*01E*/ BOOLEAN         MaintainTypeList;    // OBJECT_CREATOR_INFO
/*01F*/ BYTE            Reserved2;
/*020*/ POOL_TYPE       PagedPool;
/*024*/ DWORD           DefaultPagedPoolCharge;
/*028*/ DWORD           DefaultNonPagedPoolCharge;
/*02C*/ NTPROC          DumpProcedure;
/*030*/ NTPROC          OpenProcedure;
/*034*/ NTPROC          CloseProcedure;
/*038*/ NTPROC          DeleteProcedure;
/*03C*/ NTPROC_VOID     ParseProcedure;
/*040*/ NTPROC_SECURITY SecurityProcedure; // SeDefaultObjectMethod
/*044*/ NTPROC_VOID     QueryNameProcedure;
/*048*/ NTPROC_BOOLEAN  OkayToCloseProcedure;
/*04C*/ }
        OBJECT_TYPE_INITIALIZER,
     * POBJECT_TYPE_INITIALIZER,
    **PPOBJECT_TYPE_INITIALIZER;

// -----------------------------------------------------------------

#define OB_TYPE_INDEX_TYPE              1 // [ObjT] "Type"
#define OB_TYPE_INDEX_DIRECTORY         2 // [Dire] "Directory"
#define OB_TYPE_INDEX_SYMBOLIC_LINK     3 // [Symb] "SymbolicLink"
#define OB_TYPE_INDEX_TOKEN             4 // [Toke] "Token"
#define OB_TYPE_INDEX_PROCESS           5 // [Proc] "Process"
#define OB_TYPE_INDEX_THREAD            6 // [Thre] "Thread"
#define OB_TYPE_INDEX_JOB               7 // [Job ] "Job"
#define OB_TYPE_INDEX_EVENT             8 // [Even] "Event"
#define OB_TYPE_INDEX_EVENT_PAIR        9 // [Even] "EventPair"
#define OB_TYPE_INDEX_MUTANT           10 // [Muta] "Mutant"
#define OB_TYPE_INDEX_CALLBACK         11 // [Call] "Callback"
#define OB_TYPE_INDEX_SEMAPHORE        12 // [Sema] "Semaphore"
#define OB_TYPE_INDEX_TIMER            13 // [Time] "Timer"
#define OB_TYPE_INDEX_PROFILE          14 // [Prof] "Profile"
#define OB_TYPE_INDEX_WINDOW_STATION   15 // [Wind] "WindowStation"
#define OB_TYPE_INDEX_DESKTOP          16 // [Desk] "Desktop"
#define OB_TYPE_INDEX_SECTION          17 // [Sect] "Section"
#define OB_TYPE_INDEX_KEY              18 // [Key ] "Key"
#define OB_TYPE_INDEX_PORT             19 // [Port] "Port"
#define OB_TYPE_INDEX_WAITABLE_PORT    20 // [Wait] "WaitablePort"
#define OB_TYPE_INDEX_ADAPTER          21 // [Adap] "Adapter"
#define OB_TYPE_INDEX_CONTROLLER       22 // [Cont] "Controller"
#define OB_TYPE_INDEX_DEVICE           23 // [Devi] "Device"
#define OB_TYPE_INDEX_DRIVER           24 // [Driv] "Driver"
#define OB_TYPE_INDEX_IO_COMPLETION    25 // [IoCo] "IoCompletion"
#define OB_TYPE_INDEX_FILE             26 // [File] "File"
#define OB_TYPE_INDEX_WMI_GUID         27 // [WmiG] "WmiGuid"

typedef struct _OBJECT_TYPE
        {
/*000*/ ERESOURCE      Lock;
/*038*/ LIST_ENTRY     ObjectListHead; // OBJECT_CREATOR_INFO
/*040*/ UNICODE_STRING ObjectTypeName; // see above
/*048*/ union
            {
/*048*/     PVOID DefaultObject; // ObpDefaultObject
/*048*/     DWORD Code;          // File: 5C, WaitablePort: A0
            };
/*04C*/ DWORD                   ObjectTypeIndex; // OB_TYPE_INDEX_*
/*050*/ DWORD                   ObjectCount;
/*054*/ DWORD                   HandleCount;
/*058*/ DWORD                   PeakObjectCount;
/*05C*/ DWORD                   PeakHandleCount;
/*060*/ OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
/*0AC*/ DWORD                   ObjectTypeTag;   // OB_TYPE_TAG_*
/*0B0*/ }
        OBJECT_TYPE,
     * POBJECT_TYPE,
    **PPOBJECT_TYPE;


inline POBJECT_HEADER GetObjectHeader(PVOID Object)
{
    return POBJECT_HEADER((PUCHAR)Object - sizeof OBJECT_HEADER);
}

inline ULONG ObGetObjectPointerCount(IN PVOID Object)
{
    return GetObjectHeader(Object)->PointerCount;
}

struct CONFIG_PARSE_CONTEXT {
	ULONG Unknown1;
    UNICODE_STRING Class;
    ULONG CreateOptions;
    ULONG Disposition;
};


#define SEC_BASED           0x00200000 // Map section at same address in each process
#define SEC_NO_CHANGE       0x00400000 // Disable changes to protection of pages
#define SEC_IMAGE           0x01000000 // Map section as an image
#define SEC_VLM             0x02000000 // Map section in VLM region
#define SEC_NOCACHE         0x10000000 // Mark pages as non-cacheable


#define PROCESS_TERMINATE         (0x0001)  
#define PROCESS_CREATE_THREAD     (0x0002)  
#define PROCESS_SET_SESSIONID     (0x0004)  
#define PROCESS_VM_OPERATION      (0x0008)  
#define PROCESS_VM_READ           (0x0010)  
#define PROCESS_VM_WRITE          (0x0020)  
#define PROCESS_DUP_HANDLE        (0x0040)  
#define PROCESS_CREATE_PROCESS    (0x0080)  
#define PROCESS_SET_QUOTA         (0x0100)  
#define PROCESS_SET_INFORMATION   (0x0200)  
#define PROCESS_QUERY_INFORMATION (0x0400)  
#define PROCESS_SUSPEND_RESUME    (0x0800)  
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFF)

#define THREAD_TERMINATE               (0x0001)  
#define THREAD_SUSPEND_RESUME          (0x0002)  
#define THREAD_GET_CONTEXT             (0x0008)  
#define THREAD_SET_CONTEXT             (0x0010)  
#define THREAD_SET_INFORMATION         (0x0020)  
#define THREAD_QUERY_INFORMATION       (0x0040)  
#define THREAD_SET_THREAD_TOKEN        (0x0080)
#define THREAD_IMPERSONATE             (0x0100)
#define THREAD_DIRECT_IMPERSONATION    (0x0200)
// begin_ntddk begin_wdm begin_ntifs

#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0x3FF)

// end_ntddk end_wdm end_ntifs
#define JOB_OBJECT_ASSIGN_PROCESS           (0x0001)
#define JOB_OBJECT_SET_ATTRIBUTES           (0x0002)
#define JOB_OBJECT_QUERY                    (0x0004)
#define JOB_OBJECT_TERMINATE                (0x0008)
#define JOB_OBJECT_SET_SECURITY_ATTRIBUTES  (0x0010)
#define JOB_OBJECT_ALL_ACCESS       (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                        0x1F )

#define IO_COMPLETION_MODIFY_STATE  0x0002  
#define IO_COMPLETION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 
#define DUPLICATE_CLOSE_SOURCE      0x00000001  
#define DUPLICATE_SAME_ACCESS       0x00000002  


#ifndef _NTIFS_

//
// Token Specific Access Rights.
//
#define TOKEN_ASSIGN_PRIMARY    (0x0001)
#define TOKEN_DUPLICATE         (0x0002)
#define TOKEN_IMPERSONATE       (0x0004)
#define TOKEN_QUERY             (0x0008)
#define TOKEN_QUERY_SOURCE      (0x0010)
#define TOKEN_ADJUST_PRIVILEGES (0x0020)
#define TOKEN_ADJUST_GROUPS     (0x0040)
#define TOKEN_ADJUST_DEFAULT    (0x0080)
#define TOKEN_ADJUST_SESSIONID  (0x0100)

#define TOKEN_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED  |\
                          TOKEN_ASSIGN_PRIMARY      |\
                          TOKEN_DUPLICATE           |\
                          TOKEN_IMPERSONATE         |\
                          TOKEN_QUERY               |\
                          TOKEN_QUERY_SOURCE        |\
                          TOKEN_ADJUST_PRIVILEGES   |\
                          TOKEN_ADJUST_GROUPS       |\
                          TOKEN_ADJUST_DEFAULT )

#define TOKEN_READ       (STANDARD_RIGHTS_READ      |\
                          TOKEN_QUERY)


#define TOKEN_WRITE      (STANDARD_RIGHTS_WRITE     |\
                          TOKEN_ADJUST_PRIVILEGES   |\
                          TOKEN_ADJUST_GROUPS       |\
                          TOKEN_ADJUST_DEFAULT)

#define TOKEN_EXECUTE    (STANDARD_RIGHTS_EXECUTE)

//
//
// Token Types
//

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
    } TOKEN_TYPE;
typedef TOKEN_TYPE *PTOKEN_TYPE;

NTKERNELAPI
NTSTATUS
SeQuerySessionIdToken(
    IN PACCESS_TOKEN,
    IN PULONG pSessionId
    );

#else // #ifndef _NTIFS_

//
// Thread Information Classes
//

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
    );

#endif // #ifndef _NTIFS_


//
// Timer Specific Access Rights.
//

#define TIMER_QUERY_STATE       0x0001
#define TIMER_MODIFY_STATE      0x0002

#define TIMER_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|\
                          TIMER_QUERY_STATE|TIMER_MODIFY_STATE)

/*
 * Windowstation-specific access flags
 */
#define WINSTA_ENUMDESKTOPS         0x0001L
#define WINSTA_READATTRIBUTES       0x0002L
#define WINSTA_ACCESSCLIPBOARD      0x0004L
#define WINSTA_CREATEDESKTOP        0x0008L
#define WINSTA_WRITEATTRIBUTES      0x0010L
#define WINSTA_ACCESSGLOBALATOMS    0x0020L
#define WINSTA_EXITWINDOWS          0x0040L
#define WINSTA_ENUMERATE            0x0100L
#define WINSTA_READSCREEN           0x0200L

#define WINSTA_ALL_ACCESS           (WINSTA_ENUMDESKTOPS  | WINSTA_READATTRIBUTES  | WINSTA_ACCESSCLIPBOARD | \
                                     WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES | WINSTA_ACCESSGLOBALATOMS | \
                                     WINSTA_EXITWINDOWS   | WINSTA_ENUMERATE       | WINSTA_READSCREEN)

/*
 * Desktop-specific access flags
 */
#define DESKTOP_READOBJECTS         0x0001L
#define DESKTOP_CREATEWINDOW        0x0002L
#define DESKTOP_CREATEMENU          0x0004L
#define DESKTOP_HOOKCONTROL         0x0008L
#define DESKTOP_JOURNALRECORD       0x0010L
#define DESKTOP_JOURNALPLAYBACK     0x0020L
#define DESKTOP_ENUMERATE           0x0040L
#define DESKTOP_WRITEOBJECTS        0x0080L
#define DESKTOP_SWITCHDESKTOP       0x0100L

//
// Lpc ports
//
#define PORT_CONNECT				0x0001L
#define PORT_ALL_ACCESS				(PORT_CONNECT | READ_CONTROL | DELETE)


NTSYSAPI
NTSTATUS 
ZwQuerySymbolicLinkObject(
			IN HANDLE  LinkHandle,
			IN OUT PUNICODE_STRING LinkTarget,
			OUT PULONG ReturnedLength
			);

NTSYSAPI
NTSTATUS 
ZwOpenSymbolicLinkObject(
			OUT PHANDLE  LinkHandle,
			IN ACCESS_MASK	DesiredAccess,
			IN POBJECT_ATTRIBUTES  ObjectAttributes
			);

typedef
NTSTATUS
(*_IoAttachDeviceToDeviceStackSafe)(
    IN PDEVICE_OBJECT  SourceDevice,
    IN PDEVICE_OBJECT  TargetDevice,
    IN OUT PDEVICE_OBJECT  *AttachedToDeviceObject 
    );

typedef
NTSTATUS
(*_IoCreateFileSpecifyDeviceObjectHint)(
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

typedef
NTSTATUS
(*_IoQueryFileDosDeviceName)(
    IN PFILE_OBJECT FileObject,
    OUT POBJECT_NAME_INFORMATION *ObjectNameInformation
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryDirectoryFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN PUNICODE_STRING FileName OPTIONAL,
    IN BOOLEAN RestartScan
    );

NTKERNELAPI
PEPROCESS
IoThreadToProcess(
    IN PETHREAD Thread
    );

#if !defined(_NTIFS_)

typedef struct _TOKEN_STATISTICS {
    LUID TokenId;
    LUID AuthenticationId;
    LARGE_INTEGER ExpirationTime;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    ULONG DynamicCharged;
    ULONG DynamicAvailable;
    ULONG GroupCount;
    ULONG PrivilegeCount;
    LUID ModifiedId;
} TOKEN_STATISTICS, *PTOKEN_STATISTICS;

NTKERNELAPI
PACCESS_TOKEN
PsReferencePrimaryToken(
    IN PEPROCESS Process
    );

//
// VOID
// PsDereferencePrimaryToken(
//    IN PACCESS_TOKEN PrimaryToken
//    );
//
#define PsDereferencePrimaryToken(T) (ObDereferenceObject((T)))

NTKERNELAPI
PACCESS_TOKEN
PsReferenceImpersonationToken(
    IN PETHREAD Thread,
    OUT PBOOLEAN CopyOnOpen,
    OUT PBOOLEAN EffectiveOnly,
    OUT PSECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    );

//
// VOID
// PsDereferenceImpersonationToken(
//    In PACCESS_TOKEN ImpersonationToken
//    );
//
#define PsDereferenceImpersonationToken(T)                                          \
            {if (ARGUMENT_PRESENT(T)) {                                       \
                (ObDereferenceObject((T)));                                   \
             } else {                                                         \
                ;                                                             \
             }                                                                \
            }
#endif // #if !defined(_NTIFS_)

typedef
BOOLEAN
( *_PsIsThreadImpersonating)(
  IN PETHREAD  Thread
    ); 

#ifndef _NTIFS_

typedef struct _PORT_MESSAGE {
	USHORT DataSize;
	USHORT MessageSize;
	USHORT MessageType;
	USHORT VirtualRangesOffset;
	CLIENT_ID ClientId;
	ULONG MessageId;
	ULONG SectionSize;
	// UCHAR Data[];
} PORT_MESSAGE, *PPORT_MESSAGE;

#endif // #ifndef _NTIFS_

#if (_WIN32_WINNT <= 0x0500)
//
// Named Pipe file control code and structure declarations
//

//
// External named pipe file control operations
//

#define FSCTL_PIPE_ASSIGN_EVENT         CTL_CODE(FILE_DEVICE_NAMED_PIPE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_DISCONNECT           CTL_CODE(FILE_DEVICE_NAMED_PIPE, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_LISTEN               CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_PEEK                 CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)
#define FSCTL_PIPE_QUERY_EVENT          CTL_CODE(FILE_DEVICE_NAMED_PIPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_TRANSCEIVE           CTL_CODE(FILE_DEVICE_NAMED_PIPE, 5, METHOD_NEITHER,  FILE_READ_DATA | FILE_WRITE_DATA)
#define FSCTL_PIPE_WAIT                 CTL_CODE(FILE_DEVICE_NAMED_PIPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_IMPERSONATE          CTL_CODE(FILE_DEVICE_NAMED_PIPE, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_CLIENT_PROCESS   CTL_CODE(FILE_DEVICE_NAMED_PIPE, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_QUERY_CLIENT_PROCESS CTL_CODE(FILE_DEVICE_NAMED_PIPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Internal named pipe file control operations
//

#define FSCTL_PIPE_INTERNAL_READ        CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2045, METHOD_BUFFERED, FILE_READ_DATA)
#define FSCTL_PIPE_INTERNAL_WRITE       CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2046, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_PIPE_INTERNAL_TRANSCEIVE  CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2047, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define FSCTL_PIPE_INTERNAL_READ_OVFLOW CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2048, METHOD_BUFFERED, FILE_READ_DATA)

//
// Define entry types for query event information
//

#define FILE_PIPE_READ_DATA             0x00000000
#define FILE_PIPE_WRITE_SPACE           0x00000001

//
// Named pipe file system control structure declarations
//

// This is an extension to the client process info buffer containing the client
// computer name

#define FILE_PIPE_COMPUTER_NAME_LENGTH 15

#define FSCTL_MAILSLOT_PEEK             CTL_CODE(FILE_DEVICE_MAILSLOT, 0, METHOD_NEITHER, FILE_READ_DATA) 

#endif // #if (_WIN32_WINNT <= 0x0500)

typedef
PDEVICE_OBJECT
(*_IoGetLowerDeviceObject)(
    IN PDEVICE_OBJECT  DeviceObject
    );

typedef struct _CURDIR
{
   UNICODE_STRING DosPath;
   PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
   USHORT Flags;
   USHORT Length;
   ULONG TimeStamp;
   UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _PEB_FREE_BLOCK
{
   struct _PEB_FREE_BLOCK* Next;
   ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

/* RTL_USER_PROCESS_PARAMETERS.Flags */

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
   ULONG    MaximumLength;    //  00h
   ULONG    Length;        //  04h
   ULONG    Flags;         //  08h
   ULONG    DebugFlags;    //  0Ch
   PVOID    ConsoleHandle;    //  10h
   ULONG    ConsoleFlags;     //  14h
   HANDLE      InputHandle;      //  18h
   HANDLE      OutputHandle;     //  1Ch
   HANDLE      ErrorHandle;      //  20h
   CURDIR      CurrentDirectory; //  24h
   UNICODE_STRING DllPath;    //  30h
   UNICODE_STRING ImagePathName;    //  38h
   UNICODE_STRING CommandLine;      //  40h
   PVOID    Environment;      //  48h
   ULONG    StartingX;     //  4Ch
   ULONG    StartingY;     //  50h
   ULONG    CountX;        //  54h
   ULONG    CountY;        //  58h
   ULONG    CountCharsX;      //  5Ch
   ULONG    CountCharsY;      //  60h
   ULONG    FillAttribute;    //  64h
   ULONG    WindowFlags;      //  68h
   ULONG    ShowWindowFlags;  //  6Ch
   UNICODE_STRING WindowTitle;      //  70h
   UNICODE_STRING DesktopInfo;      //  78h
   UNICODE_STRING ShellInfo;     //  80h
   UNICODE_STRING RuntimeData;      //  88h
   RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20]; // 90h
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define  PEB_BASE        (0x7FFDF000)


typedef struct _PEB_LDR_DATA
{
   ULONG Length;
   BOOLEAN Initialized;
   PVOID SsHandle;
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef VOID (*PPEBLOCKROUTINE)(PVOID);

typedef struct _PEB
{
   UCHAR InheritedAddressSpace;                     // 00h
   UCHAR ReadImageFileExecOptions;                  // 01h
   UCHAR BeingDebugged;                             // 02h
   UCHAR Spare;                                     // 03h
   PVOID Mutant;                                    // 04h
   PVOID ImageBaseAddress;                          // 08h
   PPEB_LDR_DATA Ldr;                               // 0Ch
   PRTL_USER_PROCESS_PARAMETERS ProcessParameters;  // 10h
   PVOID SubSystemData;                             // 14h
   PVOID ProcessHeap;                               // 18h
   PVOID FastPebLock;                               // 1Ch
   PPEBLOCKROUTINE FastPebLockRoutine;              // 20h
   PPEBLOCKROUTINE FastPebUnlockRoutine;            // 24h
   ULONG EnvironmentUpdateCount;                    // 28h
   PVOID* KernelCallbackTable;                      // 2Ch
   PVOID EventLogSection;                           // 30h
   PVOID EventLog;                                  // 34h
   PPEB_FREE_BLOCK FreeList;                        // 38h
   ULONG TlsExpansionCounter;                       // 3Ch
   PVOID TlsBitmap;                                 // 40h
   ULONG TlsBitmapBits[0x2];                        // 44h
   PVOID ReadOnlySharedMemoryBase;                  // 4Ch
   PVOID ReadOnlySharedMemoryHeap;                  // 50h
   PVOID* ReadOnlyStaticServerData;                 // 54h
   PVOID AnsiCodePageData;                          // 58h
   PVOID OemCodePageData;                           // 5Ch
   PVOID UnicodeCaseTableData;                      // 60h
   ULONG NumberOfProcessors;                        // 64h
   ULONG NtGlobalFlag;                              // 68h
   UCHAR Spare2[0x4];                               // 6Ch
   LARGE_INTEGER CriticalSectionTimeout;            // 70h
   ULONG HeapSegmentReserve;                        // 78h
   ULONG HeapSegmentCommit;                         // 7Ch
   ULONG HeapDeCommitTotalFreeThreshold;            // 80h
   ULONG HeapDeCommitFreeBlockThreshold;            // 84h
   ULONG NumberOfHeaps;                             // 88h
   ULONG MaximumNumberOfHeaps;                      // 8Ch
   PVOID** ProcessHeaps;                            // 90h
   PVOID GdiSharedHandleTable;                      // 94h
   PVOID ProcessStarterHelper;                      // 98h
   PVOID GdiDCAttributeList;                        // 9Ch
   PVOID LoaderLock;                                // A0h
   ULONG OSMajorVersion;                            // A4h
   ULONG OSMinorVersion;                            // A8h
   ULONG OSBuildNumber;                             // ACh
   ULONG OSPlatformId;                              // B0h
   ULONG ImageSubSystem;                            // B4h
   ULONG ImageSubSystemMajorVersion;                // B8h
   ULONG ImageSubSystemMinorVersion;                // C0h
   ULONG GdiHandleBuffer[0x22];                     // C4h
} PEB, *PPEB;

} // extern "C" {


namespace AdApi {
    NTSTATUS Init(VOID);
    BOOLEAN InitShadowTable(VOID);

	extern _ObSetSecurityObjectByPointer ObSetSecurityObjectByPointer;
	extern _ZwOpenProcessTokenEx ZwOpenProcessTokenEx;
	extern _IoAttachDeviceToDeviceStackSafe IoAttachDeviceToDeviceStackSafe;
	extern _IoCreateFileSpecifyDeviceObjectHint IoCreateFileSpecifyDeviceObjectHint;
	extern _IoQueryFileDosDeviceName IoQueryFileDosDeviceName;
	extern _IoGetLowerDeviceObject IoGetLowerDeviceObject;
	extern _PsIsThreadImpersonating PsIsThreadImpersonating;
	extern POBJECT_TYPE GetObjectType(PVOID Object);
	extern ULONG NtVer;
};

#endif