//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswioctl_h__
#define __gswioctl_h__

#define FILE_DEVICE_GESWALL             FILE_DEVICE_UNKNOWN
//
// Driver device name
//
#define DEVICE_NAME                     L"GESWALL"
#define VERSION							0x500
#define RELEASE_ID						0x020900

#define GESWALL_USER_DEVICE_NAME        L"\\\\.\\"DEVICE_NAME

//
// Common headers
//
const ULONG AttrNum = 6;

struct EntityAttributes {
    ULONG Param[AttrNum];
};

enum AttrSetFunction {
	asfNone,
	asfOr,
	asfAnd
};

enum NtObjectType {
    nttUnknown          = 0,
    nttDebug            = 1,
    nttDesktop          = 2,
    nttDirectory        = 3,
    nttEvent            = 4,
    nttFile             = 5,
    nttIoCompletion     = 6,
    nttJob              = 7,
    nttKey              = 8,
    nttKeyedEvent       = 9,
    nttMutant           = 10,
    nttPort             = 11,
    nttProcess          = 12,
    nttProfile          = 13,
    nttSection          = 14,
    nttSemaphore        = 15,
    nttSymbolicLink     = 16,
    nttThread           = 17,
    nttToken            = 18,
    nttTimer            = 19,
    nttWaitablePort     = 20,
    nttWindowStation    = 21,
    nttDevice           = 22,
    nttDriver           = 23,
    nttAny              = 24,
	nttNetwork			= 25,
	nttSystemObject		= 26,
	nttWindow			= 27
};

enum BufferType {
    bufUnknown,
    bufObjectName,
    bufOwnerSid,
    bufSignature,
	bufIP4Address
};

struct RuleRecord {
    CHAR Label[4];
    ULONG RuleId;
    EntityAttributes Attr;
    NtObjectType Type;
    BufferType BufType;
    ULONG BufSize;
    PUCHAR Buf[1];
};

struct RulePack {
    ULONG PackVersion;
    ULONG RulesNumber;
    RuleRecord Record[1];
};

#define PACK_VERSION                    (2)

enum ProtocolType {
    proUnknown      =   0,  // Unrecognized protocol
    proEthernet     =   1,  // Ethernet
    proIp           =   2,  // Raw ip
    proIcmp         =   3,  // ICMP
    proIgmp         =   4,  // IGMP
    proUdp          =   5,  // UDP
    proTcp          =   6,  // TCP
    proNetbios      =   7,  // NETBEUI (not used)
    proIpx          =   8   // IPX (not used)
};

struct IP4Address {
	USHORT Port;
	ULONG Ip;
	ULONG Mask;
};

//
// Add rule record
//
#define  GESWALL_IOCTL_ADD_RULES            CTL_CODE(FILE_DEVICE_GESWALL, 0x000, METHOD_BUFFERED, FILE_WRITE_ACCESS)

//
// Delete all rules 
//
#define  GESWALL_IOCTL_DELETE_ALL_RULES     CTL_CODE(FILE_DEVICE_GESWALL, 0x001, METHOD_BUFFERED, FILE_WRITE_ACCESS)

//
// Update rules from registry
//
#define  GESWALL_IOCTL_REFRESH_RULES        CTL_CODE(FILE_DEVICE_GESWALL, 0x002, METHOD_BUFFERED, FILE_WRITE_ACCESS)

//
// win32 hooks adjustment
//

enum W32Func {
    ntuQueryWindow,
    ntuPostThreadMesage,
    ntuAttachThreadInput,
    ntuMessageCall,
    ntuPostMessage,
    ntuSendMessageCallback,
    ntuSendNotifyMessage,
    ntuGetClassName,
	ntuSendInput,
	ntuGetKeyState,
	ntuGetAsyncKeyState,
	ntuSetWindowsHookEx,
	ntuRegisterRawInputDevices,
	ntuBitBlt,
	ntuCallOneParam,
	ntuSetClipboardViewer,
	ntuGetClipboardData,
	ntuGetClipboardOwner,
    ntuMax
};

struct W32HooksetSyncParams {
    W32Func Func;
    UCHAR ParamSize;
    ULONG TestParamsNum;
    struct {
        ULONG Offset;
        ULONG Size;
        ULONG_PTR Param;
    } Param[6];
};

#define  GESWALL_IOCTL_W32HOOKSET_INIT      CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x003, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define  GESWALL_IOCTL_W32HOOKSET_RELEASE   CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x004, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define  GESWALL_IOCTL_W32HOOKSET_SYNC      CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x005, METHOD_BUFFERED, FILE_WRITE_ACCESS)


const SIZE_T MaxReqDataSize = 65536;

enum RequestFlags {
	reqWaitReply		= 1,
	reqMatchSession		= 2
};

struct RequestData {
    ULONG Type;
    ULONG Options;
    SIZE_T Size;
    PVOID Id;
	ULONG Code;
	ULONG Flags;
	LARGE_INTEGER Timeout;
};

struct ResponseData {
    SIZE_T Size;
    PVOID Id;
    ULONG Result;
};

enum RequestType {
    reqThreatPointSubject,
	reqNotIsolateTracked,
    reqProcExec,
    reqCreateFile,
    reqAccessSecretFile,
	reqEventNotification,
    reqMax
};

enum RequestOption {
    ropCached           = 1,
    ropGUI              = 2
};

enum GUIReply {
    gurUndefined        = 0,
    gurYes              = 1,
    gurNo               = 2,
    gurYesAlways        = 3,
    gurNoAlways         = 4
};

const LONG UserWaitSecs     = 90;
const int DefaultGUIReply   = gurYes;

#define GESWALL_IOCTL_GET_REQUEST           CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x006, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define GESWALL_IOCTL_POST_REPLY            CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x007, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define GESWALL_IOCTL_REPLY_REQUEST         CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x008, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define GESWALL_IOCTL_STOP_HANDLING         CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x009, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define GESWALL_IOCTL_REGISTER_HANDLER      CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x00a, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define GESWALL_IOCTL_GET_NOTIFICATION      CTL_CODE(FILE_DEVICE_GESWALL, VERSION + 0x00b, METHOD_BUFFERED, FILE_READ_ACCESS)

                        
struct RequestDataGUI : RequestData {
    HANDLE ProcessId;
};

struct ThreatPointSubjectReq : RequestDataGUI {
    ThreatPointSubjectReq(void) 
    { 
        Type = reqThreatPointSubject; 
        Size = sizeof ThreatPointSubjectReq; 
        Options = ropCached | ropGUI;
		Code = GESWALL_IOCTL_GET_REQUEST;
		Flags = reqWaitReply;
		Timeout.QuadPart = LONGLONG(5)*LONGLONG(60)*LONGLONG(1000)*LONGLONG(10000);

    }
    EntityAttributes Attr;
	ULONG RuleId;
    WCHAR FileName[512];
	NtObjectType ResourceType;
	WCHAR ResourceName[512];
};

enum ThreatPointSubjectResult {
	tpsKeepTrusted	= FALSE,
	tpsIsolate		= TRUE,
	tpsOnceTrusted
};

struct NotIsolateTrackedReq : RequestDataGUI {
    NotIsolateTrackedReq(void) 
    { 
        Type = reqNotIsolateTracked; 
        Size = sizeof NotIsolateTrackedReq; 
        Options = ropGUI;
		Code = GESWALL_IOCTL_GET_REQUEST;
		Flags = reqWaitReply;
		Timeout.QuadPart = LONGLONG(5)*LONGLONG(60)*LONGLONG(1000)*LONGLONG(10000);
    }
    EntityAttributes Attr;
	HANDLE ParentProcessId;
	ULONG RuleId;
    WCHAR FileName[512];
};

struct AccessSecretFileReq : RequestDataGUI {
    AccessSecretFileReq(void) 
    { 
        Type = reqAccessSecretFile; 
        Size = sizeof AccessSecretFileReq; 
        Options = ropCached | ropGUI;
		Code = GESWALL_IOCTL_GET_REQUEST;
		Flags = reqWaitReply;
		Timeout.QuadPart = LONGLONG(5)*LONGLONG(60)*LONGLONG(1000)*LONGLONG(10000);
    }
    EntityAttributes FileAttr;
    EntityAttributes ProcAttr;
	ULONG RuleId;
    WCHAR FileName[512];
    WCHAR ProcFileName[512];
};


struct ProcExecReq : RequestData {
    ProcExecReq(void)
    {
        Type = reqProcExec;
        Size = sizeof ProcExecReq;
        Options = 0;
		Code = GESWALL_IOCTL_GET_REQUEST;
		Flags = reqWaitReply;
		Timeout.QuadPart = LONGLONG(10)*LONGLONG(1000)*LONGLONG(10000);
    }
    CHAR Label[4];
    ULONG RuleId;
    HANDLE ProcessId;
    HANDLE ThreadId;
	PVOID Process;
    EntityAttributes Attr;
    WCHAR FileName[512];
};

struct ProcExecReply {
    EntityAttributes Attr;
    RulePack Pack;
};

struct CreateFileReq : RequestData {
    CreateFileReq(void)
    {
        Type = reqCreateFile;
        Size = sizeof CreateFileReq;
        Options = 0;
		Code = GESWALL_IOCTL_GET_REQUEST;
		Flags = reqWaitReply;
		Timeout.QuadPart = LONGLONG(10)*LONGLONG(1000)*LONGLONG(10000);
    }
    HANDLE ProcessId;
	ULONG RuleId;
    HANDLE hFile;
    EntityAttributes Attr;
    WCHAR FileName[512];
};

struct EventNotification : RequestData {
    EventNotification(void)
    {
        Type = reqEventNotification;
        Size = sizeof EventNotification;
        Options = 0;
		Code = GESWALL_IOCTL_GET_NOTIFICATION;
		Flags = reqMatchSession;
		Timeout.QuadPart = LONGLONG(10)*LONGLONG(1000)*LONGLONG(10000);
    }
    HANDLE ProcessId;
	ULONG RuleId;
    EntityAttributes Attr;
    WCHAR ProcFileName[512];
    WCHAR EventString[512];
};

struct SetAttributesInfo {
    HANDLE hObject;
    NtObjectType ResType;
    CHAR Label[4];
    EntityAttributes Attr;
};

#define GESWALL_IOCTL_SET_ATTRIBUTES        CTL_CODE(FILE_DEVICE_GESWALL, 0x010, METHOD_BUFFERED, FILE_WRITE_ACCESS)


struct GetSubjAttributesInfo {
    HANDLE ProcessId;
    CHAR Label[4];
};

struct SubjAttributesInfo {
	EntityAttributes Attr;
	ULONG RuleId;
};

#define GESWALL_IOCTL_GET_SUBJ_ATTRIBUTES   CTL_CODE(FILE_DEVICE_GESWALL, 0x011, METHOD_BUFFERED, FILE_READ_ACCESS)

struct GetObjectAttributesInfo {
	HANDLE hObject;
	NtObjectType Type;
	ULONG RuleId;
	CHAR Label[4];
};

struct ObjectAttributesInfo {
	EntityAttributes Attr;
};

#define GESWALL_IOCTL_GET_OBJ_ATTRIBUTES	CTL_CODE(FILE_DEVICE_GESWALL, 0x012, METHOD_BUFFERED, FILE_READ_ACCESS)

#define GESWALL_IOCTL_REFRESH_SETTINGS		CTL_CODE(FILE_DEVICE_GESWALL, 0x013, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define GESWALL_IOCTL_DISABLE_REDIRECT		CTL_CODE(FILE_DEVICE_GESWALL, 0x014, METHOD_BUFFERED, FILE_READ_ACCESS)

#define GESWALL_IOCTL_GET_CURRENT_SUBJ_ATTRIBUTES	CTL_CODE(FILE_DEVICE_GESWALL, 0x015, METHOD_BUFFERED, FILE_READ_ACCESS)

#define GESWALL_IOCTL_GET_PROCESSID			CTL_CODE(FILE_DEVICE_GESWALL, 0x016, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define GESWALL_IOCTL_GET_PROCESS_EXECNAME	CTL_CODE(FILE_DEVICE_GESWALL, 0x017, METHOD_BUFFERED, FILE_READ_ACCESS)

#define GESWALL_IOCTL_GET_RELEASE_ID		CTL_CODE(FILE_DEVICE_GESWALL, 0x018, METHOD_BUFFERED, FILE_READ_ACCESS)


inline WCHAR *GetNtTypeString(NtObjectType Type)
{
    switch ( Type )  {
        case nttUnknown:
            return L"Unknown";
        case nttDebug:
            return L"Debug";
        case nttDesktop:
            return L"Desktop";
        case nttDevice:
            return L"Device";
        case nttDirectory:
            return L"Directory";
        case nttEvent:
            return L"Event";
        case nttFile:
            return L"File";
        case nttIoCompletion:
            return L"IoCompletion";
        case nttJob:
            return L"Job";
        case nttKey:
            return L"Registry";
        case nttKeyedEvent:
            return L"KeyedEvent";
        case nttMutant:
            return L"Mutant";
        case nttPort:
            return L"Port";
        case nttProcess:
            return L"Process";
        case nttProfile:
            return L"Profile";
        case nttSection:
            return L"Section";
        case nttSemaphore:
            return L"Semaphore";
        case nttSymbolicLink:
            return L"SymbolicLink";
        case nttThread:
            return L"Thread";
        case nttToken:
            return L"Token";
        case nttTimer:
            return L"Timer";
        case nttWaitablePort:
            return L"WaitablePort";
        case nttWindowStation:
            return L"WindowStation";
        case nttAny:
            return L"Any";
        case nttNetwork:
            return L"Network";
		case nttSystemObject:
			return L"SystemObject";
    }

    return L"Unknown";
}


#endif // __gswioctl_h__