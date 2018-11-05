//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "log.h"
#include "lock.h"
#include "tools.h"
#include "ntrulemap.h"
#include "hook.h"
#include "request.h"

namespace Log {

    struct Record {
        LIST_ENTRY Entry;
        InfoType Type;
        ULONG Length;
        WCHAR Buf[1];
    };

    VOID WriteThread(PVOID Context);

    const WCHAR *LogFileName = L"\\SystemRoot\\gswlog.txt";
    const WCHAR *DebugFileName = L"\\SystemRoot\\gswdebug.txt";
    LogLevel CurrentLogLevel = llvDisabled;
    DebugLevel CurrentDebugLevel = dlvDisabled;
    CEResource Syn;
    KEVENT DestructorEvent;
    LIST_ENTRY RecordsList;
    PVOID WriteThreadObject = NULL;
	BOOLEAN bInited = FALSE;
};


NTSTATUS Log::Init(VOID)
{
    NTSTATUS rc;

    KeInitializeEvent(&DestructorEvent, NotificationEvent, FALSE);
    InitializeListHead(&RecordsList);

    rc = Syn.Init();
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    //
    // Read Log level
    //
    ULONG Size = sizeof CurrentLogLevel;
    PVOID Buf = &CurrentLogLevel;
    rc = RegReadValue(&usRegParamName, L"LogLevel", &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) {
        CurrentLogLevel = llvDisabled;
        ERR(rc);
        rc = STATUS_SUCCESS;
    }

    Size = sizeof CurrentDebugLevel;
    Buf = &CurrentDebugLevel;
    rc = RegReadValue(&usRegParamName, L"DebugLevel", &Buf, &Size, NULL);
    if ( !NT_SUCCESS(rc) ) {
        CurrentDebugLevel = dlvDisabled;
        ERR(rc);
        rc = STATUS_SUCCESS;
    }


    HANDLE hThread;
    rc = PsCreateSystemThread( &hThread, THREAD_ALL_ACCESS,
                              NULL, NULL, NULL, WriteThread, NULL);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

    rc = ObReferenceObjectByHandle(hThread, 0, NULL, KernelMode, &WriteThreadObject, NULL);
    ZwClose(hThread);
    if ( !NT_SUCCESS(rc) ) {
        ERR(rc);
        return rc;
    }

	bInited = TRUE;
    return rc;
}

VOID Log::Release(VOID)
{
    if ( !bInited ) return;

    if ( WriteThreadObject != NULL ) {
        KeSetEvent(&DestructorEvent, 0, FALSE);
        KeWaitForSingleObject(WriteThreadObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(WriteThreadObject);
    }

    Syn.Exclusive();
	while ( !IsListEmpty(&RecordsList) ) {
        PLIST_ENTRY pEntry = RemoveTailList(&RecordsList);
		Record *Rec = CONTAINING_RECORD(pEntry, Record, Entry);
        delete Rec;
	}
    Syn.Release();
    Syn.Destroy();
}

NTSTATUS Log::Write(LogLevel Level, WCHAR *Format, ... )
{
    if ( Level > CurrentLogLevel || !bInited )
        return STATUS_SUCCESS;

    NTSTATUS rc = STATUS_SUCCESS;
    static const ULONG Size = 1000;
    Record *Rec = (Record *) new CHAR[FIELD_OFFSET(Record, Buf) + Size * sizeof WCHAR];
    if ( Rec == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    va_list ap;
    va_start(ap, Format);
    rc = RtlStringCchVPrintfW(Rec->Buf, Size, Format, ap);
    if ( !NT_SUCCESS(rc) ) {
        delete[] Rec;
        return STATUS_UNSUCCESSFUL;
    }

    Rec->Type = typLog;
	Rec->Length = wcslen(Rec->Buf) * sizeof WCHAR;

    Syn.Exclusive();
    InsertTailList(&RecordsList, &Rec->Entry);
    Syn.Release();

    return rc;
}

NTSTATUS Log::AccessRecord(PEPROCESS Subject, EntityAttributes *Attr, ULONG RuleId, WCHAR *Format, ... )
{
    NTSTATUS rc = STATUS_SUCCESS;
    static const ULONG Size = 1000;
    Record *Rec = (Record *) new CHAR[FIELD_OFFSET(Record, Buf) + Size * sizeof WCHAR];
    if ( Rec == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        ERR(rc);
        return rc;
    }

    va_list ap;
    va_start(ap, Format);
    rc = RtlStringCchVPrintfW(Rec->Buf, Size, Format, ap);
    if ( !NT_SUCCESS(rc) ) {
        delete[] Rec;
        return STATUS_UNSUCCESSFUL;
    }
	SIZE_T Len = wcslen(Rec->Buf);

	//
	// Notification
	//
	if ( NtRuleMap::Notification > GesRule::ntlDisabled ) {
		EventNotification *Req = new(PagedPool) EventNotification;
		if ( Req != NULL ) {
			//
			Req->ProcessId = PsGetCurrentProcess() == Subject ? PsGetCurrentProcessId() : Hook::GetProcessId(Subject);
			Req->Attr = *Attr;
			Req->RuleId = RuleId;
			Req->ProcFileName[0] = 0;
			ULONG Length;
			PUNICODE_STRING usFileName = Hook::GetProcessFileName(Subject);
			if ( usFileName != NULL ) {
				Length = min(usFileName->Length, sizeof Req->ProcFileName -  sizeof WCHAR);
				RtlCopyMemory(Req->ProcFileName, usFileName->Buffer, Length);
				Req->ProcFileName[Length / sizeof WCHAR] = 0;
				delete[] usFileName;
			}
			Length = min(Len * sizeof WCHAR, sizeof Req->EventString -  sizeof WCHAR);
			RtlCopyMemory(Req->EventString, Rec->Buf, Length);
			Req->EventString[Length / sizeof WCHAR] = 0;

			Request::UserCall(Req, NULL, NULL);
			delete Req;
		}
	}
	//
	//
	//
    Rec->Type = typAccessLog;
    Rec->Length = Len * sizeof WCHAR;

    Syn.Exclusive();
    InsertTailList(&RecordsList, &Rec->Entry);
    Syn.Release();

    return rc;
}

VOID Log::SetLogLevel(LogLevel Level)
{
    CurrentLogLevel = Level;
}

BOOLEAN Log::IsAllowedLogLevel(LogLevel Level)
{
    return Level <= CurrentLogLevel;
}


NTSTATUS Log::DebugMessage(CHAR *Format, ... )
{
#if !defined(DBG)
	if ( CurrentDebugLevel == dlvDisabled ) return STATUS_SUCCESS;
#endif

    NTSTATUS rc = STATUS_SUCCESS;
    static const ULONG Size = 1000;
    Record *Rec = (Record *) new CHAR[FIELD_OFFSET(Record, Buf) + Size];
    if ( Rec == NULL ) {
        rc = STATUS_INSUFFICIENT_RESOURCES;
        return rc;
    }

    va_list ap;
    va_start(ap, Format);
    ULONG Len = _vsnprintf((CHAR *)Rec->Buf, Size - 1, Format, ap);
    ((CHAR *)Rec->Buf)[Size - 1] = 0;
    if ( Len == 0 ) {
        delete[] Rec;
        return STATUS_UNSUCCESSFUL;
    }

#if DBG
    DbgPrint((CHAR *)Rec->Buf);
	if ( CurrentDebugLevel == dlvDisabled ) {
		delete[] Rec;
		return STATUS_SUCCESS;
	}
#endif

    if ( !bInited ) {
        delete[] Rec;
        return STATUS_SUCCESS;
    }

    Rec->Type = typDebug;
    Rec->Length = Len;

    Syn.Exclusive();
    InsertTailList(&RecordsList, &Rec->Entry);
    Syn.Release();

    return rc;
}

VOID Log::SetDebugLevel(DebugLevel Level)
{
    CurrentDebugLevel = Level;
}

BOOLEAN Log::IsAllowedDebugLevel(DebugLevel Level)
{
    return Level <= CurrentDebugLevel;
}


VOID Log::WriteThread(PVOID Context)
{
    NTSTATUS rc;
    HANDLE hLogFile = NULL, hDebugFile = NULL, hAccessLogFile = NULL;
    LARGE_INTEGER Pause;
    Pause.QuadPart = - LONGLONG(3)*LONGLONG(1000)*LONGLONG(10000); // 3 secs
	CSHORT Day = 0;

    while ( TRUE ) {
        rc = KeWaitForSingleObject(&DestructorEvent, Executive, KernelMode, FALSE, &Pause);
        if ( rc == STATUS_SUCCESS )
            break;
        if ( rc != STATUS_TIMEOUT )
            break;

        if ( hLogFile == NULL && CurrentLogLevel != llvDisabled ) {
            OBJECT_ATTRIBUTES oa;
            IO_STATUS_BLOCK ios;

            UNICODE_STRING usFileName;
            RtlInitUnicodeString(&usFileName, LogFileName);

            InitializeObjectAttributes(&oa, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            rc = ZwCreateFile(&hLogFile,  FILE_APPEND_DATA,  &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL, 
                              FILE_SHARE_READ, FILE_OPEN_IF, 
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if ( !NT_SUCCESS(rc) ) {
                hLogFile = NULL;
                ERR(rc);
            }
        }

        if ( hDebugFile == NULL && CurrentDebugLevel != dlvDisabled ) {
            OBJECT_ATTRIBUTES oa;
            IO_STATUS_BLOCK ios;

            UNICODE_STRING usFileName;
            RtlInitUnicodeString(&usFileName, DebugFileName);

            InitializeObjectAttributes(&oa, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            rc = ZwCreateFile(&hDebugFile,  FILE_APPEND_DATA,  &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL, 
                              FILE_SHARE_READ, FILE_OPEN_IF, 
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if ( !NT_SUCCESS(rc) ) {
                hDebugFile = NULL;
                ERR(rc);
            }
        }

		LARGE_INTEGER SysTime, Time;
		KeQuerySystemTime(&SysTime);
		ExSystemTimeToLocalTime(&SysTime, &Time);
		TIME_FIELDS TimeFields;
		RtlTimeToTimeFields(&Time, &TimeFields);

		if ( hAccessLogFile == NULL || TimeFields.Day != Day ) {
			//
			// Do not open file until first log entry, if file is opened at early at boot stage
			// it may prevent unmount request of various disk utilities, such as chkdsk
			//
			Syn.Exclusive();
			if ( IsListEmpty(&RecordsList) ) {
				Syn.Release();
				continue;
			}
			Syn.Release();

			if ( hAccessLogFile != NULL ) {
				ZwClose(hAccessLogFile);
				hAccessLogFile = NULL;
			}
            OBJECT_ATTRIBUTES oa;
            IO_STATUS_BLOCK ios;

            UNICODE_STRING usFileName;
			static const SIZE_T Size = 256;
			WCHAR *Buffer = new(PagedPool) WCHAR[Size];
			if ( Buffer != NULL ) {

				RtlStringCchPrintfW(Buffer, Size, L"%s\\%4d%02d%02d.txt", NtRuleMap::AccessLogDir, TimeFields.Year,  TimeFields.Month, TimeFields.Day);
				RtlInitUnicodeString(&usFileName, Buffer);
				InitializeObjectAttributes(&oa, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
				rc = ZwCreateFile(&hAccessLogFile,  FILE_APPEND_DATA,  &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL, 
								FILE_SHARE_READ, FILE_OPEN_IF, 
								FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
				delete[] Buffer;
				if ( !NT_SUCCESS(rc) ) {
					hAccessLogFile = NULL;
					ERR(rc);
				}
				Day = TimeFields.Day;
			}
        }

        while ( hLogFile != NULL || hDebugFile != NULL || hAccessLogFile != NULL ) {
            Syn.Exclusive();
            if ( IsListEmpty(&RecordsList) ) {
                Syn.Release();
                break;
            }
            PLIST_ENTRY pEntry = RemoveHeadList(&RecordsList);
            Syn.Release();

            Record *Rec = CONTAINING_RECORD(pEntry, Record, Entry);

            IO_STATUS_BLOCK ios;
            if ( Rec->Type == typLog && hLogFile != NULL )
                rc = ZwWriteFile(hLogFile, NULL, NULL, NULL, &ios, Rec->Buf, Rec->Length, NULL, NULL);
            else
            if ( Rec->Type == typDebug && hDebugFile != NULL )
                rc = ZwWriteFile(hDebugFile, NULL, NULL, NULL, &ios, Rec->Buf, Rec->Length, NULL, NULL);
			else 
			if ( Rec->Type == typAccessLog && hAccessLogFile != NULL )
				rc = ZwWriteFile(hAccessLogFile, NULL, NULL, NULL, &ios, Rec->Buf, Rec->Length, NULL, NULL);

            if ( !NT_SUCCESS(rc) ) {
                Syn.Exclusive();
                InsertTailList(&RecordsList, &Rec->Entry);
                Syn.Release();
                ERR(rc);
                break;
            }
            delete[] Rec;
        }
    }

    if ( hLogFile != NULL ) ZwClose(hLogFile);
    if ( hDebugFile != NULL ) ZwClose(hDebugFile);
	if ( hAccessLogFile != NULL ) ZwClose(hAccessLogFile);
    PsTerminateSystemThread(STATUS_SUCCESS);
}