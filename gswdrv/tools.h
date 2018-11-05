//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __tools_h__
#define __tools_h__

enum ServiceType {
    srvSystem,
    srvWin32
};

// Maximum length of NT process name
#define NT_PROCNAMELEN              32


VOID GetProcessNameOffset( VOID );
BOOLEAN GetProcessNameByPointer(_EPROCESS *curproc, PCHAR theName);
SIZE_T GetProcessNameByPointer(_EPROCESS *curproc, WCHAR *theName);
NTSTATUS GetProcessNameById(ULONG ProcessId, PUNICODE_STRING ProcessName);
HANDLE GetProcessIdByProcess(PEPROCESS Process);
NTSTATUS GetObjectName(PVOID Object, PUNICODE_STRING *ObjectName);
NTSTATUS GetObjectName(PFILE_OBJECT FileObject, PUNICODE_STRING *FileName);
NTSTATUS GetRegistryObjectName(PVOID Object, PUNICODE_STRING ValueName, PUNICODE_STRING *ObjectName);
NTSTATUS RegReadValue(HANDLE hKey, PUNICODE_STRING usValue, PVOID *Buf, ULONG *BufSize, ULONG *Type OPTIONAL);
NTSTATUS RegReadValue(HANDLE hKey, WCHAR *ValueName, PVOID *Buf, ULONG *BufSize, ULONG *Type OPTIONAL);
NTSTATUS RegReadValue(PUNICODE_STRING usKeyName, WCHAR *ValueName, PVOID *Buf, ULONG *BufSize, ULONG *Type OPTIONAL);
NTSTATUS RegSaveValue(PUNICODE_STRING usKeyName, WCHAR *ValueName, PVOID Buf, ULONG BufSize, ULONG Type);

NTSTATUS QueryFile(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject, 
                   FILE_INFORMATION_CLASS FileInformationClass, PVOID FileQueryBuffer,
                   ULONG FileQueryBufferLength);

NTSTATUS QuerySecurityFile(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject,
                           SECURITY_INFORMATION SecurityInformation, 
                           PSECURITY_DESCRIPTOR sd, ULONG *Length);

NTSTATUS SetSecurityFile(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject,
                         SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR sd);

NTSTATUS SetFile(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject, FILE_INFORMATION_CLASS FileInformationClass,
				   PVOID FileQueryBuffer, ULONG FileQueryBufferLength);

NTSTATUS BufferRequest(ULONG MajorFunction, PFILE_OBJECT FileObject, PVOID Buf, 
					   ULONG &Size, PLARGE_INTEGER pOffset);

NTSTATUS CopyFile(HANDLE hSource, HANDLE hDest);

USHORT BinToHex(UCHAR *Bin, LONG BinLength, WCHAR *Str, LONG StrLength);

NTSTATUS SendControl(PDEVICE_OBJECT DeviceObject, ULONG IoControlCode, PVOID InBuf, 
					 ULONG InSize, PVOID OutBuf, ULONG &OutSize);

inline BOOLEAN CompareNames(PUNICODE_STRING Str1, PUNICODE_STRING Str2)
{
	if ( Str1->Length < Str2->Length ) return FALSE;
	//if ( Str2->Buffer[0] == '*' ) return TRUE;
    UNICODE_STRING pr = *Str1;
    pr.Length = Str2->Length;
    return !RtlCompareUnicodeString(&pr, Str2, TRUE);
}


typedef unsigned char md5_hash[16];
BOOLEAN GetMD5(PVOID Buf, ULONG Length, md5_hash hash);

NTSTATUS ResolveSymLink(WCHAR *SymLink, PUNICODE_STRING ResolvedName);
NTSTATUS TranslateToUserRegistryName(PUNICODE_STRING RegName);

VOID SleepEx(LONG Milliseconds, BOOLEAN bAlertable);
NTSTATUS DeleteSubKeys(PUNICODE_STRING KeyName);
NTSTATUS GetFileSecurity(PFILE_OBJECT FileObject, PSECURITY_DESCRIPTOR *sd);
BOOLEAN IsInteractiveContext(VOID);
PUNICODE_STRING CopyUnicodeString(PUNICODE_STRING Src);
PUNICODE_STRING GetProcessImageName(PEPROCESS Process);

#endif