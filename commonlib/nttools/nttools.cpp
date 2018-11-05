//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "ntnative.h"
#include "nttools.h"

#include <algorithm>

using namespace std;

namespace nttools {

using namespace NT;

size_t QueryXxx (const wstring& rootDir, StringList& objectNameList, const ObjectTypeIndex typeIndex, TransformType transformType)
{
  return QueryXxx (rootDir, objectNameList, ObjectType[static_cast <int> (typeIndex)], transformType);
} // QueryXxx

size_t QueryXxx (const wstring& rootDir, StringList& objectNameList, const wchar_t* type, TransformType transformType)
{
  if (true == rootDir.empty ())
    return 0;
    
  wstring               strPath        = rootDir;
  size_t                initialSizeList = objectNameList.size ();
  NT::UNICODE_STRING    dirString;
  NT::OBJECT_ATTRIBUTES dirAttr;
  NT::NTSTATUS          NtStatus;
  NT::HANDLE            hDir;
  char                  buf[1024];
  NT::POBJECT_NAMETYPE_INFO pObjName   = (NT::POBJECT_NAMETYPE_INFO) buf;
  NT::ULONG             objectIndex    = 0; 
  NT::ULONG             lengthReturned = 0;
  NT::ULONG             index          = 0;
  NT::BOOLEAN           bFirst         = TRUE;
  bool                  bAddSlash;
  
  bAddSlash = (strPath.c_str () [strPath.size () - 1] != L'\\');
  NT::RtlInitUnicodeString (&dirString, strPath.c_str ());
  InitializeObjectAttributes (&dirAttr, &dirString, OBJ_CASE_INSENSITIVE, NULL, NULL);
  NtStatus = NT::NtOpenDirectoryObject (&hDir, DIRECTORY_QUERY, &dirAttr);
  if (STATUS_SUCCESS == NtStatus)
  {
    if (true == bAddSlash)
      strPath.append (L"\\");
    while (NT::NtQueryDirectoryObject (hDir, buf, sizeof (buf), NT::ObjectArray, bFirst, &objectIndex, &lengthReturned) >= 0)
    {
      bFirst = FALSE;
      for (int i=0; index<objectIndex; ++index, ++i)
      {
        if (!wcsncmp (pObjName[i].ObjectType.Buffer, L"Directory", pObjName[i].ObjectType.Length/sizeof(NT::WCHAR)))
        {
          QueryXxx (strPath + wstring (pObjName[i].ObjectName.Buffer, pObjName[i].ObjectName.Length/sizeof(NT::WCHAR)), objectNameList, type);
        }
        else
        {
          if (NULL == type || !wcsncmp (pObjName[i].ObjectType.Buffer, type, pObjName[i].ObjectType.Length/sizeof(NT::WCHAR)))
          {
            wstring name = strPath + wstring (pObjName[i].ObjectName.Buffer, pObjName[i].ObjectName.Length/sizeof(NT::WCHAR));
            switch (transformType)
            {
              case Toupper:
                   transform (name.begin (), name.end (), name.begin (), toupper);
                   break;
              case Tolower:
                   transform (name.begin (), name.end (), name.begin (), tolower);
                   break;     
            }
            objectNameList.push_back (name);
          }  
        }
      }
    }
    
    NT::ZwClose (hDir);
  } // if (STATUS_SUCCESS == NtStatus)
  
  return objectNameList.size () - initialSizeList;
} // QueryXxx

wstring QueryObjectType (NT::HANDLE hDir, const wstring& objectName)
{
  wstring               type;
  char                  buf[1024];
  NT::POBJECT_NAMETYPE_INFO pObjName   = (NT::POBJECT_NAMETYPE_INFO) buf;
  NT::BOOLEAN           bFirst         = TRUE;
  NT::ULONG             objectIndex    = 0; 
  NT::ULONG             lengthReturned = 0;
  NT::ULONG             index          = 0;
  
  while (NT::NtQueryDirectoryObject (hDir, buf, sizeof (buf), NT::ObjectArray, bFirst, &objectIndex, &lengthReturned) >= 0)
  {
    bFirst = FALSE;
    for (int i=0; index<objectIndex; ++index, ++i)
    {
      NT::POBJECT_NAMETYPE_INFO _pObjName = &pObjName[i];
      if (0 == _wcsnicmp (pObjName[i].ObjectName.Buffer, objectName.c_str (), pObjName[i].ObjectName.Length/sizeof(NT::WCHAR)))
      {
        type.append (pObjName[i].ObjectType.Buffer, pObjName[i].ObjectType.Length/sizeof(NT::WCHAR));
        return type;
      }
    } // for (...)
  } // while (...)
  
  return type;
} // QueryObjectType

wstring QueryObjectType (const wstring& dirName, const wstring& objectName)
{
  wstring               type;
  NT::UNICODE_STRING    dirString;
  NT::OBJECT_ATTRIBUTES dirAttr;
  NT::NTSTATUS          NtStatus;
  NT::HANDLE            hDir;
  
  NT::RtlInitUnicodeString (&dirString, dirName.c_str ());
  InitializeObjectAttributes (&dirAttr, &dirString, OBJ_CASE_INSENSITIVE, NULL, NULL);
  NtStatus = NT::NtOpenDirectoryObject (&hDir, DIRECTORY_QUERY, &dirAttr);
  if (STATUS_SUCCESS == NtStatus)
  {
    type = QueryObjectType (hDir, objectName);
    NT::ZwClose (hDir);
  } // if (STATUS_SUCCESS == NtStatus)
  
  return type;
} // QueryObjectType

wstring QuerySymLinkTarget (const wstring& symLinkFullName, TransformType transformType)
{
  wstring                   targetName;
  NT::ULONG                 dwSizeSymLinkObj = 0;
  NT::UNICODE_STRING        SymLinkString;
  NT::OBJECT_ATTRIBUTES     SymAttr;
  NT::HANDLE                hSymLink;
  NT::WCHAR                 buffer [1024];
  
  NT::RtlInitUnicodeString (&SymLinkString, symLinkFullName.c_str ());
  InitializeObjectAttributes (&SymAttr, &SymLinkString, OBJ_CASE_INSENSITIVE, NULL, NULL);
  if (STATUS_SUCCESS == NT::ZwOpenSymbolicLinkObject (&hSymLink, SYMBOLIC_LINK_QUERY, &SymAttr))
  {
    SymLinkString.Buffer = buffer;
    SymLinkString.Length = 0;
    SymLinkString.MaximumLength = sizeof (buffer);

    if (STATUS_SUCCESS == NT::ZwQuerySymbolicLinkObject (hSymLink, &SymLinkString, &dwSizeSymLinkObj))
    {
      targetName.append (buffer, SymLinkString.Length / sizeof (NT::WCHAR));
      switch (transformType)
      {
        case Toupper:
             transform (targetName.begin (), targetName.end (), targetName.begin (), toupper);
             break;
        case Tolower:
             transform (targetName.begin (), targetName.end (), targetName.begin (), tolower);
             break;     
      }
    }
    NT::ZwClose (hSymLink);
  }
  
  return targetName;
} // QuerySymLinkTarget

wstring QueryObjectName(::HANDLE Handle)
{
	wstring Result;
	static const size_t size = 256;
	byte Buffer[size];
	NT::ULONG ReturnLength;

	NT::NTSTATUS rc = NT::ZwQueryObject(Handle, NT::ObjectNameInformation, Buffer, size, &ReturnLength);
	if ( NT_SUCCESS(rc) ) {
		POBJECT_NAME_INFORMATION NameInfo = (POBJECT_NAME_INFORMATION) Buffer;
		Result.assign(NameInfo->Name.Buffer, NameInfo->Name.Length / sizeof NT::WCHAR);
	}
	
	return Result;
}


DWORD GetParentProcessId(DWORD ProcessId)
{
	::HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if ( hProcess == NULL )
		return 0;

	NT::PROCESS_BASIC_INFORMATION pbi;
	DWORD Length;
	NT::NTSTATUS rc = NT::NtQueryInformationProcess(hProcess, NT::ProcessBasicInformation, &pbi, sizeof pbi, &Length);
	CloseHandle(hProcess);

	if ( !NT_SUCCESS(rc) )
		return 0;

	return (DWORD) pbi.InheritedFromUniqueProcessId;
}


} // namespace nttools


