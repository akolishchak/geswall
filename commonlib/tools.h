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

#ifndef __GSW_NO_STD_AFX__
 #include "stdafx.h"
#else
 #include <windows.h>
#endif // __GSW_NO_STD_AFX__ 

#include <sddl.h>

#include "gsw/gswioctl.h"
#include "db/storage.h"

#include <string>
#include <list>
#include <boost/smart_ptr.hpp> 

using namespace Storage;
using namespace std;

namespace commonlib {
namespace Tools {

wstring FullNameToDOSName (const wstring& fullName);
size_t  FullNameToDOSName (wstring& dosName, const wstring& fullName);

wstring FullNameToUNCName (const wstring& fullName);
size_t  FullNameToUNCName (wstring& uncName, const wstring& fullName);

wstring DOSNameToFullName (const wstring& dosName);
size_t  DOSNameToFullName (wstring& fullName, const wstring& dosName);

wstring UNCNameToFullName (const wstring& uncName);
size_t  UNCNameToFullName (wstring& fullName, const wstring& uncName);

wstring LongNameToShortName (const wstring& longName);
size_t  LongNameToShortName (wstring& shortName, const wstring& longName);

wstring ShortNameToLongName (const wstring& shortName);
size_t  ShortNameToLongName (wstring& longName, const wstring& shortName);

wstring RegLinkToRegName (const wstring& link, HANDLE processId);
size_t  RegLinkToRegName (wstring& name, const wstring& link, HANDLE processId);

wstring QueryObjectContent (const wstring& fullName);
size_t  QueryObjectContent (wstring& content, const wstring& fullName);

typedef boost::shared_ptr<RuleRecord> PtrToRuleRecord;
typedef std::list<PtrToRuleRecord>    RuleRecordList;

bool    fillRulesPack (RulePack* rulePack, const RuleRecordList& rulesList);
DWORD   getRulesPackLength (const RuleRecordList& rulesList);
bool    createRuleRecord (RuleRecordList &List, PtrToResourceItem& resItem, HANDLE processId, ULONG RuleId);
bool    GetSidByName (const wchar_t *Name, byte *&Sid, size_t &SidSize);
DWORD GetProcessIdByName(const wchar_t *ProcessName);

typedef boost::shared_array<BYTE>          PtrToByte;

} // namespace Tools
} // namespace commonlib

#endif // __tools_h__