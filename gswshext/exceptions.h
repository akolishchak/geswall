//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __exceptions_h__
#define __exceptions_h__


//---remove rule if rulename exists
LPWSTR ExceptItem[]=	{
							L"\\",
							L"C:",
							L"(null)"

						};
//---remove rule if part of the rulename exists
LPWSTR ExceptItemPart[]={
							L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache\\Paths",
							L"Software\\Microsoft\\Windows\\ShellNoRoam",
							L"Device\\NamedPipe\\wkssvc",
							L"Services\\PerfOS\\Performance\\Error Count",
							L"Software\\Microsoft\\Windows\\CurrentVersion\\Telephony\\HandoffPriorities"
						};
//-- remove rule with this extension in rulename:
LPWSTR ExceptExt[]=		{
							L".exe",
							L".dll"
						};


#endif // __exceptions_h__