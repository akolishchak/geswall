//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include <lm.h>
#include "ruleutils.h"

bool GetOwnerSid(wchar_t *Str, PUCHAR &Buffer, DWORD &BufSize)
{
    Buffer = NULL;
    BufSize = 0;
    DWORD dwLevel = 1;
    LPWKSTA_USER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus;

    nStatus = NetWkstaUserGetInfo(NULL, dwLevel, (LPBYTE *) &pBuf);
    if (nStatus != NERR_Success)
        return false;

    char sid[80];
    WCHAR DomainName[100];
    DWORD DomainSize = sizeof DomainName;
    DWORD SidSize = sizeof sid;
    SID_NAME_USE sid_use; 

    if (!LookupAccountName(pBuf->wkui1_logon_server, Str, sid, &SidSize,
        DomainName, &DomainSize, &sid_use)) {
        printf("LookupAccountName error: %d\n", GetLastError());
        NetApiBufferFree(pBuf);
        return false;
    }

    NetApiBufferFree(pBuf);
    BufSize = GetLengthSid((PSID)sid);
    Buffer = new UCHAR[BufSize];
    memcpy(Buffer, sid, BufSize);
    return true;
}
/*bool GetOwnerName(LPTSTR Str, PBYTE sid)
{
    DWORD dwLevel = 1;
    LPWKSTA_USER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus;

    nStatus = NetWkstaUserGetInfo(NULL, dwLevel, (LPBYTE *) &pBuf);
    if (nStatus != NERR_Success)
        return false;

    
    WCHAR DomainName[100];
    DWORD DomainSize = sizeof DomainName;
    DWORD StrSize = 128;
	WCHAR Str2[128];
DWORD err=0;
    SID_NAME_USE sid_use; 

    if (!LookupAccountSid(pBuf->wkui1_logon_server,(PSID) sid, Str2, &StrSize,
        DomainName, &DomainSize, &sid_use)) {
        printf("LookupAccountName error: %d\n", err = GetLastError());
        NetApiBufferFree(pBuf);
        return false;
    }

    NetApiBufferFree(pBuf);
   
    return true;
}*/
bool GetOwnerName(const PSID Sid, std::wstring &Str)
{
    DWORD dwLevel = 1;
    LPWKSTA_USER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus;

    nStatus = NetWkstaUserGetInfo(NULL, dwLevel, (LPBYTE *) &pBuf);
    if (nStatus != NERR_Success)
        return false;

    WCHAR DomainName[100];
	DWORD err;
    DWORD DomainSize = sizeof DomainName;
    WCHAR UserName[100];
    DWORD NameSize = sizeof UserName / sizeof UserName[0];
    SID_NAME_USE sid_use;

    if (!LookupAccountSid(pBuf->wkui1_logon_server, Sid, UserName, &NameSize,
        DomainName, &DomainSize, &sid_use)) {
		printf("LookupAccountName error: %d\n", err = GetLastError());
        NetApiBufferFree(pBuf);
        return false;
    }

    NetApiBufferFree(pBuf);

	Str = DomainName;
	Str += L"\\";
	Str += UserName;
    return true;
}
