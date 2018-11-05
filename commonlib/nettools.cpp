//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "nettools.h"

namespace commonlib {
namespace nettools {

bool GetSidByName(const wchar_t *Name, PtrToByte &Sid, size_t &SidSize)
{
	SidSize = 0;

	static const wchar_t SidStringStart[] = L"S-";
	if ( !wcsncmp(Name, SidStringStart, sizeof SidStringStart / sizeof SidStringStart[0] - 1) ) {
		::PSID SidBuf = NULL;
		if ( ConvertStringSidToSid(Name, &SidBuf) ) {
 			SidSize = GetLengthSid((PSID)SidBuf);
			Sid.reset(new byte[SidSize]);
			memcpy(Sid.get(), SidBuf, SidSize);
			LocalFree(SidBuf);
			return true;
		}
	}

	DWORD dwLevel = 1;
	LPWKSTA_USER_INFO_1 pBuf = NULL;
	NET_API_STATUS nStatus;

	nStatus = NetWkstaUserGetInfo(NULL, dwLevel, (LPBYTE *) &pBuf);
	if (nStatus != NERR_Success) return false;

	char SidBuf[80];
	WCHAR DomainName[100];
	DWORD DomainSize = sizeof DomainName;
	DWORD Size = sizeof SidBuf;
	SID_NAME_USE sid_use;

	if (!LookupAccountName(pBuf->wkui1_logon_server, Name, SidBuf, &Size,
		DomainName, &DomainSize, &sid_use)) {
		NetApiBufferFree(pBuf);
		return false;
	}

	NetApiBufferFree(pBuf);
	SidSize = GetLengthSid((PSID)SidBuf);
	Sid.reset(new byte[SidSize]);
	memcpy(Sid.get(), SidBuf, SidSize);
	return true;
}

bool GetStringSidByName(const wchar_t *Name, std::wstring &StringSid)
{
	PtrToByte Sid;
	size_t Size;
	if ( !GetSidByName(Name, Sid, Size) ) return false;

	wchar_t *wcStringSid = NULL;
    bool Result = ConvertSidToStringSid((PSID)Sid.get(), &wcStringSid) == TRUE;
	if ( Result ) StringSid = wcStringSid;
	LocalFree(wcStringSid);
	return Result;
}

bool GetNameBySid(const byte *Sid, std::wstring &Name)
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

    if (!LookupAccountSid(pBuf->wkui1_logon_server, (PSID)Sid, UserName, &NameSize,
        DomainName, &DomainSize, &sid_use)) {
		printf("LookupAccountName error: %d\n", err = GetLastError());
        NetApiBufferFree(pBuf);
        return false;
    }

    NetApiBufferFree(pBuf);

	Name = DomainName;
	Name += L"\\";
	Name += UserName;
    return true;
}

bool GetNameByStringSid(const wchar_t *StringSid, std::wstring &Name)
{
	byte *Sid = NULL;
	if ( !ConvertStringSidToSid(StringSid, (PSID *)&Sid) ) return false;
	
	bool Result = GetNameBySid(Sid, Name);
	LocalFree(Sid);
	return Result;
}

} //namespace nettools {
} //namespace stdlib {
