//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "aci.h"
#include "acidef.h"

using namespace Aci;

bool CAci::GetAttr(HANDLE hObject, EntityAttributes &Attr, const ULONG Label)
{
	memset(&Attr, 0, sizeof Attr);

	BOOL rc;
	char Buf[1024];
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) Buf;
	DWORD Length = sizeof Buf;
	rc = GetKernelObjectSecurity(hObject, SACL_SECURITY_INFORMATION, sd, Length, &Length);
    if ( ! rc ) {
		Length = GetLastError();
        return false;
    }

	BOOL Present;
	BOOL Default;
	PACL Acl = NULL;
	rc = GetSecurityDescriptorSacl(sd, &Present, &Acl, &Default);
    if ( ! rc || !Present || Acl == NULL) {
        return false;
    }

	SYSTEM_AUDIT_ACE *Ace = (SYSTEM_AUDIT_ACE *) ((PUCHAR) Acl + sizeof(ACL));
	for (ULONG i=0;i < Acl->AceCount; i++) {

        Sid *InfoSid = (Sid *)&Ace->SidStart;
		if ( !memcmp(InfoSid, &BasicSid, FIELD_OFFSET(Sid, SubAuthority[1])) && 
		     InfoSid->SubAuthority[1] == Label ) {

			memcpy(Attr.Param, &InfoSid->SubAuthority[2], sizeof Attr.Param);
            return true;
		}

		Ace = (SYSTEM_AUDIT_ACE *)((PCHAR)Ace + Ace->Header.AceSize);
    }

	return false;
}

bool CAci::SetAttr(HANDLE hObject, EntityAttributes Attr, const ULONG Label)
{
    BOOLEAN bAllocateAcl = FALSE;
    PACL NewAcl = NULL;

	BOOL rc;
	char Buf[1024];
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) Buf;
	DWORD Length = sizeof Buf;
	rc = GetKernelObjectSecurity(hObject, SACL_SECURITY_INFORMATION, sd, Length, &Length);
    if ( ! rc ) {
        return false;
    }

	DWORD Size;
	BOOL Present;
	BOOL Default;
	PACL Acl = NULL;
	rc = GetSecurityDescriptorSacl(sd, &Present, &Acl, &Default);
    if ( ! rc || !Present || Acl == NULL) {
        //
        // There are no Sacl, create it
        //
        Size = sizeof ACL;
        Acl = (PACL) new UCHAR[Size];
        bAllocateAcl = TRUE;

        rc = InitializeAcl(Acl, Size, ACL_REVISION);
        if ( !rc ) {
			delete[] Acl;
			return false;
        }
    }

    //
    // Check if our sid already exist
    //
    BOOLEAN bSidPresent = FALSE;
	SYSTEM_AUDIT_ACE *Ace = (SYSTEM_AUDIT_ACE *) ((PUCHAR) Acl + sizeof(ACL));
	for (ULONG i=0;i < Acl->AceCount; i++) {

        Sid *InfoSid = (Sid *)&Ace->SidStart;
		if ( !memcmp(InfoSid, &BasicSid, FIELD_OFFSET(Sid, SubAuthority[1])) && 
			 InfoSid->SubAuthority[1] == Label ) {

            bSidPresent = TRUE;
            break;
		}
		Ace = (SYSTEM_AUDIT_ACE *)((PCHAR)Ace + Ace->Header.AceSize);
    }

    if ( bSidPresent )
        Size = Acl->AclSize;
    else
        Size = Acl->AclSize + sizeof SYSTEM_AUDIT_ACE - sizeof ULONG + sizeof BasicSid;

    NewAcl = (PACL) new CHAR[Size];

    RtlCopyMemory(NewAcl, Acl, Acl->AclSize);
    Ace = (SYSTEM_AUDIT_ACE *) ((PUCHAR)NewAcl + ( (PUCHAR)Ace - (PUCHAR)Acl ) ); 

    if ( !bSidPresent ) {
        //
        // We have to add our sid
        //
        Ace->Header.AceType = SYSTEM_AUDIT_ACE_TYPE;
        Ace->Header.AceFlags = FAILED_ACCESS_ACE_FLAG;
        Ace->Header.AceSize = sizeof SYSTEM_AUDIT_ACE - sizeof ULONG + sizeof BasicSid;
        Ace->Mask = GENERIC_ALL;
        RtlCopyMemory(&Ace->SidStart, &BasicSid, sizeof BasicSid);
        ((Sid *)&Ace->SidStart)->SubAuthority[1] = Label;
        NewAcl->AclSize = (WORD)Size;
        NewAcl->AceCount++;
    }

	memcpy(&((Sid *)&Ace->SidStart)->SubAuthority[2], Attr.Param, sizeof Attr.Param);

    SECURITY_DESCRIPTOR NewSd;
    rc = InitializeSecurityDescriptor(&NewSd, SECURITY_DESCRIPTOR_REVISION);
    if ( !rc ) {
		if ( bAllocateAcl ) delete[] Acl;
		delete[] NewAcl;
		return false;
    }

    rc = SetSecurityDescriptorSacl(&NewSd, TRUE, NewAcl, FALSE);
    if ( !rc ) {
		if ( bAllocateAcl ) delete[] Acl;
		delete[] NewAcl;
		return false;
    }

    rc = SetKernelObjectSecurity(hObject, SACL_SECURITY_INFORMATION, &NewSd);
	if ( bAllocateAcl ) delete[] Acl;
	delete[] NewAcl;
    if ( !rc ) {
		return false;
    }

	return true;
}

bool CAci::RemoveAttr(HANDLE hObject, EntityAttributes Attr, const ULONG Label)
{
    BOOLEAN bAllocateAcl = FALSE;
    PACL NewAcl = NULL;

	BOOL rc;
	char Buf[1024];
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) Buf;
	DWORD Length = sizeof Buf;
	rc = GetKernelObjectSecurity(hObject, SACL_SECURITY_INFORMATION, sd, Length, &Length);
    if ( ! rc ) {
        return false;
    }

	BOOL Present;
	BOOL Default;
	PACL Acl = NULL;
	rc = GetSecurityDescriptorSacl(sd, &Present, &Acl, &Default);
    if ( ! rc || !Present || Acl == NULL) {
        //
        // There are no Sacl, fine!
        //
		return true;
    }

    //
    // Check if our sid already exist
    //
    BOOLEAN bSidPresent = FALSE;
	SYSTEM_AUDIT_ACE *Ace = (SYSTEM_AUDIT_ACE *) ((PUCHAR) Acl + sizeof(ACL));
	for (ULONG i=0; i < Acl->AceCount; i++) {

        Sid *InfoSid = (Sid *)&Ace->SidStart;
		if ( !memcmp(InfoSid, &BasicSid, FIELD_OFFSET(Sid, SubAuthority[1])) && 
			 InfoSid->SubAuthority[1] == Label ) {

            bSidPresent = TRUE;
			WORD RemovedSize = Ace->Header.AceSize;
			RtlCopyMemory(Ace, (PCHAR)Ace + Ace->Header.AceSize,
						  Acl->AclSize - ((PCHAR)Ace - (PCHAR)Acl) - RemovedSize);
			Acl->AclSize -= RemovedSize;
			Acl->AceCount--;
            break;
		}
		Ace = (SYSTEM_AUDIT_ACE *)((PCHAR)Ace + Ace->Header.AceSize);
    }

    if ( !bSidPresent )
		return false;

	if ( Acl->AceCount == NULL ) {
		Present = FALSE;
		Acl = NULL;
	} else 
		Present = TRUE;

    SECURITY_DESCRIPTOR NewSd;
    rc = InitializeSecurityDescriptor(&NewSd, SECURITY_DESCRIPTOR_REVISION);
    if ( !rc ) {
		return false;
    }

    rc = SetSecurityDescriptorSacl(&NewSd, Present, Acl, FALSE);
    if ( !rc ) {
		return false;
    }

    rc = SetKernelObjectSecurity(hObject, SACL_SECURITY_INFORMATION, &NewSd);
    if ( !rc ) {
		return false;
    }

	return true;
}

bool CAci::GetOwner(HANDLE hObject, PSID SidBuf, DWORD BufLength)
{
	BOOL rc;
	char Buf[1024];
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) Buf;
	DWORD Length = sizeof Buf;
	rc = GetKernelObjectSecurity(hObject, OWNER_SECURITY_INFORMATION, sd, Length, &Length);
    if ( ! rc ) {
        return false;
    }
	PSID Owner;
	BOOL Defaulted;
	rc = GetSecurityDescriptorOwner(sd, &Owner, &Defaulted);
	if ( ! rc ) return false;

	Length = GetLengthSid(Owner);
	if ( Length > BufLength )
		return false;

	memcpy(SidBuf, Owner, Length);

	return true;
}

bool CAci::SetOwner(HANDLE hObject, PSID Owner)
{
	BOOL rc;
	char Buf[1024];
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) Buf;
	DWORD Length = sizeof Buf;
	rc = GetKernelObjectSecurity(hObject, OWNER_SECURITY_INFORMATION, sd, Length, &Length);
    if ( ! rc ) {
        return false;
    }

	rc = SetSecurityDescriptorOwner(sd, Owner, FALSE);
	if ( ! rc ) return false;

	return true;
}

bool CAci::CheckOwner(HANDLE hObject, PSID UserSid)
{
	BOOL rc;
	char Buf[1024];
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) Buf;
	DWORD Length = sizeof Buf;
	rc = GetKernelObjectSecurity(hObject, OWNER_SECURITY_INFORMATION, sd, Length, &Length);
    if ( ! rc ) {
        return false;
    }
	PSID Owner;
	BOOL Defaulted;
	rc = GetSecurityDescriptorOwner(sd, &Owner, &Defaulted);
	if ( ! rc || Owner == NULL ) return false;

	return EqualSid(Owner, UserSid) == TRUE;
}

CAci::CAci(void)
{
	BOOL rc;
    HANDLE hToken;
    rc = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    if ( ! rc ) {
		printf("Can not open process token (%d)\n", GetLastError());
        return;
    }

    TOKEN_PRIVILEGES Priv;
    Priv.PrivilegeCount = 1;
    Priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    rc = LookupPrivilegeValue(NULL, SE_SECURITY_NAME, &Priv.Privileges[0].Luid);
    if ( ! rc ) {
		CloseHandle(hToken);
		printf("Can not find privilege (%d)\n", GetLastError());
        return;
    }

	DWORD Length;
    rc = AdjustTokenPrivileges(hToken, FALSE, &Priv, sizeof PrevPrivileges, 
							  (PTOKEN_PRIVILEGES)PrevPrivileges, &Length);
	CloseHandle(hToken);
    if ( ! rc ) {
		printf("Can not adjust privileges (%d)\n", GetLastError());
        return;
    }

    HKEY hKey;
    DWORD Disposition;
    //
    // Get resision
    //
    rc = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                        L"SYSTEM\\CurrentControlSet\\Services\\geswall\\Parameters",
                        0,
                        NULL,
                        REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS,
                        NULL,
                        &hKey,
                        &Disposition);

    if (rc == ERROR_SUCCESS) {

        DWORD Size = sizeof SidRevision;
        rc = RegQueryValueEx(hKey, L"SidRevision", NULL, NULL, (PUCHAR) &SidRevision, &Size);
        if (rc != ERROR_SUCCESS)
	        SidRevision = 1;
	}

	BasicSid.SubAuthority[0] = SidRevision;
}

CAci::~CAci()
{
    HANDLE hToken;
	BOOL rc;
    rc = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    if ( ! rc ) {
		printf("Can not open process token (%d)\n", GetLastError());
        return;
    }

    rc = AdjustTokenPrivileges(hToken, FALSE, (PTOKEN_PRIVILEGES)PrevPrivileges, 0, NULL, NULL);
	CloseHandle(hToken);
    if ( ! rc ) {
		printf("Can not restore privileges (%d)\n", GetLastError());
        return;
    }
}
