//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __aci_h__
#define __aci_h__

class CAci {

public:
	CAci(void);
	~CAci();

	bool GetAttr(HANDLE hObject, EntityAttributes &Attr, const ULONG Label);
	bool SetAttr(HANDLE hObject, EntityAttributes Attr, const ULONG Label);
	bool RemoveAttr(HANDLE hObject, EntityAttributes Attr, const ULONG Label);
	bool GetOwner(HANDLE hObject, PSID SidBuf, DWORD BufLength);
	bool SetOwner(HANDLE hObject, PSID Owner);
	bool CheckOwner(HANDLE hObject, PSID UserSid);
private:
	char PrevPrivileges[1024];
	ULONG SidRevision;
};



#endif // __aci_h__