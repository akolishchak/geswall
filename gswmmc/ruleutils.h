//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"

bool GetOwnerName(const PSID Sid, std::wstring &Str);
bool GetOwnerSid(wchar_t *Str, PUCHAR &Buffer, DWORD &BufSize);