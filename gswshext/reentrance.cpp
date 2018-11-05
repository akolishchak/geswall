//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "reentrance.h"

namespace ReEntrance {

DWORD TlsIndex = 0;

void Init(void)
{
	TlsIndex = TlsAlloc();
}

void Release(void)
{
	TlsFree(TlsIndex);
}

Check::Check()
{
	PVOID Data = TlsGetValue(TlsIndex);
	if ( Data == NULL ) {
		CheckResult = false;
		TlsSetValue(TlsIndex, this);
	} else {
		CheckResult = true;
	}
}

Check::~Check()
{
	if ( CheckResult == false ) TlsSetValue(TlsIndex, NULL);
}

bool Check::IsTrue(void)
{
	return CheckResult;
}

}; // namespace ReEntrance {
