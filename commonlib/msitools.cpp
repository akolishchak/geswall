//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "msitools.h"

namespace commonlib {

Msi::Msi(void)
{
	hMsi = NULL;
}

Msi::Msi(const MSIHANDLE _hMsi)
{
	Init(_hMsi);
}

Msi::~Msi()
{
}

bool Msi::Init(MSIHANDLE _hMsi)
{
	hMsi = _hMsi;
	return true;
}

bool Msi::OpenProduct(const wchar_t *Product)
{
	return true;
}

bool Msi::GetFilePath(const wchar_t *FileKey, std::wstring &FileName)
{
	PMSIHANDLE hRec = MsiCreateRecord(1);
	if ( !hRec ) return false;

	std::wstring Value = L"[#";
	Value += FileKey;
	Value += L"]";
	if ( ERROR_SUCCESS != MsiRecordSetString(hRec, 0, Value.c_str()) ) return false;

	// determine buffer size
	wchar_t FilePath[512];
	DWORD PathLength = sizeof FilePath / sizeof FilePath[0];
	if ( ERROR_SUCCESS != MsiFormatRecord(hMsi, hRec, FilePath, &PathLength) ) return false;

	FileName = FilePath;
	return true;
}

bool Msi::GetProperty(const wchar_t *PropertyName, std::wstring &Value)
{
	DWORD Size = 0;
	UINT rc = MsiGetProperty(hMsi, PropertyName, L"", &Size);
	if ( rc != ERROR_MORE_DATA ) return false;

	Size++;
	wchar_t *Buf = new wchar_t[Size];
	rc = MsiGetProperty(hMsi, PropertyName, Buf, &Size);
	if ( rc != ERROR_SUCCESS ) return false;

	Value = Buf;
	delete Buf;
	return true;
}

}; // namespace stdlib