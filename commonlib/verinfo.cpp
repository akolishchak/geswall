//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <windows.h>
#include <stdio.h>
#include "verinfo.h"
#include "commonlib.h"
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

namespace commonlib {

#pragma warning( push )
#pragma warning( disable : 4200 )
struct VerInfoItem { 
  WORD   wLength; 
  WORD   wValueLength; 
  WORD   wType; 
  WCHAR  szKey[]; 
};
#pragma warning( pop ) 

wchar_t *VerInfo::UndefinedStr = L"N/A";

VerInfo::VerInfo(void)
{
	Data = NULL;
	DataSize = 0;
	LangPrefix[0] = 0;
	Inited = false;
}

VerInfo::~VerInfo()
{
	Release();
}

bool VerInfo::Init(const wchar_t *FileName = NULL)
{
	if ( Inited ) Release();

	DWORD Handle;
	UINT Size = GetFileVersionInfoSize(FileName, &Handle);
	if ( Size == 0 ) return false;

	Data = new byte[Size];
	if ( Data == NULL ) return false;

	if ( !GetFileVersionInfo(FileName, Handle, Size, Data) ) Release();
	DataSize = Size;
	if ( !SetLangPrefix() ) Release();

	Inited = true;
	return true;
}

bool VerInfo::Init(const byte *_Data, const size_t Size)
{
	Data = new byte[Size];
	if ( Data == NULL ) return false;
	memcpy(Data, _Data, Size);
	DataSize = Size;

	if ( !SetLangPrefix() ) Release();

	Inited = true;
	return true;
}

void VerInfo::Release(void)
{
	if ( Data != NULL ) {
		delete[] Data;
		Data = NULL;
		DataSize = 0;
		LangPrefix[0] = 0;
	}

	Inited = false;
}

bool VerInfo::Get(const wchar_t *ValueName, wchar_t **Value)
{
	*Value = NULL;
	if ( Data == NULL ) return false;

	wchar_t SubBlock[1024];
	StringCchCopy(SubBlock, sizeof SubBlock / sizeof SubBlock[0], LangPrefix);
	StringCchCat(SubBlock, sizeof SubBlock / sizeof SubBlock[0], ValueName);

	UINT Size;
	if ( !VerQueryValue(Data, SubBlock, (LPVOID *)Value, &Size) ) return false;
	//
	// remove suffixes
	//
	static const wchar_t Mui[] = L".mui";
	static const size_t MuiSize = sizeof Mui / sizeof Mui[0];
	if ( *Value != NULL && Size > MuiSize && wcsicmp(*Value + Size - MuiSize, Mui) == 0 ) (*Value)[Size - MuiSize] = 0;

	return true;
}

bool VerInfo::GetStr(const wchar_t *ValueName, wchar_t **Value)
{
	bool bRes = Get(ValueName, Value);
	if ( *Value == NULL ) *Value = UndefinedStr;
	return bRes;
}

bool VerInfo::Load(const wchar_t *FileName)
{
	if ( Inited ) Release();

	if ( !commonlib::LoadBinaryFile(FileName, Data, DataSize) ) return false;
	if ( !SetLangPrefix() ) Release();

	Inited = true;

	return true;
}

bool VerInfo::Save(const wchar_t *FileName)
{
	if ( !Inited ) return false;

	return commonlib::SaveBinaryFile(FileName, Data, DataSize);
}

bool VerInfo::SetLangPrefix(void)
{
	UINT Size;
	Langs = NULL;
	if ( VerQueryValue(Data, L"\\VarFileInfo\\Translation", (LPVOID *)&Langs, &Size) && Langs != NULL ) {
		_snwprintf(LangPrefix, sizeof LangPrefix / sizeof LangPrefix[0], L"\\StringFileInfo\\%04x%04x\\", 
					Langs->language, Langs->codepage);
		LangPrefix[sizeof LangPrefix / sizeof LangPrefix[0] - 1] = 0;
	} else {
		LangPrefix[0] = 0;
	}

	PVOID Value;
	if ( Langs == NULL || !VerQueryValue(Data, LangPrefix, &Value, &Size) ) {
		//
		// there are no string tables with such lang specificator, use a first one
		//
		StringCchCopy(LangPrefix, sizeof LangPrefix / sizeof LangPrefix[0], L"\\StringFileInfo\\");
		if ( !VerQueryValue(Data, LangPrefix, &Value, &Size) ) return false;

		VerInfoItem *TableItem = (VerInfoItem *)Value;
		if ( TableItem->wLength == 0 )
			TableItem = (VerInfoItem *) ((PBYTE)Value + sizeof WORD);
		StringCchCat(LangPrefix, sizeof LangPrefix / sizeof LangPrefix[0], TableItem->szKey);
		StringCchCat(LangPrefix, sizeof LangPrefix / sizeof LangPrefix[0], L"\\");
	}

	return true;
}

}; // namespace commonlib
