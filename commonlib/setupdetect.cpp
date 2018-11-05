//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "setupdetect.h"
#include "commonlib.h"
#include "verinfo.h"


namespace commonlib {

namespace SetupDetect {

bool CheckAppInfo(const std::wstring &fname);
bool ParseStringTable(const std::wstring &fname);
bool ParseObjTable(const std::wstring &fname, const char* SectionName, const DWORD ScanLimit);

bool CheckSetupString2(const byte *Buf, const size_t BufSize);
bool CheckSetupString(const wchar_t *Str);

BOOL CALLBACK EnumNamesFunc(HMODULE hModule, LPCTSTR lpType, LPTSTR lpName, LONG lParam);

struct _SetupItem {
	wchar_t *Str;
	size_t Size;
};

_SetupItem SetupItems[]={
					{ L"some installation files are corrupt", 0 },
					{ L"error reading setup initialization file", 0 },
					{ L"setup cannot extract files necessary to install", 0 },
					{ L"the installation program appears to be damaged or corrupted", 0 },
					{ L"setup was unable to shutdown system", 0 },
					{ L"corrupt cabinet file", 0 },
					{ L"the installer you are trying to use is corrupted", 0 },
					{ L"hotfix package", 0}
};

_SetupItem SetupSmallItems[]={
					{ L"install", 0 },
					{ L"setup", 0 },
					{ L"hotfix package", 0},
					{ L"self-extractor", 0}
};


bool IsSetup(const std::wstring &fname)
{
	if ( SetupItems[0].Size == 0 ) {
		for ( size_t i = 0; i < sizeof SetupItems / sizeof SetupItems[0]; i++ ) SetupItems[i].Size = wcslen(SetupItems[i].Str);
		for ( size_t i = 0; i < sizeof SetupSmallItems / sizeof SetupSmallItems[0]; i++ ) SetupSmallItems[i].Size = wcslen(SetupSmallItems[i].Str);
	}

	//if ( fname.find(L":") == std::wstring::npos ) return false;

	try {
		//-------extract file name without *.exe extension
		std::wstring::size_type slash_index = slash_index = fname.find_last_of(L"\\", fname.size() - 1);
		if ( CheckSetupString(fname.substr(slash_index + 1, fname.size() - slash_index).c_str()) ) return true;

		return CheckAppInfo(fname) || /* ParseStringTable(fname) || */ ParseObjTable(fname,".data", 1024) || ParseObjTable(fname,".rdata",0);
	} catch ( ... ) {
		return false;
	}
}

bool CheckAppInfo(const std::wstring &fname)
{
	commonlib::VerInfo Version;
	Version.Init(fname.c_str());

	wchar_t *Value;
	Version.Get(L"Comments", &Value);
	if ( Value != NULL && CheckSetupString(Value) ) return true;

	Version.Get(L"FileDescription", &Value);
	if ( Value != NULL && CheckSetupString(Value) ) return true;

	Version.Get(L"InternalName", &Value);
	if ( Value != NULL && CheckSetupString(Value) ) return true;

	Version.Get(L"LegalCopyright", &Value);
	if ( Value != NULL && CheckSetupString(Value) ) return true;

	Version.Get(L"OriginalFilename", &Value);
	if ( Value != NULL && CheckSetupString(Value) ) return true;

	Version.Get(L"ProductName", &Value);
	if ( Value != NULL && CheckSetupString(Value) ) return true;

	Version.Get(L"Installer Version", &Value);
	if ( Value != NULL ) return true;

	return false;
}

bool FindSubString(const wchar_t *Buf, const size_t BufLen, const wchar_t *Str, const size_t StrLen)
{
	if ( BufLen < StrLen ) return false;
	size_t MaxOff = BufLen - StrLen;

	for ( size_t Off = 0; Off <= MaxOff; Off++ ) {
		if ( wcsnicmp(Buf + Off, Str, StrLen) == 0 ) return true;
	}

	return false;
}

bool CheckSetupString(const wchar_t *Str)
{
    for( size_t i = 0; i < sizeof(SetupSmallItems) / sizeof(SetupSmallItems[0]); i++) {
		if ( FindSubString(Str, wcslen(Str), SetupSmallItems[i].Str, SetupSmallItems[i].Size) ) return true;
	}

	return false;
}

bool CheckSetupString2(const byte* Buf, const size_t BufSize)
{
    for( size_t i = 0; i < sizeof(SetupItems) / sizeof(SetupItems[0]); i++) {
		if ( FindSubString((wchar_t *)Buf, BufSize / sizeof wchar_t, SetupItems[i].Str, SetupItems[i].Size) ) return true;
	}

	return false;
}

bool ParseStringTable(const std::wstring &fname)
{
	HMODULE hModule = LoadLibrary(fname.c_str());
	if ( hModule == NULL ) return false;
	
	bool installation_detected = false;
	EnumResourceNames(hModule, RT_STRING, (ENUMRESNAMEPROC)EnumNamesFunc, (LONG_PTR) &installation_detected);

	FreeLibrary(hModule);
	return installation_detected;
}

BOOL CALLBACK EnumNamesFunc(HMODULE hModule, LPCTSTR lpType, LPTSTR lpName, LONG_PTR lParam)
{
	wchar_t lpBuffer[255];
	ULONG_PTR hg = (ULONG_PTR)lpName;
	bool *installation_detected = (bool *) lParam;
	/*The Resource Name given by EnumNamesFunc is the blockID. The string ID in
	LoadString() is given by (block ID - 1) * 16 + the index of the string in
	that block.
	*/

	if (hg < 0x0000FFFF)
	{
		hg = (hg - 1) * 16;
		for (int i=0;i<=15;i++)
		{
			ZeroMemory(lpBuffer,sizeof(lpBuffer));
			int string_loaded=LoadString(hModule, (UINT)hg + i,lpBuffer,sizeof(lpBuffer)/sizeof(lpBuffer[0]));
			//MessageBox(NULL,lpBuffer,L"Str!!!",MB_OK);	
			if ( CheckSetupString2((byte *)lpBuffer, wcslen(lpBuffer)*sizeof wchar_t) ) 
			{
				*installation_detected = true;
				return FALSE;
			}
		}
	}

	return TRUE;
}
//--------------------------------------
bool ParseObjTable(const std::wstring &fname, const char* SectionName, const DWORD ScanLimit)
{
	HANDLE hFile = CreateFile(fname.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) return false;
	
	IMAGE_DOS_HEADER DosHeader;
	DWORD Size;
	BOOL rc = ReadFile(hFile, &DosHeader, sizeof DosHeader, &Size, NULL);
	if ( !rc || Size != sizeof DosHeader || DosHeader.e_magic != 0x5a4d ) {
		CloseHandle(hFile);
		return false;
	}

	if ( SetFilePointer(hFile, DosHeader.e_lfanew, NULL, FILE_BEGIN) != DosHeader.e_lfanew ) {
		CloseHandle(hFile);
		return false;
	}

	IMAGE_NT_HEADERS NTHeader;
	rc = ReadFile(hFile, &NTHeader, sizeof NTHeader, &Size, NULL);
	if ( !rc || Size != sizeof NTHeader || NTHeader.FileHeader.NumberOfSections > 100 ) {
		CloseHandle(hFile);
		return false;
	}

	Size = DosHeader.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NTHeader.FileHeader.SizeOfOptionalHeader;
	if ( SetFilePointer(hFile, Size, NULL, FILE_BEGIN) != Size ) {
		CloseHandle(hFile);
		return false;
	}

	PIMAGE_SECTION_HEADER Section = new IMAGE_SECTION_HEADER[NTHeader.FileHeader.NumberOfSections];
	rc = ReadFile(hFile, Section, NTHeader.FileHeader.NumberOfSections * sizeof IMAGE_SECTION_HEADER, &Size, NULL);
	if ( !rc || Size != NTHeader.FileHeader.NumberOfSections * sizeof IMAGE_SECTION_HEADER ) {
		delete[] Section;
		CloseHandle(hFile);
		return false;
	}

	bool Result = false;
	for ( WORD i = 0; i < NTHeader.FileHeader.NumberOfSections; i++ ) {
		Section[i].Name[sizeof Section[i].Name / sizeof Section[i].Name[0] - 1] = 0;
		if ( stricmp((char *)Section[i].Name, SectionName) == 0 ) {
			//
			// check if headers data is valid
			//
			if ( SetFilePointer(hFile, Section[i].PointerToRawData + Section[i].SizeOfRawData, NULL, FILE_BEGIN) != ( Section[i].PointerToRawData + Section[i].SizeOfRawData ) ) break;
			
			//
			// Read section data
			//
			if ( SetFilePointer(hFile, Section[i].PointerToRawData, NULL, FILE_BEGIN) != Section[i].PointerToRawData ) break;
			if ( ScanLimit != 0 ) Section[i].SizeOfRawData = min(ScanLimit, Section[i].SizeOfRawData); 
			byte *Buf = new byte[Section[i].SizeOfRawData];
			if ( Buf == NULL ) break;

			rc = ReadFile(hFile, Buf, Section[i].SizeOfRawData, &Size, NULL);
			if ( !rc || Size != Section[i].SizeOfRawData ) {
				delete[]  Buf;
				break;
			}

			Result = CheckSetupString2(Buf, Section[i].SizeOfRawData);
			delete[] Buf;
			break;
		}
	}

	delete[] Section;
	CloseHandle(hFile);

	return Result;
}

} // namespace SetupDetect {

} // namespace commonlib