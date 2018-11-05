//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __verinfo_h__
#define __verinfo_h__

namespace commonlib {


class VerInfo {
public:
	VerInfo(void);
	~VerInfo();
	bool Init(const wchar_t *FileName);
	bool Init(const byte *_Data, const size_t Size);
	void Release(void);
	bool Get(const wchar_t *ValueName, wchar_t **Value);
	bool GetStr(const wchar_t *ValueName, wchar_t **Value);
	DWORD GetLang(void) 
	{ 
		if ( !Inited || Langs == NULL ) return 0;
		return MAKELONG(Langs->language, Langs->codepage); 
	}
	bool IsValid(void) { return Inited; }
	bool Load(const wchar_t *FileName);
	bool Save(const wchar_t *FileName);

	static wchar_t *UndefinedStr;

private:
	byte *Data;
	size_t DataSize;
	bool Inited;

	struct LANGANDCODEPAGE {        
		WORD language;        
		WORD codepage;    
	} *Langs;
	wchar_t LangPrefix[50];

	bool SetLangPrefix(void);
};

}; // namespace commonlib


#endif // __verinfo_h__
