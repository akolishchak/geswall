//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __msitools_h__
#define __msitools_h__

#include <windows.h>
#include <msiquery.h>
#include <string>

namespace commonlib {

class Msi {

public:
	Msi(void);
	Msi(MSIHANDLE _hMsi);
	~Msi();

	bool Init(MSIHANDLE _hMsi);
	bool OpenProduct(const wchar_t *Product);
	bool GetFilePath(const wchar_t *FileKey, std::wstring &FileName);
	bool GetProperty(const wchar_t *PropertyName, std::wstring &Value);

private:
	MSIHANDLE hMsi;
};

}; // namespace commonlib


#endif // __msitools_h__
