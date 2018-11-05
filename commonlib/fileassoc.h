//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __fileassoc_h__
#define __fileassoc_h__
#include <string>

namespace FileAssoc {

std::wstring GetFileExtension(std::wstring szfile);
bool IsFileAssociated(wchar_t *FileName, wchar_t *AppName);	
std::wstring GetFileFromExtension(const wchar_t *ExtName,const wchar_t *lpVerb);
std::wstring ExtendedSearch(const wchar_t *ExtName,const wchar_t *lpVerb);

}; // namespace FileAssoc 


#endif // __fileassoc_h__