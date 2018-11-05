//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include "homepage.h"
#include "config/configurator.h"



// {36EF9F80-1597-46af-A77A-4123145CB020}
const GUID CHomePage::thisGuid = 
{ 0x36ef9f80, 0x1597, 0x46af, { 0xa7, 0x7a, 0x41, 0x23, 0x14, 0x5c, 0xb0, 0x20 } };


LPOLESTR CreateWWWPath
( 
   LPOLESTR szResource      //[in] Path to stored resource
) 
{ 
   _TCHAR szBuffer[MAX_PATH];
            
   ZeroMemory(szBuffer, sizeof(szBuffer));
	
   MAKE_TSTRPTR_FROMWIDE(szname, szResource);
   _tcscpy(szBuffer, szname);
            
   MAKE_WIDEPTR_FROMTSTR(wszname, szBuffer);
   LPOLESTR szOutBuffer = static_cast<LPOLESTR>(CoTaskMemAlloc((wcslen(wszname) + 1)  * sizeof(WCHAR)));

   wcscpy(szOutBuffer, wszname);
            
   return szOutBuffer;

} //end CreateResoucePath()


static LPOLESTR OleDuplicateString(LPOLESTR lpStr) {
    LPOLESTR tmp = static_cast<LPOLESTR>(CoTaskMemAlloc((wcslen(lpStr) + 1)  * sizeof(WCHAR)));
    wcscpy(tmp, lpStr);

    return tmp;
}

//==============================================================
//
//  implementation
//
//
CHomePage::CHomePage()
{
	config::Configurator::PtrToINode Node = config::Configurator::getDriverNode();
	InstallDir = Node->getString(L"InstallDir");
}

CHomePage::~CHomePage()
{
}


HRESULT CHomePage::GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions)
{
	std::wstring StartPage = InstallDir;
	StartPage += L"\\usermanual\\usermanual.html";
	MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, StartPage.c_str());

	*ppViewType = CreateWWWPath(pszW );

    *pViewOptions = MMC_VIEW_OPTIONS_NONE;
    return S_OK; 
}
