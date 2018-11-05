//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdafx.h>
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
#include "lcount.h"
#include "config/configurator.h"
#include "logcount.h"
#include "license/licensemanager.h"
#include "db/storage.h"

// {B2598F87-0A91-451c-9B62-41EB0FA739CF}
const GUID CLcount::thisGuid = 
{ 0xb2598f87, 0xa91, 0x451c, { 0x9b, 0x62, 0x41, 0xeb, 0xf, 0xa7, 0x39, 0xcf } };




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
CLcount::CLcount()
{
	config::Configurator::PtrToINode Node = config::Configurator::getDriverNode();
	InstallDir = Node->getString(L"InstallDir");
}

CLcount::~CLcount()
{
}

LPOLESTR CLcount::CreateWWWPath( 
   LPOLESTR szResource)      //[in] Path to stored resource
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

HRESULT CLcount::GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions)
{
	std::wstring SummaryPage; 
	const dwBufSize=4096;
	wchar_t  lpPathBuffer[dwBufSize];
//------------
     // Get the temp path.
     DWORD dwRetVal = GetTempPath(dwBufSize,     // length of the buffer
                            lpPathBuffer); // buffer for path 
     if (dwRetVal > dwBufSize)
     {
         printf ("GetTempPath failed with error %d.\n", 
                 GetLastError());
         return (2);
     }
//------------
	lstrcat(lpPathBuffer,L"gswsmr.tmp");
    SummaryPage=lpPathBuffer;
	CreateHtml(SummaryPage);
	MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, SummaryPage.c_str());
	*ppViewType = CreateWWWPath(pszW );
    *pViewOptions = MMC_VIEW_OPTIONS_NONE;
    return S_OK; 
}




void CLcount::CreateHtml(std::wstring SummaryPage)
{	using namespace std;
    gswui::logcount::IntLog today,lastweek,lastmonth,total;
	wstring tab = L"";
	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCopy(License);
	int AppsNumber = 0;
	wchar_t AppsNumberString[20];
	try {
		AppsNumber = Storage::GetAppsNumber();
	} catch ( ... ) {}

	if ( AppsNumber > 0 ) {
		_itow (AppsNumber, AppsNumberString, 10);
	} else {
		StringCchCopy(AppsNumberString, sizeof AppsNumberString / sizeof AppsNumberString[0], L"undefined");
	}
/*
//------------Convert Summary Page------------
	int ilen= WideCharToMultiByte(CP_ACP, 0, SummaryPage.c_str(), -1, NULL, 0, NULL, NULL);	
	char *fname = new char[ilen+1];
	ZeroMemory(fname, sizeof(fname));
	WideCharToMultiByte(CP_ACP, 0,SummaryPage.c_str(), ilen, fname, ilen+1, NULL, NULL);

//------------Convert InstallDir--------------
	ilen= WideCharToMultiByte(CP_ACP, 0, InstallDir.c_str(), -1, NULL, 0, NULL, NULL);	
	char *instdir = new char[ilen+1];
	ZeroMemory(instdir, sizeof(instdir));
	WideCharToMultiByte(CP_ACP, 0,InstallDir.c_str(), ilen, instdir, ilen+1, NULL, NULL);
//--------------------------------------------
*/
//=====colorlines for counters=========
 wstring attack_s   =tab+L"<img src=\""+ InstallDir +L"\\Pix\\redline.gif\">&nbsp;";
 wstring notifics_s =tab+L"<img src=\""+ InstallDir +L"\\Pix\\yellowline.gif\">&nbsp;";
 wstring isolated_s= tab+L"<img src=\""+ InstallDir +L"\\Pix\\greenline.gif\">&nbsp;";
//-----------------------------
  wstring header= L"<td valign=\"top\" width=\"200\" nowrap> \n"
	             //"<ul class=\"blue\">\n"
				 L"<li><b>Attacks Prevented:</b></li>\n"
				 L"<li><b>Operations Restricted:</b></li>\n"
				 L"<li><b>Applications Isolated:</b></li>\n"
				 //"<ul>\n"
				 L"</td>\n";
//------------------------------

	today    =gswui::logcount::CalculateLogs(0);
	lastweek =gswui::logcount::CalculateLogs(7);
	lastmonth=gswui::logcount::CalculateLogs(30);
	total    =gswui::logcount::CalculateLogs(-1);
	
	std::wstring Buffer;
//#####################-Begin HTML-#######################

//-------------html upper header--------------------------
//statfile<<L""
Buffer =

L"<html>"
L"<head>"
L"<title>GeSWall_Summary</title>"
L"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">"
L"</head>"

L"<body bgcolor=\"#FFFFFF\" text=\"#000000\">"
L"<link href=\""+ InstallDir +L"\\usermanual\\main.css\" rel=\"stylesheet\" type=\"text/css\">\n"
//--------------------------------------------------------
L"<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"500\"><tr>"
L"<td valign=\"top\" nowrap>"
L"<font color=\"#336699\">"
L"<h2>GeSWall Summary</h2>\n"
L"</font>"
+L"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color=\"#336699\"><b>"+License.ProductString+L"</b></font><br>"
+L"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"+License.Features+L"<br>"
+L"<table><tr><td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color=\"#336699\"><b>Licensed to:</b></font></td><td>"+License.LicensedTo+L"</td></tr>"
L"<tr><td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color=\"#336699\"><b>Expires:</b></font></td><td>"+License.Expired+L"</td></tr></table>"
L"<table><tr><td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color=\"#336699\"><b>Safe Applications in database:</b></font></td><td>"+AppsNumberString+L"</td></tr>"
L"</table>"
L"</td><td align=\"right\">"
L"<img src=\"" + InstallDir + L"\\Pix\\logo_summary.png\" width=\"153\" height=\"146\" alt=\"\" border=\"0\" vspace=\"8\">"
L"</td>"
L"</tr></table>"
//L"<table width=\"510\">"
L"<div class=\"border\">\n"
 L"<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\" width=\"500\">\n"
    L"<tr class=\"row1\"> \n"
      
L"<td height=\"88\" width=\"100\" valign=\"top\" nowrap>\n"
L"  <font color=\"#336699\"><b>Today</b></font></td>"

+header+L""
			L"<td valign=\"top\" nowrap>"
			+attack_s
			+gswui::logcount::ConvertLongNumber(today.attacks)+L"<br>\n"
			+notifics_s
			+gswui::logcount::ConvertLongNumber(today.notify)+L"<br>\n"
			+isolated_s
			+gswui::logcount::ConvertLongNumber(today.isolated)+L"<br>\n"
			L"</tr>\n"

L"<tr class=\"row2\">\n"
L"<td height=\"88\" valign=\"top\" nowrap><font color=\"#336699\"><b>Last week</b></font></td>\n"


+header+L""
			L"<td valign=\"top\" nowrap>\n"
			+attack_s
			+gswui::logcount::ConvertLongNumber(lastweek.attacks)+L"<br>\n"
			+notifics_s
			+gswui::logcount::ConvertLongNumber(lastweek.notify)+L"<br>\n"
			+isolated_s
			+gswui::logcount::ConvertLongNumber(lastweek.isolated)+L"<br>\n"
			L"</tr>\n"

L"<tr class=\"row1\">\n "
L"<td height=\"88\" valign=\"top\" nowrap><font color=\"#336699\"><b>Last month</b></font></td>\n"

+header+L""

			L"<td valign=\"top\" nowrap>\n"
			+attack_s
			+gswui::logcount::ConvertLongNumber(lastmonth.attacks)+L"<br>\n"
			+notifics_s
			+gswui::logcount::ConvertLongNumber(lastmonth.notify)+L"<br>\n"
			+isolated_s
			+gswui::logcount::ConvertLongNumber(lastmonth.isolated)+L"<br>\n"
			L"</tr>\n"

L"<tr class=\"row2\"> \n"
L"<td height=\"88\" valign=\"top\" nowrap><font color=\"#336699\"><b>Total</b></font></td>\n"

+header+L""
			L"<td valign=\"top\" nowrap>\n"
			+attack_s
			+gswui::logcount::ConvertLongNumber(total.attacks)+L"<br>\n"
			+notifics_s
			+gswui::logcount::ConvertLongNumber(total.notify)+L"<br>\n"
			+isolated_s
			+gswui::logcount::ConvertLongNumber(total.isolated)+L"<br>\n"
			L"</tr>\n"

L"</table>\n"
L"</div>\n"
//L"</table>"

L"</body>"
L"</html>";

//#####################-End HTML-#######################
	HANDLE hFile = CreateFile(SummaryPage.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
	if ( hFile != INVALID_HANDLE_VALUE ) {
		int Len= WideCharToMultiByte(CP_ACP, 0, Buffer.c_str(), -1, NULL, 0, NULL, NULL);	
		char *Buf = new char[Len+1];
		WideCharToMultiByte(CP_ACP, 0,Buffer.c_str(), Len, Buf, Len+1, NULL, NULL);
		DWORD Written;
		::WriteFile(hFile, Buf, Len, &Written, NULL);
		delete[] Buf;
		CloseHandle(hFile);
	}

}