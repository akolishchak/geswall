//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include <commctrl.h>
#include <stdlib.h>
#include "log.h"
#include "resource.h"
#include "Comp.h"
#include "CompData.h"
#include "DataObj.h"
#include "config/configurator.h"
#include "commonlib.h"


// {57002918-514B-478a-897B-3AF807CA8363}
const GUID CLog::thisGuid  = 
{ 0x57002918, 0x514b, 0x478a, { 0x89, 0x7b, 0x3a, 0xf8, 0x7, 0xca, 0x83, 0x63 } };

bool CLog::ActiveDialog = false;

LPOLESTR CreateFilePath
( 
  LPOLESTR szResource      //[in] Path to stored resource
) 
{ 
   _TCHAR szBuffer[MAX_PATH];
            
   ZeroMemory(szBuffer, sizeof(szBuffer));
            
   _tcscpy(szBuffer, _T("file://"));
            
   _TCHAR *szTemp = szBuffer + _tcslen(szBuffer);
   //GetModuleFileName(hInst, szTemp, (DWORD)sizeof(szBuffer) - _tcslen(szBuffer));
   //_tcscat(szBuffer, _T("c:\\!\\"));        
   //_tcscat(szBuffer, _T("/"));
   MAKE_TSTRPTR_FROMWIDE(szname, szResource);
   _tcscat(szBuffer, szname);
            
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
CLog::CLog()
{		
	SYSTEMTIME st;
	GetLocalTime(&st);
	SysTimeFrom = SysTimeTo = st;
}

CLog::~CLog()
{
}


HRESULT CLog::GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions)
{
	config::Configurator::PtrToINode Node = Configurator::getGswlPolicyNode();
	std::wstring LogPath = Node->getString(L"AccessLogDir");
	if ( LogPath.size() == 0 ) {
		wchar_t Buf[MAX_PATH];
		// GetEnvironmentVariable
		if ( GetEnvironmentVariable(L"SystemRoot", Buf, sizeof Buf / sizeof Buf[0]) ) {
			LogPath = Buf;
			LogPath += L"\\geswall\\logs\\";
		}
	} else {
		if ( LogPath.find(L"\\??\\") == 0 ) LogPath.erase(0, lenghtOf(L"\\??\\") - 1);
		LogPath += L"\\";
	}
	
	std::wstring taskpad = LogPath;
	wchar_t Str[50];		
	if(SysTimeFrom.wYear == SysTimeTo.wYear && SysTimeFrom.wMonth == SysTimeTo.wMonth && SysTimeFrom.wDay == SysTimeTo.wDay )
	{
	 if(GetDateFormat(LOCALE_SYSTEM_DEFAULT, NULL, &SysTimeFrom, L"yyyyMMdd", Str, sizeof Str / sizeof Str[0]))
	 {	taskpad += Str;
		taskpad += L".txt";
	 }

	 if ( GetFileAttributes(taskpad.c_str()) == INVALID_FILE_ATTRIBUTES )
	 {
		 config::Configurator::PtrToINode Node = Configurator::getDriverNode();
		 taskpad = Node->getString(L"InstallDir");
		 taskpad += L"\\logerror.html";
	 }
  	}
	else
	{
			static SYSTEMTIME st; 
			static FILETIME from, to, fst;		
			static ULARGE_INTEGER c_time,f_time,t_time;
			std::wstring LogFileOut, LogFileIn;
			FILE *istream, *ostream;

			static const size_t BufferSize = 10000000;
			byte * buffer = new byte[BufferSize];

			SystemTimeToFileTime(&SysTimeFrom, &from);
			SystemTimeToFileTime(&SysTimeTo, &to);
			memcpy(&f_time,&from, sizeof(t_time));
			memcpy(&t_time,&to, sizeof(t_time));
			c_time.QuadPart = f_time.QuadPart;

			LogFileOut = LogPath;
			LogFileOut += L"log.txt";
			if((ostream = _wfopen(LogFileOut.c_str(),L"wb")) == NULL) 
			{ MessageBox(NULL,L"Can't open output log file!",L"Error",MB_OK|MB_ICONINFORMATION);
				return S_FALSE;
			}

			while(c_time.QuadPart <= t_time.QuadPart)
			{
				memcpy(&fst,&c_time,sizeof(c_time));
				FileTimeToSystemTime(&fst, &st);
				GetDateFormat(LOCALE_SYSTEM_DEFAULT, NULL, &st, L"yyyyMMdd", Str, 20);
				
				LogFileIn = LogPath;
				LogFileIn += Str;
				LogFileIn += L".txt";
				if((istream = _wfopen(LogFileIn.c_str(),L"rb")) == NULL) 
					{ //MessageBox(NULL,L"Can't open log file!",L"Error",MB_OK|MB_ICONINFORMATION);
					  //return S_FALSE;
						c_time.QuadPart += ULONGLONG(1000)*ULONGLONG(10000)*ULONGLONG(3600)*ULONGLONG(24);
						continue;
					}

				int count = 0;
				while(count = (int)fread(buffer, sizeof buffer[0], BufferSize, istream))
					fwrite(buffer, sizeof buffer[0], count, ostream);

				fclose(istream);

				c_time.QuadPart += ULONGLONG(1000)*ULONGLONG(10000)*ULONGLONG(3600)*ULONGLONG(24);

			}

			fclose(ostream);
			taskpad += L"log.txt";
	}
	
    //MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, taskpad);

	*ppViewType = CreateFilePath((LPOLESTR)taskpad.c_str());

    *pViewOptions = MMC_VIEW_OPTIONS_NONE;
    return S_OK; 
}

HRESULT CLog::OnPropertyChange(IConsole *pConsole, CComponent *pComponent)
{

    pConsole->SelectScopeItem(GetParentScopeItem());
	return S_OK;
}

HRESULT CLog::OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    HRESULT hr = S_OK;
	long flag = (ActiveDialog)?  MF_GRAYED : 0;
	
    CONTEXTMENUITEM menuItemsNew[] =
    {
        {
            L"Log properties...", L"Set log period and properties",
                ID_LOG_PROPERTIES,  CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, CCM_SPECIAL_DEFAULT_ITEM    },
		
		
		{ NULL, NULL, 0, 0, 0, 0 }
    };
	

    // Loop through and add each of the menu items
    if (*pInsertionsAllowed & CCM_INSERTIONALLOWED_NEW)
    {
        for (LPCONTEXTMENUITEM m = menuItemsNew; m->strName; m++)
        {
            hr = pContextMenuCallback->AddItem(m);
            
            if (FAILED(hr))
                break;
        }
    }
    
    return hr;
}


HRESULT CLog::OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
    m_ipConsole = pConsole;
	m_ipDataObject = piDataObject;
	
	switch (lCommandID)
    {

   
   case ID_LOG_PROPERTIES:
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 0);
		break;

    }
    
    return S_OK;
}

HRESULT CLog::HasPropertySheets()
{
    // say "yes" when MMC asks if we have pages
    
	return S_OK;
}



INT_PTR CALLBACK CLog::LogDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CLog *pLog = NULL;
	static SYSTEMTIME st; 
	static FILETIME from, to, fst;		
	static ULARGE_INTEGER c_time,f_time,t_time;
	//wchar_t Str[20];

	
   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pLog = reinterpret_cast<CLog *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
	
	
		DateTime_SetSystemtime(GetDlgItem(hwndDlg,IDC_DATE_FROM),GDT_VALID, &(pLog->SysTimeFrom));
		DateTime_SetSystemtime(GetDlgItem(hwndDlg,IDC_DATE_TO),GDT_VALID, &(pLog->SysTimeTo));
		
		//SendMessage(GetDlgItem(hwndDlg,IDC_DATE_FROM), DTM_SETRANGE,(WPARAM) GDTR_MAX, (LPARAM)&st); 
		//SendMessage(GetDlgItem(hwndDlg,IDC_DATE_TO), DTM_SETRANGE,(WPARAM) GDTR_MAX, (LPARAM)&st); 

       break;

     case WM_COMMAND:
        // turn the Apply button on
        //if (HIWORD(wParam) == EN_CHANGE ||
         //   HIWORD(wParam) == CBN_SELCHANGE)
         //   SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);

		 break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pLog->m_ppHandle);
        break;

    case WM_NOTIFY:
        
		if (((NMHDR *) lParam)->code == PSN_KILLACTIVE )
		{ 
			DateTime_GetSystemtime(GetDlgItem(hwndDlg,IDC_DATE_FROM),&(pLog->SysTimeFrom));
			DateTime_GetSystemtime(GetDlgItem(hwndDlg,IDC_DATE_TO),&(pLog->SysTimeTo));

			SystemTimeToFileTime(&(pLog->SysTimeFrom), &from);
			SystemTimeToFileTime(&(pLog->SysTimeTo), &to);
						
			
			if(CompareFileTime(&from, &to) > 0 )
			{
			 MessageBox(hwndDlg,L"Incorrect bounds of time interval!",L"Error",MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			}else
			{	 SetWindowLong(hwndDlg, DWL_MSGRESULT, FALSE);
			}
			
			return TRUE;
			
			
		} //if PSN_KILLACTIVE
			
		if (((NMHDR *) lParam)->code == PSN_APPLY )
		{	
			
			HRESULT hr = MMCPropertyChangeNotify(pLog->m_ppHandle, (LPARAM)pLog);
			_ASSERT(SUCCEEDED(hr));
			pLog->ActiveDialog = false;
			//(pLog->m_ipConsole)->SelectScopeItem(pLog->GetParentScopeItem());
			
			return PSNRET_NOERROR;
		}
		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pLog->ActiveDialog = false;
			return FALSE;
		}
    }//switch
	
   		
  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

HRESULT CLog::CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle)
{
    PROPSHEETPAGE psp = { 0 };
    HPROPSHEETPAGE hPage = NULL;
	// cache this handle so we can call MMCPropertyChangeNotify
    m_ppHandle = handle;

    // create the property page for this node.
    // NOTE: if your node has multiple pages, put the following
    // in a loop and create multiple pages calling
    // lpProvider->AddPage() for each page.
    psp.dwSize = sizeof(PROPSHEETPAGE);
    psp.dwFlags = PSP_DEFAULT | PSP_USETITLE | PSP_USEICONID;
    psp.hInstance = g_hinst;
    psp.pszTemplate = MAKEINTRESOURCE(IDD_LOG_PROPERTY);
    psp.pfnDlgProc =  LogDialogProc;
    psp.lParam = reinterpret_cast<LPARAM>(this);
    psp.pszTitle = MAKEINTRESOURCE(IDS_LOG);
    //psp.pszIcon = MAKEINTRESOURCE();


   hPage = CreatePropertySheetPage(&psp);
   _ASSERT(hPage);
   return  lpProvider->AddPage(hPage);
}

HRESULT CLog::OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent)
{
  m_ipConsoleNameSpace = pConsoleNameSpace;
  m_ipConsole = pConsole;
  return S_OK;
}

HRESULT CLog::GetWatermarks(HBITMAP *lphWatermark,
                               HBITMAP *lphHeader,
                               HPALETTE *lphPalette,
                               BOOL *bStretch)
{
    return S_FALSE;
}


HRESULT CLog::InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page)
{
    HRESULT hr = S_FALSE;
    LPCWSTR szTitle = L"Log";

    //
    //Create an instance of the MMC Node Manager to obtain
    //an IPropertySheetProvider interface pointer
    //
    
    IPropertySheetProvider *pPropertySheetProvider = NULL;
 
    hr = CoCreateInstance (CLSID_NodeManager, NULL, 
         CLSCTX_INPROC_SERVER, 
         IID_IPropertySheetProvider, 
          (void **)&pPropertySheetProvider);
    
    if (FAILED(hr))
        return S_FALSE;
    
    //
    //Create the property sheet
    //
	  hr = pPropertySheetProvider->CreatePropertySheet
    (
        szTitle,  // pointer to the property page title
        TRUE,     // property sheet
        (MMC_COOKIE)this,  // cookie of current object - can be NULL
                     // for extension snap-ins
        piDataObject, // data object of selected node
        NULL          // specifies flags set by the method call
    );
 
    if (FAILED(hr))
    {
        pPropertySheetProvider->Release();
        return hr;
    }
     
    //
    //Call AddPrimaryPages. MMC will then call the
    //IExtendPropertySheet methods of our
    //property sheet extension object
 //static_cast<IComponent*>
	IComponentData * pComponent;
	hr = (pComponentData)->QueryInterface(IID_IComponentData, (void**)&pComponent);
	
	
	if (FAILED(hr))
    {
        pPropertySheetProvider->Release();
        return hr;
    }
	//m_ipConsole = g_Component->m_ipConsole;

try {
	PSProvider = pPropertySheetProvider;
	hr = pPropertySheetProvider->AddPrimaryPages
    (
       pComponent, // pointer to our 
	               // object's IUnknown
        TRUE, // specifies whether to create a notification 
               // handle
        NULL,  // must be NULL
        TRUE   // scope pane; FALSE for result pane
    );
}
catch (...) 
{

}
    if (FAILED(hr))
    {
        pPropertySheetProvider->Release();
        return hr;
    }
 
    //
    // Allow property page extensions to add
    // their own pages to the property sheet
    //
    hr = pPropertySheetProvider->AddExtensionPages();
    
    if (FAILED(hr))
    {
        pPropertySheetProvider->Release();
        return hr;
    }
 
    //
    //Display property sheet
    //
	CDelegationBase *base = GetOurDataObject(piDataObject)->GetBaseNodeObject();

	HWND hWnd = NULL; 
	(pComponentData->m_ipConsole)->GetMainWindow(&hWnd);
	
    hr = pPropertySheetProvider->Show((LONG_PTR)hWnd, page); 
         //NULL is allowed for modeless prop sheet
    
    if (FAILED(hr))
    {
        pPropertySheetProvider->Release();
        return hr;
    }
 
    //Release IPropertySheetProvider interface
    pPropertySheetProvider->Release();
 
    return hr;
 
}