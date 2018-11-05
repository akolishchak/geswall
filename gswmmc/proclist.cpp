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
#include "proclist.h"
#include "config/configurator.h"
#include "license/licensemanager.h"
#include "db/storage.h"
#include <Tlhelp32.h>
#include <winbase.h>
#include "app/application.h"
#include "commonlib.h"
#include "license/trialmanager.h"


// {B2598F87-0A91-451c-9B62-41EB0FA739CF}
const GUID CProcList::thisGuid = 
{ 0xb2598f87, 0xa91, 0x451c, { 0x9b, 0x62, 0x41, 0xeb, 0xf, 0xa7, 0x39, 0xcf } };

DWORD CProcList::CurrentPID = 0;
std::wstring CProcList::CurrentWnd;


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
CProcList::CProcList()
{
	config::Configurator::PtrToINode Node = config::Configurator::getDriverNode();
	InstallDir = Node->getString(L"InstallDir");
	cycflag = false;
}

CProcList::~CProcList()
{
}

LPOLESTR CProcList::CreateWWWPath( 
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

HRESULT CProcList::GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions)
{
	TCHAR taskpad[1024];
    TCHAR szThis[16];
    cycflag=false;

    _ultot((unsigned long)this, szThis, 16);

	OSVERSIONINFO VerInfo;
	VerInfo.dwOSVersionInfoSize = sizeof OSVERSIONINFO;
	GetVersionEx(&VerInfo);

	if ( VerInfo.dwMajorVersion == 5 && VerInfo.dwMinorVersion == 0 ) {
		_tcscpy(taskpad, _T("procload_w2k.htm#"));
	} else {
		_tcscpy(taskpad, _T("procload.htm#"));
	}
	_tcscat(taskpad, szThis);
    MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, taskpad);
	*ppViewType = CreateResourcePath( g_hinst, pszW );
    *pViewOptions = MMC_VIEW_OPTIONS_NONE;
    return S_OK; 

}

LPOLESTR CProcList::CreateResourcePath
( 
  HINSTANCE hInst,         //[in] Global instance handle
  LPOLESTR szResource      //[in] Path to stored resource
) 
{ 
   _TCHAR szBuffer[MAX_PATH];
            
   ZeroMemory(szBuffer, sizeof(szBuffer));
            
   _tcscpy(szBuffer, _T("res://"));
            
   _TCHAR *szTemp = szBuffer + _tcslen(szBuffer);
   GetModuleFileName(hInst, szTemp, (DWORD)sizeof(szBuffer) - _tcslen(szBuffer));
            
   _tcscat(szBuffer, _T("/"));
   MAKE_TSTRPTR_FROMWIDE(szname, szResource);
   _tcscat(szBuffer, szname);
            
   MAKE_WIDEPTR_FROMTSTR(wszname, szBuffer);
   LPOLESTR szOutBuffer = static_cast<LPOLESTR>(CoTaskMemAlloc((wcslen(wszname) + 1)  * sizeof(WCHAR)));

   wcscpy(szOutBuffer, wszname);
            
   return szOutBuffer;

} //end CreateResoucePath()


MMC_TASK *CProcList::GetTaskList(LPOLESTR szTaskGroup, LONG *nCount)
{
	if (!cycflag) {
		cycflag=true;
		return 0;
	} else
		cycflag=false;

	TaskArray.clear();
	GetAllTasks();

	std::wstring fullstring;
	*nCount = (LONG)TaskArray.size();	
	if ( *nCount==0 ) *nCount = 1;

	_TCHAR buf[256];
	MMC_TASK *tasks = new MMC_TASK[TaskArray.size()+1];		
	WCHAR *picstr[2][1] = { {	    L"green_close.png"
								},
								{	//L"red.gif",
									L"green_close_b.png"
								}
							};
						

	if ( TaskArray.size() == 0 )
	{
		tasks[0].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, picstr[1][0]);
		tasks[0].sDisplayObject.uBitmap.szMouseOffBitmap =  CreateResourcePath (g_hinst,picstr[0][0]);
		tasks[0].sDisplayObject.eDisplayType = MMC_TASK_DISPLAY_TYPE_VANILLA_GIF;
		_stprintf(buf, _T("Task #%d"), 0);
		MAKE_WIDEPTR_FROMTSTR(wszText, buf);
		tasks[0].szText = OleDuplicateString(L"<b>There are no isolated applications</b>");
		_stprintf(buf, _T(""));
		MAKE_WIDEPTR_FROMTSTR(wszHelpString, buf);
		tasks[0].szHelpString = OleDuplicateString(wszHelpString);
		tasks[0].eActionType = MMC_ACTION_ID;
		tasks[0].nCommandID = 0;
		return tasks;
	}

	//=======Sorting Process List========
	std::sort(TaskArray.begin(), TaskArray.end());

	for( size_t t = 0; t < TaskArray.size(); t++ )
	{      
		fullstring=L"<font color='#000000' size='+1'>";
		fullstring+=TaskArray[t].TaskName;
		fullstring+=L"</font><br>";
		std::wstring currpath=TaskArray[t].TaskPath;
		//CheckPath(currpath);

		AddToString(fullstring,L"Caption",TaskArray[t].Caption.c_str());
		AddToString(fullstring,L"Path",currpath.c_str());

		wchar_t *Str;
		commonlib::VerInfo Ver;
		Ver.Init(currpath.c_str());
		Ver.GetStr(L"FileDescription", &Str);
		AddToString(fullstring, L"Description", Str);

		Ver.GetStr(L"ProductName", &Str);
		AddToString(fullstring, L"Product", Str);

		Ver.GetStr(L"CompanyName", &Str);
		AddToString(fullstring, L"Company", Str);

		tasks[t].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath (g_hinst,picstr[1][0]);
		tasks[t].sDisplayObject.uBitmap.szMouseOffBitmap =  CreateResourcePath (g_hinst,picstr[0][0]);
	
		tasks[t].sDisplayObject.eDisplayType = MMC_TASK_DISPLAY_TYPE_BITMAP;
				
		_stprintf(buf, _T("Task #%d"), t);
		MAKE_WIDEPTR_FROMTSTR(wszText, buf);
		tasks[t].szText = OleDuplicateString((LPOLESTR)fullstring.c_str());

		_stprintf(buf, _T("Press 'Terminate' button to terminate process"));
		MAKE_WIDEPTR_FROMTSTR(wszHelpString, buf);
		tasks[t].szHelpString = OleDuplicateString(wszHelpString);

		tasks[t].eActionType = MMC_ACTION_ID;
		tasks[t].nCommandID = t;
	}

	return tasks;
}

HRESULT CProcList::TaskNotify(IConsole *pConsole, VARIANT *v1, VARIANT *v2)
{
	if ( !license::TrialManager::IsOperationAllowed(license::TrialManager::opTerminateIsolatedApp, g_hinst) ) return S_OK;

	TaskItem *Item = &TaskArray[v1->lVal];
	if (Item->ProcessID==NULL) return S_OK;

	wstring procstr =L"Process [";
    procstr+=Item->TaskName;
	procstr+=L"] ";
	bool rez =commonlib::SlayProcess(Item->ProcessID) == TRUE;
    if (rez) procstr+=L"successfully terminated!";
	else     procstr+=L": can`t terminate process!";

    MessageBox(NULL,procstr.c_str(),L"GeSWall",MB_OK);
	pConsole->SelectScopeItem(GetParentScopeItem());
	return S_OK;
}

HRESULT CProcList::GetTaskpadTitle(LPOLESTR *pszTitle)
{
   *pszTitle = OleDuplicateString(L"Isolated Applications");
   return S_OK;
}

HRESULT CProcList::GetTaskpadDescription(LPOLESTR *pszDescription)
{
	*pszDescription = OleDuplicateString(L"Isolated Applications:");
        return S_OK;
}

HRESULT CProcList::GetTaskpadBackground(MMC_TASK_DISPLAY_OBJECT *pTDO)
{
        pTDO->eDisplayType = MMC_TASK_DISPLAY_TYPE_BITMAP;
        pTDO->uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, L"empty.gif");
        return S_OK;
}

HRESULT CProcList::GetListpadInfo(MMC_LISTPAD_INFO *lpListPadInfo)
{
        return S_FALSE;
}

HRESULT CProcList::OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    HRESULT hr = S_OK;
    CONTEXTMENUITEM menu_items[] = {
            {
                L"Refresh", 
                L"Refresh applications list", 
                ID_REFRESH_UNTRUSTED_APPS_LIST, 
                CCM_INSERTIONPOINTID_PRIMARY_TOP, 
                0, 
                0 // CCM_SPECIAL_DEFAULT_ITEM
            },
            {
                L"Terminate all", 
                L"Terminate all", 
                ID_TERMINATE_ALL, 
                CCM_INSERTIONPOINTID_PRIMARY_TOP, 
                0, 
                0 // CCM_SPECIAL_DEFAULT_ITEM
            },
            { NULL, NULL, 0, 0, 0, 0 }
        };
    //
    // Loop through and add each of the menu items
    if (CCM_INSERTIONALLOWED_TOP == (*pInsertionsAllowed & CCM_INSERTIONALLOWED_TOP))
    if (*pInsertionsAllowed & (CCM_INSERTIONALLOWED_TOP | CCM_INSERTIONALLOWED_NEW | CCM_INSERTIONALLOWED_TASK))
    {
        for (LPCONTEXTMENUITEM m = menu_items; m->strName; ++m)
        {
            hr = pContextMenuCallback->AddItem (m);
            
            if (TRUE == FAILED(hr))
                break;
        }
    }
    
    return hr;
}

HRESULT CProcList::OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
	if ( !license::TrialManager::IsOperationAllowed(license::TrialManager::opTerminateIsolatedApp, g_hinst) ) return S_OK;

    switch ( lCommandID ) {
        case ID_TERMINATE_ALL:
			{
				TerminateAll();

				IDataObject *dummy = NULL;
				pConsole->UpdateAllViews(dummy, GetParentScopeItem(), UPDATE_SCOPEITEM);
			}
			break;

		case ID_REFRESH_UNTRUSTED_APPS_LIST:
			{
				IDataObject *dummy = NULL;
				pConsole->UpdateAllViews(dummy, GetParentScopeItem(), UPDATE_SCOPEITEM);
			}
			break;

	}
			
    return S_OK;
}

bool CProcList::GetAllTasks()
{
	bool  ContinueLoop;
	HANDLE  FSnapshotHandle;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE; 
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 FProcessEntry32;
	MODULEENTRY32 me32;


	int  result= 0;
	bool fval=false;
	TaskItem TaskIt;

	FSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	FProcessEntry32.dwSize = sizeof(FProcessEntry32);
	ContinueLoop = Process32First(FSnapshotHandle, &FProcessEntry32) == TRUE;
  
  
	while (ContinueLoop)
	{
		if (!CheckIsolated(FProcessEntry32.th32ProcessID))
		{
			ContinueLoop = Process32Next(FSnapshotHandle, &FProcessEntry32) == TRUE;
			continue;
		}

		HANDLE hp = commonlib::GetProcessHandleWithEnoughRights( FProcessEntry32.th32ProcessID, PROCESS_ALL_ACCESS );
		if( hp )
		{
			TaskIt.TaskPath.clear();

			hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, FProcessEntry32.th32ProcessID ); 
			if( hModuleSnap != INVALID_HANDLE_VALUE ) 
			{ 
				me32.dwSize = sizeof( MODULEENTRY32 ); 
				if( Module32First( hModuleSnap, &me32 ) ) 
				{ 
						TaskIt.TaskPath = me32.szExePath;
				} 
				CloseHandle( hModuleSnap );
			} 

			CurrentPID=FProcessEntry32.th32ProcessID;
			CurrentWnd.clear();
			EnumThreadWindows(0,etw,0);
			TaskIt.Caption = CurrentWnd;

			TaskIt.ProcessID =FProcessEntry32.th32ProcessID;
			TaskIt.ModuleID  =FProcessEntry32.th32ModuleID;
			TaskIt.ParentProcessID =FProcessEntry32.th32ParentProcessID;
			TaskIt.TaskName = FProcessEntry32.szExeFile;
			fval=true;
			TaskArray.push_back(TaskIt);
		}

		ContinueLoop = Process32Next(FSnapshotHandle, &FProcessEntry32) == TRUE;
	}
/*
	if (!fval) 
	{
		TaskIt.ProcessID =0;
		TaskArray.push_back(TaskIt);
	}
*/
	CloseHandle(FSnapshotHandle);

	return true;
}

void CProcList::TerminateAll(void)
{
	HANDLE FSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 FProcessEntry32;
	FProcessEntry32.dwSize = sizeof(FProcessEntry32);
	bool ContinueLoop = Process32First(FSnapshotHandle, &FProcessEntry32) == TRUE;
  
	while ( ContinueLoop ) {

		if ( CheckIsolated(FProcessEntry32.th32ProcessID) ) {
			if ( commonlib::SlayProcess(FProcessEntry32.th32ProcessID) == TRUE ) {
				//CloseHandle(FSnapshotHandle);
				//FSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				//ContinueLoop = Process32First(FSnapshotHandle, &FProcessEntry32) == TRUE;
				//continue;
			}
		}
		ContinueLoop = Process32Next(FSnapshotHandle, &FProcessEntry32) == TRUE;
	}

	CloseHandle(FSnapshotHandle);
}

bool CProcList::AddToString(std::wstring &fullstr, const wchar_t* name1, const wchar_t* name2)
{
			if (lstrcmp(name2,L"")!=0)
			{
						fullstr+=L"<b>";
						fullstr+=name1;
						fullstr+=L": </b>";
						fullstr+=name2;
						fullstr+=L"<br>";
						return true;
			}
			else return false;

}

BOOL CALLBACK CProcList::etw(HWND wnd, LPARAM lParam)
{
	wchar_t WindowText[MAX_PATH];
	DWORD procid;
	GetWindowThreadProcessId(wnd,&procid);
	if ((procid==CurrentPID)&&(IsWindowVisible(wnd) || IsIconic(wnd)) && 
		((GetWindowLongPtr(wnd, GWL_HWNDPARENT) == 0) || (GetWindowLongPtr(wnd, GWL_HWNDPARENT) == (LONG_PTR)GetDesktopWindow())) &&
		((GetWindowLong(wnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) == 0)
	   )
	{
		ZeroMemory(WindowText,sizeof(WindowText));
		GetWindowText(wnd,WindowText,MAX_PATH-1);
		CurrentWnd=WindowText;
		if (CurrentWnd!=L"") return false;
	}

	return true;
}

bool CProcList::CheckIsolated(DWORD procid)
{
	return Drv.GetSubjIntegrity(procid) != GesRule::modTCB;
}
