//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "gswshellext.h"

#include "shellextmain.h"
#include "commonlib/debug.h" 
#include "commonlib/commonlib.h" 
#include "gsw/gswioctl.h"
#include "commonlib/gswdrv.h" 
#include "config/configurator.h"
#include "resource.h"
#include "interface/gswclient.h"
#include "reentrance.h"
#include "appwizard.h"
#include "config/w32registrynode.h"
#include "license/trialmanager.h"
#include "commonlib/fileassoc.h"
#include "commonlib/hin/hin.h"

#include "commonlib/debug.h"

namespace shellext {

CGswDrv Drv;
HBITMAP     m_hRegBmp1, m_hRegBmp2;
bool zip_enter=false;
wstring zip_file_link=L"";
/*
commonlib::hin::HOOK_HANDLE hShellExecuteExW = NULL;
typedef BOOL (STDAPICALLTYPE *_ShellExecuteExW)(LPSHELLEXECUTEINFOW lpExecInfo);
_ShellExecuteExW ShellExecuteExW_Original = NULL;

BOOL STDAPICALLTYPE ShellExecuteExW_Hook(LPSHELLEXECUTEINFOW lpExecInfo)
{
	HRESULT hr = GswShellExt::Execute(lpExecInfo);
	if ( hr == S_OK ) return TRUE;

	return ShellExecuteExW_Original(lpExecInfo);
}
*/
bool GswShellExt::GlobalInit(void)
{
	//
	// hook ShellExecuteExW
	//
	//hShellExecuteExW = commonlib::hin::HookExported("shell32.dll", "ShellExecuteExW", reinterpret_cast <void*>(ShellExecuteExW_Hook), reinterpret_cast <void**>(&ShellExecuteExW_Original));
	//commonlib::Debug::SetMode(commonlib::Debug::outFile);
	return true;
}

void GswShellExt::GlobalRelease(void)
{
	//
	// unhook
	//
	//commonlib::hin::UnHook(hShellExecuteExW);
}

GswShellExt::GswShellExt ()
 : m_data_obj (NULL)
{
	//create bitmap icon
	m_hRegBmp1=LoadBitmap ( shellext::m_module_instance, MAKEINTRESOURCE(IDB_BITMAP1));
	m_hRegBmp2=LoadBitmap ( shellext::m_module_instance, MAKEINTRESOURCE(IDB_BITMAP2));
	m_ref_counter = 0;
    inc_module_reference ();

} // GswShellExt

GswShellExt::~GswShellExt ()
{//destroy bitmap icon
	if ( NULL != m_hRegBmp1 ) DeleteObject ( m_hRegBmp1 );
	if ( NULL != m_hRegBmp2 ) DeleteObject ( m_hRegBmp2 );

    dec_module_reference ();
} // ~GswShellExt

STDMETHODIMP_(ULONG) GswShellExt::AddRef ()
{
    //return m_ref_counter.increment ();
    return commonlib::sync::ExternalAtomicCounter (m_ref_counter).increment ();
} // AddRef

STDMETHODIMP_(ULONG) GswShellExt::Release ()
{
    if (0 != (commonlib::sync::ExternalAtomicCounter (m_ref_counter)).decrement () )
        return m_ref_counter;
    //if (0 != m_ref_counter.decrement ())
    //    return m_ref_counter.value ();

    delete this;

    return 0L;
} // Release

STDMETHODIMP GswShellExt::QueryInterface (REFIID riid, LPVOID FAR *ppv)
{
    *ppv = NULL;

    if (TRUE == IsEqualIID(riid, IID_IContextMenu))
    {
//        ODS("CShellExt::QueryInterface()==>IID_IGswShellExt\r\n");

        *ppv = (LPCONTEXTMENU) this;
        AddRef ();
        
        return NOERROR;
    }
	else if (TRUE == IsEqualIID (riid, IID_IShellIconOverlayIdentifier))
    {
        *ppv = (IShellIconOverlayIdentifier*) this;
        AddRef ();

        return NOERROR;
    }
    else if (TRUE == IsEqualIID (riid, IID_IShellExtInit) || TRUE == IsEqualIID (riid, IID_IUnknown))
    {
        *ppv = (LPSHELLEXTINIT) this;
        AddRef ();

        return NOERROR;
    }
    else if (TRUE == IsEqualIID (riid, IID_IShellExecuteHook))
    {
        *ppv = (IShellExecuteHook*) this;
        AddRef ();

        return NOERROR;
    }
	return E_NOINTERFACE;
} // QueryInterface

STDMETHODIMP GswShellExt::Initialize (LPCITEMIDLIST pIDFolder, LPDATAOBJECT pDataObj, HKEY hRegKey)
{
    // Initialize can be called more than once
    if (NULL != m_data_obj)
        m_data_obj->Release ();

    // duplicate the object pointer and registry handle
    if (NULL != pDataObj)
    {
        m_data_obj = pDataObj;
        m_data_obj->AddRef ();
    }

	FORMATETC fmt = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
	STGMEDIUM stg = { TYMED_HGLOBAL };
	HDROP     hDrop;
    // Look for CF_HDROP data in the data object.
    if ( FAILED( pDataObj->GetData ( &fmt, &stg ) ))
        {
        // Nope! Return an "invalid argument" error back to Explorer.
        return E_INVALIDARG;
        }

    // Get a pointer to the actual data.
    hDrop = (HDROP) GlobalLock ( stg.hGlobal );

    // Make sure it worked.
    if ( NULL == hDrop )
        return E_INVALIDARG;

    // Sanity check - make sure there is at least one filename.
	UINT uNumFiles = DragQueryFile ( hDrop, 0xFFFFFFFF, NULL, 0 );
	HRESULT hr = S_OK;

    if ( 0 == uNumFiles )
        {
        GlobalUnlock ( stg.hGlobal );
        ReleaseStgMedium ( &stg );
        return E_INVALIDARG;
        }

    // Get the name of the first file and store it in our member variable m_szFile.
    if ( 0 == DragQueryFile ( hDrop, 0, m_szFile, MAX_PATH ) )
        hr = E_INVALIDARG;
    
//	wzFile=m_szFile;
    
	GlobalUnlock ( stg.hGlobal );
    ReleaseStgMedium ( &stg );

    return NOERROR;
} // Initialize

#define IDC_RUN_ISOLATED		0
#define IDC_APP_WIZARD			1
#define IDC_LABEL_TRUSTED		2
#define IDC_LABEL_UNTRUSTED		3
#define IDC_UNDEFINED			4

STDMETHODIMP GswShellExt::QueryContextMenu (HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
    UINT    indexMenuFirst = indexMenu;
    bool    bAppendItems = true;
    char    menu_text1 [64] = "Run Isolated";
	char    menu_text2 [64] = "Application Wizard";
	char	menu_text3 [64] = "Label as Trusted";
	char	menu_text4 [64] = "Label as Untrusted";
    

    if ((uFlags & 0x000F) == CMF_NORMAL)  //Check == here, since CMF_NORMAL=0
    {
    }
    else if (uFlags & CMF_VERBSONLY)
    {
    }
    else if (uFlags & CMF_EXPLORE)
    {
    }
    else if (uFlags & CMF_DEFAULTONLY)
    {
        bAppendItems = false;
    }
    else 
    {
        bAppendItems = false;
    }

    if ( bAppendItems )
    {
		InsertMenuA (hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, 0, NULL);

		UINT Flags = MF_STRING|MF_BYPOSITION;
		// check if runisolated enabled
		config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
		if ( GesRule::TranslateSecurityLevel((GesRule::SecurityLevel)Node->getInt(L"SecurityLevel")) & GesRule::ploIsolatedOnlyJailed ) {
			Flags |= MF_GRAYED;
		}
		InsertMenuA (hMenu, indexMenu, Flags, idCmdFirst + IDC_RUN_ISOLATED, menu_text1);
		if ( NULL != m_hRegBmp1 ) SetMenuItemBitmaps ( hMenu, indexMenu, MF_BYPOSITION, m_hRegBmp1, NULL );
		indexMenu++;

		if (GswAppWizard::AppWizard::CheckExtension(m_szFile,L".exe")) 
		{

			config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
			HANDLE hFile = CreateFile(Node->getString(L"connectString").c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if ( hFile != INVALID_HANDLE_VALUE ) {
				CloseHandle(hFile);
				Flags =  MF_STRING | MF_BYPOSITION;
			} else {
				if ( commonlib::IsUACSupported() && !commonlib::IsElevatedContext() )
					Flags =  MF_STRING | MF_BYPOSITION;
				else
					Flags =  MF_STRING | MF_BYPOSITION | MF_GRAYED;
			}

			InsertMenuA (hMenu, indexMenu, Flags, idCmdFirst + IDC_APP_WIZARD, menu_text2);//AppWiz---<
			if ( NULL != m_hRegBmp2 ) SetMenuItemBitmaps ( hMenu, indexMenu, MF_BYPOSITION, m_hRegBmp2, NULL );//AppWiz---<
			indexMenu++;
		}

		if ( Drv.GetSubjIntegrity(GetCurrentProcessId()) == GesRule::modTCB ) {

			HANDLE hFile = CreateFile(m_szFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if ( hFile != INVALID_HANDLE_VALUE ) {
				CloseHandle(hFile);
				Flags =  MF_STRING | MF_BYPOSITION;
			} else {
				Flags =  MF_STRING | MF_BYPOSITION | MF_GRAYED;
			}

			if ( Drv.IsFileUntrusted(m_szFile) ) {
				InsertMenuA (hMenu, indexMenu++, Flags, idCmdFirst + IDC_LABEL_TRUSTED, menu_text3);
			} else {
				InsertMenuA (hMenu, indexMenu++, Flags, idCmdFirst + IDC_LABEL_UNTRUSTED, menu_text4);
			}
		}

        InsertMenuA (hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, idCmdFirst + IDC_UNDEFINED, NULL);

        //Must return number of menu
        //items we added.
        return ResultFromScode(MAKE_SCODE(SEVERITY_SUCCESS, 0, indexMenu - indexMenuFirst)); 
    }

    return NOERROR;
} // QueryGswShellExt

STDMETHODIMP GswShellExt::InvokeCommand (LPCMINVOKECOMMANDINFO lpcmi)
{
    HRESULT hr = E_INVALIDARG;

    //If HIWORD(lpcmi->lpVerb) then we have been called programmatically
    //and lpVerb is a command that should be invoked.  Otherwise, the shell
    //has called us, and LOWORD(lpcmi->lpVerb) is the menu ID the user has
    //selected.  Actually, it's (menu ID - idCmdFirst) from QueryGswShellExt().
    if (!HIWORD(lpcmi->lpVerb))
    {
        UINT idCmd = LOWORD(lpcmi->lpVerb);

        switch (idCmd)
        {
            case IDC_RUN_ISOLATED:
			{
				GswClient Client;
				//
				// add modifier
				//
				Client.SetParamsModifier(modAutoIsolate, GetCurrentProcessId(), GetCurrentThreadId());
				//
				// CreateProcess
				//
				ShellExecute(NULL, NULL, m_szFile, NULL, NULL, SW_SHOWNORMAL);
				//
				// release modifier
				//
				Client.SetParamsModifier(modRemove, GetCurrentProcessId(), GetCurrentThreadId());
				break;
			}
			case IDC_APP_WIZARD:
			{
				 //Check if extension =".exe"
				 //Run Wizard
//				 if (!CheckExeExtension(m_szFile)) break;

				if ( commonlib::IsUACSupported() && !commonlib::IsElevatedContext() ) {

					wchar_t DllName[MAX_PATH];
					GetModuleFileName(m_module_instance, DllName, sizeof DllName / sizeof DllName[0]);

					ShellExecute(NULL, L"runas", L"rundll32.exe", std::wstring(L"\"").append(DllName).append(L"\", AppWizard ").append(m_szFile).c_str(), NULL, SW_SHOW);
					break;
				}

				config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
				Storage::SetDBSetting(Node);

				if ( license::TrialManager::IsOperationAllowed(license::TrialManager::opRunAppWizard, m_module_instance) ) {
 					GswAppWizard::AppWizard wizard; //Run Application Wizard				 
					wizard.RunWizard(m_szFile); //argument - current file path
				}

				Storage::close ();
				break;
			}
			case IDC_LABEL_TRUSTED:
			case IDC_LABEL_UNTRUSTED:
			{
				config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
				Storage::SetDBSetting(Node);
				bool Allowed = license::TrialManager::IsOperationAllowed(license::TrialManager::opSetLabels, m_module_instance);
				Storage::close ();

				if ( !Allowed ) break;

				HANDLE hFile = CreateFile(m_szFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
				if ( hFile == INVALID_HANDLE_VALUE ) break;
				//
				// Chck for UAC
				//
				if ( commonlib::IsUACSupported() && !commonlib::IsElevatedContext() ) {
					CloseHandle(hFile);
					MessageBox(NULL, L"The operation requires elevated privileges.\n"
										L"To proceed please disable UAC (User Account Control).", L"GeSWall's Labels", MB_OK);
					break;
				}

				EntityAttributes Attributes;
				if ( Drv.GetObjectAttributes(hFile, nttFile, 0, &Attributes) ) {
					Attributes.Param[GesRule::attIntegrity] = idCmd == IDC_LABEL_TRUSTED ? GesRule::modTCB : GesRule::modThreatPoint;
					SetAttributesInfo Info;
					Info.hObject = hFile;
					Info.Attr = Attributes;
					memcpy(Info.Label, &GesRule::GswLabel, sizeof GesRule::GswLabel);
					Info.ResType = nttFile;
					Drv.SetAttributes(&Info);
					//
					// Force shell refreshing
					//
					SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
				}
				CloseHandle(hFile);
				break;
			}
        }
    }
    
    return hr;
} // InvokeCommand

//--------------------------------------


STDMETHODIMP GswShellExt::GetCommandString (UINT_PTR idCmd, UINT uFlags, UINT FAR *reserved, LPSTR pszName, UINT cchMax)
{
    switch (idCmd)
    {
        case 0:
            //wcsncpy ((wchar_t*)pszName, L"New menu item number 1", cchMax);
            lstrcpynA (pszName, "Run this application isolated.", cchMax);
            break;
       case 1:
            //wcsncpy ((wchar_t*)pszName, L"New menu item number 1", cchMax);
            lstrcpynA (pszName, "Add rules for application.", cchMax);
            break;
       case 2:
            //wcsncpy ((wchar_t*)pszName, L"New menu item number 1", cchMax);
            lstrcpynA (pszName, "Label a file as trusted.", cchMax);
            break;
    }
    return NOERROR;
} // GetCommandString


STDMETHODIMP GswShellExt::IsMemberOf (LPCWSTR pwszPath, DWORD dwAttr)
{
//	SYSTEMTIME Time;

//	GetSystemTime(&Time);
//	commonlib::Debug::Write("%02d:%02d:%02d START: ShellExt::IsMemberOf(%S, %x)\r\n", Time.wHour, Time.wMinute, Time.wSecond, pwszPath, dwAttr);

	//
	// get string length
	//
	size_t Length = 0;
	HRESULT hr = StringCchLength(pwszPath, STRSAFE_MAX_CCH, &Length);
	if ( hr != S_OK || Length == 0 )
		return S_FALSE;

	//
	// Exclude root folders
	//
	if ( pwszPath[Length - 1] == '\\' )
		return S_FALSE;

	if ( !( dwAttr & ( FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_REPARSE_POINT ) ) && Drv.IsFileUntrusted(pwszPath) ) {
//		GetSystemTime(&Time);
//		commonlib::Debug::Write("%02d:%02d:%02d END_MATCH: ShellExt::IsMemberOf(%S, %x)\r\n", Time.wHour, Time.wMinute, Time.wSecond, pwszPath, dwAttr);
		return S_OK;
	}

//	GetSystemTime(&Time);
//	commonlib::Debug::Write("%02d:%02d:%02d END: ShellExt::IsMemberOf(%S, %x)\r\n", Time.wHour, Time.wMinute, Time.wSecond, pwszPath, dwAttr);

	return S_FALSE;
}

STDMETHODIMP GswShellExt::GetOverlayInfo (LPWSTR pwszIconFile, int cchMax, LPINT pIndex, LPDWORD pdwFlags)
{
	// Get our module's full path
	GetModuleFileNameW(shellext::m_module_instance, pwszIconFile, cchMax);

	// Use first icon in the resource
	*pIndex=0; 

	*pdwFlags = ISIOI_ICONFILE | ISIOI_ICONINDEX | GIL_SIMULATEDOC;
	return S_OK;
}

STDMETHODIMP GswShellExt::GetPriority (LPINT pPriority)
{
	// we want highest priority 
	*pPriority=0;
	return S_OK;
}

STDMETHODIMP GswShellExt::Execute(LPSHELLEXECUTEINFOW lpei)
{
	//
	// Check re-entrance first
	//
	SHELLEXECUTEINFO pei;
    pei.cbSize = sizeof(SHELLEXECUTEINFO);
	pei=*lpei;

	//MessageBox(NULL,pei.lpVerb,pei.lpParameters,MB_OK);

	ReEntrance::Check ReEntranceCheck;
	if ( ReEntranceCheck.IsTrue() ) return S_FALSE;

	//
	// No re-entrance, do our stuff
	// Check if a file is untrusted, accept any verb
	//	
	if ( &pei == NULL || pei.lpFile == NULL) return S_FALSE;
    bool isuntrusted=Drv.IsFileUntrusted(pei.lpFile);

	//=========try to start in the separate process==========
//  std::wstring tmpstr;
//	tmpstr=pei.lpFile;
//	wchar_t wtmpstr[255];
//	ZeroMemory(wtmpstr,sizeof(wtmpstr));
//	tmpstr.copy(wtmpstr,tmpstr.length(),0);
//	if (FileAssoc::IsFileAssociated(wtmpstr, L"D:\\Program Files\\Microsoft Office\\Office10\\WINWORD.EXE"))
//	 MessageBox(NULL,L"Word",L"!!!",MB_OK);

    std::wstring exepath=L"";
	std::wstring params =L"";
	bool prcext=false;
	
	if (ProcessExtension(&pei,exepath,params)) //return true if processed, and false if not.
	{   
        pei.lpVerb =L"open";
        pei.lpFile = exepath.c_str();
        pei.lpParameters = params.c_str();
        pei.nShow = SW_NORMAL;
        pei.fMask = NULL;
        pei.hwnd = NULL;
        pei.lpDirectory = NULL;
        pei.hInstApp = NULL;
		prcext=true;
	}
	//=======================================================

	if((!isuntrusted)&&(!prcext)) return S_FALSE;

	// Execution of untrusted file
	// add modifier
	GswClient Client;
	if (isuntrusted) Client.SetParamsModifier(modForceIsolation, GetCurrentProcessId(), GetCurrentThreadId());
	//if (isuntrusted) Client.SetParamsModifier(modAutoIsolate, GetCurrentProcessId(), GetCurrentThreadId());

	ShellExecuteEx(&pei);

	// release modifier
	if (isuntrusted) Client.SetParamsModifier(modRemove, GetCurrentProcessId(), GetCurrentThreadId());

	return S_OK;
}

bool GswShellExt::ProcessExtension(LPSHELLEXECUTEINFOW pei,std::wstring &exepath,std::wstring &params)
{
	//
	if (pei->lpFile==L"") return false;
	std::wstring extn;
	extn=FileAssoc::GetFileExtension(pei->lpFile);
	extn=CharLowerW((LPWSTR)extn.c_str());
	if ((extn==L"")||(extn==L".exe")) return false;
	bool lpVerbNull=false;
	if (pei->lpVerb==NULL) {bool lpVerbNull=true;pei->lpVerb=L"open";}
	std::wstring progpath=L"";

	progpath=FileAssoc::GetFileFromExtension(extn.c_str(),pei->lpVerb);

	if (lpVerbNull==true) pei->lpVerb=NULL;
	if (progpath==L"") return false;

	if (!ReplaceFunc(progpath,L"\"%1\"",L""))
			ReplaceFunc(progpath,L"%1",L"");
	std::wstring newparam=L"";
	std::wstring progpathl;
	progpathl=progpath;
	progpathl=CharLower((LPWSTR)progpathl.c_str());	

	bool insparam=false;

	//=== check file and add parameter for separate process
	if (progpathl.find(L"excel.exe")   !=-1) {newparam=L" / ";insparam=true;}
	if (progpathl.find(L"winword.exe") !=-1) {newparam=L" / ";insparam=true;}
	if (progpathl.find(L"acrord32.exe")!=-1) {newparam=L" /n ";insparam=true;}
	if (progpathl.find(L"acrobat.exe") !=-1) {newparam=L" /n ";insparam=true;}
	if (progpathl.find(L"zipfldr.dll") !=-1) {newparam=L" /separate, ";insparam=true;}
	if(!insparam) return false;

	if (extn==L".zip")
	{
		exepath=L"explorer.exe";
		params =newparam;
		params+=L" \"";
		params+=pei->lpFile;
		params+=L"\"";
		return true;
	}

	//===extract path and add new param 
	wchar_t fchar[2];
	ZeroMemory(fchar,sizeof(fchar));
	progpath.copy(fchar,1,0);
	int npos;
	if (lstrcmp(fchar,L"\"")==0)
			npos=(int)progpath.find_first_of(L"\"",2);
	else
			npos=(int)progpath.find_first_of(L" ",2);
	if (npos==-1) return false;
	progpath.insert(npos+1,newparam);

	//=== fill parameters for return: exepath and params
	wchar_t tempstr[255];
	ZeroMemory(tempstr,sizeof(tempstr));
	progpath.copy(tempstr,npos+1,0);
	exepath=tempstr;
	ZeroMemory(tempstr,sizeof(tempstr));
	progpath.copy(tempstr,progpath.length()-npos,npos+1);
	params=tempstr;
	params+=L" \"";
	params+=pei->lpFile;
	params+=L"\"";
	return true;
}

bool GswShellExt::ReplaceFunc(wstring &str1,wstring str2,wstring str3)
	{
	//===find in string str1 string str2 and replace with str3
	std::wstring tstr;
	int npos;
	tstr=str1;
	tstr=CharLowerW((LPWSTR)tstr.c_str());
	str2=CharLowerW((LPWSTR)str2.c_str());
	npos=(int)tstr.find(str2.c_str());
    if (npos!=-1) {str1.replace(npos,str2.length(),str3.c_str());return true;}
	
	return false;
	}

} // namespace shellext

