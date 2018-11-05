//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "StatNode.h"
#include "rootfolder.h"
#include "BaseSnap.h"
#include "Resources.h"
#include "Applications.h"
#include "homepage.h"
#include "log.h"
#include "lcount.h"
#include "untrusted_files_page.h"
#include "proclist.h"
#include "config/configurator.h"
#include "config/w32registrynode.h"
#include "gswclient.h"
#include "guids.h"
#include "db/setting.h"
#include <Userenv.h>

const GUID CStaticNode::thisGuid = 
{ 0xd5ae7c65, 0x7022, 0x493d, { 0xb5, 0x4a, 0xaf, 0x51, 0x44, 0xe8, 0xd2, 0x15 } };

static LPOLESTR CreateResourcePath
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


static LPOLESTR OleDuplicateString(LPOLESTR lpStr) {
    LPOLESTR tmp = static_cast<LPOLESTR>(CoTaskMemAlloc((wcslen(lpStr) + 1)  * sizeof(WCHAR)));
    wcscpy(tmp, lpStr);

    return tmp;
}
//==============================================================
//
// CStaticNode implementation
//
//
CStaticNode::CStaticNode()
{
  m_pGPTInformation = NULL;

  config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
  Storage::SetDBSetting(Node);
  Storage::GetSecureTypeList(SecureTypeMap);

  license::LicenseManager::LicenseEssentials License;
  license::LicenseManager::LicenseCopy(License);
  Product = License.Product;
  if ( Product == license::gswServer || Product == license::gswEnterprise )
	  Mode = snmGPExtension;
  else
	  Mode = snmStandAlone;

  if ( Mode == snmGPExtension )
	Node = config::Configurator::getGPNode();
  else
	Node = config::Configurator::getGswlPolicyNode();

  SecuriyLevel = (GesRule::SecurityLevel) Node->getInt(L"SecurityLevel");

  VerInfo.dwOSVersionInfoSize = sizeof OSVERSIONINFO;
  GetVersionEx(&VerInfo);

  if ( Mode == snmGPExtension )
  { 
	NUMBER_OF_CHILDREN = 1;
	children[0] = new CRootFolder(this);
  }
  else
  {	
	NUMBER_OF_CHILDREN = 7;
	children[0] = new CLcount();
	children[1] = new CResourceScope(this);
	children[2] = new CApplicationFolder(this); 
	children[3] = new untrusted_files_page (); 
	children[4] = new CProcList();
	children[5] = new CLog(); 
	children[6] = new CHomePage(); 
  }
}

CStaticNode::~CStaticNode()
{
    for (int n = 0; n < NUMBER_OF_CHILDREN; n++)
        if (children[n]) {
            delete children[n];
        }
}

HRESULT CStaticNode::OnInitialExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, LPDATAOBJECT pDataObject)
{
	HRESULT hr = S_OK;
		
	if ( Mode == snmGPExtension ) {
		//DebugBreak();
		hr = pDataObject->QueryInterface(IID_IGPEInformation, (LPVOID *)&m_pGPTInformation);
		if ( hr != S_OK ) return hr;
		wchar_t Path[MAX_PATH];
		hr = m_pGPTInformation->GetFileSysPath(GPO_SECTION_MACHINE, Path, sizeof Path / sizeof Path[0]);
		if ( hr != S_OK ) return hr;
		std::wstring DataFile = std::wstring(Path) + L"\\geswall.dat";
		if ( GetFileAttributes(DataFile.c_str()) == INVALID_FILE_ATTRIBUTES ) {
			//
			// Data file doesn't exists or local gpo, copy it
			//
			CopyFile(Storage::Setting::getConnectString().c_str(), DataFile.c_str(), TRUE);
		}
		Storage::Setting::setConnectString(DataFile);
/*
		if ( m_pGPTInformation != NULL ) {
			HKEY hKey;
			HRESULT hr = m_pGPTInformation->GetRegistryKey(GPO_SECTION_MACHINE, &hKey);
			if ( SUCCEEDED(hr) ) {
				config::W32RegistryNode Node(hKey, L"Software\\Policies\\GentleSecurity\\GeSWall", true);
				SecuriyLevel = Node.getInt(L"SecurityLevel");
			}
		}
*/
	}

	return hr;
}

HRESULT CStaticNode::OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent)
{
    SCOPEDATAITEM sdi;
    m_hParentHScopeItem = parent;
	m_ipConsole = pConsole;
	m_ipConsoleNameSpace = pConsoleNameSpace;

    if (!bExpanded) {
        // create the child nodes, then expand them

        for (int n = 0; n < NUMBER_OF_CHILDREN; n++) {
            ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |   // Displayname is valid
                SDI_PARAM     |   // lParam is valid
                SDI_IMAGE     |   // nImage is valid
                SDI_OPENIMAGE |   // nOpenImage is valid
                SDI_PARENT	  |
                SDI_CHILDREN;
            
            sdi.relativeID  = (HSCOPEITEM)parent;
            sdi.nImage      = children[n]->GetBitmapIndex();
            sdi.nOpenImage  = children[n]->GetBitmapIndex(); //INDEX_SNAPIN;
            sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)children[n];       // The cookie
            sdi.cChildren   = (n == 1); //(n == 0); // only the first child has children
            
            HRESULT hr = pConsoleNameSpace->InsertItem( &sdi );
            
			_ASSERT( SUCCEEDED(hr) );

			children[n]->SetScopeItemValue(sdi.ID);
        }
    }
    
	return S_OK;
}

HRESULT CStaticNode::GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions)
{
	TCHAR taskpad[1024];
    TCHAR szThis[16];

	*pViewOptions = MMC_VIEW_OPTIONS_NONE;
	*ppViewType = NULL;

    if(Mode == snmGPExtension)
	  return S_OK;
	
    _ultot((unsigned long)this, szThis, 16);
	if ( VerInfo.dwMajorVersion == 5 && VerInfo.dwMinorVersion == 0 ) {
		_tcscpy(taskpad, _T("settings_w2k.htm#"));
	} else {
		_tcscpy(taskpad, _T("settings.htm#"));
	}
    _tcscat(taskpad, szThis);
    MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, taskpad);

	*ppViewType = CreateResourcePath( g_hinst, pszW );

    return S_OK; 
}


MMC_TASK *CStaticNode::GetTaskList(LPOLESTR szTaskGroup, LONG *nCount)
{
	*nCount = 3;
	_TCHAR buf[256];

    MMC_TASK *tasks = new MMC_TASK[*nCount];
	WCHAR *tstr[] = {	L"Aut-isolation, no pop-up dialogs",
						//L"Isolate network applications",
						L"Isolate defined applications",
						L"Isolate jailed applications" 
						};
	WCHAR *picstr[][3] = { {	//L"red2.gif",
								L"brown2_h.gif",
								L"yellow2.gif",
								L"green2.gif" },
							{	//L"red.gif",
								L"brown_h.gif",
								L"yellow.gif",
								L"green.gif" }
						 };
					


	for (int t = 0; t < *nCount; t++) {
       
		if( PosToSecurityLevel(t) == SecuriyLevel )
		{
			tasks[t].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, picstr[0][t]);
			tasks[t].sDisplayObject.uBitmap.szMouseOffBitmap = CreateResourcePath(g_hinst,  picstr[0][t]);
		}
		else {
			tasks[t].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, picstr[1][t]);
			tasks[t].sDisplayObject.uBitmap.szMouseOffBitmap = CreateResourcePath(g_hinst, picstr[1][t]);
		}

		tasks[t].sDisplayObject.eDisplayType = MMC_TASK_DISPLAY_TYPE_BITMAP;
			
		_stprintf(buf, _T("Task #%d"), t);
        MAKE_WIDEPTR_FROMTSTR(wszText, buf);
        tasks[t].szText = OleDuplicateString(L""/*tstr[t]*/);

        _stprintf(buf, _T("Click here to change security level"));
        MAKE_WIDEPTR_FROMTSTR(wszHelpString, buf);
        tasks[t].szHelpString = OleDuplicateString(wszHelpString);

        tasks[t].eActionType = MMC_ACTION_ID;
        tasks[t].nCommandID = t;
    }

    return tasks;
}

HRESULT CStaticNode::TaskNotify(IConsole *pConsole, VARIANT *v1, VARIANT *v2)
{
	SecuriyLevel = PosToSecurityLevel(v1->lVal);
	config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
	Node->setInt(L"SecurityLevel", SecuriyLevel);
	GswClient Client;
	Client.RefreshSettings();
	//
    pConsole->SelectScopeItem(GetParentScopeItem());

    return S_OK;
}

HRESULT CStaticNode::GetTaskpadTitle(LPOLESTR *pszTitle)
{
        *pszTitle = OleDuplicateString(L"Geswall Security Level");
        return S_OK;
}

HRESULT CStaticNode::GetTaskpadDescription(LPOLESTR *pszDescription)
{
	*pszDescription = OleDuplicateString(L"GeSWall Security Level:");
        return S_OK;
}

HRESULT CStaticNode::GetTaskpadBackground(MMC_TASK_DISPLAY_OBJECT *pTDO)
{
        pTDO->eDisplayType = MMC_TASK_DISPLAY_TYPE_BITMAP;
        pTDO->uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, L"empty.gif");
        return S_OK;
}

HRESULT CStaticNode::GetListpadInfo(MMC_LISTPAD_INFO *lpListPadInfo)
{
        return S_FALSE;
}

bool CStaticNode::ActiveRefresh = false;

HRESULT CStaticNode::OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    HRESULT hr = S_OK;
	long flag = (ActiveRefresh)?  MF_GRAYED : 0;
	
    CONTEXTMENUITEM menuItemsNew[] =
    {
        {
            L"Repair Application Database", L"Repair Application Database",
                ID_REFRESH_DATABASE,  CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, CCM_SPECIAL_DEFAULT_ITEM    },
		
		
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

HRESULT CStaticNode::OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
    m_ipConsole = pConsole;
	
	switch (lCommandID) {
		case ID_REFRESH_DATABASE:
			HWND hWnd = FindWindow(L"GsWUINotificationWindow", NULL);
			if ( hWnd == NULL ) break;
			try {
				Storage::SetUpdateVersion(0);
			} catch ( ... ) {
				break;
			}
			SendMessage(hWnd, WM_COMMAND, IDC_UPDATE_DB, NULL);
			break;
    }
    
    return S_OK;
}

bool CStaticNode::PolicyChanged(void)
{
	if ( m_pGPTInformation != NULL && Mode == snmGPExtension ) {
		GROUP_POLICY_OBJECT_TYPE gpoType = GPOTypeLocal;
		m_pGPTInformation->GetType(&gpoType);
		if ( gpoType != GPOTypeLocal ) {
			GUID Extension = CLSID_GESWALL_GPO;
			GUID Snapin = CLSID_CComponentData;//CLSID_CCGroupPolicy;
			m_pGPTInformation->PolicyChanged(TRUE, TRUE, &Extension, &Snapin);
			//RefreshPolicy(TRUE);
			return true;
		}
	}

	return false;
}

bool CStaticNode::LevelChange(void)
{
	if ( m_pGPTInformation != NULL && Mode == snmGPExtension ) {
		HKEY hKey;
		HRESULT hr = m_pGPTInformation->GetRegistryKey(GPO_SECTION_MACHINE, &hKey);
		if ( SUCCEEDED(hr) ) {
			config::W32RegistryNode Node(hKey, L"Software\\Policies\\GentleSecurity\\GeSWall", true);
			Node.setInt(L"SecurityLevel", SecuriyLevel);
			return true;
		}
	}
	return false;
}

GesRule::SecurityLevel CStaticNode::PosToSecurityLevel(int Pos)
{
	if ( Product != license::gswServer ) {
		switch ( Pos ) {
			case 0:
				return GesRule::secLevel3;
			case 1:
				return GesRule::secLevel2;
			case 2:
				return GesRule::secLevel1;
		}
	} else {
		switch ( Pos ) {
			case 0:
				return GesRule::secLevel3;
			case 1:
				return GesRule::secLevel6;
		}
	}

	return GesRule::secLevel1;
}