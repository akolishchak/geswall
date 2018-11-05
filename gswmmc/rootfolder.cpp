//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include "rootfolder.h"
#include "Resources.h"
#include "Applications.h"
#include "homepage.h"
#include "log.h"
#include "lcount.h"
#include "untrusted_files_page.h"
#include "proclist.h"
#include "config/configurator.h"
#include "gswclient.h"


// {5D210590-D77D-4cbd-8354-9D30B4B3A165}
const GUID CRootFolder::thisGuid  = 
{ 0x5d210590, 0xd77d, 0x4cbd, { 0x83, 0x54, 0x9d, 0x30, 0xb4, 0xb3, 0xa1, 0x65 } };

//---------------------------------------------------------------------------
//  Creates a string with the format  
//    "res://<Path to this object>/<path to resource>
//
//  It is up to the caller to make sure the memory allocated with 
//  CoTaskMemAlloc for the string is freed.
//  If null is passed in the first parameter, the path to MMC.EXE will be
//  returned, if the instance handle is passed the returned path will point
//  the Snap-in dll.
//
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
//  implementation
//
//
CRootFolder::CRootFolder(CStaticNode *StaticNode):m_parent(StaticNode)
{
	 //m_parent->SecuriyLevel = (GesRule::secUndefined);
	children[0] = new CLcount();
    children[1] = new CResourceScope(StaticNode);
	children[2] = new CApplicationFolder(StaticNode); 
	children[3] = new untrusted_files_page();
	children[4] = new CProcList();
	children[5] = new CLog(); 
	children[6] = new CHomePage();
}

CRootFolder::~CRootFolder()
{
    for (int n = 0; n < NUMBER_OF_CHILDREN; n++)
        delete children[n];
}

HRESULT CRootFolder::OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent)
{
    SCOPEDATAITEM sdi;
	m_ipConsoleNameSpace = pConsoleNameSpace;
	m_ipConsole = pConsole;

    if (!bExpanded) {
        // create the child nodes, then expand them
        for (int n = 0; n < NUMBER_OF_CHILDREN; n++) {
			//
			// Do not show log folder for non local targets
			//
			if ( n == 2 && m_parent->m_pGPTInformation != NULL ) {
				GROUP_POLICY_OBJECT_TYPE gpoType = GPOTypeLocal;
				m_parent->m_pGPTInformation->GetType(&gpoType);
				if ( gpoType != GPOTypeLocal ) continue;
			}

            ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |  // Displayname is valid
                SDI_PARAM     |			// lParam is valid
                SDI_IMAGE     |			// nImage is valid
                SDI_OPENIMAGE |			// nOpenImage is valid
                SDI_PARENT    |			// relativeID is valid
                SDI_CHILDREN;			// cChildren is valid

            sdi.relativeID  = (HSCOPEITEM)parent;
            sdi.nImage      = children[n]->GetBitmapIndex();
			switch(n)
			{	case 0 : sdi.nOpenImage = INDEX_RESOURCES; break;
				case 1 : sdi.nOpenImage = INDEX_APPLICATIONS; break;
				case 2 : sdi.nOpenImage = INDEX_LCOUNT; break;
				case 3 : sdi.nOpenImage = INDEX_LOG; break;
				case 4 : sdi.nOpenImage = INDEX_HOMEPAGE; break;
				case 5 : sdi.nOpenImage = INDEX_LCOUNT; break;
				
			}
            sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)children[n];       // The cookie
            sdi.cChildren   = (n==1);

            HRESULT hr = pConsoleNameSpace->InsertItem( &sdi );

            _ASSERT( SUCCEEDED(hr) );

            children[n]->SetScopeItemValue(sdi.ID);
        }
    }

    return S_OK;
}
HRESULT CRootFolder::GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions)
{
	TCHAR taskpad[1024];
    TCHAR szThis[16];

    _ultot((unsigned long)this, szThis, 16);
	if ( m_parent->VerInfo.dwMajorVersion == 5 && m_parent->VerInfo.dwMinorVersion == 0 ) {
		_tcscpy(taskpad, _T("settings_w2k.htm#"));
	} else {
		_tcscpy(taskpad, _T("settings.htm#"));
	}
	_tcscat(taskpad, szThis);
    MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, taskpad);

	*ppViewType = CreateResourcePath( g_hinst, pszW );

    *pViewOptions = MMC_VIEW_OPTIONS_NONE;
    return S_OK; 
}


MMC_TASK *CRootFolder::GetTaskList(LPOLESTR szTaskGroup, LONG *nCount)
{
	if ( m_parent->Product != license::gswServer ) {
		*nCount = 3;
		_TCHAR buf[256];

		MMC_TASK *tasks = new MMC_TASK[*nCount];
		WCHAR *tstr[] = {	L"Auto-isolation, no pop-up dialogs",
							//L"Isolate network applications",
							L"Isolate defined applications",
							L"Isolate jailed applications" };
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
	       
			
			if( m_parent->PosToSecurityLevel(t) == m_parent->SecuriyLevel )
			{
				tasks[t].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, picstr[0][t]);
				tasks[t].sDisplayObject.uBitmap.szMouseOffBitmap = CreateResourcePath(g_hinst,  picstr[0][t]);
			}
			else {  tasks[t].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, picstr[1][t]);
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
	} else {
		*nCount = 2;
		_TCHAR buf[256];

		MMC_TASK *tasks = new MMC_TASK[*nCount];
		WCHAR *tstr[] = {	L"Isolation ON",
							L"Isolation OFF, Log Only" };
		WCHAR *picstr[][2] = { {	L"red2_s.gif",
									L"green2_s.gif" },
								{	L"red_s.gif",
									L"green_s.gif" }
							};
						
		for (int t = 0; t < *nCount; t++) 
		{
			if( m_parent->PosToSecurityLevel(t) == m_parent->SecuriyLevel )
			{
				tasks[t].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, picstr[0][t]);
				tasks[t].sDisplayObject.uBitmap.szMouseOffBitmap = CreateResourcePath(g_hinst,  picstr[0][t]);
			}
			else {  tasks[t].sDisplayObject.uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, picstr[1][t]);
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
}

HRESULT CRootFolder::TaskNotify(IConsole *pConsole, VARIANT *v1, VARIANT *v2)
{
	m_parent->SecuriyLevel = m_parent->PosToSecurityLevel(v1->lVal);
	config::Configurator::PtrToINode Node;
	if ( m_parent->Mode == snmGPExtension ) {
		m_parent->LevelChange();
	}

	if ( m_parent->Mode != snmGPExtension || !m_parent->PolicyChanged() ) {
		Node = config::Configurator::getGswlPolicyNode();
		Node->setInt(L"SecurityLevel", m_parent->SecuriyLevel);
		if ( m_parent->Mode == snmGPExtension ) {
			Node = config::Configurator::getGPNode();
			Node->setInt(L"SecurityLevel", m_parent->SecuriyLevel);
		}
		GswClient Client;
		Client.RefreshSettings();
	}
	//
    pConsole->SelectScopeItem(GetParentScopeItem());

    return S_OK;
}

HRESULT CRootFolder::GetTaskpadTitle(LPOLESTR *pszTitle)
{
   *pszTitle = OleDuplicateString(L"Geswall Security Level");
   return S_OK;
}

HRESULT CRootFolder::GetTaskpadDescription(LPOLESTR *pszDescription)
{
	*pszDescription = OleDuplicateString(L"GeSWall Security Level:");
        return S_OK;
}

HRESULT CRootFolder::GetTaskpadBackground(MMC_TASK_DISPLAY_OBJECT *pTDO)
{
        pTDO->eDisplayType = MMC_TASK_DISPLAY_TYPE_BITMAP;
        pTDO->uBitmap.szMouseOverBitmap = CreateResourcePath(g_hinst, L"empty.gif");
        return S_OK;
}

HRESULT CRootFolder::GetListpadInfo(MMC_LISTPAD_INFO *lpListPadInfo)
{
        return S_FALSE;
}