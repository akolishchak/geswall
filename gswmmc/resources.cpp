//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include <hash_map>

#include "StatNode.h"
#include "Resources.h"
#include "Comp.h"
#include "DataObj.h"
#include "resource.h"
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
#include "gesruledef.h"
#include "ruleutils.h"
#include "seluser.h"
#include "gswclient.h"
#include "nettools.h"


// {5580E218-08B7-4f07-AFFE-A4200D92ADF3}
 const GUID CResourceScope::thisGuid = 
{ 0x5580e218, 0x8b7, 0x4f07, { 0xaf, 0xfe, 0xa4, 0x20, 0xd, 0x92, 0xad, 0xf3 } };
// {23ECE3D8-0704-48fe-8EC6-465163EF5CAA}
 const GUID CResourceResult::thisGuid = 
{ 0x23ece3d8, 0x704, 0x48fe, { 0x8e, 0xc6, 0x46, 0x51, 0x63, 0xef, 0x5c, 0xaa } };

	using namespace std;
	using namespace GesRule;


//==============================================================
//
// CResourceResult implementation
//
//
CResourceResult::CResourceResult(Storage::PtrToResourceItem ri, CResourceScope *parent, CStaticNode *StaticNode)
: m_Resource(ri), m_ppHandle(0),m_pParent(parent)
{
	m_StaticNode = StaticNode;
  	m_Component = NULL;
	this->nId = 0;
	isDeleted = FALSE;
}

CResourceResult::~CResourceResult()
{
   
}

const _TCHAR *CResourceResult::GetDisplayName(int nCol)
{
    const size_t cchBuffer = 128;
    static	_TCHAR buf[cchBuffer];
		
    // StringCchPrintf and StringCchCopy always null-terminate the destination string.
    // However the string may be a truncation of the ideal result (indicated by  return value other than S_OK).
	
	switch (nCol) 
	{
    case 0:
       switch (m_Resource->Identity.Type)
		{       
		case Storage::idnOwner: 
			
			StringCchPrintf(buf, cchBuffer, _T("Owner: %s"),m_Resource->Identity.Owner.Owner);
          	break;
		 case Storage::idnPath:
 			StringCchPrintf(buf, cchBuffer, _T("Path: %s"), m_Resource->Identity.Path.Path);
			
           break;
		 case Storage::idnCertificate:
			 StringCchPrintf(buf, cchBuffer, _T("Certificate: %s"), m_Resource->Identity.Cert.IssuedTo);
			
           break;
		 case Storage::idnDigest:
 			 StringCchPrintf(buf, cchBuffer, _T("Digest: %s"), _T(""));
			
			 break;
		 case Storage::idnContent:
			  StringCchPrintf(buf, cchBuffer, _T("Content: %s"), _T(""));
			
            break;
		 }
        break;

    case 1:
        StringCchPrintf(buf, cchBuffer, _T("%s"), GetNtTypeString(m_Resource->Identity.GetResourceType()));
        break;

    case 2:
		Storage::SECMAP_ITER i = GetScopeParent()->m_StaticNode->SecureTypeMap.find(m_Resource->Params.Id);
		StringCchPrintf(buf, cchBuffer, _T("%s"),(i)->second.c_str());
        break;

   }

    return buf;
}

HRESULT CResourceScope::GetResultViewType(/* [out] */ LPOLESTR __RPC_FAR *ppViewType,
                                   /* [out] */ long __RPC_FAR *pViewOptions)
{
       *pViewOptions = MMC_VIEW_OPTIONS_NONE;
       *ppViewType = NULL;
  
    return S_OK;
}
HRESULT CResourceResult::GetResultViewType(/* [out] */ LPOLESTR __RPC_FAR *ppViewType,
                                   /* [out] */ long __RPC_FAR *pViewOptions)
{
       *pViewOptions = MMC_VIEW_OPTIONS_NONE;
       *ppViewType = NULL;
  
    return S_OK;
}

// handle anything special when the user clicks Apply or Ok
// on the property sheet.  This sample directly accesses the
// operated-on object, so there's nothing special to do when the user presses Ok.
// when the user presses Apply, we update the currently selected result item
HRESULT CResourceResult::OnPropertyChange(IConsole *pConsole, CComponent *pComponent)
{

   HRESULT hr = S_FALSE;

    //Call IConsole::UpdateAllViews to redraw the item
    //in all views. We need a data object because of the
    //way UpdateAllViews is implemented, and because
    //MMCN_PROPERTY_CHANGE doesn't give us one

    LPDATAOBJECT pDataObject;
    hr = pComponent->QueryDataObject((MMC_COOKIE)this, CCT_RESULT, &pDataObject );
    _ASSERT( S_OK == hr);       
        
    hr = pConsole->UpdateAllViews(pDataObject, nId, UPDATE_RESULTITEM);
    _ASSERT( S_OK == hr);

    pDataObject->Release();

    return hr;
	
/*	//redraw the item 
    IResultData *pResultData = NULL;

	HRESULT hr;

	hr = pConsole->QueryInterface(IID_IResultData, (void **)&pResultData);
	_ASSERT( SUCCEEDED(hr) );	

	HRESULTITEM myhresultitem;	
	
	//lparam == this. See CSpaceVehicle::OnShow
	hr = pResultData->FindItemByLParam( (LPARAM)this, &myhresultitem );
	_ASSERT( SUCCEEDED(hr) ); 

	hr = pResultData->UpdateItem( myhresultitem );     
	_ASSERT( SUCCEEDED(hr) );    
	
    pResultData->Release();
	
	
	return S_OK;
*/
}

HRESULT CResourceResult::OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect)
{

    // enable rename, refresh, and delete verbs
    IConsoleVerb *pConsoleVerb;

    HRESULT hr = pConsole->QueryConsoleVerb(&pConsoleVerb);
    _ASSERT(SUCCEEDED(hr));

    //hr = pConsoleVerb->SetVerbState(MMC_VERB_RENAME, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_REFRESH, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_DELETE, ENABLED, TRUE);


    // can't get to properties (via the standard methods) unless
    // we tell MMC to display the Properties menu item and
    // toolbar button, this will give the user a visual cue that
    // there's "something" to do
    hr = pConsoleVerb->SetVerbState(MMC_VERB_PROPERTIES, ENABLED, TRUE);

    //also set MMC_VERB_PROPERTIES as the default verb
    hr = pConsoleVerb->SetDefaultVerb(MMC_VERB_PROPERTIES);

    pConsoleVerb->Release();

        // now set toolbar button states
    if (bSelect) {
	       		}

    return S_OK;
}
// Implement the dialog proc
INT_PTR CALLBACK CResourceResult::DialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
    static CResourceResult *pResource = NULL;
	int indexSecType = 0, i;
	HANDLE hImage = NULL;

   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pResource = reinterpret_cast<CResourceResult *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		i = 0;
		for (Storage::SECMAP_ITER iter = pResource->GetScopeParent()->m_StaticNode->SecureTypeMap.begin(); iter != pResource->GetScopeParent()->m_StaticNode->SecureTypeMap.end(); iter++,i++)
			{   
				SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_ADDSTRING, 0, 
                                   (LPARAM)iter->second.c_str()); 
				SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_SETITEMDATA, i, (LPARAM)iter->first);
				if(iter->first == pResource->m_Resource->Params.Id) indexSecType = i;
				
			}
			SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_SETCURSEL, indexSecType, 0); 
		
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttFile));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttKey));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttDevice));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttNetwork));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttSystemObject));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttSection));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttAny));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 0, (LPARAM)nttFile);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 1, (LPARAM)nttKey);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 2, (LPARAM)nttDevice);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 3, (LPARAM)nttNetwork);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 4, (LPARAM)nttSystemObject);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 5, (LPARAM)nttSection);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 6, (LPARAM)nttAny);
			
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SELECTSTRING, -1, (LPARAM)GetNtTypeString(pResource->m_Resource->Identity.GetResourceType())); 
			EnableWindow(GetDlgItem(hwndDlg,IDC_RESTYPE),false);

			EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_OWNER),false);
			EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_NAME),false);
			EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_CERT),false);
			EnableWindow(GetDlgItem(hwndDlg,IDC_OWNER_BROWSE),false);
			//EnableWindow(GetDlgItem(hwndDlg,IDC_OWNER_E),false);
			//EnableWindow(GetDlgItem(hwndDlg,IDC_NAME_E),false);
			//EnableWindow(GetDlgItem(hwndDlg,IDC_CERT_E),false);
	
			 hImage = LoadImage(g_hinst, MAKEINTRESOURCE(IDB_LGBMP),
							IMAGE_BITMAP, 0, 0,	 LR_LOADTRANSPARENT | LR_DEFAULTCOLOR); 

			//SendDlgItemMessage(hwndDlg,IDC_LOGO, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hImage); 

        switch(pResource->m_Resource->Identity.Type)
		{ case Storage::idnOwner:
			EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_OWNER),true);
			EnableWindow(GetDlgItem(hwndDlg,IDC_OWNER_BROWSE),true);
			//EnableWindow(GetDlgItem(hwndDlg,IDC_OWNER_E),true);
			SendDlgItemMessage(hwndDlg,IDC_RADIO_OWNER, BM_SETCHECK, BST_CHECKED, 0); 
			SetDlgItemText(hwndDlg, IDC_NAME_E, pResource->m_Resource->Identity.Owner.Owner);
			SetDlgItemText(hwndDlg, IDC_DESCRIPTION, ResourceString<>(IDS_OWNER_DESC));
			
			break;
		  case Storage::idnPath:
				EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_NAME),true);
				//EnableWindow(GetDlgItem(hwndDlg,IDC_NAME_E),true);
				SendDlgItemMessage(hwndDlg,IDC_RADIO_NAME, BM_SETCHECK, BST_CHECKED, 0); 
				SetDlgItemText(hwndDlg, IDC_NAME_E, pResource->m_Resource->Identity.Path.Path);
				SetDlgItemText(hwndDlg, IDC_DESCRIPTION, ResourceString<>(IDS_NAME_DESC));
			
			break;

		  case Storage::idnCertificate:

				SendDlgItemMessage(hwndDlg,IDC_RADIO_CERT, BM_SETCHECK, BST_CHECKED, 0); 
				EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_CERT),true);
				//EnableWindow(GetDlgItem(hwndDlg,IDC_CERT_E),true);
				SetDlgItemText(hwndDlg, IDC_NAME_E, pResource->m_Resource->Identity.Cert.IssuedTo);
				SetDlgItemText(hwndDlg, IDC_DESCRIPTION, ResourceString<>(IDS_CERT_DESC));
			
			break;

		}

       break;

     case WM_COMMAND:
        // turn the Apply button on
        if (HIWORD(wParam) == EN_CHANGE ||
            HIWORD(wParam) == CBN_SELCHANGE)
            SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);

		if (HIWORD(wParam) == BN_CLICKED) 
           { 
            switch (LOWORD(wParam)) 
             { 
              case IDC_OWNER_BROWSE: 
				OnSelusers(hwndDlg);
			  break;

			  case IDC_RADIO_OWNER: 
				 break; 

              case IDC_RADIO_NAME: 
				 break;

              case IDC_RADIO_CERT: 
				 break; 
			  } 
            } 

        break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pResource->m_ppHandle);
        break;

    case WM_NOTIFY:
        if (((NMHDR *) lParam)->code == PSN_APPLY )
		{
			int n = 0, result = 0;
			//SecureZeroMemory(pResource->Resource, sizeof(ResourceItem));
			
			int class_selection = (int)SendDlgItemMessage(hwndDlg, IDC_SECUR, CB_GETCURSEL, 0, 0);
			int sec_class = (int)SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_GETITEMDATA, class_selection , 0);
			pResource->m_Resource->Params.Id= sec_class;

				
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_OWNER, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{    n = (int)SendDlgItemMessage(hwndDlg, IDC_NAME_E, WM_GETTEXTLENGTH, 0, 0);
				if (n != 0) {
				GetDlgItemText(hwndDlg, IDC_NAME_E, pResource->m_Resource->Identity.Owner.Owner, n + 1);
           		}else
					{  MessageBox(hwndDlg,L"Resource string can not be empty.",L"Resource error",MB_OK|MB_ICONINFORMATION);
						break;
					}
				pResource->m_Resource->Identity.Owner.ParentId = sec_class;
				//pResource->m_Resource->Identity.Type = idnOwner;
				Storage::OwnerInfo Owner = pResource->m_Resource->Identity.Owner;
				std::wstring StringSid;
				if ( commonlib::nettools::GetStringSidByName(Owner.Owner, StringSid) ) {
					StringCchCopy(Owner.Owner, sizeof Owner.Owner / sizeof Owner.Owner[0], StringSid.c_str());
				}
				Owner.Options |= Storage::dboUserModified;
				try {
					result = Storage::UpdateOwner(Owner.Id, Owner);
					pResource->m_Resource->Identity.Owner.Id = result;
					pResource->m_StaticNode->PolicyChanged();
				} catch ( ... ) {
					MessageBox(hwndDlg,L"Owner resource update is failed",L"Database error",MB_OK|MB_ICONINFORMATION);
				}
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_NAME, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{    n = (int)SendDlgItemMessage(hwndDlg, IDC_NAME_E, WM_GETTEXTLENGTH, 0, 0);
				if (n != 0) {
				GetDlgItemText(hwndDlg, IDC_NAME_E, pResource->m_Resource->Identity.Path.Path, n + 1);
				}
				pResource->m_Resource->Identity.Path.ParentId = sec_class;
				//pResource->m_Resource->Identity.Type = idnPath;
				pResource->m_Resource->Identity.Path.Options |= Storage::dboUserModified;
				try {
					result = Storage::UpdatePath(pResource->m_Resource->Identity.Path.Id, pResource->m_Resource->Identity.Path);
					pResource->m_Resource->Identity.Path.Id = result;
					pResource->m_StaticNode->PolicyChanged();
				} catch ( ... ) {
					MessageBox(hwndDlg,L"Path resource update is failed",L"Database error",MB_OK|MB_ICONINFORMATION);
				}
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_CERT, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{    n = (int)SendDlgItemMessage(hwndDlg, IDC_NAME_E, WM_GETTEXTLENGTH, 0, 0);
				if (n != 0) {
				GetDlgItemText(hwndDlg, IDC_NAME_E, pResource->m_Resource->Identity.Cert.IssuedTo, n + 1);
				}
				pResource->m_Resource->Identity.Cert.ParentId = sec_class;
				//pResource->m_Resource->Identity.Type = idnCertificate;
				pResource->m_Resource->Identity.Cert.Type = Storage::crtUnknown;
				pResource->m_Resource->Identity.Cert.ThumbprintSize =  wcslen(L"N/A");
				StringCchCopy((wchar_t*)pResource->m_Resource->Identity.Cert.Thumbprint, 
							sizeof pResource->m_Resource->Identity.Cert.Thumbprint / sizeof wchar_t,
							L"N/A");
				StringCchCopy(pResource->m_Resource->Identity.Cert.IssuedBy, 
							sizeof pResource->m_Resource->Identity.Cert.IssuedBy / sizeof wchar_t,
							L"N/A");
				pResource->m_Resource->Identity.Cert.Expiration = 0;

				pResource->m_Resource->Identity.Cert.Options |= Storage::dboUserModified;
				try {
					result = Storage::UpdateCertificate(pResource->m_Resource->Identity.Cert.Id, pResource->m_Resource->Identity.Cert);
					pResource->m_Resource->Identity.Cert.Id = result;
					pResource->m_StaticNode->PolicyChanged();
				} catch ( ... ) {
					MessageBox(hwndDlg,L"Certificate resource update is failed",L"Database error",MB_OK|MB_ICONINFORMATION);
				}
			}
			//
			// Send update notification to gswserv
			//
			if ( result != 0 ) {
				GswClient Client;
				Client.RefreshResources();
			}
			
			HRESULT hr = MMCPropertyChangeNotify(pResource->m_ppHandle, (LPARAM)pResource);
			_ASSERT(SUCCEEDED(hr));
			return PSNRET_NOERROR;
		}
    }

    return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

HRESULT CResourceResult::HasPropertySheets()
{
    // say "yes" when MMC asks if we have pages
   
	return S_OK;
	 
}

HRESULT CResourceResult::CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle)
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
    psp.pszTemplate = MAKEINTRESOURCE(IDD_RESOURCE1);
    psp.pfnDlgProc = DialogProc;
    psp.lParam = reinterpret_cast<LPARAM>(this);
    psp.pszTitle = MAKEINTRESOURCE(IDS_PST_ROCKET);
    //psp.pszIcon = MAKEINTRESOURCE(IDI_PSI_ROCKET);


    hPage = CreatePropertySheetPage(&psp);
    _ASSERT(hPage);

    return lpProvider->AddPage(hPage);
}

HRESULT CResourceResult::GetWatermarks(HBITMAP *lphWatermark,
                               HBITMAP *lphHeader,
                               HPALETTE *lphPalette,
                               BOOL *bStretch)
{
    return S_FALSE;
}

HRESULT CResourceResult::OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype)

{
    HRESULT hr = S_FALSE;

    _ASSERT(NULL != this || isDeleted || RESULT == itemtype);                   

    //redraw the item
    IResultData *pResultData = NULL;

    hr = pConsole->QueryInterface(IID_IResultData, (void **)&pResultData);
    _ASSERT( SUCCEEDED(hr) );   

    HRESULTITEM myhresultitem;
    _ASSERT(NULL != &myhresultitem);    
        
    //lparam == this. See CSpaceStation::OnShow
    hr = pResultData->FindItemByLParam( (LPARAM)this, &myhresultitem );

    if ( FAILED(hr) )
    {
        // Failed : Reason may be that current view does not have this item.
        // So exit gracefully.
        hr = S_FALSE;
    } else

    {
        hr = pResultData->UpdateItem( myhresultitem );
        _ASSERT( SUCCEEDED(hr) );
    }

    pResultData->Release();
        
    return hr; 
}

HRESULT CResourceResult::OnRefresh(IConsole *pConsole)

{
    //Call IConsole::UpdateAllViews to redraw all views
    //owned by the parent scope item

    IDataObject *dummy = NULL;

    HRESULT hr;

    hr = pConsole->UpdateAllViews(dummy, m_pParent->GetParentScopeItem(), UPDATE_SCOPEITEM);
    _ASSERT( S_OK == hr);

    return hr;
}

HRESULT CResourceResult::OnDelete(CComponentData * pCompData, IConsole *pConsoleComp)
{
    HRESULT hr = S_FALSE;
	wstring Objects[3] = {L"Owner",L"Path",L"Certificate"};
	const size_t cchBuffer = 64;
    static wchar_t message[cchBuffer];

	int result = 0;
    //Delete the item
    
	switch(m_Resource->Identity.Type)
	{
		case Storage::idnOwner: 
			if( false == Storage::DeleteOwner(m_Resource->Identity.Owner.Id)) result = 1;
			m_StaticNode->PolicyChanged();
			break;

		case Storage::idnPath:
			if( false == Storage::DeletePath(m_Resource->Identity.Path.Id))  result = 2;
			m_StaticNode->PolicyChanged();
			break;

		case Storage::idnCertificate:
			if( false == Storage::DeleteCertificate(m_Resource->Identity.Cert.Id))  result = 3;
			m_StaticNode->PolicyChanged();
			break;
	}
	
	if(result) 
	{ 
		StringCchPrintf(message, cchBuffer, _T("Can't delete \'%s\' resource."), (Objects[result-1]).c_str());
		pConsoleComp->MessageBox(message, L"Database error", MB_OK|MB_ICONINFORMATION, NULL);
		return hr;
	}
	//
	// Send update notification to gswserv
	//
	GswClient Client;
	Client.RefreshResources();

	IResultData *pResultData = NULL;

    hr = pConsoleComp->QueryInterface(IID_IResultData, (void **)&pResultData);
    _ASSERT( SUCCEEDED(hr) );   

    HRESULTITEM myhresultitem;  
        
    //lparam == this. See OnShow
    hr = pResultData->FindItemByLParam( (LPARAM)this, &myhresultitem );
    if ( FAILED(hr) )
    {
        // Failed : Reason may be that current view does not have this item.
        // So exit gracefully.
        hr = S_FALSE;
    } else

    {
        hr = pResultData->DeleteItem( myhresultitem, 0 );
        _ASSERT( SUCCEEDED(hr) );
    }
        
    pResultData->Release();

    //Now set isDeleted member so that the parent doesn't try to
    //to insert it again in OnShow. Admittedly, a hack...
    SetDeleted();

    return hr;
}

//==============================================================
//
// CResourceScope implementation 
//
//
CResourceScope::CResourceScope(CStaticNode *root):m_StaticNode(root)
{
	InitCom();

	bool result;
	result = Storage::GetResourceList (ResourceList);
	if (true == result)
	{ for (Storage::ResourceItemList::iterator i = ResourceList.begin (); i != ResourceList.end (); ++i)
		{
			if ( (*i)->Identity.Type == Storage::idnOwner ) {
				//
				// Resolve sids to names
				//

				std::wstring Name;
				if ( commonlib::nettools::GetNameByStringSid((*i)->Identity.Owner.Owner, Name) ) {
					StringCchCopy((*i)->Identity.Owner.Owner, 
								  sizeof (*i)->Identity.Owner.Owner / sizeof (*i)->Identity.Owner.Owner[0], 
								  Name.c_str());
				}
			}
			CResourceResult *rr = new CResourceResult(static_cast <Storage::PtrToResourceItem> (*i), this, m_StaticNode);
			m_children.push_back(rr);
		}
	}
	m_ipConsole = NULL;
	m_ipDataObject = NULL;
	m_CompData = NULL;
}

CResourceScope::~CResourceScope()
{
     
	for (RESLIST::iterator iter = m_children.begin(); iter != m_children.end(); iter++)
	{
		delete (*iter);
	}

}

HRESULT CResourceScope::OnShow(IConsole *pConsole, BOOL bShow, HSCOPEITEM scopeitem)
{
    HRESULT      hr = S_OK;

    IHeaderCtrl *pHeaderCtrl = NULL;
    IResultData *pResultData = NULL;
	
	m_pConsole = pConsole;
    m_hParentHScopeItem = scopeitem;

	if (bShow) {
        hr = pConsole->QueryInterface(IID_IHeaderCtrl, (void **)&pHeaderCtrl);
        _ASSERT( SUCCEEDED(hr) );

        hr = pConsole->QueryInterface(IID_IResultData, (void **)&pResultData);
        _ASSERT( SUCCEEDED(hr) );

        // Set the column headers in the results pane
          hr = pHeaderCtrl->InsertColumn( 0, L"Identity", 0, MMCLV_AUTO );
        _ASSERT( S_OK == hr );
        hr = pHeaderCtrl->InsertColumn( 1, L"Type", 0, MMCLV_AUTO );
        _ASSERT( S_OK == hr );
        hr = pHeaderCtrl->InsertColumn( 2, L"Class", 0, MMCLV_AUTO );
        _ASSERT( S_OK == hr );

		EnumerateResultItems(pResultData);

        pHeaderCtrl->Release();
        pResultData->Release();
    }

    return hr;
}

HRESULT CResourceScope::OnViewChange(IConsole *pConsole, LPDATAOBJECT ipDataObject, LPARAM nArg, LPARAM nParam, LONG_PTR pComponent)
{
	HRESULT hr = S_FALSE;
	LPRESULTDATA ipResultData = NULL;

	hr = pConsole->QueryInterface(IID_IResultData, (void **)&ipResultData);
    _ASSERT( SUCCEEDED(hr) );

	CComponent* pComp = reinterpret_cast<CComponent*>(pComponent);
	LONG_PTR pScopeCookie = pComp->GetScopeCookie();

	if ( pScopeCookie == (LONG_PTR)this )
		hr = EnumerateResultItems(ipResultData);

	ipResultData->Release();

	return hr;
}

//*************************************************************************
INT_PTR CALLBACK CResourceScope::DialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CResourceScope *pResource = NULL;
	HRESULT hr;
	int i = 0;
  
	switch (uMsg) 
    {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pResource = reinterpret_cast<CResourceScope *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
	   // catch the "this" pointer so we can actually operate on the object
     	for (Storage::SECMAP_ITER iter = pResource->m_StaticNode->SecureTypeMap.begin(); iter != pResource->m_StaticNode->SecureTypeMap.end(); i++, iter++)
			{   
				SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_ADDSTRING, 0, 
                                   (LPARAM)iter->second.c_str()); 
				SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_SETITEMDATA, i, (LPARAM)iter->first);
			}
			SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_SETCURSEL, 0, 0); 

			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttFile));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttKey));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttDevice));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttNetwork));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttSystemObject));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttSection));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_ADDSTRING, 0, (LPARAM)GetNtTypeString(nttAny));
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 0, (LPARAM)nttFile);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 1, (LPARAM)nttKey);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 2, (LPARAM)nttDevice);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 3, (LPARAM)nttNetwork);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 4, (LPARAM)nttSystemObject);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 5, (LPARAM)nttSection);
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETITEMDATA, 6, (LPARAM)nttAny);
			
			SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SETCURSEL, 0, 0); 

			SendDlgItemMessage(hwndDlg,IDC_RADIO_OWNER, BM_SETCHECK, BST_CHECKED, 0);
			SetDlgItemText(hwndDlg, IDC_DESCRIPTION, ResourceString<>(IDS_OWNER_DESC));
			SetFocus(GetDlgItem(hwndDlg,IDC_NAME_E));
				

        break;

     case WM_COMMAND:
        // turn the Apply button on
        //if (HIWORD(wParam) == EN_CHANGE ||
        //    HIWORD(wParam) == CBN_SELCHANGE)
        //   SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);

		if (HIWORD(wParam) == BN_CLICKED) 
           { 
            switch (LOWORD(wParam)) 
             { 
            
			  case IDC_OWNER_BROWSE: 
				OnSelusers(hwndDlg);
			  break;
			  
			  case IDC_RADIO_OWNER: 
				EnableWindow(GetDlgItem(hwndDlg,IDC_RESTYPE),true);
				SetFocus(GetDlgItem(hwndDlg,IDC_NAME_E));
				EnableWindow(GetDlgItem(hwndDlg,IDC_OWNER_BROWSE),true); 
				SetDlgItemText(hwndDlg, IDC_DESCRIPTION, ResourceString<>(IDS_OWNER_DESC));
				break; 

              case IDC_RADIO_NAME: 
				 
				EnableWindow(GetDlgItem(hwndDlg,IDC_RESTYPE),true);
				EnableWindow(GetDlgItem(hwndDlg,IDC_OWNER_BROWSE),false); 
				SetFocus(GetDlgItem(hwndDlg,IDC_NAME_E));
				SetDlgItemText(hwndDlg, IDC_DESCRIPTION, ResourceString<>(IDS_NAME_DESC));
				 break;

              case IDC_RADIO_CERT: 
				EnableWindow(GetDlgItem(hwndDlg,IDC_OWNER_BROWSE),false); 
				SetFocus(GetDlgItem(hwndDlg,IDC_NAME_E));
				SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_SELECTSTRING, -1, (LPARAM)GetNtTypeString(nttFile)); 
				EnableWindow(GetDlgItem(hwndDlg,IDC_RESTYPE),false);
				SetDlgItemText(hwndDlg, IDC_DESCRIPTION, ResourceString<>(IDS_CERT_DESC));
			
				 break; 

			  } 
            } 
        break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pResource->m_ppHandle);
        break;

    case WM_NOTIFY:
		
        if (((NMHDR *) lParam)->code == PSN_APPLY )
		{
			if ( pResource->MainThreadId != GetCurrentThreadId() ) return pResource->ComDialogProc((WNDPROC)DialogProc, hwndDlg, uMsg, wParam, lParam);

			int n = 0, result = 0;
			Storage::ResourceItem RI;
			//SecureZeroMemory(pResource->Resource, sizeof(ResourceItem));
			
			int class_selection = (int)SendDlgItemMessage(hwndDlg, IDC_SECUR, CB_GETCURSEL, 0, 0);
			int sec_class = (int)SendDlgItemMessage(hwndDlg,IDC_SECUR, CB_GETITEMDATA, class_selection , 0);
			//pResource->RC->m_Resource->Params.Id = sec_class;
			RI.Params.Id = sec_class;
			
			int type_selection = (int)SendDlgItemMessage(hwndDlg, IDC_RESTYPE, CB_GETCURSEL, 0, 0);
			NtObjectType type = (NtObjectType)SendDlgItemMessage(hwndDlg,IDC_RESTYPE, CB_GETITEMDATA, type_selection , 0);
				
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_OWNER, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{    n = (int)SendDlgItemMessage(hwndDlg, IDC_NAME_E, WM_GETTEXTLENGTH, 0, 0);
				if (n != 0) {
				GetDlgItemText(hwndDlg, IDC_NAME_E,RI.Identity.Owner.Owner /*pResource->RC->m_Resource->Identity.Owner.Owner*/, n + 1);
				}else
					{  MessageBox(hwndDlg,L"Resource string can not be empty.",L"Resource error",MB_OK|MB_ICONINFORMATION);
						break;
					}
				RI.Identity.Owner.Type = type;
				RI.Identity.Owner.param_type = Storage::parResource;
				RI.Identity.Type = Storage::idnOwner;
				RI.Identity.Owner.ParentId = sec_class;
				Storage::OwnerInfo Owner = RI.Identity.Owner;
				std::wstring StringSid;
				if ( commonlib::nettools::GetStringSidByName(Owner.Owner, StringSid) ) {
					StringCchCopy(Owner.Owner, sizeof Owner.Owner / sizeof Owner.Owner[0], StringSid.c_str());
				}
				RI.Identity.Owner.Options = Storage::dboUserCreated;
				try {
					Storage::InsertOwner(Owner, result);
					RI.Identity.Owner.Id = result;
					pResource->m_StaticNode->PolicyChanged();
				} catch ( ... ) {
					MessageBox(hwndDlg,L"Owner resource insert is failed",L"Database error",MB_OK|MB_ICONINFORMATION);
				}
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_NAME, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{    n = (int)SendDlgItemMessage(hwndDlg, IDC_NAME_E, WM_GETTEXTLENGTH, 0, 0);
				if (n != 0) {
				GetDlgItemText(hwndDlg, IDC_NAME_E, RI.Identity.Path.Path/*RC->m_Resource->Identity.Path.Path*/, n + 1);
				}
				RI.Identity.Path.Type = type;
				RI.Identity.Path.param_type = Storage::parResource;
				RI.Identity.Type = Storage::idnPath;
				RI.Identity.Path.ParentId = sec_class;
				RI.Identity.Path.Options = Storage::dboUserCreated;
				try {
					result = Storage::InsertPath(RI.Identity.Path);
					RI.Identity.Path.Id = result;
					pResource->m_StaticNode->PolicyChanged();
				} catch ( ... ) {
					MessageBox(hwndDlg,L"Path resource insert is failed",L"Database error",MB_OK|MB_ICONINFORMATION);
				}
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_CERT, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{    n = (int)SendDlgItemMessage(hwndDlg, IDC_NAME_E, WM_GETTEXTLENGTH, 0, 0);
				if (n != 0) {
				GetDlgItemText(hwndDlg, IDC_NAME_E, RI.Identity.Cert.IssuedTo/*pResource->RC->m_Resource->Identity.Cert.IssuedTo*/, n + 1);
				}
				RI.Identity.Type = Storage::idnCertificate;
				RI.Identity.Cert.param_type = Storage::parResource;
				RI.Identity.Cert.ParentId = sec_class;
				RI.Identity.Cert.Type = Storage::crtUnknown;
				RI.Identity.Cert.ThumbprintSize = 1;
				memset(RI.Identity.Cert.Thumbprint, 0, sizeof RI.Identity.Cert.Thumbprint);
				StringCchCopy(RI.Identity.Cert.IssuedBy, sizeof RI.Identity.Cert.IssuedBy / sizeof wchar_t, L"N/A");
				RI.Identity.Cert.Expiration = 0;
				RI.Identity.Cert.Options = Storage::dboUserCreated;
				try {
					Storage::InsertCertificate(RI.Identity.Cert, result);
					RI.Identity.Cert.Id = result;
					pResource->m_StaticNode->PolicyChanged();
				} catch ( ... ) {
					MessageBox(hwndDlg,L"Certificate resource insert is failed",L"Database error",MB_OK|MB_ICONINFORMATION);
				}
			}

			if ( result != 0 ) {
				pResource->AddResource(RI);
				//
				// Send update notification to gswserv
				//
				GswClient Client;
				Client.RefreshResources();
			}
			hr = MMCPropertyChangeNotify(pResource->m_ppHandle, (LPARAM)pResource);
			_ASSERT(SUCCEEDED(hr));
			return PSNRET_NOERROR;
        }
    }

    return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

//*******************

HRESULT CResourceScope::OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    HRESULT hr = S_OK;
    CONTEXTMENUITEM menuItemsNew[] =
    {
        {
            L"Add resource...", L"Add new resource",
                ID_ADD_RESOURCE, CCM_INSERTIONPOINTID_PRIMARY_TOP, 0, CCM_SPECIAL_DEFAULT_ITEM
        },
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


HRESULT CResourceScope::AddResource(const Storage::ResourceItem &RI)

{  
	Storage::PtrToResourceItem itemResource (new Storage::ResourceItem ());
	*itemResource = RI;
	
	CResourceResult *rr = new CResourceResult(static_cast<Storage::PtrToResourceItem>(itemResource), this, m_StaticNode);
	m_children.push_back(rr); 

	HRESULT hr = m_ipConsole->UpdateAllViews(m_ipDataObject, 0, 0);
    _ASSERT( S_OK == hr);

	return S_OK;
}

HRESULT CResourceScope::OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
    switch (lCommandID)
    {
    case ID_ADD_RESOURCE:
      
		m_ipConsole = pConsole;
		m_ipDataObject = piDataObject;
		m_CompData = pComData;

		InvokeAddResource(pConsole, piDataObject, pComData);

		break;
    }
    
    return S_OK;
}

HRESULT CResourceScope::HasPropertySheets()
{
    // say "yes" when MMC asks if we have pages
    
	return S_OK;
}

HRESULT CResourceScope::CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle)
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
    psp.pszTemplate = MAKEINTRESOURCE(IDD_RESOURCE1);
    psp.pfnDlgProc =  DialogProc;
    psp.lParam = reinterpret_cast<LPARAM>(this);
    psp.pszTitle = MAKEINTRESOURCE(IDS_PST_ROCKET);
    //psp.pszIcon = MAKEINTRESOURCE(IDI_PSI_ROCKET);


    hPage = CreatePropertySheetPage(&psp);
    _ASSERT(hPage);

    return lpProvider->AddPage(hPage);
}

HRESULT CResourceScope::GetWatermarks(HBITMAP *lphWatermark,
                               HBITMAP *lphHeader,
                               HPALETTE *lphPalette,
                               BOOL *bStretch)
{
    return S_FALSE;
}



HRESULT CResourceScope::InvokeAddResource(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData)
{
    HRESULT hr = S_FALSE;
    LPCWSTR szTitle = L"Resource";

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
	
    hr = pPropertySheetProvider->Show((LONG_PTR)hWnd,0); 
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

HRESULT CResourceScope::EnumerateResultItems(LPRESULTDATA pResultData)
{
	_ASSERT( NULL != pResultData );
	HRESULT hr = S_FALSE;
    // insert items here
    RESULTDATAITEM rdi;

	hr = pResultData->DeleteAllRsltItems();
    _ASSERT( SUCCEEDED(hr) );

    if (!bExpanded) {
		// create the child nodes, then expand them
        for (RESLIST::iterator iter = m_children.begin(); iter != m_children.end(); iter++) {
			    if(!(*iter)->getDeletedStatus()) {
	 			ZeroMemory(&rdi, sizeof(RESULTDATAITEM) );
                rdi.mask       = RDI_STR  | RDI_IMAGE  |  RDI_PARAM;   

                rdi.nImage      = (*iter)->GetBitmapIndex();
                rdi.str         = MMC_CALLBACK;
                rdi.nCol        = 0;
                rdi.lParam      = (LPARAM)(*iter);

                hr = pResultData->InsertItem( &rdi );

                _ASSERT( SUCCEEDED(hr) );
		   }
        }
	}

	return hr; 
}
