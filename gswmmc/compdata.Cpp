//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "Comp.h"
#include "CompData.h"
#include "BaseSnap.h"
#include "DataObj.h"
#include "guids.h"
#include "resource.h"
#include <crtdbg.h>

extern CComponentData* g_ComponentData;


// we need to do this to get around MMC.IDL - it explicitly defines
// the clipboard formats as WCHAR types...
#define _T_CCF_DISPLAY_NAME _T("CCF_DISPLAY_NAME")
#define _T_CCF_NODETYPE _T("CCF_NODETYPE")
#define _T_CCF_SNAPIN_CLASSID _T("CCF_SNAPIN_CLASSID")

// These are the clipboard formats that we must supply at a minimum.
// mmc.h actually defined these. We can make up our own to use for
// other reasons. We don't need any others at this time.
UINT CComponentData::s_cfDisplayName = RegisterClipboardFormat(_T_CCF_DISPLAY_NAME);
UINT CComponentData::s_cfNodeType    = RegisterClipboardFormat(_T_CCF_NODETYPE);
UINT CComponentData::s_cfSnapInCLSID = RegisterClipboardFormat(_T_CCF_SNAPIN_CLASSID);

 
// {8FC0B739-A0E1-11D1-A7D3-0000F87571E3}
const GUID CComponentData::gpGuid = 
  { 0x8FC0B739, 0xA0E1, 0x11D1, { 0xA7, 0xD3, 0x0, 0x0, 0xF8, 0x75, 0x71, 0xE3 } };

CComponentData::CComponentData()
: m_cref(0), m_ipConsoleNameSpace(NULL), m_ipConsole(NULL), m_bInitialExpand(FALSE)
{
    m_pStaticNode = NULL;
//	m_pRootFolder = NULL;
	m_bInitialExpand = FALSE;

	OBJECT_CREATED;
	g_ComponentData = this;

	
    m_pStaticNode = new CStaticNode();

/* 
		if(exist(HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MMC\\SnapIns\\{snapin guid}\\Standalone))
		  m_pRootFolder = new CRootFolder();
		  else m_pStaticNode = new CStaticNode;

*/
}

CComponentData::~CComponentData()
{
    if (m_pStaticNode) {
        delete m_pStaticNode;
    }

    OBJECT_DESTROYED;
		if(g_ComponentData == this)
		g_ComponentData = NULL;
}

///////////////////////
// IUnknown implementation
///////////////////////

STDMETHODIMP CComponentData::QueryInterface(REFIID riid, LPVOID *ppv)
{
    if (!ppv)
        return E_FAIL;

    *ppv = NULL;

    if (IsEqualIID(riid, IID_IUnknown))
        *ppv = static_cast<IComponentData *>(this);
    else if (IsEqualIID(riid, IID_IComponentData))
        *ppv = static_cast<IComponentData *>(this);
	 else if (IsEqualIID(riid, IID_IExtendContextMenu))
        *ppv = static_cast<IExtendContextMenu *>(this);

    // first things first, make sure that when MMC
    // asks if we do property sheets, that we actually
    // say "yes"
    else if (IsEqualIID(riid, IID_IExtendPropertySheet) ||
        IsEqualIID(riid, IID_IExtendPropertySheet2))
        *ppv = static_cast<IExtendPropertySheet2 *>(this);

    else if (IsEqualIID(riid, IID_ISnapinHelp2))
        *ppv = static_cast<ISnapinHelp2*>(this);

    if (*ppv)
    {
        reinterpret_cast<IUnknown *>(*ppv)->AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CComponentData::AddRef()
{
    return InterlockedIncrement((LONG *)&m_cref);
}

STDMETHODIMP_(ULONG) CComponentData::Release()
{
    if (InterlockedDecrement((LONG *)&m_cref) == 0)
    {
        // we need to decrement our object count in the DLL
        delete this;
        return 0;
    }

    return m_cref;
}

///////////////////////////////
// Interface IComponentData
///////////////////////////////
HRESULT CComponentData::Initialize(
                                   /* [in] */ LPUNKNOWN pUnknown)
{
    HRESULT      hr;

    //
    // Get pointer to name space interface
    //
    hr = pUnknown->QueryInterface(IID_IConsoleNameSpace, (void **)&m_ipConsoleNameSpace);
    _ASSERT( S_OK == hr );

    //
    // Get pointer to console interface
    //
    hr = pUnknown->QueryInterface(IID_IConsole, (void **)&m_ipConsole);
    _ASSERT( S_OK == hr );

    IImageList *pImageList;
    m_ipConsole->QueryScopeImageList(&pImageList);
    _ASSERT( S_OK == hr );

    hr = pImageList->ImageListSetStrip( (long *)m_pStaticNode->m_pBMapSm, // pointer to a handle
        (long *)m_pStaticNode->m_pBMapLg, // pointer to a handle
        0, // index of the first image in the strip
        RGB(0, 128, 128)  // color of the icon mask
        );

    pImageList->Release();

    return S_OK;
}
	
HRESULT CComponentData::CreateComponent(
                                        /* [out] */ LPCOMPONENT __RPC_FAR *ppComponent)
{
    *ppComponent = NULL;

    CComponent *pComponent = new CComponent(this);

    if (NULL == pComponent)
        return E_OUTOFMEMORY;

     HRESULT hr = pComponent->QueryInterface(IID_IComponent, (void **)ppComponent);
	
	if(S_OK == hr)
	{
		LPVOID pVoid = this;
		(*ppComponent)->AddRef();
		(*ppComponent)->QueryDataObject((MMC_COOKIE)&pVoid, CCT_UNINITIALIZED, NULL);
		m_pComponent = (CComponent*)pVoid;
	}
	return hr;
}

HRESULT CComponentData::Notify(
                               /* [in] */ LPDATAOBJECT lpDataObject,
                               /* [in] */ MMC_NOTIFY_TYPE event,
                               /* [in] */ LPARAM arg,
                               /* [in] */ LPARAM param)
{
    MMCN_Crack(TRUE, lpDataObject, this, NULL, event, arg, param);

	HRESULT hr = S_FALSE;
    CDataObject *pDataObject = GetOurDataObject(lpDataObject);
	CDelegationBase *base; 
	GUID myGuid;
	GUID* pGUID= &myGuid;

	if (NULL == pDataObject)
	{ base = m_pStaticNode;  }
	else
		base = pDataObject->GetBaseNodeObject();

	if (MMCN_PROPERTY_CHANGE == event) {
        base = (CDelegationBase *)param;
    }

	switch (event)
	{
		
	
		case MMCN_EXPAND:

			
			// extract GUID of the the currently selected node type from the data object
			hr = ExtractObjectTypeGUID(lpDataObject, pGUID);
			_ASSERT( S_OK == hr );

			if ( m_bInitialExpand == FALSE )
			{
				hr = base->OnInitialExpand(m_ipConsoleNameSpace, m_ipConsole, lpDataObject);
				m_bInitialExpand = TRUE;
			}

			// compare node type GUIDs of currently selected node and the node type 
			// we want to extend. If they are are equal, currently selected node
			// is the type we want to extend, so we add our items underneath it
			if (IsEqualGUID(*pGUID, getPrimaryNodeType()))
				// return S_OK;
				base->OnExpand(m_ipConsoleNameSpace, m_ipConsole, (HSCOPEITEM)param);

			else
			// currently selected node is one of ours instead
			{
				hr = base->OnExpand(m_ipConsoleNameSpace, m_ipConsole, (HSCOPEITEM)param);
			}

			break;

		case MMCN_PROPERTY_CHANGE:
			hr = base->OnPropertyChange(m_ipConsole, m_pComponent);
			break;

		case MMCN_SELECT:
			hr = base->OnSelect( m_pComponent,m_ipConsole, (BOOL)LOWORD(arg), (BOOL)HIWORD(arg));
			break;
		
		case MMCN_ADD_IMAGES:
			hr = base->OnAddImages((IImageList *)arg, (HSCOPEITEM)param);
			break;	
			
		// we dont handle these ones for now
		case MMCN_LISTPAD:
		case MMCN_SHOW:
		case MMCN_RENAME:
		case MMCN_CONTEXTHELP:
		case MMCN_ACTIVATE:
		case MMCN_BTN_CLICK:
		case MMCN_COLUMN_CLICK:
		case MMCN_CUTORMOVE:
		case MMCN_DBLCLICK:
		case MMCN_DELETE:
			hr = base->OnDelete(this, m_ipConsole);
			break;
		

		case MMCN_DESELECT_ALL:
		case MMCN_MENU_BTNCLICK:
		case MMCN_MINIMIZED:
		case MMCN_PASTE:
		case MMCN_QUERY_PASTE:
		case MMCN_REFRESH:
		case MMCN_REMOVE_CHILDREN:
		case MMCN_VIEW_CHANGE:
		case MMCN_SNAPINHELP:
		case MMCN_INITOCX:
		case MMCN_FILTER_CHANGE:
		case MMCN_FILTERBTN_CLICK:
		case MMCN_RESTORE_VIEW:
		case MMCN_PRINT:
		case MMCN_PRELOAD:
		case MMCN_EXPANDSYNC:
		case MMCN_COLUMNS_CHANGED:
			break;						
			
	}	
	
    return hr;
}




HRESULT CComponentData::Destroy( void)
{
    // Free interfaces
    if (m_ipConsoleNameSpace) {
        m_ipConsoleNameSpace->Release();
        m_ipConsoleNameSpace = NULL;
    }

    if (m_ipConsole) {
        m_ipConsole->Release();
        m_ipConsole = NULL;
    }

    return S_OK;
}

HRESULT CComponentData::QueryDataObject(
                                        /* [in] */ MMC_COOKIE cookie,
                                        /* [in] */ DATA_OBJECT_TYPES type,
                                        /* [out] */ LPDATAOBJECT *ppDataObject)
{
    CDataObject *pObj = NULL;

    if (cookie == 0)
        pObj = new CDataObject((MMC_COOKIE)m_pStaticNode, type);
    else
        pObj = new CDataObject(cookie, type);

    if (!pObj)
        return E_OUTOFMEMORY;

    pObj->QueryInterface(IID_IDataObject, (void **)ppDataObject);

    return S_OK;
}

HRESULT CComponentData::GetDisplayInfo(
                                       SCOPEDATAITEM *pScopeDataItem)
{
    HRESULT hr = S_FALSE;

    // if they are asking for the SDI_STR we have one of those to give
    if (pScopeDataItem->lParam) {
        CDelegationBase *base = (CDelegationBase *)pScopeDataItem->lParam;
        if (pScopeDataItem->mask & SDI_STR) {
                        LPCTSTR pszT = base->GetDisplayName();
                        MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, pszT);
            pScopeDataItem->displayname = pszW;
        }

        if (pScopeDataItem->mask & SDI_IMAGE) {
            pScopeDataItem->nImage = base->GetBitmapIndex();
        }
		 if (pScopeDataItem->mask & SDI_OPENIMAGE) {
            pScopeDataItem->nOpenImage = base->GetBitmapIndex();
        }
    }

    return hr;
}

HRESULT CComponentData::CompareObjects(
                                       /* [in] */ LPDATAOBJECT lpDataObjectA,
                                       /* [in] */ LPDATAOBJECT lpDataObjectB)
{
    CDelegationBase *baseA = GetOurDataObject(lpDataObjectA)->GetBaseNodeObject();
    CDelegationBase *baseB = GetOurDataObject(lpDataObjectB)->GetBaseNodeObject();

    // compare the object pointers
    if (baseA->GetCookie() == baseB->GetCookie())
        return S_OK;

    return S_FALSE;
}

///////////////////////////////////
// Interface IExtendPropertySheet2
///////////////////////////////////
HRESULT CComponentData::CreatePropertyPages(
                                            /* [in] */ LPPROPERTYSHEETCALLBACK lpProvider,
                                            /* [in] */ LONG_PTR handle,
                                            /* [in] */ LPDATAOBJECT lpIDataObject)
{
    CDelegationBase *base = GetOurDataObject(lpIDataObject)->GetBaseNodeObject();

    return base->CreatePropertyPages(lpProvider, handle);
}

HRESULT CComponentData::QueryPagesFor(
                                      /* [in] */ LPDATAOBJECT lpDataObject)
{
    CDelegationBase *base = GetOurDataObject(lpDataObject)->GetBaseNodeObject();

    return base->HasPropertySheets();
}

HRESULT CComponentData::GetWatermarks(
                                      /* [in] */ LPDATAOBJECT lpIDataObject,
                                      /* [out] */ HBITMAP __RPC_FAR *lphWatermark,
                                      /* [out] */ HBITMAP __RPC_FAR *lphHeader,
                                      /* [out] */ HPALETTE __RPC_FAR *lphPalette,
                                      /* [out] */ BOOL __RPC_FAR *bStretch)
{
    CDelegationBase *base = GetOurDataObject(lpIDataObject)->GetBaseNodeObject();

    return base->GetWatermarks(lphWatermark, lphHeader, lphPalette, bStretch);
}

///////////////////////////////
// Interface IExtendContextMenu
///////////////////////////////
HRESULT CComponentData::AddMenuItems(
                                     /* [in] */ LPDATAOBJECT piDataObject,
                                     /* [in] */ LPCONTEXTMENUCALLBACK piCallback,
                                     /* [out][in] */ long __RPC_FAR *pInsertionAllowed)
{
    CDelegationBase *base = GetOurDataObject(piDataObject)->GetBaseNodeObject();

    return base->OnAddMenuItems(piCallback, pInsertionAllowed);
}

HRESULT CComponentData::Command(
                                /* [in] */ long lCommandID,
                                /* [in] */ LPDATAOBJECT piDataObject)
{
    CDelegationBase *base = GetOurDataObject(piDataObject)->GetBaseNodeObject();

    return base->OnMenuCommand(m_ipConsole, lCommandID, piDataObject, this);
}



///////////////////////////////
// CComponentData::OnExpand
///////////////////////////////


///////////////////////////////
// Member functions for extracting
// information from a primary's 
// data object
///////////////////////////////

HRESULT CComponentData::ExtractData( IDataObject* piDataObject,
                                           CLIPFORMAT   cfClipFormat,
                                           BYTE*        pbData,
                                           DWORD        cbData )
{
    HRESULT hr = S_OK;
    
    FORMATETC formatetc = {cfClipFormat, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM stgmedium = {TYMED_HGLOBAL, NULL};
    
    stgmedium.hGlobal = ::GlobalAlloc(GPTR, cbData);
    do // false loop
    {
        if (NULL == stgmedium.hGlobal)
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        hr = piDataObject->GetDataHere( &formatetc, &stgmedium );
        if ( FAILED(hr) )
        {
            break;
        }
        
        BYTE* pbNewData = reinterpret_cast<BYTE*>(stgmedium.hGlobal);
        if (NULL == pbNewData)
        {
            hr = E_UNEXPECTED;
            break;
        }
        ::memcpy( pbData, pbNewData, cbData );
    } while (FALSE); // false loop
    
    if (NULL != stgmedium.hGlobal)
    {
        ::GlobalFree(stgmedium.hGlobal);
    }
    return hr;
} // ExtractData()

HRESULT CComponentData::ExtractString( IDataObject *piDataObject,
                                             CLIPFORMAT   cfClipFormat,
                                             _TCHAR       *pstr,
                                             DWORD        cchMaxLength)
{
    return ExtractData( piDataObject, cfClipFormat, (PBYTE)pstr, cchMaxLength );
}

HRESULT CComponentData::ExtractSnapInCLSID( IDataObject* piDataObject, CLSID* pclsidSnapin )
{
    return ExtractData( piDataObject, s_cfSnapInCLSID, (PBYTE)pclsidSnapin, sizeof(CLSID) );
}

HRESULT CComponentData::ExtractObjectTypeGUID( IDataObject* piDataObject, GUID* pguidObjectType )
{
    return ExtractData( piDataObject, s_cfNodeType, (PBYTE)pguidObjectType, sizeof(GUID) );
}

HRESULT CComponentData::GetHelpTopic(/* [out] */ LPOLESTR *lpCompiledHelpFile)
{
	static const wchar_t *HelpFileName = L"";
    *lpCompiledHelpFile = static_cast<LPOLESTR>(CoTaskMemAlloc((wcslen(HelpFileName) + 1) * sizeof(WCHAR)));
    wcscpy(*lpCompiledHelpFile, HelpFileName);
    
    return S_OK;
}
