//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "Comp.h"
#include "DataObj.h"
#include <commctrl.h>        // Needed for button styles...
#include <crtdbg.h>
#include "globals.h"
#include "resource.h"
#include "DeleBase.h"
#include "CompData.h"
#include "Resources.h"
#include "Applications.h"

extern CComponent*		g_Component;

CComponent::CComponent(CComponentData *parent)
: m_pComponentData(parent),m_pParent(parent), m_cref(0), m_ipConsole(NULL), m_ipDisplayHelp(NULL)
{
    OBJECT_CREATED;
	g_Component = this;
	m_pScopeCookie = 0;
}

CComponent::~CComponent()
{
    OBJECT_DESTROYED;
	if(g_Component == this)
		g_Component = NULL;
}

STDMETHODIMP CComponent::QueryInterface(REFIID riid, LPVOID *ppv)
{
    if (!ppv)
        return E_FAIL;

    *ppv = NULL;

    if (IsEqualIID(riid, IID_IUnknown))
        *ppv = static_cast<IComponent *>(this);
    else if (IsEqualIID(riid, IID_IComponent))
        *ppv = static_cast<IComponent *>(this);

    // first things first, make sure that when MMC
    // asks if we do property sheets, that we actually
    // say "yes"
     else if (IsEqualIID(riid, IID_IExtendPropertySheet))
        *ppv = static_cast<IExtendPropertySheet *>(this);
     else if (IsEqualIID(riid, IID_IExtendPropertySheet2))
        *ppv = static_cast<IExtendPropertySheet2 *>(this);
	 else if (IsEqualIID(riid, IID_IExtendContextMenu))
        *ppv = static_cast<IExtendContextMenu *>(this);
	 else if (IsEqualIID(riid, IID_IExtendTaskPad))
        *ppv = static_cast<IExtendTaskPad *>(this);


    if (*ppv)
    {
        reinterpret_cast<IUnknown *>(*ppv)->AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CComponent::AddRef()
{
    return InterlockedIncrement((LONG *)&m_cref);
}

STDMETHODIMP_(ULONG) CComponent::Release()
{
    if (InterlockedDecrement((LONG *)&m_cref) == 0)
    {
        delete this;
        return 0;
    }
    return m_cref;

}

///////////////////////////////
// Interface IComponent
///////////////////////////////
STDMETHODIMP CComponent::Initialize(
                                    /* [in] */ LPCONSOLE lpConsole)
{
    HRESULT hr = S_OK;

    // Save away all the interfaces we'll need.
    // Fail if we can't QI the required interfaces.

    m_ipConsole = lpConsole;
    m_ipConsole->AddRef();

	  hr = m_ipConsole->QueryInterface(IID_IConsole2,
        reinterpret_cast<void**>(&m_ipConsole2));

    _ASSERT( NULL != m_ipConsole2 );

    hr = m_ipConsole2->IsTaskpadViewPreferred();
    m_bIsTaskpadPreferred = (hr == S_OK) ? TRUE : FALSE;
	
    return hr;
}

STDMETHODIMP CComponent::Notify(
                                /* [in] */ LPDATAOBJECT lpDataObject,
                                /* [in] */ MMC_NOTIFY_TYPE event,
                                /* [in] */ LPARAM arg,
                                /* [in] */ LPARAM param)
{
	MMCN_Crack(FALSE, lpDataObject, NULL, this, event, arg, param);

    HRESULT hr = S_FALSE;
    CDelegationBase *base = NULL;
	static CDelegationBase *pLastPasteQuery = NULL;
 

    if (MMCN_CUTORMOVE == event && pLastPasteQuery != NULL)
    {
        //arg contains the data object of the cut object
        //we get its CDelegationBase and then cast it
        //to its proper type.
        CDelegationBase *base = GetOurDataObject( (LPDATAOBJECT)arg )->GetBaseNodeObject();
        CApplicationItem *pApplicationItem = dynamic_cast<CApplicationItem *>(base);

        if (NULL == pApplicationItem)
        {// The cut item is a scope item. Delete it.
            CGroupFolder * pGroup = dynamic_cast<CGroupFolder*>(base);
            if (NULL != pGroup)
            {
				hr = pGroup->OnDeleteScopeItem(m_pParent->GetConsoleNameSpace());

            }
			
              return hr;
        }
		
		
		// ?? hr = pApplicationItem->OnDeleteScopeItem(m_pParent->GetConsoleNameSpace());
		pApplicationItem->OnDeleteScopeItem(m_pParent->GetConsoleNameSpace());

        //Update the source scope item in all views. We need
        //a dummy data object for UpdateAllViews.
        //pLastPasteQuery is the lpDataObject of the source scope item
        //See MMCN_SHOW below
        IDataObject *pDummy = NULL;
        hr = (HRESULT) m_pParent->m_ipConsole->UpdateAllViews(pDummy, (long)(pLastPasteQuery->GetParentScopeItem()), UPDATE_SCOPEITEM);
        _ASSERT( S_OK == hr);

        return S_OK;
    }
    // we need to watch for property change and delegate it
    // a little differently, we're actually going to send
    // the CDelegationBase object pointer in the property page
    // PSN_APPLY handler via MMCPropPageNotify()
    if (MMCN_PROPERTY_CHANGE != event && MMCN_VIEW_CHANGE != event) {
        if ( NULL == lpDataObject )
            return S_FALSE;

		CDataObject *pDataObject = GetOurDataObject(lpDataObject);
		if ( pDataObject == NULL ) {
			// special data object?
			return S_FALSE;
		}
        base = pDataObject->GetBaseNodeObject();

    } else if (MMCN_PROPERTY_CHANGE == event) {
        base = (CDelegationBase *)param;
    }


	// MMCN_VIEW_CHANGE

	if (MMCN_VIEW_CHANGE == event) {	

		switch (param) 
		{				//arg holds the data. For a scope item, this is the
						//item's myhscopeitem. For a result item, this is
						//the item's nId value, but we don't use it

						//param holds the hint passed to IConsole::UpdateAllViews.
					    //hint is a value of the UPDATE_VIEWS_HINT enumeration
		
		case UPDATE_SCOPEITEM:
			hr = m_ipConsole->SelectScopeItem( (HSCOPEITEM)arg );
			_ASSERT( S_OK == hr);
			break;
		case UPDATE_RESULTITEM:
			base = GetOurDataObject(lpDataObject)->GetBaseNodeObject();
			hr = base->OnUpdateItem(m_ipConsole, (long)arg, RESULT);
			break;
		default:
			base = GetOurDataObject(lpDataObject)->GetBaseNodeObject();
			hr = base->OnViewChange(m_ipConsole, lpDataObject, arg, param, (LONG_PTR)this);
			break;
		}

		return S_OK;
	}




	//The remaining notifications

    switch (event)      {
    case MMCN_SHOW:
		m_pScopeCookie = (LONG_PTR)base;
		if (arg)
        {//scope item selected
         //We use this for drag-and-drop operations.
            pLastPasteQuery = base;
        }

        hr = base->OnShow(m_ipConsole, (BOOL)arg, (HSCOPEITEM)param);
        break;

    case MMCN_ADD_IMAGES:
        hr = base->OnAddImages((IImageList *)arg, (HSCOPEITEM)param);
        break;

    case MMCN_SELECT:
		//check for multiselection
		if ( MMC_MULTI_SELECT_COOKIE == GetOurDataObject(lpDataObject)->GetCookie() ) {
			if ( (BOOL)LOWORD(arg) == 0 && (BOOL)HIWORD(arg) == 1 ) {
				//We need the cookie of any of the multiselection items to enable the delete verb for all the items.
				MMC_COOKIE ourCookie = GetOurDataObject(lpDataObject)->GetMultiSelectCookie(0);
	 
				base = reinterpret_cast<CDelegationBase *>(ourCookie);
				hr = base->OnSelect(this, m_ipConsole, (BOOL)LOWORD(arg), (BOOL)HIWORD(arg));
			}
			return hr;
		}  
		else {
	        hr = base->OnSelect(this, m_ipConsole, (BOOL)LOWORD(arg), (BOOL)HIWORD(arg));
		}
        break;

    case MMCN_LISTPAD:
        hr = base->OnListpad(m_ipConsole, (BOOL)arg);
        break;
	
	case MMCN_RENAME:
        hr = base->OnRename((LPOLESTR)param);

		//Now call IConsole::UpdateAllViews to redraw the item in all views.
		hr = m_pComponentData->m_ipConsole->UpdateAllViews(lpDataObject, 0, UPDATE_RESULTITEM);
		_ASSERT( S_OK == hr);		
		break;

	case MMCN_REFRESH:
		//we pass CComponentData's stored IConsole pointer here,
		//so that the IConsole::UpdateAllViews can be called in OnRefresh
		hr = base->OnRefresh(m_pComponentData->m_ipConsole);
		break;

	case MMCN_DELETE: {		
		//first delete the selected result item
		hr = base->OnDelete(m_pComponentData, m_pComponentData->m_ipConsole);

		//Now call IConsole::UpdateAllViews to redraw all views
		//owned by the parent scope item. OnRefresh already does
		//this for us, so use it.
		hr = base->OnRefresh(m_pComponentData->m_ipConsole);
		break;
	}
    // handle the property change notification if we need to do anything
    // special with it
    case MMCN_PROPERTY_CHANGE:
		//we pass CComponentData's stored IConsole pointer here,
		//so that the IConsole::UpdateAllViews can be called in OnPropertyChange
        hr = base->OnPropertyChange(m_pComponentData->m_ipConsole, this);
        break;
    

	case MMCN_QUERY_PASTE:
        {
            CDataObject *pPastedDO = GetOurDataObject((IDataObject *)arg);
            if (pPastedDO != NULL)
            {
                CDelegationBase *pasted = pPastedDO->GetBaseNodeObject();

                if (pasted != NULL)
                {
                    hr = base->OnQueryPaste(pasted);
                }
            }
        }
        break;

    case MMCN_PASTE:
        {
            CDataObject *pPastedDO = GetOurDataObject((IDataObject *)arg);
            if (pPastedDO != NULL)
            {
                CDelegationBase *pasted = pPastedDO->GetBaseNodeObject();

                if (pasted != NULL)
                {
                    hr = base->OnPaste(m_ipConsole, m_pParent, pasted);

                    if (hr == S_OK)
                    {
                        // Determine if the item to be pasted is scope or result item.
                        //CApplicationItem* pApplicationItem = dynamic_cast<CApplicationItem*>(pasted);
                        // BOOL bResult = pApplicationItem ? TRUE : FALSE;     
						// CDataObject *pObj = new CDataObject((MMC_COOKIE)pasted, bResult ? CCT_RESULT : CCT_SCOPE);

						
						// Application and group items are always scope items.
						CDataObject *pObj = new CDataObject((MMC_COOKIE)pasted, CCT_SCOPE);

                        if (!pObj)
                            return E_OUTOFMEMORY;

                        pObj->QueryInterface(IID_IDataObject, (void **)param);

                        //now update the destination scope item in all views.
                        //But only do this if this is not a drag-and-drop
                        //operation. That is, the destination scope item
                        //is the currently selected one.

                        if (pLastPasteQuery != NULL && pLastPasteQuery == base)
                        {
                            IDataObject *pDummy = NULL;
                            hr = (long) m_pParent->m_ipConsole->UpdateAllViews(pDummy,
                             (long)(pLastPasteQuery->GetParentScopeItem()), UPDATE_SCOPEITEM);
                            _ASSERT( S_OK == hr);
                        }
                    }
                }
            }
        }

        break;
	}

    return hr;
}

STDMETHODIMP CComponent::Destroy(
                                 /* [in] */ MMC_COOKIE cookie)
{
    if (m_ipConsole) {
        m_ipConsole->Release();
        m_ipConsole = NULL;
    }

    return S_OK;
}


STDMETHODIMP CComponent::QueryDataObject(
                                         /* [in] */ MMC_COOKIE cookie,
                                         /* [in] */ DATA_OBJECT_TYPES type,
                                         /* [out] */ LPDATAOBJECT __RPC_FAR *ppDataObject)
{
	HRESULT hr;
    CDataObject *pObj = NULL;
    CDelegationBase *pBase = NULL;

	//Use The IS_SPECIAL_COOKIE macro to see if cookie is a special cookie
	if ( IS_SPECIAL_COOKIE (cookie) && MMC_MULTI_SELECT_COOKIE == cookie ) {

		pObj = new CDataObject(cookie, type);
		if (!pObj) return E_OUTOFMEMORY;

		//create the multiselection data object
		hr = GetCurrentSelections(pObj);
		_ASSERT( SUCCEEDED(hr) ); 

		hr = pObj->QueryInterface(IID_IDataObject, (void **)ppDataObject);
		_ASSERT( SUCCEEDED(hr) ); 

		return hr;
	}
	
	// Remaining code for "regular" cookies, and for the next item during a multiselection
    if ( IsBadReadPtr((void *)cookie, sizeof(CDelegationBase)) ) {
		if (NULL == m_pLastNode) return E_FAIL;
        pBase = m_pLastNode->GetChildPtr((int)cookie);
    } else {
        pBase = (cookie == 0) ? m_pComponentData->m_pStaticNode : (CDelegationBase *)cookie;
    }

    if (pBase == NULL) return E_FAIL;

    pObj = new CDataObject((MMC_COOKIE)pBase, type);
    if (!pObj)
        return E_OUTOFMEMORY;

    pObj->QueryInterface(IID_IDataObject, (void **)ppDataObject);

    return S_OK;
}

STDMETHODIMP CComponent::GetResultViewType(
                                           /* [in] */ MMC_COOKIE cookie,
                                           /* [out] */ LPOLESTR __RPC_FAR *ppViewType,
                                           /* [out] */ long __RPC_FAR *pViewOptions)
{
    CDelegationBase *base = (CDelegationBase *)cookie;

    //
    // Ask for default listview.
    //
    if (base == NULL)
    {
		if(NULL == (base = m_pComponentData->m_pStaticNode))
		{
		*pViewOptions = MMC_VIEW_OPTIONS_NONE;
        *ppViewType = NULL;
		 return S_OK;
		}
    }
 
        return base->GetResultViewType(ppViewType, pViewOptions);

  }

STDMETHODIMP CComponent::GetDisplayInfo(
                                        /* [out][in] */ RESULTDATAITEM __RPC_FAR *pResultDataItem)
{
    HRESULT hr = S_OK;
    CDelegationBase *base = NULL;

    // if they are asking for the RDI_STR we have one of those to give

    if (pResultDataItem->lParam) 
	   {
        base = (CDelegationBase *)pResultDataItem->lParam;
        if (pResultDataItem->mask & RDI_STR) {
                        LPCTSTR pszT = base->GetDisplayName(pResultDataItem->nCol);
                        MAKE_WIDEPTR_FROMTSTR_ALLOC(pszW, pszT);
            pResultDataItem->str = pszW;
        }

        if (pResultDataItem->mask & RDI_IMAGE) {
            pResultDataItem->nImage = base->GetBitmapIndex();
        }
	
	   }
    return hr;
}


STDMETHODIMP CComponent::CompareObjects(
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
HRESULT CComponent::CreatePropertyPages(
                                        /* [in] */ LPPROPERTYSHEETCALLBACK lpProvider,
                                        /* [in] */ LONG_PTR handle,
                                        /* [in] */ LPDATAOBJECT lpIDataObject)
{
    CDelegationBase *base = GetOurDataObject(lpIDataObject)->GetBaseNodeObject();

    return base->CreatePropertyPages(lpProvider, handle);
}

HRESULT CComponent::QueryPagesFor(
                                  /* [in] */ LPDATAOBJECT lpDataObject)
{
    CDelegationBase *base = GetOurDataObject(lpDataObject)->GetBaseNodeObject();

    return base->HasPropertySheets();
}

HRESULT CComponent::GetWatermarks(
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
HRESULT CComponent::AddMenuItems(
                                     /* [in] */ LPDATAOBJECT piDataObject,
                                     /* [in] */ LPCONTEXTMENUCALLBACK piCallback,
                                     /* [out][in] */ long __RPC_FAR *pInsertionAllowed)
{
	CDataObject *DataObject = GetOurDataObject(piDataObject);
	if ( DataObject->GetCookie() == MMC_MULTI_SELECT_COOKIE ) {
		CDelegationBase *base = (CDelegationBase *) DataObject->GetMultiSelectCookie(0);
		return base->OnAddMenuItems(piCallback, pInsertionAllowed);
	}

    CDelegationBase *base = DataObject->GetBaseNodeObject();
    return base->OnAddMenuItems(piCallback, pInsertionAllowed);
}

HRESULT CComponent::Command(
                                /* [in] */ long lCommandID,
                                /* [in] */ LPDATAOBJECT piDataObject)
{
	//
	// special handling for deletion
	//
	//if ( lCommandID == ID_DELETE_UNTRUSTED_FILES ) {
	//	if ( MessageBox(GetForegroundWindow(), L"Are you sure you want to delete selected file(s)?", L"Delete", MB_YESNO) != IDYES ) return FALSE;
	//}

	CDataObject *DataObject = GetOurDataObject(piDataObject);
	if ( DataObject->GetCookie() == MMC_MULTI_SELECT_COOKIE ) {
		int Num = DataObject->GetMultiSelectCookiesNumber();
		for ( int i = 0; i < Num; i++ ) {
			CDelegationBase *base = (CDelegationBase *) DataObject->GetMultiSelectCookie(i);
			base->OnMenuCommand(m_ipConsole, lCommandID, piDataObject,MfxGetComponentData());
		}
		return S_OK;
	}

	CDelegationBase *base = GetOurDataObject(piDataObject)->GetBaseNodeObject();
	return base->OnMenuCommand(m_ipConsole, lCommandID, piDataObject,MfxGetComponentData());

    //return FALSE;
}

///////////////////////////////
// Interface IExtendTaskPad
///////////////////////////////
HRESULT CComponent::TaskNotify(
                               /* [in] */ IDataObject __RPC_FAR *pdo,
                               /* [in] */ VARIANT __RPC_FAR *arg,
                               /* [in] */ VARIANT __RPC_FAR *param)
{
    CDelegationBase *base = GetOurDataObject(pdo)->GetBaseNodeObject();

    return base->TaskNotify(m_ipConsole, arg, param);
}

HRESULT CComponent::EnumTasks(
                              /* [in] */ IDataObject __RPC_FAR *pdo,
                              /* [string][in] */ LPOLESTR szTaskGroup,
                              /* [out] */ IEnumTASK __RPC_FAR *__RPC_FAR *ppEnumTASK)
{
    CDelegationBase *base = GetOurDataObject(pdo)->GetBaseNodeObject();

    // GetTaskList will allocate the entire task structure, it's
    // up to the enumerator to free the list when destroyed
    LONG nCount;
    MMC_TASK *tasks = base->GetTaskList(szTaskGroup, &nCount);

    if (tasks != NULL) {
        CEnumTASK *pTask = new CEnumTASK(tasks, nCount);

        if (pTask) {
            reinterpret_cast<IUnknown *>(pTask)->AddRef();
            HRESULT hr = pTask->QueryInterface (IID_IEnumTASK, (void **)ppEnumTASK);
            reinterpret_cast<IUnknown *>(pTask)->Release();

            return hr;
        }
    }

    return S_OK;
}


HRESULT CComponent::GetTitle(
                             /* [string][in] */ LPOLESTR pszGroup,
                             /* [string][out] */ LPOLESTR __RPC_FAR *pszTitle)
{
    CDelegationBase *base = (CDelegationBase *)wcstoul(pszGroup, NULL, 16);

    if (NULL == base)
            return S_FALSE;

    return base->GetTaskpadTitle(pszTitle);
}

HRESULT CComponent::GetDescriptiveText(
                                       /* [string][in] */ LPOLESTR pszGroup,
                                       /* [string][out] */ LPOLESTR __RPC_FAR *pszDescriptiveText)
{
        CDelegationBase *base = (CDelegationBase *)wcstoul(pszGroup, NULL, 16);

        if (NULL == base)
                return S_FALSE;

    return base->GetTaskpadDescription(pszDescriptiveText);
}

HRESULT CComponent::GetBackground(
                                  /* [string][in] */ LPOLESTR pszGroup,
                                  /* [out] */ MMC_TASK_DISPLAY_OBJECT __RPC_FAR *pTDO)
{
        CDelegationBase *base = (CDelegationBase *)wcstoul(pszGroup, NULL, 16);

        if (NULL == base)
                return S_FALSE;

    return base->GetTaskpadBackground(pTDO);
}

HRESULT CComponent::GetListPadInfo(
                                   /* [string][in] */ LPOLESTR pszGroup,
                                   /* [out] */ MMC_LISTPAD_INFO __RPC_FAR *lpListPadInfo)
{
        CDelegationBase *base = (CDelegationBase *)wcstoul(pszGroup, NULL, 16);

        if (NULL == base)
                return S_FALSE;

}

//
// GetCurrentSelections() finds the currently selected result items and the data object passed to it with their cookie values.
// The multi-select cookie is cached so that we don't have to calculate multiselection dataobject for other notifications.
// It is destroyed at appropriate time.
//
HRESULT CComponent::GetCurrentSelections(CDataObject *pMultiSelectDataObject)
{
	HRESULT hr = S_FALSE;

	//GetCurrentSelections only works for multiselection data objects
	if ( !( MMC_MULTI_SELECT_COOKIE == GetOurDataObject(pMultiSelectDataObject)->GetCookie() ) )
		return hr = E_INVALIDARG;
	
	IResultData *pResultData = NULL;

	hr = m_ipConsole->QueryInterface(IID_IResultData, (void **)&pResultData);
	_ASSERT( SUCCEEDED(hr) );	

    RESULTDATAITEM rdi;
	
	BOOL isLastSelected = FALSE;
	int nIndex = -1;
	int nIndexCookies = 0;

	while (!isLastSelected)
	{
		ZeroMemory(&rdi, sizeof(RESULTDATAITEM) );
		rdi.mask	= RDI_STATE;		// nState is valid 
		rdi.nCol	= 0;
		rdi.nIndex  = nIndex;			// nIndex == -1 to start at first item
		rdi.nState  = LVIS_SELECTED;	// only interested in selected items

		hr = pResultData->GetNextItem(&rdi);
		_ASSERT( SUCCEEDED(hr) ); 

		if (rdi.nIndex != -1) {

			//rdi is the RESULTDATAITEM of a selected item. add its
			//lParam to the pCookies array of the pMultiSelectDataObject data object
			
			//_ASSERT( nIndexCookies < 20 ); // MAX_COOKIES == 20
			pMultiSelectDataObject->AddMultiSelectCookie(nIndexCookies, rdi.lParam);
			nIndexCookies++;
			nIndex = rdi.nIndex;
		}
		else 
			isLastSelected = TRUE;

	}

	pResultData->Release();
	
	return hr;

}
