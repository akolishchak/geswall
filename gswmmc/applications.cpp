//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>

#include "StatNode.h"
#include "Applications.h"
#include "DeleBase.h"
#include "Comp.h"
#include "DataObj.h"
#include "resource.h"
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
#include "gesruledef.h"
#include "app/application.h"
#include "commonlib.h"
#include "storage.h"
#include "replication.h"
#include "storageexception.h"
#include "macro/macroresolver.h"
#include "images.h"
#include "gswclient.h"
#include "license/trialmanager.h"


// {6DE8BA0D-31CA-411c-B7B8-D6C462C1A23B}
 const GUID CApplicationFolder::thisGuid = 
{ 0x6de8ba0d, 0x31ca, 0x411c, { 0xb7, 0xb8, 0xd6, 0xc4, 0x62, 0xc1, 0xa2, 0x3b } };
 // {03654107-4676-4360-90C6-EC536F3958BD}
 const GUID CGroupFolder::thisGuid = 
{ 0x3654107, 0x4676, 0x4360, { 0x90, 0xc6, 0xec, 0x53, 0x6f, 0x39, 0x58, 0xbd } };
// {1B3BC1F6-9D6A-4a03-9B47-A9FD2F7268B8}
const GUID CApplicationItem::thisGuid = 
{ 0x1b3bc1f6, 0x9d6a, 0x4a03, { 0x9b, 0x47, 0xa9, 0xfd, 0x2f, 0x72, 0x68, 0xb8 } };
// {79A6FA82-B136-4175-BE94-F715E9018607}
 const GUID CApplicationRule::thisGuid = 
{ 0x79a6fa82, 0xb136, 0x4175, { 0xbe, 0x94, 0xf7, 0x15, 0xe9, 0x1, 0x86, 0x7 } };

bool CApplicationFolder::ActiveDialog = false;
bool CGroupFolder::ActiveDialog = false;
bool CApplicationItem::ActiveDialog = false;

HRESULT CApplicationItem::OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect)
{
    IConsoleVerb *pConsoleVerb;
	m_ipConsoleNameSpace = pComponent->m_pParent->GetConsoleNameSpace();

    HRESULT hr = pConsole->QueryConsoleVerb(&pConsoleVerb);
    _ASSERT(SUCCEEDED(hr));

    hr = pConsoleVerb->SetVerbState(MMC_VERB_CUT, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_CUT, HIDDEN, FALSE);
    //hr = pConsoleVerb->SetVerbState(MMC_VERB_COPY, ENABLED, TRUE);
    //hr = pConsoleVerb->SetVerbState(MMC_VERB_COPY, HIDDEN, FALSE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_DELETE, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_DELETE, HIDDEN, FALSE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_PASTE, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_PASTE, HIDDEN, FALSE);

    pConsoleVerb->Release();

    return S_OK;
}


HRESULT CApplicationFolder::OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect)
{
    IConsoleVerb *pConsoleVerb;
	m_ipConsoleNameSpace = pComponent->m_pParent->GetConsoleNameSpace();

    HRESULT hr = pConsole->QueryConsoleVerb(&pConsoleVerb);
    _ASSERT(SUCCEEDED(hr));

	hr = pConsoleVerb->SetVerbState(MMC_VERB_PASTE, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_PASTE, HIDDEN, FALSE);

    pConsoleVerb->Release();

    return S_OK;
}
HRESULT CGroupFolder::OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect)
{
    IConsoleVerb *pConsoleVerb;
	m_ipConsoleNameSpace = pComponent->m_pParent->GetConsoleNameSpace();

    HRESULT hr = pConsole->QueryConsoleVerb(&pConsoleVerb);
    _ASSERT(SUCCEEDED(hr));

    hr = pConsoleVerb->SetVerbState(MMC_VERB_CUT, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_CUT, HIDDEN, FALSE);
    //hr = pConsoleVerb->SetVerbState(MMC_VERB_COPY, ENABLED, TRUE);
    //hr = pConsoleVerb->SetVerbState(MMC_VERB_COPY, HIDDEN, FALSE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_DELETE, ENABLED, TRUE);
	hr = pConsoleVerb->SetVerbState(MMC_VERB_DELETE, HIDDEN, (bEmpty)? FALSE:TRUE);
	hr = pConsoleVerb->SetVerbState(MMC_VERB_PASTE, ENABLED, TRUE);
    hr = pConsoleVerb->SetVerbState(MMC_VERB_PASTE, HIDDEN, FALSE);

    pConsoleVerb->Release();

    return S_OK;
}

HRESULT CGroupFolder::Expand(IConsoleNameSpace *pConsoleNameSpace)
{
        //Expand the CSpaceStation if necessary.
        //This method is called by the object's OnPaste method during paste operations.

        HRESULT hr = S_FALSE;

        //First, need the IConsoleNameSpace2 interface to call Expand.
        IConsoleNameSpace2 *pConsoleNamespace2 = NULL;
        hr = pConsoleNameSpace->QueryInterface(IID_IConsoleNameSpace2, (void **)&pConsoleNamespace2);
        _ASSERT( SUCCEEDED(hr) );

        hr = pConsoleNamespace2->Expand((HSCOPEITEM)GetParentScopeItem());

        pConsoleNamespace2->Release();

        return hr;
}
HRESULT CApplicationFolder::Expand(IConsoleNameSpace *pConsoleNameSpace)
{
        //Expand the CSpaceStation if necessary.
        //This method is called by the object's OnPaste method during paste operations.

        HRESULT hr = S_FALSE;

        //First, need the IConsoleNameSpace2 interface to call Expand.
        IConsoleNameSpace2 *pConsoleNamespace2 = NULL;
        hr = pConsoleNameSpace->QueryInterface(IID_IConsoleNameSpace2, (void **)&pConsoleNamespace2);
        _ASSERT( SUCCEEDED(hr) );

        hr = pConsoleNamespace2->Expand((HSCOPEITEM)GetParentScopeItem());

        pConsoleNamespace2->Release();

        return hr;
}
HRESULT CApplicationFolder::OnPaste(IConsole *pConsole, CComponentData *pComponentData, CDelegationBase *pPasted)
{
       
        HRESULT hr = S_OK;
		int nId =0;

          SCOPEDATAITEM sdi;
                ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
                sdi.mask = SDI_STR|   // Displayname is valid
                    SDI_PARAM     |   // lParam is valid
                    SDI_IMAGE     |   // nImage is valid
                    SDI_OPENIMAGE |   // nOpenImage is valid
                    SDI_PARENT    |
                    SDI_CHILDREN;

                sdi.relativeID  = (HSCOPEITEM)GetParentScopeItem();
                sdi.displayname = MMC_CALLBACK;
                sdi.cChildren   = 0;
				
				CApplicationItem *pAppItem = dynamic_cast<CApplicationItem *>(pPasted);
		if (NULL != pAppItem)
        {
            // See if this is CGroupFolder, if so paste it into this item.
            // This sample simply creates a new CGroupFolder
            // and inserts it as a child of the destination of the paste.
			pAppItem->ApplicationItem->Params.GroupId = 0;
			pAppItem->ApplicationItem->Params.Options |= Storage::dboUserModified;
			try
			{ 	if(0 == (nId = Storage::UpdateApplication(pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId], *pAppItem->ApplicationItem)))
				  return S_FALSE;
				m_StaticNode->PolicyChanged();
				
			}
			catch(Storage::StorageException &e) 
			{
				pConsole->MessageBox(e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION,NULL);
				  return S_FALSE;
			}
			//CApplicationItem* pNewApp = new CApplicationItem(pAppItem/*->ApplicationItem*/,m_RootNode, this);
	        CApplicationItem * pNewApp = new CApplicationItem(pAppItem->ApplicationItem, this, m_StaticNode);
			pNewApp->ApplicationItem->Params.Id = nId;

	        sdi.lParam      = (LPARAM)pNewApp;       // pNewApp The cookie
			sdi.nOpenImage  = INDEX_APPLICATIONS;
			sdi.nImage      = pNewApp->GetBitmapIndex();
            hr = Expand(pComponentData->GetConsoleNameSpace());
			if(S_FALSE == hr)
			{
			hr = pComponentData->GetConsoleNameSpace()->InsertItem( &sdi );
            _ASSERT( SUCCEEDED(hr) );
			 pNewApp->SetScopeItemValue(sdi.ID);
			}
			bEmpty = FALSE;

			 return hr;

		}else
		{
            CGroupFolder* pGroup = dynamic_cast<CGroupFolder*>(pPasted);
			if ( (NULL != pGroup) && (pGroup->m_parent != this) )
            {
                // Regardless of whether this item is expanded or not
                // always try to expand this scopeitem (so that paste can
                // succeed).
                hr = Expand(pComponentData->GetConsoleNameSpace());

                pGroup->ApplicationItem->Params.GroupId = 0;

				pGroup->ApplicationItem->Params.Options |= Storage::dboUserModified;
				try
				{ 	if(0== (nId = Storage::UpdateApplicationGroup(pGroup->ApplicationItem->Params)))
					return S_FALSE;
					m_StaticNode->PolicyChanged();
				}
				catch(Storage::StorageException &e) 
				{
					pConsole->MessageBox(e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION,NULL);
					return S_FALSE;
				}
			
				CGroupFolder* pNewGroup = new CGroupFolder(pGroup->ApplicationItem,  this, m_StaticNode);
				pNewGroup->ApplicationItem->Params.Id = nId;
	            pNewGroup->bEmpty = pGroup->bEmpty;
				

				sdi.nOpenImage  = INDEX_OPENFOLDER;
				sdi.lParam      = (LPARAM)pNewGroup;           // The cookie 
                sdi.nImage      = pNewGroup->GetBitmapIndex();
				sdi.cChildren   = (pNewGroup->bEmpty)? 0:1;

                hr = pComponentData->GetConsoleNameSpace()->InsertItem( &sdi );
                _ASSERT( SUCCEEDED(hr) );

                pNewGroup->SetScopeItemValue(sdi.ID);
				bEmpty = FALSE;

				return hr;
            }
		}
            
      
       return S_FALSE;
}

HRESULT CApplicationFolder::OnQueryPaste(CDelegationBase *pPasted)
{
        CApplicationItem *pApplicationItem = dynamic_cast<CApplicationItem *>(pPasted);

        if (NULL == pApplicationItem)
        {
            // See if this is CGroupFolder.
            CGroupFolder* pGroup = dynamic_cast<CGroupFolder*>(pPasted);
            if ( (NULL != pGroup) &&
                 (pGroup->m_parent != this)
				 )
            {
               
			
					return S_OK; // TODO: Restore normal group drag&drop operation; return S_OK;
            }

            return S_FALSE;
        }

        if (pApplicationItem->m_parent != this) return S_OK;
                  
        return S_FALSE;
}

HRESULT CApplicationFolder::OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype)

{
        HRESULT hr = S_OK;

        _ASSERT(item);
        _ASSERT(SCOPE == itemtype);

        //refresh all result pane views
        hr = pConsole->SelectScopeItem( (HSCOPEITEM)item );
        _ASSERT( S_OK == hr);

        return hr;
}


HRESULT CApplicationFolder::OnDeleteScopeItem (IConsoleNameSpace *pConsoleNameSpace)

{
     
        return S_FALSE;
}

HRESULT CGroupFolder::OnPaste(IConsole *pConsole, CComponentData *pComponentData, CDelegationBase *pPasted)
{
       
        HRESULT hr = S_OK;
		int nId = 0;

          SCOPEDATAITEM sdi;
                ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
                sdi.mask = SDI_STR|   // Displayname is valid
                    SDI_PARAM     |   // lParam is valid
                    SDI_IMAGE     |   // nImage is valid
                    SDI_OPENIMAGE |   // nOpenImage is valid
                    SDI_PARENT    |
                    SDI_CHILDREN;

                sdi.relativeID  = (HSCOPEITEM)GetParentScopeItem();
                sdi.displayname = MMC_CALLBACK;
                sdi.cChildren   = 0;
				
				CApplicationItem *pAppItem = dynamic_cast<CApplicationItem *>(pPasted);
		if (NULL != pAppItem)
        {
            // See if this is CGroupFolder, if so paste it into this item.
            // This sample simply creates a new CGroupFolder
            // and inserts it as a child of the destination of the paste.
			pAppItem->ApplicationItem->Params.GroupId = ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId]; //ApplicationItem->Params.Id;
			pAppItem->ApplicationItem->Params.Options |= Storage::dboUserModified;
			try
			{ 	if(0 == (nId = Storage::UpdateApplication(pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId], *pAppItem->ApplicationItem)))
				  return S_FALSE;
				m_StaticNode->PolicyChanged();
			}
			catch(Storage::StorageException &e) 
			{
				pConsole->MessageBox(e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION,NULL);
				  return S_FALSE;
			}
			//CApplicationItem* pNewApp = new CApplicationItem(pAppItem/*->ApplicationItem*/,m_RootNode, this);
	        CApplicationItem * pNewApp = new CApplicationItem(pAppItem->ApplicationItem, this, m_StaticNode);
			pNewApp->ApplicationItem->Params.Id = nId; 
	        sdi.lParam      = (LPARAM)pNewApp;       // pNewApp The cookie
			sdi.nOpenImage  = INDEX_APPLICATIONS;
			sdi.nImage      = pNewApp->GetBitmapIndex();
            hr = Expand(pComponentData->GetConsoleNameSpace());
			if(S_FALSE == hr)
			{
			hr = pComponentData->GetConsoleNameSpace()->InsertItem( &sdi );
            _ASSERT( SUCCEEDED(hr) );
			 pNewApp->SetScopeItemValue(sdi.ID);
			}
			bEmpty = FALSE;

			 return hr;

		}else
		{
            CGroupFolder* pGroup = dynamic_cast<CGroupFolder*>(pPasted);
            if ( (NULL != pGroup) && (pGroup != this) )
            {
                // Regardless of whether this item is expanded or not
                // always try to expand this scopeitem (so that paste can
                // succeed).
                hr = Expand(pComponentData->GetConsoleNameSpace());

                pGroup->ApplicationItem->Params.GroupId = ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId];//ApplicationItem->Params.Id;
				pGroup->ApplicationItem->Params.Options |= Storage::dboUserModified;
				try
				{ 	if(0 == (nId = Storage::UpdateApplicationGroup(pGroup->ApplicationItem->Params)))
					return S_FALSE;
					m_StaticNode->PolicyChanged();
				}
				catch(Storage::StorageException &e) 
				{
					pConsole->MessageBox(e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION,NULL);
					return S_FALSE;
				}
			
				CGroupFolder* pNewGroup = new CGroupFolder(pGroup->ApplicationItem,  this, m_StaticNode);
				pGroup->ApplicationItem->Params.Id = nId;
				pNewGroup->bEmpty = pGroup->bEmpty;

				sdi.nOpenImage  = INDEX_OPENFOLDER;
				sdi.lParam      = (LPARAM)pNewGroup;           // The cookie 
                sdi.nImage      = pNewGroup->GetBitmapIndex();
				sdi.cChildren   = (pNewGroup->bEmpty)? 0:1;

                hr = pComponentData->GetConsoleNameSpace()->InsertItem( &sdi );
                _ASSERT( SUCCEEDED(hr) );

                pNewGroup->SetScopeItemValue(sdi.ID);
				
				return hr;
            }
		}
            
      
       return S_FALSE;
}

HRESULT CGroupFolder::OnQueryPaste(CDelegationBase *pPasted)
{
        list <CDelegationBase *>::iterator result;

		CApplicationItem *pApplicationItem = dynamic_cast<CApplicationItem *>(pPasted);

        if (NULL == pApplicationItem)
        {
            // See if this is CGroupFolder.
            CGroupFolder* pGroup = dynamic_cast<CGroupFolder*>(pPasted);
            if ( (NULL != pGroup) &&
                 (pGroup != this) &&
                 (pGroup->m_parent != this) )
            {
              	result = find( m_ParentList.begin( ), m_ParentList.end( ), pPasted );
				if  ( result == m_ParentList.end( ) )
				  return S_OK; 
            }

            return S_FALSE;
        }

        if (pApplicationItem->m_parent != this) return S_OK;
                  
        return S_FALSE;
}

HRESULT CGroupFolder::OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype)

{
        HRESULT hr = S_OK;

        _ASSERT(item);
        _ASSERT(SCOPE == itemtype);

        //refresh all result pane views
        hr = pConsole->SelectScopeItem( (HSCOPEITEM)item );
        _ASSERT( S_OK == hr);

        return hr;
}


HRESULT CGroupFolder::OnDeleteScopeItem (IConsoleNameSpace *pConsoleNameSpace)

{
        HRESULT hr = S_FALSE;
		BOOL Empty = FALSE;
        HSCOPEITEM hCutItem = (HSCOPEITEM)GetParentScopeItem();

        //Get handle and cookie of parent scope item. We need these to
        //remove the "+" sign if the parent's m_cChildSpaceStations goes to zero.
        HSCOPEITEM hParentItem;
        MMC_COOKIE cookieParentItem;

        HRESULT hr1 = pConsoleNameSpace->GetParentItem(hCutItem, &hParentItem,
                                                                                                        (long *)&cookieParentItem);

        //Delete the cut item
        hr = pConsoleNameSpace->DeleteItem(hCutItem, TRUE);
        _ASSERT(S_OK == hr);

        if (SUCCEEDED(hr1))
        {
                //Decrement parent's m_cChildSpaceStations count and
                //remove "+" sign if necessary
                //CGroupFolder * pParentGroup = reinterpret_cast<CGroupFolder*>(cookieParentItem);
               
		
		
			if(m_parent) 
			{ 
				CGroupFolder * pGroup = dynamic_cast <CGroupFolder *> (m_parent);
				if(pGroup != NULL)
				{ 
					pGroup->m_children.remove(this);
					Empty = pGroup->bEmpty = (pGroup->m_children.size())? FALSE : TRUE;
				}else
				{
					CApplicationFolder * pAppFolder = dynamic_cast <CApplicationFolder *> (m_parent); 
					if(pAppFolder != NULL)
					{ 
						pAppFolder->m_children.remove(this);
						Empty = pAppFolder->bEmpty = (pAppFolder->m_children.size())? FALSE : TRUE;
					}
					else _ASSERT(FALSE);
				}
			  }

			if ( Empty )
                {
					
                        SCOPEDATAITEM sdi;

                        ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
                        sdi.mask                = SDI_CHILDREN; //cChildren is valid
                        sdi.ID          = (HSCOPEITEM)hParentItem;
                        sdi.cChildren   = 0;

                        hr = pConsoleNameSpace->SetItem( &sdi );
                        _ASSERT( SUCCEEDED(hr) );
                }

        }

        return hr;
}

HRESULT CApplicationItem::OnDeleteScopeItem (IConsoleNameSpace *pConsoleNameSpace)

{
        HRESULT hr = S_FALSE;
		BOOL Empty = FALSE;
        HSCOPEITEM hCutItem = (HSCOPEITEM)GetParentScopeItem();

        //Get handle and cookie of parent scope item. We need these to
        //remove the "+" sign if the parent's m_cChildSpaceStations goes to zero.
        HSCOPEITEM hParentItem;
        MMC_COOKIE cookieParentItem;

        HRESULT hr1 = pConsoleNameSpace->GetParentItem(hCutItem, &hParentItem,
                                                                                                        (long *)&cookieParentItem);

        //Delete the cut item
        hr = pConsoleNameSpace->DeleteItem(hCutItem, TRUE);
        _ASSERT(S_OK == hr);

        if (SUCCEEDED(hr1))
        {
                //remove "+" sign if necessary
                //CGroupFolder * pParentGroup = reinterpret_cast<CGroupFolder*>(cookieParentItem);
               
			if(m_parent) 
			{ 
				CGroupFolder * pGroup = dynamic_cast <CGroupFolder *> (m_parent);
				if(pGroup != NULL)
				{ 
					pGroup->m_children.remove(this);
					Empty = pGroup->bEmpty = (pGroup->m_children.size())? FALSE : TRUE;
				}else
				{
					CApplicationFolder * pAppFolder = dynamic_cast <CApplicationFolder *> (m_parent); 
					if(pAppFolder != NULL)
					{ 
						pAppFolder->m_children.remove(this);
						Empty = pAppFolder->bEmpty = (pAppFolder->m_children.size())? FALSE : TRUE;
					}
					else _ASSERT(FALSE);
				}
			  }

			if ( Empty )
                {
					
                        SCOPEDATAITEM sdi;

                        ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
                        sdi.mask                = SDI_CHILDREN; //cChildren is valid
                        sdi.ID          = (HSCOPEITEM)hParentItem;
                        sdi.cChildren   = 0;

                        hr = pConsoleNameSpace->SetItem( &sdi );
                        _ASSERT( SUCCEEDED(hr) );
                }

        }

        return hr;
}
/////////////////////////////////////////////////////////////////////
CGroupFolder::CGroupFolder(Storage::PtrToApplicationItem appItem, CDelegationBase * parent, CStaticNode *StaticNode):m_parent(parent),ApplicationItem(appItem)
{
	InitCom();

	m_StaticNode = StaticNode;
	ActiveDialog = false;
	CApplicationFolder * af = dynamic_cast <CApplicationFolder *> (parent);
	if ( af == NULL )
	{
		CGroupFolder * gf = static_cast <CGroupFolder *> (parent);
		m_ParentList = gf->m_ParentList;
		m_ParentList.push_back(parent);
	}
}

#define  IDC_CONSOLE_STARTED		  1504

/////////////////////////////////////////////////////////////////////
HRESULT CGroupFolder::OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent)
{
    SCOPEDATAITEM sdi;
	Storage::PtrToApplicationItem pAppItem;
	m_hParentHScopeItem = parent;
	m_ipConsoleNameSpace = pConsoleNameSpace;
    bool result;
	CDelegationBase *ar;

	if (!bExpanded) {
	
	bExpanded = true;
	int GroupId = ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId];
	result = Storage::GetApplicationList (GroupId,ApplicationList); //ApplicationItem->Params.Id
	if (true == result)
	{ for (Storage::ApplicationItemList::iterator i = ApplicationList.begin (); i != ApplicationList.end (); ++i)
		{
			if((*i)->Params.Type == Storage::parAppGroup)
			{	ar = new CGroupFolder(static_cast <Storage::PtrToApplicationItem> (*i), this, m_StaticNode);
				ar->bEmpty = Storage::GroupIsEmpty((*i)->Params.Attributes.Param[GesRule::attSubjectId]);
			}
			else
				ar = new CApplicationItem(static_cast <Storage::PtrToApplicationItem> (*i), this, m_StaticNode);
			
			
			m_children.push_back(ar);
		}
	}
        // create the child nodes, then expand them
       for (BASELIST::iterator iter = m_children.begin(); iter != m_children.end(); iter++)
		{     
			ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |   // Displayname is valid
                SDI_PARAM     |   // lParam is valid
                SDI_IMAGE     |   // nImage is valid
                SDI_OPENIMAGE |   // nOpenImage is valid
                SDI_PARENT    |   // relativeID is valid
                SDI_CHILDREN;     // cChildren is valid

            sdi.relativeID  = (HSCOPEITEM)parent;
            sdi.nImage      = (*iter)->GetBitmapIndex();
			(*iter)->GetApplicationItem(&pAppItem);
			if(pAppItem->Params.Type == Storage::parAppGroup)
				 sdi.nOpenImage  = INDEX_OPENFOLDER;
			else sdi.nOpenImage  = INDEX_APPLICATIONS;
            sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)(*iter);       // The cookie
			sdi.cChildren   = ((*iter)->bEmpty)? 0:1;

            HRESULT hr = pConsoleNameSpace->InsertItem( &sdi );

            _ASSERT( SUCCEEDED(hr) );

            (*iter)->SetScopeItemValue(sdi.ID);
        }

    return S_OK;

	}
    return S_FALSE;
}    


HRESULT CGroupFolder::OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    HRESULT hr = S_OK;
	long flag = (ActiveDialog)?  MF_GRAYED : 0;
	
    CONTEXTMENUITEM menuItemsNew[] =
    {
        {
            L"Add Application...", L"Add new application",
                ID_ADD_APPLICATION,  CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, CCM_SPECIAL_DEFAULT_ITEM    },
		{
            L"Add Group...", L"Add new group",
                ID_ADD_GROUP, CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, 0    },
		{
            L"Properties", L"Group Properties",
                ID_GROUP_PROP, CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, 0    },
		
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
HRESULT CGroupFolder::OnDelete(CComponentData * pCompData, IConsole *pConsole)
{	
	if(Storage::DeleteApplicationGroup(ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId]))
		{
			pCompData->GetConsoleNameSpace()->DeleteItem(GetParentScopeItem(), true);
			if(m_parent) 
			{ 
				CGroupFolder * pGroup = dynamic_cast <CGroupFolder *> (m_parent);
				if(pGroup != NULL)
				{ 
					pGroup->m_children.remove(this);
					pGroup->bEmpty = (pGroup->m_children.size())? FALSE : TRUE;
					
				}else
				{
					CApplicationFolder * pAppFolder = dynamic_cast <CApplicationFolder *> (m_parent); 
					if(pAppFolder != NULL)
					{ 
						pAppFolder->m_children.remove(this);
						pAppFolder->bEmpty = (pAppFolder->m_children.size())? FALSE : TRUE;
					}
					else { _ASSERT(FALSE); return S_FALSE; }
				}
			}
			m_StaticNode->PolicyChanged();

		}else
			pConsole->MessageBox(L"Can't delete application group",L"Error",MB_OK|MB_ICONINFORMATION,0);

		return S_OK;
}
HRESULT CGroupFolder::OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
    m_ipConsole = pConsole;
	m_ipDataObject = piDataObject;
	m_ipConsoleNameSpace = pComData->GetConsoleNameSpace();

	switch (lCommandID)
    {

   
   case ID_ADD_GROUP:
		ActivePage = 0;
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 0);
		break;

	case ID_ADD_APPLICATION:
		if ( !license::TrialManager::IsOperationAllowed(license::TrialManager::opAddApplication, g_hinst) ) break;
		ActivePage = 1;
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 1);
		break;
	
	case ID_GROUP_PROP:

		ActivePage = 2;
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 0);
		break;
    }
    
    return S_OK;
}

HRESULT CGroupFolder::HasPropertySheets()
{
    // say "yes" when MMC asks if we have pages
    
	return S_OK;
}
HRESULT CGroupFolder::CreateGroup(Storage::ApplicationItem &appItem)
{
	HRESULT hr;
	// set group code to zero for all groups created by user
	appItem.Params.Attributes.Param[1] = 0;
	CoCreateGuid((GUID *)&appItem.Params.Attributes.Param[2]);
	appItem.Params.Options = Storage::dboUserCreated;
	try{
		int GroupId;
		Storage::InsertApplicationGroup(appItem.Params, true, GroupId);
		appItem.Params.Id = GroupId;
		m_StaticNode->PolicyChanged();
		} 
		catch(Storage::StorageException &e) { throw e; }
	
	if(appItem.Params.Id)
	{
	Storage::PtrToApplicationItem itemApplication (new Storage::ApplicationItem (appItem));
	CDelegationBase *group = new CGroupFolder(static_cast<Storage::PtrToApplicationItem>(itemApplication), this, m_StaticNode);
	hr = Expand(m_ipConsoleNameSpace);
	
	if(S_FALSE == hr)
	{
	m_children.push_back(group); 

			SCOPEDATAITEM sdi;
			ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |   // Displayname is valid
                SDI_PARAM     |   // lParam is valid
                SDI_IMAGE     |   // nImage is valid
                SDI_OPENIMAGE |   // nOpenImage is valid
                SDI_PARENT    |   // relativeID is valid
                SDI_CHILDREN;     // cChildren is valid

            sdi.relativeID  = (HSCOPEITEM)GetParentScopeItem();
            sdi.nImage      = group->GetBitmapIndex();
			sdi.nOpenImage  = INDEX_OPENFOLDER;

			sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)group;       // The cookie
			sdi.cChildren   = 0;

           
			hr = m_ipConsoleNameSpace->InsertItem( &sdi );
            _ASSERT( SUCCEEDED(hr) );
			 group->SetScopeItemValue(sdi.ID);
			}
			bEmpty = FALSE;
			// hr = m_ipConsole->UpdateAllViews(m_ipDataObject, 0, 0);
			//_ASSERT( S_OK == hr);

	return S_OK;
	}
	return S_FALSE;
}


INT_PTR CALLBACK CGroupFolder::GroupPropDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CGroupFolder *pAppFolder = NULL;
	
   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pAppFolder = reinterpret_cast<CGroupFolder *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		SetDlgItemText(hwndDlg, IDC_GROUPNAME, pAppFolder->ApplicationItem->Params.Description);
       break;

     case WM_COMMAND:
        // turn the Apply button on
       // if (HIWORD(wParam) == EN_CHANGE ||
       //     HIWORD(wParam) == CBN_SELCHANGE)
       //      SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);

		 break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pAppFolder->m_ppHandle);
        break;

    case WM_NOTIFY:
        if (((NMHDR *) lParam)->code == PSN_APPLY )
		{
			if ( pAppFolder->MainThreadId != GetCurrentThreadId() ) return pAppFolder->ComDialogProc((WNDPROC)GroupPropDialogProc, hwndDlg, uMsg, wParam, lParam);

			int n = (int)SendDlgItemMessage(hwndDlg, IDC_GROUPNAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{
			  MessageBox(hwndDlg,L"Group name can not be empty.",L"Error",MB_OK|MB_ICONINFORMATION);
				break;
			}else
				if( n >= sizeof pAppFolder->newGroup.Params.Description / sizeof pAppFolder->newGroup.Params.Description[0] )
				{ MessageBox(hwndDlg,L"Group name is too long!",L"Error",MB_OK|MB_ICONINFORMATION);
					break;
				}
				else
				{ 
				pAppFolder->newGroup = *pAppFolder->ApplicationItem;
				GetDlgItemText(hwndDlg, IDC_GROUPNAME, pAppFolder->newGroup.Params.Description, n + 1);
				pAppFolder->newGroup.Params.Options |= Storage::dboUserModified;
				try 
				{
					Storage::UpdateApplicationGroup(pAppFolder->newGroup.Params);
					*pAppFolder->ApplicationItem = pAppFolder->newGroup;
					pAppFolder->m_StaticNode->PolicyChanged();
				}
				catch(Storage::StorageException &e)
				{ MessageBox(hwndDlg,e.getMessage().c_str(),L"Error",MB_OK|MB_ICONINFORMATION);
				}
				}
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}

			// call parent handle?
			HRESULT hr = MMCPropertyChangeNotify(pAppFolder->m_ppHandle, (LPARAM)pAppFolder);
			_ASSERT(SUCCEEDED(hr));
			pAppFolder->ActiveDialog = false;
			return PSNRET_NOERROR;
		}
		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pAppFolder->ActiveDialog = false;
			return FALSE;
		}
    }

  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}


HRESULT CGroupFolder::CreateApplication(Storage::ApplicationItem &appItem)
{
	HRESULT hr;

	appItem.Params.Options = Storage::dboUserCreated;
	//license::LicenseManager::LicenseEssentials License;
	//license::LicenseManager::LicenseCopy(License);
	//if ( License.StateFlags & license::stateTrial ) appItem.Params.Options |= Storage::dboLabel1;
	try {
		int AppId;
		Storage::InsertApplication(appItem, AppId);
		appItem.Params.Id = AppId;
		m_StaticNode->PolicyChanged();
	} 	
	catch(Storage::StorageException &e) { throw e; }
		
	if(appItem.Params.Id)
	{
	GswClient Client;
	Client.RefreshApp(appItem.Params.Id);
	appItem.Params.Attributes.Param[GesRule::attSubjectId] = appItem.Params.Id;
	Storage::PtrToApplicationItem itemApplication (new Storage::ApplicationItem (appItem));
	CDelegationBase *application = new CApplicationItem(static_cast<Storage::PtrToApplicationItem>(itemApplication), this, m_StaticNode);
	hr = Expand(m_ipConsoleNameSpace);
	if(S_FALSE == hr)
	{
	m_children.push_back(application); 

			SCOPEDATAITEM sdi;
			ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |   // Displayname is valid
                SDI_PARAM     |   // lParam is valid
                SDI_IMAGE     |   // nImage is valid
                SDI_OPENIMAGE |   // nOpenImage is valid
                SDI_PARENT    |   // relativeID is valid
                SDI_CHILDREN;     // cChildren is valid

            sdi.relativeID  = (HSCOPEITEM)GetParentScopeItem();
            sdi.nImage      = application->GetBitmapIndex();
			sdi.nOpenImage  = INDEX_APPLICATIONS;

			sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)application;       // The cookie
			sdi.cChildren   = 0;

			/* hr = m_ipConsoleNameSpace->InsertItem( &sdi );

            _ASSERT( SUCCEEDED(hr) );
			application->SetScopeItemValue(sdi.ID);
			bEmpty = FALSE;
			*/
			
			hr = m_ipConsoleNameSpace->InsertItem( &sdi );
            _ASSERT( SUCCEEDED(hr) );
			 application->SetScopeItemValue(sdi.ID);
			}
			bEmpty = FALSE;

			// hr = m_ipConsole->UpdateAllViews(m_ipDataObject, 0, 0);
			//_ASSERT( S_OK == hr);

	return S_OK;
	}
	return S_FALSE;
}

INT_PTR CALLBACK CGroupFolder::GroupDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CGroupFolder *pAppFolder = NULL;
	HRESULT result;

   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pAppFolder = reinterpret_cast<CGroupFolder *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		
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
        MMCFreeNotifyHandle(pAppFolder->m_ppHandle);
        break;

    case WM_NOTIFY:
        
		if (((NMHDR *) lParam)->code == PSN_KILLACTIVE )
		{ 
			if ( pAppFolder->MainThreadId != GetCurrentThreadId() ) return pAppFolder->ComDialogProc((WNDPROC)GroupDialogProc, hwndDlg, uMsg, wParam, lParam);
			
			int n = (int)SendDlgItemMessage(hwndDlg, IDC_GROUPNAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{
			  MessageBox(hwndDlg,L"Group name can not be empty.",L"Group addition error",MB_OK|MB_ICONINFORMATION);
				SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
				return TRUE;
			}else
			  {
				if(n >= sizeof pAppFolder->newGroup.Params.Description / sizeof pAppFolder->newGroup.Params.Description[0] )
				{ MessageBox(hwndDlg,L"Group name is too long!",L"New group error",MB_OK|MB_ICONINFORMATION);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
					return TRUE;
				}
				else
				{ 
				GetDlgItemText(hwndDlg, IDC_GROUPNAME, pAppFolder->newGroup.Params.Description, n + 1);
				pAppFolder->newGroup.Params.GroupId = pAppFolder->ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId];//pAppFolder->ApplicationItem->Params.Id;
				
				
				
			try
			{ 	result = pAppFolder->CreateGroup(pAppFolder->newGroup);
			}
			catch(Storage::StorageException &e) 
			{
			 MessageBox(hwndDlg, e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			 return TRUE;
			}
	
			if(result == S_FALSE)
			{
			 MessageBox(hwndDlg,L"New group creation error!",L"Error",MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			}else
			{	 SetWindowLong(hwndDlg, DWL_MSGRESULT, FALSE);
			}
				
			return TRUE;
			
			
			}// else n > sizeof
		  } // else n==0
			return TRUE;
		} //if PSN_KILLACTIVE
			
		if (((NMHDR *) lParam)->code == PSN_APPLY )
		{	
				
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}
			
			HRESULT hr = MMCPropertyChangeNotify(pAppFolder->m_ppHandle, (LPARAM)pAppFolder);
			_ASSERT(SUCCEEDED(hr));
			pAppFolder->ActiveDialog = false;
			return PSNRET_NOERROR;
		}
		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pAppFolder->ActiveDialog = false;
			return FALSE;
		}
    }//switch

  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

void OnFileSelectApplication(HWND hwnd, bool showdialog, Storage::ApplicationItem &Item)
{
	OPENFILENAME ofn;       // common dialog box structure
	wchar_t szFile[260];       // buffer for file name

	if(showdialog == true)
	{

// Initialize OPENFILENAME
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFile;
//
// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
// use the contents of szFile to initialize itself.
//
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof szFile / sizeof szFile[0];
	ofn.lpstrFilter = L"Application\0*.EXE\0All\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileName(&ofn)) {
        //lstrcpy(g_szFileName, szFileName);
		 SetDlgItemText(hwnd, IDC_EDIT_FILENAME, szFile);
		}
	}
	else
	{		int n = (int)SendDlgItemMessage(hwnd, IDC_EDIT_FILENAME, WM_GETTEXTLENGTH, 0, 0);
			if (n && n < sizeof szFile / sizeof szFile[0]) GetDlgItemText(hwnd, IDC_EDIT_FILENAME, szFile, n + 1);
	}
	wstring Resolved;
	size_t Length = macro::process(Resolved, szFile, LongToHandle(GetCurrentProcessId()));
	
	App::Application::FillApplicationInfo(Resolved.c_str(), Item, App::UserCreated);
	SetDlgItemText(hwnd, IDC_PRODUCT_NAME, Item.ProductName);
	SetDlgItemText(hwnd, IDC_PRODUCT_DESC, Item.FileDescription);
	SetDlgItemText(hwnd, IDC_PRODUCT_COMP, Item.CompanyName);
	if( !App::Application::IsIdentifiedByVerinfo(&Item)
		&& 0 == SendDlgItemMessage(hwnd,IDC_IDENTITYBY, CB_GETCURSEL, 0, 0))
		{ 
		 SendDlgItemMessage(hwnd,IDC_IDENTITYBY, CB_SETCURSEL, 1, 0); 
		}
	HICON hExecIcon = commonlib::Bytes2Hicon(Item.Icon, sizeof Item.Icon);
	if(hExecIcon)  
	 SendDlgItemMessage(hwnd, IDC_PRODUCT_ICON, STM_SETIMAGE, IMAGE_ICON, (LPARAM)hExecIcon);


}
void OnFileSelectRule(HWND hwnd)
{
	OPENFILENAME ofn;       // common dialog box structure
	wchar_t szFile[260];       // buffer for file name

// Initialize OPENFILENAME
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFile;
//
// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
// use the contents of szFile to initialize itself.
//
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof szFile / sizeof szFile[0];
	ofn.lpstrFilter = L"All\0*.*\0Application\0*.EXE\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileName(&ofn)) {
        //lstrcpy(g_szFileName, szFileName);
		 SetDlgItemText(hwnd, IDC_EDIT_RULE, szFile);
		}

}
//*** Application Dialog Procedure **************
INT_PTR CALLBACK CGroupFolder::ApplicationDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CGroupFolder *pAppFolder = NULL;
	wchar_t FileName[255];
	int n;
	HRESULT result;

   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pAppFolder = reinterpret_cast<CGroupFolder *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Version Info");
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Name");
		//SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Digest");
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 0, (LPARAM)Storage::parAppContent);
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 1, (LPARAM)Storage::parAppPath);
		//SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 2, (LPARAM)Storage::parAppDigest);
			
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETCURSEL, 0, 0); 

		if ( pAppFolder->m_StaticNode->Product != license::gswServer ) {
			SendDlgItemMessage(hwndDlg,IDC_RADIO_TRUST, BM_SETCHECK, BST_CHECKED, 0);
		} else {
			SendDlgItemMessage(hwndDlg,IDC_RADIO_JAIL, BM_SETCHECK, BST_CHECKED, 0);
			EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_TRUST),false);
		}
		
		memset(&pAppFolder->newApp, 0, sizeof pAppFolder->newApp);
		SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_FILENAME));
       break;

     case WM_COMMAND:
        // turn the Apply button on
        //if (HIWORD(wParam) == EN_CHANGE ||
        //    HIWORD(wParam) == CBN_SELCHANGE)
        //    SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);
		if (HIWORD(wParam) == CBN_SELCHANGE) 
           {  
			if (LOWORD(wParam) == IDC_IDENTITYBY)
			{ if( !App::Application::IsIdentifiedByVerinfo(&pAppFolder->newApp)
				 && 0 == SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_GETCURSEL, 0, 0))
				{ 
					SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETCURSEL, 1, 0); 
				}
			 }
		   }

		   if (HIWORD(wParam) == EN_KILLFOCUS) 
           {  
			switch (LOWORD(wParam)) 
             { 
              case IDC_EDIT_FILENAME: 
				if(0 < (n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_FILENAME, WM_GETTEXTLENGTH, 0, 0)))
				{  GetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, FileName, n + 1);
				    
				 if(wcscmp(FileName,pAppFolder->newApp.FileName))
				   OnFileSelectApplication(hwndDlg, false, pAppFolder->newApp);
				}
				  break;
			 }
		   }

		 if (HIWORD(wParam) == EN_SETFOCUS) 
           {  
			switch (LOWORD(wParam)) 
             { 
              case IDC_EDIT_DISPLAYNAME: 
				if(0 == (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, WM_GETTEXTLENGTH, 0, 0))
				  { if(0 != (n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_NAME, WM_GETTEXTLENGTH, 0, 0)))
				    { GetDlgItemText(hwndDlg, IDC_PRODUCT_NAME, pAppFolder->newApp.ProductName, n + 1);
				      SetDlgItemText(hwndDlg, IDC_EDIT_DISPLAYNAME, pAppFolder->newApp.ProductName);
					  SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, EM_SETSEL, 0, -1);
					}
				  }
				  break;
			 }
		   }

       
		if (HIWORD(wParam) == BN_CLICKED) 
           { 
            switch (LOWORD(wParam)) 
             { 
              case IDC_FILE_BROWSE: 
				OnFileSelectApplication(hwndDlg, true, pAppFolder->newApp);
				SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_DISPLAYNAME));

			  break;
			  }
		   }
		 break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pAppFolder->m_ppHandle);
        break;

    case WM_NOTIFY:
        if (((NMHDR *) lParam)->code == PSN_KILLACTIVE )
		{ 
			if ( pAppFolder->MainThreadId != GetCurrentThreadId() ) return pAppFolder->ComDialogProc((WNDPROC)ApplicationDialogProc, hwndDlg, uMsg, wParam, lParam);

			// GetDisplayName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application Display Name can not be empty.",L"Application addition error",MB_OK|MB_ICONINFORMATION);
				return TRUE;
			}else
				if(n >= sizeof pAppFolder->newApp.Params.Description / sizeof pAppFolder->newApp.Params.Description[0])
				{ MessageBox(hwndDlg,L"Application product name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					return TRUE;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_DISPLAYNAME, pAppFolder->newApp.Params.Description, n + 1);
			
			// GetFileName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_FILENAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application File Name can not be empty.",L"Application addition error",MB_OK|MB_ICONINFORMATION);
				break;
			}else
				if(n >= sizeof (FileName))
				{ MessageBox(hwndDlg,L"Application File Name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					break;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, FileName, n + 1);
		
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_NAME, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_NAME, pAppFolder->newApp.ProductName, n + 1);
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_COMP, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_COMP, pAppFolder->newApp.CompanyName, n + 1);
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_DESC, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_DESC,(wchar_t *) pAppFolder->newApp.FileDescription, n + 1);

			// GetSecurityLevel
			for(int i=0;i<AttrNum;i++) pAppFolder->newApp.Params.Attributes.Param[i] = 0;
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_ALLTRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboKeepTrusted;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_TRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_JAIL, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboAutoIsolate;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_UNTRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modUntrusted;
				//pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboJail;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_NOPOPUPS, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboNoPopups;
			}

			// GetApplicationIdentity
			int current_identity = (int)SendDlgItemMessage(hwndDlg, IDC_IDENTITYBY, CB_GETCURSEL, 0, 0);
			Storage::ParamsType identity = (Storage::ParamsType)SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_GETITEMDATA, current_identity , 0);
			pAppFolder->newApp.Params.Type = identity;
			
			switch(identity)
			{	case Storage::parAppContent: 
					pAppFolder->newApp.Identity.Info.param_type = identity;
					App::Application::SetVerinfoIdentity(&pAppFolder->newApp, App::UserCreated);
					StringCchPrintf(pAppFolder->newApp.Identity.Info.FileName, 
									sizeof pAppFolder->newApp.Identity.Info.FileName / sizeof pAppFolder->newApp.Identity.Info.FileName[0], 
									_T("%s"), FileName);
					break;
				
				case Storage::parAppPath:	 
					pAppFolder->newApp.Identity.Path.param_type = identity;
					pAppFolder->newApp.Identity.Type  = Storage::idnPath; 
					pAppFolder->newApp.Identity.Path.Type  = nttFile; 
					StringCchPrintf(pAppFolder->newApp.Identity.Path.Path, 
								sizeof pAppFolder->newApp.Identity.Path.Path / sizeof pAppFolder->newApp.Identity.Path.Path[0], 
								_T("%s"), FileName);
					
					// check if file is DLL
					{
						size_t Length = wcslen(FileName);
						if ( Length > 4 && _wcsicmp(FileName + Length - 4, L".dll") == 0 ) {
							pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] |= GesRule::oboAppDLL;
						}
					}
					break;

				case Storage::parAppDigest:  
					pAppFolder->newApp.Identity.Digest.param_type = identity;
					pAppFolder->newApp.Identity.Type  = Storage::idnDigest; 
					pAppFolder->newApp.Identity.Digest.Type = Storage::dgtSHA1;
					StringCchPrintf(pAppFolder->newApp.Identity.Digest.FileName, 
								sizeof pAppFolder->newApp.Identity.Digest.FileName / sizeof pAppFolder->newApp.Identity.Digest.FileName[0], 
								_T("%s"), FileName);
					
					memset(pAppFolder->newApp.Identity.Digest.Digest,0,sizeof pAppFolder->newApp.Identity.Digest.Digest);
					
					commonlib::PtrToUCharArray digest;
					size_t digestSize =  commonlib::QueryHash (CALG_SHA1, (wstring)FileName, digest);
					if(digestSize > 0)
					{ 
					  for(int i=0;i<(int)digestSize;i++) pAppFolder->newApp.Identity.Digest.Digest[i]=digest[i];
					  pAppFolder->newApp.Identity.Digest.DigestSize  = digestSize;
					}

					break;

			}

			pAppFolder->newApp.Params.Model = GesRule::GswLabel;
			pAppFolder->newApp.Params.GroupId = pAppFolder->ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId];//pAppFolder->ApplicationItem->Params.Id;
			 
			try
			{ 	result = pAppFolder->CreateApplication(pAppFolder->newApp);
			}
			catch(Storage::StorageException &e) 
			{
			 MessageBox(hwndDlg, e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			 return TRUE;
			}
			if(result == S_FALSE)
			{
			MessageBox(hwndDlg,L"New application creation error!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			}else
			{	 SetWindowLong(hwndDlg, DWL_MSGRESULT, FALSE);
			}
				
			return TRUE;

		}
		//  Create Application
		if (((NMHDR *) lParam)->code == PSN_APPLY )
		{	
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}		
			HRESULT hr = MMCPropertyChangeNotify(pAppFolder->m_ppHandle, (LPARAM)pAppFolder);
			_ASSERT(SUCCEEDED(hr));
			pAppFolder->ActiveDialog = false;
			return PSNRET_NOERROR;
		}
		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pAppFolder->ActiveDialog = false;
			return FALSE;
		}
    }

  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}


HRESULT CGroupFolder::CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle)
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
    psp.pszTemplate = MAKEINTRESOURCE(IDD_GROUP);
    psp.pfnDlgProc =  GroupDialogProc;
    psp.lParam = reinterpret_cast<LPARAM>(this);
    psp.pszTitle = MAKEINTRESOURCE(IDS_GROUP);
    //psp.pszIcon = MAKEINTRESOURCE();
 
	switch(ActivePage)
 {
 case 0:	break;

 case 1:
	psp.pszTemplate = MAKEINTRESOURCE(IDD_APPLICATION);
    psp.pfnDlgProc =  ApplicationDialogProc;
    psp.pszTitle = MAKEINTRESOURCE(IDS_APPLICATION);
  break;

 case 2:
	 psp.pfnDlgProc = GroupPropDialogProc;
     break;

 default: return S_FALSE;
 }

   hPage = CreatePropertySheetPage(&psp);
   _ASSERT(hPage);
   return  lpProvider->AddPage(hPage);
}


HRESULT CGroupFolder::GetWatermarks(HBITMAP *lphWatermark,
                               HBITMAP *lphHeader,
                               HPALETTE *lphPalette,
                               BOOL *bStretch)
{
    return S_FALSE;
}



HRESULT CGroupFolder::InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page)
{
    HRESULT hr = S_FALSE;
    LPCWSTR szTitle = L"";

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
//***********************************************************************
CApplicationFolder::CApplicationFolder(CStaticNode *rootfolder):m_StaticNode(rootfolder)
{
	InitCom();
	
	m_ipConsole = NULL;
	m_ipDataObject = NULL;

	 if(0)
		Storage::replication::Replicate (L"c:\\develop\\geswall\\gswmmc\\src.dat",
										 L"c:\\develop\\geswall\\gswmmc\\dest.dat", 
										 //Storage::replication::rplNone); 
										 Storage::replication::rplAll);
	return;
	
}


CApplicationFolder::~CApplicationFolder()
{
 for (BASELIST::iterator iter = m_children.begin(); iter != m_children.end(); iter++)
	{
		delete (*iter);
	}
}
HRESULT CApplicationFolder::CreateGroup(Storage::ApplicationItem &appItem)
{
	HRESULT hr;

	// set group code to zero for all groups created by user
	appItem.Params.Attributes.Param[1] = 0;
	CoCreateGuid((GUID *)&appItem.Params.Attributes.Param[2]);
	appItem.Params.Options = Storage::dboUserCreated;
	try{
		int GroupId;
		Storage::InsertApplicationGroup(appItem.Params, true, GroupId);
		appItem.Params.Id = GroupId;
		m_StaticNode->PolicyChanged();
		} 
		catch(Storage::StorageException &e) { throw e; }
	
	if(appItem.Params.Id)
	{
	Storage::PtrToApplicationItem itemApplication (new Storage::ApplicationItem (appItem));
	CDelegationBase *group = new CGroupFolder(static_cast<Storage::PtrToApplicationItem>(itemApplication), this, m_StaticNode);
	hr = Expand(m_ipConsoleNameSpace);
	
	if(S_FALSE == hr)
	{

	
	 m_children.push_back(group); 

			SCOPEDATAITEM sdi;
			ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |   // Displayname is valid
                SDI_PARAM     |   // lParam is valid
                SDI_IMAGE     |   // nImage is valid
                SDI_OPENIMAGE |   // nOpenImage is valid
                SDI_PARENT    |   // relativeID is valid
                SDI_CHILDREN;     // cChildren is valid

            sdi.relativeID  = (HSCOPEITEM)GetParentScopeItem();
            sdi.nImage      = group->GetBitmapIndex();
			sdi.nOpenImage  = INDEX_OPENFOLDER;

			sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)group;       // The cookie
			sdi.cChildren   = 0;

			hr = m_ipConsoleNameSpace->InsertItem( &sdi );
            _ASSERT( SUCCEEDED(hr) );
			 group->SetScopeItemValue(sdi.ID);
			}
			bEmpty = FALSE;
			
			// hr = m_ipConsole->UpdateAllViews(m_ipDataObject, 0, 0);
			//_ASSERT( S_OK == hr);

	return S_OK;
	}
	return S_FALSE;
}

HRESULT CApplicationFolder::OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent)
{
    SCOPEDATAITEM sdi;
	Storage::PtrToApplicationItem pAppItem;
	m_ipConsoleNameSpace = pConsoleNameSpace;
	m_hParentHScopeItem = parent;
	CDelegationBase *ar;
	bool result;
	
    if (!bExpanded) 
	{
		result = Storage::GetApplicationList (0,ApplicationList);
	
		if (true == result)
		{ for (Storage::ApplicationItemList::iterator i = ApplicationList.begin (); i != ApplicationList.end (); ++i)
		 {
			if((*i)->Params.Type == Storage::parAppGroup)
			{	ar = new CGroupFolder(static_cast <Storage::PtrToApplicationItem> (*i), this, m_StaticNode);
				ar->bEmpty = Storage::GroupIsEmpty((*i)->Params.Attributes.Param[GesRule::attSubjectId]);
			}	
			else
				ar = new CApplicationItem(static_cast <Storage::PtrToApplicationItem> (*i), this, m_StaticNode);
			
			m_children.push_back(ar);
		 }
		}

        // create the child nodes, then expand them
       for (BASELIST::iterator iter = m_children.begin(); iter != m_children.end(); iter++)
		{     
			ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |   // Displayname is valid
                SDI_PARAM     |   // lParam is valid
                SDI_IMAGE     |   // nImage is valid
                SDI_OPENIMAGE |   // nOpenImage is valid
                SDI_PARENT    |   // relativeID is valid
                SDI_CHILDREN;     // cChildren is valid

            sdi.relativeID  = (HSCOPEITEM)parent;
            sdi.nImage      = (*iter)->GetBitmapIndex();
            (*iter)->GetApplicationItem(&pAppItem);
			if(pAppItem->Params.Type == Storage::parAppGroup)
				 sdi.nOpenImage  = INDEX_OPENFOLDER;
			else sdi.nOpenImage  = INDEX_APPLICATIONS;
			sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)(*iter);       // The cookie
            sdi.cChildren   = ((*iter)->bEmpty)? 0:1;

            HRESULT hr = pConsoleNameSpace->InsertItem( &sdi );

            _ASSERT( SUCCEEDED(hr) );

            (*iter)->SetScopeItemValue(sdi.ID);
			//(*iter)->SetHandle((HANDLE)sdi.ID);
        }
    }

    return S_OK;
}


HRESULT CApplicationFolder::OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    HRESULT hr = S_OK;
	long flag = (ActiveDialog)?  MF_GRAYED : 0;

    CONTEXTMENUITEM menuItemsNew[] =
    {
        {
            L"Add Application...", L"Add new application",
                ID_ADD_APPLICATION,  CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, CCM_SPECIAL_DEFAULT_ITEM    },
		{
            L"Add Group...", L"Add new group",
                ID_ADD_GROUP, CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, 0    },
		
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

HRESULT CApplicationFolder::OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
 	m_ipConsole = pConsole;
	m_ipDataObject = piDataObject;
		
	switch (lCommandID)
    {
 
	case ID_ADD_GROUP:

		ActivePage = 0;
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 0);
		break;
	
	
	case ID_ADD_APPLICATION:
		if ( !license::TrialManager::IsOperationAllowed(license::TrialManager::opAddApplication, g_hinst) ) break;
		ActivePage = 1;
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 1);
		break;
	}
    
    return S_OK;
}

HRESULT CApplicationFolder::CreateApplication(Storage::ApplicationItem &appItem)
{
	HRESULT hr;
	
	appItem.Params.Options = Storage::dboUserCreated;
	//license::LicenseManager::LicenseEssentials License;
	//license::LicenseManager::LicenseCopy(License);
	//if ( License.StateFlags & license::stateTrial ) appItem.Params.Options |= Storage::dboLabel1;
	try {
		int AppId;
		Storage::InsertApplication(appItem, AppId);
		appItem.Params.Id = AppId;
		m_StaticNode->PolicyChanged();
	} 	
	catch(Storage::StorageException &e) { throw e; }
		
	if(appItem.Params.Id)
	{
	GswClient Client;
	Client.RefreshApp(appItem.Params.Id);
	appItem.Params.Attributes.Param[0] = appItem.Params.Id;
	Storage::PtrToApplicationItem itemApplication (new Storage::ApplicationItem (appItem));
	CDelegationBase *application = new CApplicationItem(static_cast<Storage::PtrToApplicationItem>(itemApplication), NULL, m_StaticNode);
	hr = Expand(m_ipConsoleNameSpace);
     
	if(S_FALSE == hr)
	{

	m_children.push_back(application); 

			SCOPEDATAITEM sdi;
			ZeroMemory(&sdi, sizeof(SCOPEDATAITEM) );
            sdi.mask = SDI_STR       |   // Displayname is valid
                SDI_PARAM     |   // lParam is valid
                SDI_IMAGE     |   // nImage is valid
                SDI_OPENIMAGE |   // nOpenImage is valid
                SDI_PARENT    |   // relativeID is valid
                SDI_CHILDREN;     // cChildren is valid

            sdi.relativeID  = (HSCOPEITEM)GetParentScopeItem();
            sdi.nImage      = application->GetBitmapIndex();
			sdi.nOpenImage  = INDEX_APPLICATIONS;

			sdi.displayname = MMC_CALLBACK;
            sdi.lParam      = (LPARAM)application;       // The cookie
			sdi.cChildren   = 0;

			hr = m_ipConsoleNameSpace->InsertItem( &sdi );
            _ASSERT( SUCCEEDED(hr) );
			 application->SetScopeItemValue(sdi.ID);
			}
			bEmpty = FALSE;
			// hr = m_ipConsole->UpdateAllViews(m_ipDataObject, 0, 0);
			//_ASSERT( S_OK == hr);

	return S_OK;
	}
	return S_FALSE;
}
HRESULT CApplicationFolder::HasPropertySheets()
{
    // say "yes" when MMC asks if we have pages
    
	return S_OK;
}

INT_PTR CALLBACK CApplicationFolder::GroupDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CApplicationFolder *pAppFolder = NULL;
	HRESULT result;

   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pAppFolder = reinterpret_cast<CApplicationFolder *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		
       break;

     case WM_COMMAND:
        // turn the Apply button on
        // if (HIWORD(wParam) == EN_CHANGE ||
        //    HIWORD(wParam) == CBN_SELCHANGE)
        //    SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);

		 break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pAppFolder->m_ppHandle);
        break;

    case WM_NOTIFY:
       if (((NMHDR *) lParam)->code == PSN_KILLACTIVE )
		{ 
			if ( pAppFolder->MainThreadId != GetCurrentThreadId() ) return pAppFolder->ComDialogProc((WNDPROC)GroupDialogProc, hwndDlg, uMsg, wParam, lParam);

			int n = (int)SendDlgItemMessage(hwndDlg, IDC_GROUPNAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{
				MessageBox(hwndDlg,L"Group name can not be empty.",L"Group addition error",MB_OK|MB_ICONINFORMATION);
				SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
				return TRUE;
			}
			else
			{
				if( n >= sizeof pAppFolder->newGroup.Params.Description / sizeof pAppFolder->newGroup.Params.Description[0] )
				{ 
					MessageBox(hwndDlg,L"Group name is too long!",L"New group error",MB_OK|MB_ICONINFORMATION);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
					return TRUE;
				}
				else
				{ 
					GetDlgItemText(hwndDlg, IDC_GROUPNAME, pAppFolder->newGroup.Params.Description, n + 1);
					pAppFolder->newGroup.Params.GroupId =pAppFolder->newGroup.Params.Attributes.Param[GesRule::attSubjectId] = 0;

					try
					{ 	result = pAppFolder->CreateGroup(pAppFolder->newGroup);
					}
					catch(Storage::StorageException &e) 
					{
					MessageBox(hwndDlg, e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
					return TRUE;
					}
			
					if(result == S_FALSE)
					{
					MessageBox(hwndDlg,L"New group creation error!",L"Error",MB_OK|MB_ICONINFORMATION);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
					}else
					{	 SetWindowLong(hwndDlg, DWL_MSGRESULT, FALSE);
					}
						
					return TRUE;
				}// else n > sizeof
			} // else n==0
			return TRUE;
		} //if PSN_KILLACTIVE
			
		if (((NMHDR *) lParam)->code == PSN_APPLY )
		{	
				
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}
			
			HRESULT hr = MMCPropertyChangeNotify(pAppFolder->m_ppHandle, (LPARAM)pAppFolder);
			_ASSERT(SUCCEEDED(hr));
			pAppFolder->ActiveDialog = false;
			return PSNRET_NOERROR;
		}
				
		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pAppFolder->ActiveDialog = false;
			return FALSE;
		}
    }//switch

  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}



INT_PTR CALLBACK CApplicationFolder::ApplicationDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CApplicationFolder *pAppFolder = NULL;
	wchar_t FileName[255];
	int n;
	HRESULT result;

   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pAppFolder = reinterpret_cast<CApplicationFolder *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Version Info");
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Name");
		//SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Digest");
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 0, (LPARAM)Storage::parAppContent);
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 1, (LPARAM)Storage::parAppPath);
		//SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 2, (LPARAM)Storage::parAppDigest);
			
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETCURSEL, 0, 0); 

		if ( pAppFolder->m_StaticNode->Product != license::gswServer ) {
			SendDlgItemMessage(hwndDlg,IDC_RADIO_TRUST, BM_SETCHECK, BST_CHECKED, 0);
		} else {
			SendDlgItemMessage(hwndDlg,IDC_RADIO_JAIL, BM_SETCHECK, BST_CHECKED, 0);
			EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_TRUST),false);
		}
		memset(&pAppFolder->newApp, 0, sizeof pAppFolder->newApp);
		
		SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_FILENAME));
       break;

     case WM_COMMAND:
        // turn the Apply button on
        //if (HIWORD(wParam) == EN_CHANGE ||
        //    HIWORD(wParam) == CBN_SELCHANGE)
        //    SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);
		if (HIWORD(wParam) == CBN_SELCHANGE) 
           {  
			if (LOWORD(wParam) == IDC_IDENTITYBY)
			{ if( !App::Application::IsIdentifiedByVerinfo(&pAppFolder->newApp)
				 && 0 == SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_GETCURSEL, 0, 0))
				{ 
					SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETCURSEL, 1, 0); 
				}
			 }
		   }

		   if (HIWORD(wParam) == EN_KILLFOCUS) 
           {  
			switch (LOWORD(wParam)) 
             { 
              case IDC_EDIT_FILENAME: 
				if(0 < (n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_FILENAME, WM_GETTEXTLENGTH, 0, 0)))
				{  GetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, FileName, n + 1);
				    
				 if(wcscmp(FileName,pAppFolder->newApp.FileName))
				   OnFileSelectApplication(hwndDlg, false, pAppFolder->newApp);
				}
				  break;
			 }
		   }
 
		 
		 if (HIWORD(wParam) == EN_SETFOCUS) 
           {  
			switch (LOWORD(wParam)) 
             { 
              case IDC_EDIT_DISPLAYNAME: 
				if(0 == (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, WM_GETTEXTLENGTH, 0, 0))
				  { if(0 != (n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_NAME, WM_GETTEXTLENGTH, 0, 0)))
				    { GetDlgItemText(hwndDlg, IDC_PRODUCT_NAME, pAppFolder->newApp.ProductName, n + 1);
				      SetDlgItemText(hwndDlg, IDC_EDIT_DISPLAYNAME, pAppFolder->newApp.ProductName);
					  SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, EM_SETSEL, 0, -1);
					}
				  }
				  break;
			 }
		   }

       
		if (HIWORD(wParam) == BN_CLICKED) 
           { 
            switch (LOWORD(wParam)) 
             { 
              case IDC_FILE_BROWSE: 
				OnFileSelectApplication(hwndDlg, true, pAppFolder->newApp);
				SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_DISPLAYNAME));

			  break;
			  }
		   }
		 break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pAppFolder->m_ppHandle);
        break;

    case WM_NOTIFY:
        if (((NMHDR *) lParam)->code == PSN_KILLACTIVE )
		{ 
			if ( pAppFolder->MainThreadId != GetCurrentThreadId() ) return pAppFolder->ComDialogProc((WNDPROC)ApplicationDialogProc, hwndDlg, uMsg, wParam, lParam);
			// GetDisplayName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application Display Name can not be empty.",L"Application addition error",MB_OK|MB_ICONINFORMATION);
				return TRUE;
			}else
				if(n >= sizeof pAppFolder->newApp.Params.Description / sizeof pAppFolder->newApp.Params.Description[0])
				{ MessageBox(hwndDlg,L"Application product name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					return TRUE;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_DISPLAYNAME, pAppFolder->newApp.Params.Description, n + 1);
			
			// GetFileName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_FILENAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application File Name can not be empty.",L"Application addition error",MB_OK|MB_ICONINFORMATION);
				break;
			}else
				if(n >= sizeof FileName / sizeof FileName[0])
				{ MessageBox(hwndDlg,L"Application File Name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					break;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, FileName, n + 1);
		
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_NAME, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_NAME, pAppFolder->newApp.ProductName, n + 1);
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_COMP, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_COMP, pAppFolder->newApp.CompanyName, n + 1);
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_DESC, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_DESC,(wchar_t *) pAppFolder->newApp.FileDescription, n + 1);

			// GetSecurityLevel
			for(int i=0;i<AttrNum;i++) pAppFolder->newApp.Params.Attributes.Param[i] = 0;
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_ALLTRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboKeepTrusted;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_TRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_JAIL, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboAutoIsolate;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_UNTRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modUntrusted;
				//pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboJail;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_NOPOPUPS, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppFolder->newApp.Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] = GesRule::oboNoPopups;
			}

			// GetApplicationIdentity
			int current_identity = (int)SendDlgItemMessage(hwndDlg, IDC_IDENTITYBY, CB_GETCURSEL, 0, 0);
			Storage::ParamsType identity = (Storage::ParamsType)SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_GETITEMDATA, current_identity , 0);
			pAppFolder->newApp.Params.Type = identity;
			
			switch(identity)
			{	case Storage::parAppContent: 
					pAppFolder->newApp.Identity.Info.param_type = identity;
					App::Application::SetVerinfoIdentity(&pAppFolder->newApp, App::UserCreated);
					StringCchPrintf(pAppFolder->newApp.Identity.Info.FileName, 
								sizeof pAppFolder->newApp.Identity.Info.FileName / sizeof pAppFolder->newApp.Identity.Info.FileName[0], 
								_T("%s"), FileName);
					break;
				
				case Storage::parAppPath:	 
					pAppFolder->newApp.Identity.Path.param_type = identity;
					pAppFolder->newApp.Identity.Type  = Storage::idnPath; 
					pAppFolder->newApp.Identity.Path.Type  = nttFile; 
					StringCchPrintf(pAppFolder->newApp.Identity.Path.Path, 
						sizeof pAppFolder->newApp.Identity.Path.Path / sizeof pAppFolder->newApp.Identity.Path.Path[0], 
						_T("%s"), FileName);

					// check if file is DLL
					{
						size_t Length = wcslen(FileName);
						if ( Length > 4 && _wcsicmp(FileName + Length - 4, L".dll") == 0 ) {
							pAppFolder->newApp.Params.Attributes.Param[GesRule::attOptions] |= GesRule::oboAppDLL;
						}
					}
					
					break;

				case Storage::parAppDigest:  
					pAppFolder->newApp.Identity.Digest.param_type = identity;
					pAppFolder->newApp.Identity.Type  = Storage::idnDigest; 
					pAppFolder->newApp.Identity.Digest.Type = Storage::dgtSHA1;
					StringCchPrintf(pAppFolder->newApp.Identity.Digest.FileName, 
						sizeof pAppFolder->newApp.Identity.Digest.FileName / sizeof pAppFolder->newApp.Identity.Digest.FileName[0], 
						_T("%s"), FileName);
					
					memset(pAppFolder->newApp.Identity.Digest.Digest,0,sizeof pAppFolder->newApp.Identity.Digest.Digest);
					
					commonlib::PtrToUCharArray digest;
					size_t digestSize =  commonlib::QueryHash (CALG_SHA1, (wstring)FileName, digest);
					if(digestSize > 0)
					{ 
					  for(int i=0;i<(int)digestSize;i++) pAppFolder->newApp.Identity.Digest.Digest[i]=digest[i];
					  pAppFolder->newApp.Identity.Digest.DigestSize  = digestSize;
					}

					break;

			}

			pAppFolder->newApp.Params.Model = GesRule::GswLabel;
			pAppFolder->newApp.Params.GroupId =pAppFolder->newApp.Params.Attributes.Param[GesRule::attSubjectId] = 0;
				 
			try
			{ 	result = pAppFolder->CreateApplication(pAppFolder->newApp);
			}
			catch(Storage::StorageException &e) 
			{
			 MessageBox(hwndDlg, e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			 return TRUE;
			}
			if(result == S_FALSE)
			{
			MessageBox(hwndDlg,L"New application creation error!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			}else
			{	 SetWindowLong(hwndDlg, DWL_MSGRESULT, FALSE);
			}
				
			return TRUE;

		}
		//  Create Application
		if (((NMHDR *) lParam)->code == PSN_APPLY )
		{	
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}		
			HRESULT hr = MMCPropertyChangeNotify(pAppFolder->m_ppHandle, (LPARAM)pAppFolder);
			_ASSERT(SUCCEEDED(hr));
			pAppFolder->ActiveDialog = false;
			return PSNRET_NOERROR;
		}
		
		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pAppFolder->ActiveDialog = false;
			return FALSE;
		}
    }

  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}


HRESULT CApplicationFolder::CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle)
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
    psp.pszTemplate = MAKEINTRESOURCE(IDD_GROUP);
    psp.pfnDlgProc =  GroupDialogProc;
    psp.lParam = reinterpret_cast<LPARAM>(this);
    psp.pszTitle = MAKEINTRESOURCE(IDS_GROUP);
    //psp.pszIcon = MAKEINTRESOURCE();
 	
	switch(ActivePage)
 {
 case 0:	break;

 case 1:
	psp.pszTemplate = MAKEINTRESOURCE(IDD_APPLICATION);
    psp.pfnDlgProc =  ApplicationDialogProc;
    psp.pszTitle = MAKEINTRESOURCE(IDS_APPLICATION);
  break;

 default: return S_FALSE;
 }

   hPage = CreatePropertySheetPage(&psp);
   _ASSERT(hPage);
   return  lpProvider->AddPage(hPage);
}

HRESULT CApplicationFolder::GetWatermarks(HBITMAP *lphWatermark,
                               HBITMAP *lphHeader,
                               HPALETTE *lphPalette,
                               BOOL *bStretch)
{
    return S_FALSE;
}



HRESULT CApplicationFolder::InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page)
{
    HRESULT hr = S_FALSE;
    LPCWSTR szTitle = L"";

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

HRESULT CApplicationRule::OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect)
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

HRESULT CApplicationRule::OnDelete(CComponentData * pCompData, IConsole *pConsoleComp)
{
    HRESULT hr = S_FALSE;
	bool result = false;
    //Delete the item
	try{
		result = Storage::DeleteApplicationResource(m_Resource->Identity.Path.Id);
		m_StaticNode->PolicyChanged();
	} 
	catch(Storage::StorageException &e)
	{
		pConsoleComp->MessageBox(e.getMessage().c_str(),L"Error",MB_OK|MB_ICONINFORMATION,0);
		return S_FALSE;
	}
	if( false == result) 
	{
		pConsoleComp->MessageBox(L"Can't delete application resource", L"Database error", MB_OK|MB_ICONINFORMATION, NULL);
		return hr;
	}
	//
	// Send update notification to gswserv
	//
	//GswClient Client;
	//Client.RefreshResources();

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

HRESULT CApplicationRule::OnRefresh(IConsole *pConsole)

{
    //Call IConsole::UpdateAllViews to redraw all views
    //owned by the parent scope item

    IDataObject *dummy = NULL;

    HRESULT hr;

    hr = pConsole->UpdateAllViews(dummy, m_pParent->GetParentScopeItem(), UPDATE_SCOPEITEM);
    _ASSERT( S_OK == hr);

    return hr;
}


CApplicationItem::CApplicationItem(Storage::PtrToApplicationItem appItem, CDelegationBase * parent, CStaticNode *StaticNode):m_parent(parent),ApplicationItem(appItem)
{
	InitCom();

	m_StaticNode = StaticNode;
	ActiveDialog = false;

	bool result;
	result = Storage::GetApplicationResources(ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId], ResourceList);
	if (true == result)
	{ for (Storage::ResourceItemList::iterator i = ResourceList.begin (); i != ResourceList.end (); ++i)
		{
			CApplicationRule *apprule = new CApplicationRule(static_cast <Storage::PtrToResourceItem> (*i),this, m_StaticNode);
			m_children.push_back(apprule);
		}
	}
	m_ipConsole = NULL;
	m_ipDataObject = NULL;
	m_CompData = NULL;
	
}

HRESULT CApplicationItem::OnViewChange(IConsole *pConsole, LPDATAOBJECT ipDataObject, LPARAM nArg, LPARAM nParam, LONG_PTR pComponent)
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


HRESULT CApplicationItem::OnShow(IConsole *pConsole, BOOL bShow, HSCOPEITEM scopeitem)
{
    HRESULT      hr = S_OK;

    IHeaderCtrl *pHeaderCtrl = NULL;
    IResultData *pResultData = NULL;
	
	//m_pConsole = pConsole;
    m_hParentHScopeItem = scopeitem;

	if (bShow) {
        hr = pConsole->QueryInterface(IID_IHeaderCtrl, (void **)&pHeaderCtrl);
        _ASSERT( SUCCEEDED(hr) );

        hr = pConsole->QueryInterface(IID_IResultData, (void **)&pResultData);
        _ASSERT( SUCCEEDED(hr) );

        // Set the column headers in the results pane
          hr = pHeaderCtrl->InsertColumn( 0, L"Resource", 0, MMCLV_AUTO );
        _ASSERT( S_OK == hr );
        hr = pHeaderCtrl->InsertColumn( 1, L"Type", 0, MMCLV_AUTO );
        _ASSERT( S_OK == hr );
        hr = pHeaderCtrl->InsertColumn( 2, L"Access", 0, MMCLV_AUTO );
        _ASSERT( S_OK == hr );

		EnumerateResultItems(pResultData);

        pHeaderCtrl->Release();
        pResultData->Release();
    }

    return hr;
}


HRESULT CApplicationItem::EnumerateResultItems(LPRESULTDATA pResultData)
{
	_ASSERT( NULL != pResultData );
	HRESULT hr = S_FALSE;
    // insert items here
    RESULTDATAITEM rdi;

	hr = pResultData->DeleteAllRsltItems();
    _ASSERT( SUCCEEDED(hr) );

    if (!bExpanded) {
		// create the child nodes, then expand them
        for (RULELIST::iterator iter = m_children.begin(); iter != m_children.end(); iter++) {
			if(!(*iter)->getDeletedStatus()) {
	 			ZeroMemory(&rdi, sizeof(RESULTDATAITEM) );
                rdi.mask       = RDI_STR       |   // Displayname is valid
                    RDI_IMAGE     |
                    RDI_PARAM;        // nImage is valid

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
HRESULT CApplicationItem::OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    HRESULT hr = S_OK;
	long flag = (ActiveDialog)?  MF_GRAYED : 0;
	
	CONTEXTMENUITEM menuItemsNew[] =
    {
        {
            L"Add Rule...", L"Add new application rule",
                ID_ADD_APPLICATION_RULE, CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, CCM_SPECIAL_DEFAULT_ITEM     },
			
			{
            L"Properties", L"Application Properties",
                ID_ADD_APPLICATION,  CCM_INSERTIONPOINTID_PRIMARY_TOP, flag, 0   },
		
		
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

HRESULT CApplicationItem::OnDelete(CComponentData * pCompData, IConsole *pConsole)
{
		if(Storage::DeleteApplication(ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId]))
		{   
			GswClient Client;
			Client.RefreshApp(ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId]);
			pCompData->GetConsoleNameSpace()->DeleteItem(GetParentScopeItem(), true);
			if(m_parent) 
			{ 
				CGroupFolder * pGroup = dynamic_cast <CGroupFolder *> (m_parent);
				if(pGroup != NULL)
				{ 
					pGroup->m_children.remove(this);
					pGroup->bEmpty = (pGroup->m_children.size())? FALSE : TRUE;
				}else
				{
					CApplicationFolder * pAppFolder = dynamic_cast <CApplicationFolder *> (m_parent); 
					if(pAppFolder != NULL)
					{ 
						pAppFolder->m_children.remove(this);
						pAppFolder->bEmpty = (pAppFolder->m_children.size())? FALSE : TRUE;
					}
					else _ASSERT(FALSE);
				}
			  }
		}
		else
			pConsole->MessageBox(L"Can't delete application",L"Error",MB_OK|MB_ICONINFORMATION,0);

		return S_OK;
}
HRESULT CApplicationItem::OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
	m_ipConsole = pConsole;
	m_ipDataObject = piDataObject;
	m_CompData = pComData;
    
	switch (lCommandID)
    {
  
	case ID_ADD_APPLICATION_RULE:
		ActivePage = 0;
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 0);
		break;

	case ID_ADD_APPLICATION:
		ActivePage = 1;
		ActiveDialog = true;
		InvokePage(pConsole, piDataObject, pComData, 1);
		break;
    }
    
    return S_OK;
}



HRESULT CApplicationItem::HasPropertySheets()
{
    // say "yes" when MMC asks if we have pages
    
	return S_OK;
}

INT_PTR CALLBACK CApplicationItem::RuleDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CApplicationItem *pAppItem = NULL;
	int n;
	
   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pAppItem = reinterpret_cast<CApplicationItem *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Allow");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Redirect");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Deny");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Read Only");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 0, (LPARAM)GesRule::oboGrantAccess);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 1, (LPARAM)GesRule::oboRedirectAccess);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 2, (LPARAM)GesRule::oboDenyAccess);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 3, (LPARAM)GesRule::oboDenyRedirectAccess);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETCURSEL, 0, 0); 

		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"File");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"Registry");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"Device");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"Network");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"System Object");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 0, (LPARAM)nttFile);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 1, (LPARAM)nttKey);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 2, (LPARAM)nttDevice);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 3, (LPARAM)nttNetwork);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 4, (LPARAM)nttSystemObject);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETCURSEL, 0, 0); 

		SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_RULE));
       break;

     case WM_COMMAND:
        // turn the Apply button on
        //if (HIWORD(wParam) == EN_CHANGE ||
        //    HIWORD(wParam) == CBN_SELCHANGE)
        //    SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);
		       
		if (HIWORD(wParam) == BN_CLICKED) 
           { 
            switch (LOWORD(wParam)) 
             { 
              case IDC_FILE_BROWSE: 
				OnFileSelectRule(hwndDlg);
				SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_DISPLAYNAME));

			  break;

			  case IDC_RULE_FILE: 
				  EnableWindow(GetDlgItem(hwndDlg,IDC_FILE_BROWSE),true); 
				
				 break; 
			  case IDC_RULE_REGISTRY:
                  EnableWindow(GetDlgItem(hwndDlg,IDC_FILE_BROWSE),false); 
				
				 break; 
			  case IDC_RULE_DEVICE: 
				  EnableWindow(GetDlgItem(hwndDlg,IDC_FILE_BROWSE),false); 
				
				 break; 

			  }
		   }
		 break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pAppItem->m_ppHandle);
        break;

    case WM_NOTIFY:
         if (((NMHDR *) lParam)->code == PSN_KILLACTIVE )
		 {	
		    if ( pAppItem->MainThreadId != GetCurrentThreadId() ) return pAppItem->ComDialogProc((WNDPROC)RuleDialogProc, hwndDlg, uMsg, wParam, lParam);

			// GetDisplayName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_RULE, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application Resource field can not be empty.",L"Application Resource addition error",MB_OK|MB_ICONINFORMATION);
				SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE); return TRUE;
			}else
				if(n >= sizeof pAppItem->newRule.Identity.Path.Path / sizeof pAppItem->newRule.Identity.Path.Path[0])
				{ MessageBox(hwndDlg,L"Application product name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE); return TRUE;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_RULE, pAppItem->newRule.Identity.Path.Path, n + 1);
			
			
			// GetRuleType
			int ObjectTypeId = (int)SendDlgItemMessage(hwndDlg, IDC_OBJECT_TYPE, CB_GETCURSEL, 0, 0);
			pAppItem->newRule.Identity.Path.Type = (NtObjectType) SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_GETITEMDATA, ObjectTypeId , 0);

			// GetRuleAccess
			int access_perm = (int)SendDlgItemMessage(hwndDlg, IDC_RULE_PERM, CB_GETCURSEL, 0, 0);
			memset (pAppItem->newRule.Params.Attributes.Param, 0, sizeof (pAppItem->newRule.Params.Attributes.Param));
			pAppItem->newRule.Identity.Type = Storage::idnPath;
			pAppItem->newRule.Params.Attributes.Param[5] = (ULONG)SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_GETITEMDATA, access_perm , 0);
			pAppItem->newRule.Params.Attributes.Param[1] = pAppItem->ApplicationItem->Params.Attributes.Param[0];
			
			try
			{ 
			 if(false == pAppItem->CreateApplicationRule(pAppItem->newRule))
			 {
			MessageBox(hwndDlg,L"New rule creation error!",L"Error",MB_OK|MB_ICONINFORMATION);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			 }else
			  {	 SetWindowLong(hwndDlg, DWL_MSGRESULT, FALSE);
			  }
			}
			catch(Storage::StorageException &e) 
			{
			 MessageBox(hwndDlg, e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			 return TRUE;
			}
				
			return TRUE;

		 }

		 // Create Application Rule
		 if (((NMHDR *) lParam)->code == PSN_APPLY )
		 {
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}
			
			HRESULT hr = MMCPropertyChangeNotify(pAppItem->m_ppHandle, (LPARAM)pAppItem);
			_ASSERT(SUCCEEDED(hr));
			pAppItem->ActiveDialog = false;
			return PSNRET_NOERROR;
		}
		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pAppItem->ActiveDialog = false;
			return FALSE;
		}
    }

  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

bool CApplicationItem::CreateApplicationRule(Storage::ResourceItem &Res)
{
	Res.Params.Options = Storage::dboUserCreated;
	Res.Identity.Path.Options = Storage::dboUserCreated;
	int Id;
	Storage::InsertApplicationResource(Res, Id);
	m_StaticNode->PolicyChanged();

	Storage::PtrToResourceItem itemResource (new Storage::ResourceItem (Res));
		
	CApplicationRule *apprule = new CApplicationRule(itemResource,this, m_StaticNode);
	m_children.push_back(apprule);
		
	HRESULT hr = m_ipConsole->UpdateAllViews(m_ipDataObject, 0, 0);
	_ASSERT( S_OK == hr);

	return true;
}

//*** Application Dialog Procedure **************
INT_PTR CALLBACK CApplicationItem::ApplicationDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CApplicationItem *pAppItem = NULL;
	wchar_t FileName[255];
	int n;
	long options=0, integrity=0;
	HRESULT result;
	HICON hExecIcon;

   switch (uMsg) 
   {
    case WM_INITDIALOG:
        // catch the "this" pointer so we can actually operate on the object
        pAppItem = reinterpret_cast<CApplicationItem *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		
		switch(pAppItem->ApplicationItem->Params.Type)
		{	case Storage::parAppContent: 
				SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Version Info");
				SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 0, (LPARAM)Storage::parAppContent);
				SetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, pAppItem->ApplicationItem->Identity.Info.FileName);
				EnableWindow(GetDlgItem(hwndDlg,IDC_EDIT_FILENAME),false); 
				EnableWindow(GetDlgItem(hwndDlg,IDC_FILE_BROWSE),false);
				break;
			case Storage::parAppPath:
				SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Name");
				SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 1, (LPARAM)Storage::parAppPath);
				SetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, pAppItem->ApplicationItem->Identity.Path.Path);
				break;
			case Storage::parAppDigest:
				SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_ADDSTRING, 0, (LPARAM)L"Digest");
				SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETITEMDATA, 1, (LPARAM)Storage::parAppDigest);
				SetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, pAppItem->ApplicationItem->Identity.Digest.FileName);
				break;
		}
		SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_SETCURSEL, 0, 0); 
		EnableWindow(GetDlgItem(hwndDlg,IDC_IDENTITYBY),false); 
		
		options =	 pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions];
		integrity = pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attIntegrity];
		
		if((integrity == GesRule::modTCB) && (options & GesRule::oboKeepTrusted))
			SendDlgItemMessage(hwndDlg,IDC_RADIO_ALLTRUST, BM_SETCHECK, BST_CHECKED, 0); 
		else 
		if((integrity == GesRule::modTCB) && (options & GesRule::oboAutoIsolate))
			SendDlgItemMessage(hwndDlg,IDC_RADIO_JAIL, BM_SETCHECK, BST_CHECKED, 0); 
		else
		if((integrity == GesRule::modTCB) && !(options & (GesRule::oboKeepTrusted | GesRule::oboAutoIsolate | GesRule::oboNoPopups)))
			  SendDlgItemMessage(hwndDlg,IDC_RADIO_TRUST, BM_SETCHECK, BST_CHECKED, 0);
		else
		if( integrity == GesRule::modUntrusted )
			SendDlgItemMessage(hwndDlg,IDC_RADIO_UNTRUST, BM_SETCHECK, BST_CHECKED, 0);
		else
		if((integrity == GesRule::modTCB) && (options & GesRule::oboNoPopups))
			  SendDlgItemMessage(hwndDlg,IDC_RADIO_NOPOPUPS, BM_SETCHECK, BST_CHECKED, 0);
		
		if ( pAppItem->m_StaticNode->Product == license::gswServer ) {
			EnableWindow(GetDlgItem(hwndDlg,IDC_RADIO_TRUST),false);
		}

		SetDlgItemText(hwndDlg, IDC_EDIT_DISPLAYNAME, pAppItem->ApplicationItem->Params.Description);
		SetDlgItemText(hwndDlg, IDC_PRODUCT_NAME, pAppItem->ApplicationItem->ProductName);
		SetDlgItemText(hwndDlg, IDC_PRODUCT_DESC, pAppItem->ApplicationItem->FileDescription);
		SetDlgItemText(hwndDlg, IDC_COMPANY_NAME, pAppItem->ApplicationItem->CompanyName);
		
		hExecIcon = commonlib::Bytes2Hicon(pAppItem->ApplicationItem->Icon, pAppItem->ApplicationItem->IconSize);
		if(hExecIcon)  
			SendDlgItemMessage(hwndDlg, IDC_PRODUCT_ICON, STM_SETIMAGE, IMAGE_ICON, (LPARAM)hExecIcon);

		SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_FILENAME));

       break;

     case WM_COMMAND:
        // turn the Apply button on
        //if (HIWORD(wParam) == EN_CHANGE ||
        //    HIWORD(wParam) == CBN_SELCHANGE)
        //    SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);
		if (HIWORD(wParam) == EN_SETFOCUS) 
           {  
			switch (LOWORD(wParam)) 
             { 
              case IDC_EDIT_DISPLAYNAME: 
				if(0 == (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, WM_GETTEXTLENGTH, 0, 0))
				  { if(0 != (n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_NAME, WM_GETTEXTLENGTH, 0, 0)))
				    { GetDlgItemText(hwndDlg, IDC_PRODUCT_NAME, pAppItem->ApplicationItem->ProductName, n + 1);
				      SetDlgItemText(hwndDlg, IDC_EDIT_DISPLAYNAME, pAppItem->ApplicationItem->ProductName);
					  SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, EM_SETSEL, 0, -1);
					}
				  }
				  break;
			 }
		   }

       
		if (HIWORD(wParam) == EN_KILLFOCUS) 
           {  
			switch (LOWORD(wParam)) 
             { 
              case IDC_EDIT_FILENAME: 
				if(0 < (n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_FILENAME, WM_GETTEXTLENGTH, 0, 0)))
				{  GetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, FileName, n + 1);
				    
				 if(wcscmp(FileName,pAppItem->ApplicationItem->FileName))
				   OnFileSelectApplication(hwndDlg, false, *pAppItem->ApplicationItem);
				}
				  break;
			 }
		   }
		   
		   if (HIWORD(wParam) == BN_CLICKED) 
           { 
            switch (LOWORD(wParam)) 
             { 
              case IDC_FILE_BROWSE: 
				OnFileSelectApplication(hwndDlg, true,  *pAppItem->ApplicationItem);
				SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_DISPLAYNAME));

			  break;
			  }
		   } 
		 break; 

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pAppItem->m_ppHandle);
        break;

    case WM_NOTIFY:
         if (((NMHDR *) lParam)->code == PSN_KILLACTIVE )
		{ 
// GetDisplayName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_DISPLAYNAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application Display Name can not be empty.",L"Application addition error",MB_OK|MB_ICONINFORMATION);
				return TRUE;
			}else
				if(n >= sizeof pAppItem->ApplicationItem->Params.Description / sizeof pAppItem->ApplicationItem->Params.Description[0])
				{ MessageBox(hwndDlg,L"Application product name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					return TRUE;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_DISPLAYNAME, pAppItem->ApplicationItem->Params.Description, n + 1);
			
			// GetFileName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_FILENAME, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application File Name can not be empty.",L"Application addition error",MB_OK|MB_ICONINFORMATION);
				return TRUE;
			}else
				if(n >= sizeof FileName / sizeof FileName[0])
				{ MessageBox(hwndDlg,L"Application File Name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					return TRUE;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_FILENAME, FileName, n + 1);
		
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_NAME, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_NAME, pAppItem->ApplicationItem->ProductName, n + 1);
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_COMP, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_COMP, pAppItem->ApplicationItem->CompanyName, n + 1);
			n = (int)SendDlgItemMessage(hwndDlg, IDC_PRODUCT_DESC, WM_GETTEXTLENGTH, 0, 0);
			if (n) GetDlgItemText(hwndDlg, IDC_PRODUCT_DESC,(wchar_t *) pAppItem->ApplicationItem->FileDescription, n + 1);

			// GetSecurityLevel
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_ALLTRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] &= ~(GesRule::oboKeepTrusted | GesRule::oboAutoIsolate | GesRule::oboNoPopups);
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] |= GesRule::oboKeepTrusted;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_TRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] &= ~(GesRule::oboKeepTrusted | GesRule::oboAutoIsolate | GesRule::oboNoPopups);
								
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_JAIL, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] &= ~(GesRule::oboKeepTrusted | GesRule::oboAutoIsolate | GesRule::oboNoPopups);
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] |= GesRule::oboAutoIsolate;
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_UNTRUST, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modUntrusted;
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] &= ~(GesRule::oboKeepTrusted | GesRule::oboAutoIsolate | GesRule::oboNoPopups);
			}else
			if(SendDlgItemMessage(hwndDlg, IDC_RADIO_NOPOPUPS, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{	pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] &= ~(GesRule::oboKeepTrusted | GesRule::oboAutoIsolate | GesRule::oboNoPopups);
				pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] |= GesRule::oboNoPopups;
			}	

			// GetApplicationIdentity
			//int current_identity = (int)SendDlgItemMessage(hwndDlg, IDC_IDENTITYBY, CB_GETCURSEL, 0, 0);
			//Storage::ParamsType identity = (Storage::ParamsType)SendDlgItemMessage(hwndDlg,IDC_IDENTITYBY, CB_GETITEMDATA, current_identity , 0);
			//pAppItem->ApplicationItem->Params.Type = identity;
			
			switch(pAppItem->ApplicationItem->Params.Type)
			{
				//
				// Update the path, version info and digests cannot be updated
				//
				case Storage::parAppPath:	 
					pAppItem->ApplicationItem->Identity.Type  = Storage::idnPath; 
					pAppItem->ApplicationItem->Identity.Path.Type  = nttFile; 
					StringCchPrintf(pAppItem->ApplicationItem->Identity.Path.Path, 
						sizeof pAppItem->ApplicationItem->Identity.Path.Path / sizeof pAppItem->ApplicationItem->Identity.Path.Path[0], 
						_T("%s"), FileName);
					
					// check if file is DLL
					{
						size_t Length = wcslen(FileName);
						if ( Length > 4 && _wcsicmp(FileName + Length - 4, L".dll") == 0 )
							pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] |= GesRule::oboAppDLL;
						else
							pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attOptions] &= ~GesRule::oboAppDLL;
					}
					break;
			}

			
			//result = pAppFolder->CreateApplication(pAppFolder->newApp);
					/////////////		
			pAppItem->ApplicationItem->Params.Options |= Storage::dboUserModified;
			try
			{ 	result = Storage::UpdateApplication(pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId], *pAppItem->ApplicationItem);
				pAppItem->m_StaticNode->PolicyChanged();
			}
			catch(Storage::StorageException &e) 
			{
			 MessageBox(hwndDlg, e.getMessage().c_str(), L"Error", MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			 return TRUE; 
			}
			if(result == 0)
			{MessageBox(hwndDlg,L"Upplication update failed!",L"Error",MB_OK|MB_ICONINFORMATION);
			 SetWindowLong(hwndDlg, DWL_MSGRESULT, TRUE);
			}else
			{	GswClient Client;
				Client.RefreshApp(pAppItem->ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId]);
 				SetWindowLong(hwndDlg, DWL_MSGRESULT, FALSE);
			}
				
			return TRUE;

		}
		// Update Application
		if (((NMHDR *) lParam)->code == PSN_APPLY )
		{	
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}
			
			HRESULT hr = MMCPropertyChangeNotify(pAppItem->m_ppHandle, (LPARAM)pAppItem);
			_ASSERT(SUCCEEDED(hr));
			pAppItem->ActiveDialog = false;
			return PSNRET_NOERROR;
		}

		if (((NMHDR *) lParam)->code == PSN_QUERYCANCEL )
		{	
			pAppItem->ActiveDialog = false;
			return FALSE;
		}
		
    }

  return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

HRESULT CApplicationItem::CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle)
{
    PROPSHEETPAGE psp = { 0 };
    HPROPSHEETPAGE hPage = NULL;
	HRESULT result;
    // cache this handle so we can call MMCPropertyChangeNotify
    m_ppHandle = handle;

    // create the property page for this node.
    // NOTE: if your node has multiple pages, put the following
    // in a loop and create multiple pages calling
    // lpProvider->AddPage() for each page.
    psp.dwSize = sizeof(PROPSHEETPAGE);
    psp.dwFlags = PSP_DEFAULT | PSP_USETITLE | PSP_USEICONID;
    psp.hInstance = g_hinst;
    psp.pszTemplate = MAKEINTRESOURCE(IDD_APPLICATION_RULE);
    psp.pfnDlgProc =  RuleDialogProc;
    psp.lParam = reinterpret_cast<LPARAM>(this);
    psp.pszTitle = MAKEINTRESOURCE(IDS_APPLICATION_RULE);
    //psp.pszIcon = MAKEINTRESOURCE();
 if(ActivePage==0)
 {
	hPage = CreatePropertySheetPage(&psp);
    _ASSERT(hPage);
    result = lpProvider->AddPage(hPage);
 }
 else
 {

	psp.pszTemplate = MAKEINTRESOURCE(IDD_APPLICATION);
    psp.pfnDlgProc =  ApplicationDialogProc;
    psp.pszTitle = MAKEINTRESOURCE(IDS_APPLICATION);
    hPage = CreatePropertySheetPage(&psp);
    _ASSERT(hPage);
    result = lpProvider->AddPage(hPage);
 }
 return result;

}

HRESULT CApplicationItem::GetWatermarks(HBITMAP *lphWatermark,
                               HBITMAP *lphHeader,
                               HPALETTE *lphPalette,
                               BOOL *bStretch)
{
    return S_FALSE;
}



HRESULT CApplicationItem::InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page)
{
    HRESULT hr = S_FALSE;
    LPCWSTR szTitle = L"";

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


CApplicationRule::CApplicationRule(Storage::PtrToResourceItem ri,CApplicationItem *parent, CStaticNode *StaticNode)
: m_Resource(ri), m_ppHandle(0),m_pParent(parent)
{
	InitCom();

	m_StaticNode = StaticNode;
	isDeleted = FALSE;
}
const _TCHAR *CApplicationRule::GetDisplayName(int nCol)
{
    const size_t cchBuffer = 128;
    static	_TCHAR buf[cchBuffer];
	int access;
		
    // StringCchPrintf and StringCchCopy always null-terminate the destination string.
    // However the string may be a truncation of the ideal result (indicated by  return value other than S_OK).
	
	switch (nCol) 
	{
    case 0:
       	 StringCchPrintf(buf, cchBuffer,L"%s",m_Resource->Identity.Path.Path);
			
           break;
		
    case 1:

		switch(m_Resource->Identity.GetResourceType())
		{
			case nttFile: StringCchPrintf(buf, cchBuffer, _T("File")); break;
			case nttKey: StringCchPrintf(buf, cchBuffer, _T("Registry")); break;
			case nttDevice: StringCchPrintf(buf, cchBuffer, _T("Device")); break;
			case nttNetwork: StringCchPrintf(buf, cchBuffer, _T("Network")); break;
			case nttSystemObject: StringCchPrintf(buf, cchBuffer, _T("System Object")); break;
			default: StringCchPrintf(buf, cchBuffer, _T("Unknown"));
		}
      
			break;

    case 2:
		access = m_Resource->Params.Attributes.Param[GesRule::attOptions];
		if(access & GesRule::oboGrantAccess)
			StringCchPrintf(buf, cchBuffer, _T("Allow"));
		else
			if(access & GesRule::oboRedirectAccess)
			StringCchPrintf(buf, cchBuffer, _T("Redirect"));
		else
			if(access & GesRule::oboDenyAccess)
			StringCchPrintf(buf, cchBuffer, _T("Deny")); 
		else
			if(access & GesRule::oboDenyRedirectAccess)
			StringCchPrintf(buf, cchBuffer, _T("Read Only")); 
		
		else StringCchPrintf(buf, cchBuffer, _T("Unknown"));
			
        break;

   }

    return buf;
}



HRESULT CApplicationRule::HasPropertySheets()
{
    // say "yes" when MMC asks if we have pages
    
	return S_OK;
}

INT_PTR CALLBACK CApplicationRule::RuleDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  )
{
	static CApplicationRule *pAppRule = NULL;
	int n, access_perm = 0, ObjectTypeId = 0;
	HRESULT result;

   switch (uMsg) 
   {
    case WM_INITDIALOG:
		
        // catch the "this" pointer so we can actually operate on the object
        pAppRule = reinterpret_cast<CApplicationRule *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Allow");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Redirect");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Deny");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_ADDSTRING, 0, (LPARAM)L"Read Only");
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 0, (LPARAM)GesRule::oboGrantAccess);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 1, (LPARAM)GesRule::oboRedirectAccess);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 2, (LPARAM)GesRule::oboDenyAccess);
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETITEMDATA, 3, (LPARAM)GesRule::oboDenyRedirectAccess);
		switch(pAppRule->m_Resource->Params.Attributes.Param[5])
		{
			case GesRule::oboGrantAccess:			access_perm = 0; break;
			case GesRule::oboRedirectAccess:		access_perm = 1; break;
			case GesRule::oboDenyAccess:			access_perm = 2; break;
			case GesRule::oboDenyRedirectAccess:	access_perm = 3; break;
		}
		SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_SETCURSEL, access_perm, 0); 

		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"File");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"Registry");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"Device");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"Network");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_ADDSTRING, 0, (LPARAM)L"System Object");
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 0, (LPARAM)nttFile);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 1, (LPARAM)nttKey);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 2, (LPARAM)nttDevice);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 3, (LPARAM)nttNetwork);
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETITEMDATA, 4, (LPARAM)nttSystemObject);

		switch(pAppRule->m_Resource->Identity.Path.Type)
		{
			case nttFile:			ObjectTypeId = 0; break;
			case nttKey:			ObjectTypeId = 1; break;
			case nttDevice:			ObjectTypeId = 2; break;
			case nttNetwork:		ObjectTypeId = 3; break;
			case nttSystemObject:	ObjectTypeId = 4; break;
		}
		
		SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_SETCURSEL, ObjectTypeId, 0); 
		SetDlgItemText(hwndDlg, IDC_EDIT_RULE, pAppRule->m_Resource->Identity.Path.Path);
		//SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_RULE));
       break;

     case WM_COMMAND:
        // turn the Apply button on
        //if (HIWORD(wParam) == EN_CHANGE ||
        //    HIWORD(wParam) == CBN_SELCHANGE)
        //    SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0);
		       
		if (HIWORD(wParam) == BN_CLICKED) 
           { 
            switch (LOWORD(wParam)) 
             { 
              case IDC_FILE_BROWSE: 
				OnFileSelectRule(hwndDlg);
				SetFocus(GetDlgItem(hwndDlg,IDC_EDIT_DISPLAYNAME));

			  break;

			  case IDC_RULE_FILE: 
				  EnableWindow(GetDlgItem(hwndDlg,IDC_FILE_BROWSE),true); 
				
				 break; 
			  case IDC_RULE_REGISTRY:
                  EnableWindow(GetDlgItem(hwndDlg,IDC_FILE_BROWSE),false); 
				
				 break; 
			  case IDC_RULE_DEVICE: 
				  EnableWindow(GetDlgItem(hwndDlg,IDC_FILE_BROWSE),false); 
				
				 break; 

			  }
		   }
		 break;

    case WM_DESTROY:
        // tell MMC that we're done with the property sheet (we got this
        // handle in CreatePropertyPages
        MMCFreeNotifyHandle(pAppRule->m_ppHandle);
        break;

    case WM_NOTIFY:
        if (((NMHDR *) lParam)->code == PSN_APPLY )
		{	// GetDisplayName
			n = (int)SendDlgItemMessage(hwndDlg, IDC_EDIT_RULE, WM_GETTEXTLENGTH, 0, 0);
			if (n == 0) 
			{  MessageBox(hwndDlg,L"Application Resource field can not be empty.",L"Application Resource addition error",MB_OK|MB_ICONINFORMATION);
				break;
			}else
				if(n >= sizeof pAppRule->m_Resource->Identity.Path.Path / sizeof pAppRule->m_Resource->Identity.Path.Path[0])
				{ MessageBox(hwndDlg,L"Application product name is too long!",L"Application addition error",MB_OK|MB_ICONINFORMATION);
					break;
				}
				else
					GetDlgItemText(hwndDlg, IDC_EDIT_RULE, pAppRule->m_Resource->Identity.Path.Path, n + 1);
			
			
			// GetRuleType
			int ObjectTypeId = (int)SendDlgItemMessage(hwndDlg, IDC_OBJECT_TYPE, CB_GETCURSEL, 0, 0);
			pAppRule->m_Resource->Identity.Path.Type = (NtObjectType) SendDlgItemMessage(hwndDlg,IDC_OBJECT_TYPE, CB_GETITEMDATA, ObjectTypeId , 0);

			// GetRuleAccess
			access_perm = (int)SendDlgItemMessage(hwndDlg, IDC_RULE_PERM, CB_GETCURSEL, 0, 0);
			pAppRule->m_Resource->Params.Attributes.Param[5] = (ULONG)SendDlgItemMessage(hwndDlg,IDC_RULE_PERM, CB_GETITEMDATA, access_perm , 0);
			pAppRule->m_Resource->Params.Options = Storage::dboUserCreated;
			pAppRule->m_Resource->Identity.Path.Options |= Storage::dboUserModified;
			result = Storage::UpdateApplicationResource(*pAppRule->m_Resource);
			pAppRule->m_StaticNode->PolicyChanged();

			if(result == false)
			MessageBox(hwndDlg,L"Application rule update failed!",L"Error",MB_OK|MB_ICONINFORMATION);
							
			//
			// Send update notification to gswserv
			//
			//if ( result != 0 ) {
			//	GswClient Client;
			//	Client.RefreshResources();
			//}
			
			HRESULT hr = MMCPropertyChangeNotify(pAppRule->m_ppHandle, (LPARAM)pAppRule);
			_ASSERT(SUCCEEDED(hr));
			return PSNRET_NOERROR;
		}
    }
	
	return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}


HRESULT CApplicationRule::CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle)
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
    psp.pszTemplate = MAKEINTRESOURCE(IDD_APPLICATION_RULE);
    psp.pfnDlgProc =  RuleDialogProc;
    psp.lParam = reinterpret_cast<LPARAM>(this);
    psp.pszTitle = MAKEINTRESOURCE(IDS_APPLICATION_RULE);
    //psp.pszIcon = MAKEINTRESOURCE();
	hPage = CreatePropertySheetPage(&psp);
    _ASSERT(hPage);
    return lpProvider->AddPage(hPage);
 
}
HRESULT CApplicationRule::OnPropertyChange(IConsole *pConsole, CComponent *pComponent)
{

   HRESULT hr = S_FALSE;

    //Call IConsole::UpdateAllViews to redraw the item
    //in all views. We need a data object because of the
    //way UpdateAllViews is implemented, and because
    //MMCN_PROPERTY_CHANGE doesn't give us one

    LPDATAOBJECT pDataObject;
    hr = pComponent->QueryDataObject((MMC_COOKIE)this, CCT_RESULT, &pDataObject );
    _ASSERT( S_OK == hr);       
        
    hr = pConsole->UpdateAllViews(pDataObject, 0, UPDATE_RESULTITEM);
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

HRESULT CApplicationRule::OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype)

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


HRESULT CApplicationRule::GetWatermarks(HBITMAP *lphWatermark,
                               HBITMAP *lphHeader,
                               HPALETTE *lphPalette,
                               BOOL *bStretch)
{
    return S_FALSE;
}

HRESULT CGroupFolder::OnPropertyChange(IConsole *pConsole, CComponent *pComponent)
{

    pConsole->SelectScopeItem(GetParentScopeItem());
	return S_OK;
}
HRESULT CApplicationItem::OnPropertyChange(IConsole *pConsole, CComponent *pComponent)
{

    pConsole->SelectScopeItem(GetParentScopeItem());
	return S_OK;
}