//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include "untrusted_file_item.h"
#include "untrusted_files_page.h"
#include "resource.h"

#include "app/application.h"
#include "commonlib/commonlib.h"
#include "commonlib/gswdrv.h"
#include "license/trialmanager.h"

// {36EF9F80-1597-46af-A77A-4123145CB020}
const GUID untrusted_file_item::m_this_guid = { 0x0A4E5BEB, 0xCF52, 0x734E, { 0xBD, 0x07, 0x03, 0xE9, 0xB7, 0x05, 0x25, 0x37 } };

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

typedef commonlib::PtrToWcharArray ptr_to_wchar_array;

untrusted_file_item::untrusted_file_item (untrusted_files_page& untrusted_files_page, const wstring& directory_name, const wstring& file_name, const EntityAttributes &attrs, const wstring& modify_time)
    : CDelegationBase (),
      m_untrusted_files_page (untrusted_files_page),
      m_parent_scope_item (NULL),
      m_console (NULL),
      m_untrusted_file (new untrusted_file_t (directory_name, file_name, attrs, modify_time))
{

} // untrusted_file_item

untrusted_file_item::untrusted_file_item (untrusted_files_page& untrusted_files_page, const ptr_to_untrusted_file& untrusted_file)
    : CDelegationBase (),
      m_untrusted_files_page (untrusted_files_page),
      m_parent_scope_item (NULL),
      m_console (NULL),
      m_untrusted_file (untrusted_file)
{

} // untrusted_file_item

untrusted_file_item::~untrusted_file_item ()
{
    try
    {
    }
    catch (...)
    {
    }
} // ~untrusted_file_item

const untrusted_file_t& untrusted_file_item::get_ref_untrusted_file () const
{
    return *m_untrusted_file;
} // get_ref_untrusted_file

const ptr_to_untrusted_file untrusted_file_item::get_untrusted_file () const
{
    return m_untrusted_file;
} // get_untrusted_file

const wstring& untrusted_file_item::get_directory_name () const
{
    return m_untrusted_file->get_directory_name ();
} // get_directory_name

const wstring& untrusted_file_item::get_file_name () const
{
    return m_untrusted_file->get_file_name ();
} // get_file_name

const wstring& untrusted_file_item::get_app_name () const
{
    return m_untrusted_file->get_app_name ();
} // get_app_name

const EntityAttributes& untrusted_file_item::get_attrs () const
{
	return m_untrusted_file->get_attrs ();
}

const wstring& untrusted_file_item::get_modify_time () const
{
    return m_untrusted_file->get_modify_time ();
} // get_modify_time

const _TCHAR* untrusted_file_item::GetDisplayName (int nCol) 
{ 
    switch (nCol)
    {
        case 0:
            return get_file_name ().c_str ();
        case 1:
            return get_directory_name ().c_str ();
        case 2:
            return get_app_name ().c_str ();
        case 3:
            return get_modify_time ().c_str ();
    }
    
    return _T("untrusted item"); 
} // GetDisplayName

const GUID& untrusted_file_item::getNodeType () 
{ 
    return m_this_guid; 
} // getNodeType

const int untrusted_file_item::GetBitmapIndex () 
{ 
    return -1; 
} // GetBitmapIndex


HRESULT untrusted_file_item::GetResultViewType (LPOLESTR *ppViewType, long *pViewOptions)
{
    *pViewOptions = MMC_VIEW_OPTIONS_NONE;
    *ppViewType = NULL;
       
    return S_OK; 
} // GetResultViewType

void untrusted_file_item::SetScopeItemValue (HSCOPEITEM hscopeitem) 
{ 
    m_parent_scope_item = hscopeitem; 
} // SetScopeItemValue

HSCOPEITEM untrusted_file_item::GetParentScopeItem () 
{ 
    return m_parent_scope_item; 
} // GetParentScopeItem

HRESULT untrusted_file_item::OnSelect (CComponent* pComponent, IConsole* pConsole, BOOL bScope, BOOL bSelect)
{
    // enable rename, refresh, and delete verbs
    IConsoleVerb* pConsoleVerb;

    HRESULT hr = pConsole->QueryConsoleVerb(&pConsoleVerb);
    _ASSERT(SUCCEEDED(hr));
    if (S_OK != hr)
        return hr;
    
    scope_guard result_finalizer = make_guard (pConsoleVerb, gswmmc::make_interface_finalizer (pConsoleVerb));

    //hr = pConsoleVerb->SetVerbState(MMC_VERB_RENAME, ENABLED, TRUE);
    //hr = pConsoleVerb->SetVerbState(MMC_VERB_REFRESH, ENABLED, TRUE);
    //hr = pConsoleVerb->SetVerbState(MMC_VERB_DELETE, ENABLED, TRUE);

    return S_OK;
} // OnSelect

HRESULT untrusted_file_item::OnDelete (CComponentData* pCompData, IConsole* pConsoleComp)
{
    return m_untrusted_files_page.on_delete_file_item (*this);
} // OnDelete

HRESULT untrusted_file_item::OnAddMenuItems (IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    //return CDelegationBase::OnAddMenuItems (pContextMenuCallback, pInsertionsAllowed);
    
    HRESULT         hr = S_OK;
    CONTEXTMENUITEM 
        menu_items[] = {
            {
                L"Delete file", 
                L"Delete file",
                ID_DELETE_UNTRUSTED_FILES, 
                CCM_INSERTIONPOINTID_PRIMARY_TOP, 
                0, 
                0 // CCM_SPECIAL_DEFAULT_ITEM
            },
            {
                L"Label as trusted", 
                L"Label as trusted",
                ID_LABEL_AS_TRUSTED, 
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
} // OnAddMenuItems

HRESULT untrusted_file_item::OnMenuCommand (IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
	if ( !license::TrialManager::IsOperationAllowed(license::TrialManager::opUntrustedFilesHandling, g_hinst) ) return S_OK;

	wstring object_name = get_directory_name () + get_file_name ();

    switch (lCommandID)
    {
        case ID_DELETE_UNTRUSTED_FILES:
			//if ( MessageBox(GetForegroundWindow(), L"Are you sure you want to delete the file?", L"Delete", MB_YESNO) == IDYES ) {
			{
				//
				// actual file deletion
				//
				SetFileAttributes(object_name.c_str(), FILE_ATTRIBUTE_NORMAL); 
				DeleteFile(object_name.c_str());
				//
				// delete from internal structures
				//
				m_untrusted_files_page.on_delete_file_item (*this);
			}
            break;

		case ID_LABEL_AS_TRUSTED:
		{
			HANDLE hFile = CreateFile(object_name.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if ( hFile == INVALID_HANDLE_VALUE ) break;

			CGswDrv Drv;
			EntityAttributes Attributes;
			bool Result = false;
			if ( Drv.GetObjectAttributes(hFile, nttFile, 0, &Attributes) ) {
				Attributes.Param[GesRule::attIntegrity] = GesRule::modTCB;
				SetAttributesInfo Info;
				Info.hObject = hFile;
				Info.Attr = Attributes;
				memcpy(Info.Label, &GesRule::GswLabel, sizeof GesRule::GswLabel);
				Info.ResType = nttFile;
				Result = Drv.SetAttributes(&Info);
			}
			CloseHandle(hFile);
			//
			// delete from internal structures
			//
			if ( Result == true ) 
				m_untrusted_files_page.on_delete_file_item (*this);
			else
				MessageBox(GetForegroundWindow(), L"The operation failed. File cannot be labeled as trusted.", L"Label as trsuted", MB_OK);

			break;
		}
    }
    
    return S_OK;
} // OnMenuCommand

