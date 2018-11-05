//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswmmc_untrusted_file_item_h_
 #define _gswmmc_untrusted_file_item_h_

#include "DeleBase.h"
#include "StatNode.h"
#include "storage.h"
#include "rootfolder.h"

#include "commonlib/commondefs.h"
#include "interface_common.h"

#include "untrusted_file.h"

#include <string>
#include <list>

class untrusted_file_item;
class untrusted_files_page;
//****************************************************************************************//

class untrusted_file_item : public CDelegationBase 
{
  private:
    typedef commonlib::sync::SyncObject      sync_object;
    typedef commonlib::sync::SyncObject::Locker locker_t;
    typedef std::wstring                     wstring;
    typedef boost::shared_ptr<wstring>       ptr_to_wstring;
    typedef boost::shared_ptr<untrusted_files_page> ptr_to_untrusted_files_page;
    
  public:
    untrusted_file_item (untrusted_files_page& untrusted_files_page, const wstring& directory_name, const wstring& file_name, const EntityAttributes &attrs, const wstring& modify_time);
    untrusted_file_item (untrusted_files_page& untrusted_files_page, const ptr_to_untrusted_file& untrusted_file);
    virtual ~untrusted_file_item ();
    
            const untrusted_file_t&     get_ref_untrusted_file () const;
            const ptr_to_untrusted_file get_untrusted_file () const;
            const wstring& get_directory_name () const;
            const wstring& get_file_name () const;
            const wstring& get_app_name () const;
			const EntityAttributes& get_attrs () const;
            const wstring& get_modify_time () const;

    virtual const _TCHAR* GetDisplayName (int nCol = 0);
    virtual const GUID&   getNodeType ();
    virtual const int     GetBitmapIndex ();

    virtual HRESULT       GetResultViewType (LPOLESTR *ppViewType, long *pViewOptions);
    
    // taskpad support
    virtual void          SetScopeItemValue (HSCOPEITEM hscopeitem);
    virtual HSCOPEITEM    GetParentScopeItem ();
    
    virtual HRESULT       OnSelect (CComponent* pComponent, IConsole* pConsole, BOOL bScope, BOOL bSelect);
    virtual HRESULT       OnDelete (CComponentData* pCompData, IConsole* pConsoleComp);
    virtual HRESULT       OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);
    virtual HRESULT       OnMenuCommand (IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData);
    
  private:
  private:
    sync_object            m_sync;
    
    untrusted_files_page&  m_untrusted_files_page;
    
    HSCOPEITEM             m_parent_scope_item;
    IConsole*              m_console;
    
    ptr_to_untrusted_file  m_untrusted_file;
    
    // {0A4E5BEB-CF52-734E-BD07-03E9B7052537}
    static const GUID      m_this_guid;
}; // class untrusted_file_item

typedef boost::shared_ptr <untrusted_file_item>      ptr_to_untrusted_file_item;

#endif // _gswmmc_untrusted_file_item_h_

