//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswmmc_untrusted_files_page_h_
 #define _gswmmc_untrusted_files_page_h_

#include "DeleBase.h"
#include "StatNode.h"
#include "storage.h"
#include "rootfolder.h"

#include "commonlib/commondefs.h"
#include "commonlib/thread.h"
#include "commonlib/gswdrv.h"

#include "interface_common.h"

#include "untrusted_files_cache.h"

#include <string>
#include <list>
#include <hash_map>

class untrusted_files_page;
class untrusted_file_item;
//****************************************************************************************//

class untrusted_files_page : public CDelegationBase
{
  private:
    typedef commonlib::sync::SyncException          sync_exception;
    typedef commonlib::sync::SyncObject             sync_object;
    typedef commonlib::sync::SyncObject::Locker     locker_t;
    typedef commonlib::sync::IntrusiveAtomicCounter atomic_counter;
    typedef std::wstring                            wstring;
    typedef boost::shared_ptr <wstring>             ptr_to_wstring;
    typedef std::list <ptr_to_wstring>              string_list;
    typedef boost::shared_ptr <untrusted_file_item> ptr_to_untrusted_file_item;
    typedef stdext::hash_map <wstring, ptr_to_untrusted_file_item> untrusted_file_items_t;
    
    typedef commonlib::thread                       work_thread;
    typedef boost::shared_ptr <work_thread>         ptr_to_work_thread;
    
  public:
    untrusted_files_page ();
    virtual ~untrusted_files_page ();

	void start_scan_thread ();
	void stop_scan_thread ();
	HWND				  m_hwndScanDlg;
	UINT				  m_Pos;

    virtual const _TCHAR* GetDisplayName (int nCol = 0);
    virtual const GUID&   getNodeType ();
	virtual const int GetBitmapIndex() { return INDEX_ISOLIST; }
	virtual CDelegationBase *GetChildPtr(int index) { 
		return NULL;
	}

    virtual HRESULT       GetResultViewType (LPOLESTR *ppViewType, long *pViewOptions);
    
    // taskpad support
    virtual void          SetScopeItemValue (HSCOPEITEM hscopeitem);
    virtual HSCOPEITEM    GetParentScopeItem ();
    
    virtual HRESULT       OnShow (IConsole* console, BOOL is_show, HSCOPEITEM scopeitem);
    virtual HRESULT       OnSelect (CComponent* pComponent, IConsole* pConsole, BOOL bScope, BOOL bSelect);
    virtual HRESULT       OnRefresh (IConsole *pConsole);
    
    virtual HRESULT       OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);
    virtual HRESULT       OnMenuCommand (IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData);
    
            HRESULT       on_delete_file_item (const untrusted_file_item& file_item);
    
  private:
    void                  refresh_drives_list (string_list& drives_list);
    bool                  is_ntfs_volume (wchar_t* volume_root_path);
    void                  scan_files ();
    void                  scan_directory (const wstring& directory, IResultData* result_page);
    void                  check_file (const wstring& directory_name, const wstring& file_name, IResultData* result_page);
    bool                  get_aci_attributes (const wstring& file_name, EntityAttributes& attrs, wstring& modify_time);
    
    void                  scan_thread ();
    void                  refresh_thread ();
    
    void                  check_cache ();
    void                  load_from_file_cache_no_sync ();
    void                  check_cache_no_sync ();
    void                  show_cached_file_items_no_sync ();
    void                  add_file_item_no_sync (const wstring& object_name, ptr_to_untrusted_file_item& file_item);
    void                  remove_file_item_no_sync (untrusted_file_items_t::iterator& i);
    void                  sleep (int timeout);
    
    static HANDLE         open_file (const wstring& file_name);
    static void           close_file (HANDLE file_handle);
    
    static wstring        get_cache_file_name ();
    static wstring        get_module_directory ();
    
  private:
    sync_object           m_sync;
    atomic_counter        m_destroy_started_flag;
    
    HSCOPEITEM            m_parent_scope_item;
    IConsole*             m_console;
    
    bool                  m_is_show;
    wstring               m_node_name;
    wstring               m_displayed_node_name;
    string_list           m_drives_list;
    untrusted_file_items_t m_file_items;
    
    ptr_to_untrusted_files_cache m_untrusted_files_cache;
    
    CGswDrv               m_gswdrv;
    ptr_to_work_thread    m_work_thread;
    ptr_to_work_thread    m_refresh_thread;

    // {75504204-D7AF-F24C-9BF2-0F0D9B0AC166}
    static const GUID m_this_guid;
}; // class untrusted_files_page

#endif // _gswmmc_untrusted_files_page_h_

