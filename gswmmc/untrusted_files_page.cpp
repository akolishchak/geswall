//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>

#include "untrusted_files_page.h"
#include "untrusted_file_item.h"

#include "resource.h"

#include "gsw/gesruledef.h"
#include "config/configurator.h"

#include <boost/function.hpp>
#include <boost/bind.hpp>

#include <io.h>
#include <commctrl.h>

// {36EF9F80-1597-46af-A77A-4123145CB020}
const GUID untrusted_files_page::m_this_guid = { 0x75504204, 0xD7AF, 0xF24C, { 0x9B, 0xF2, 0x0F, 0x0D, 0x9B, 0x0A, 0xC1, 0x66 } };

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

typedef commonlib::PtrToWcharArray ptr_to_wchar_array;

#ifdef _CB_TEST_DEBUG_
 #pragma message (__WARNING__"this is cb.test.debug configurations")
#endif // _CB_TEST_DEBUG_ 


untrusted_files_page::untrusted_files_page ()
    : CDelegationBase (),
      m_parent_scope_item (NULL),
      m_console (NULL),
      m_is_show (false),
      m_node_name (L"Untrusted Files"),
	  m_hwndScanDlg (NULL),
	  m_Pos (0)
{
} // untrusted_files_page

untrusted_files_page::~untrusted_files_page ()
{
	stop_scan_thread ();
} // ~untrusted_files_page

void untrusted_files_page::start_scan_thread ()
{
	m_work_thread = ptr_to_work_thread (new work_thread (boost::bind (&untrusted_files_page::scan_thread, boost::ref (*this))));
}

void untrusted_files_page::stop_scan_thread ()
{
    try
    {
        {
            locker_t sync_guard (m_sync);
            
            m_destroy_started_flag.increment ();
            m_sync.notifyAll ();
        }
        
		if (NULL != m_work_thread.get ())  {
            m_work_thread->join ();
			m_work_thread.reset ();
		}
        
        m_destroy_started_flag.decrement ();
    }
    catch (...)
    {
    }
}


const _TCHAR* untrusted_files_page::GetDisplayName (int nCol) 
{ 
    {
        locker_t sync_guard (m_sync);
        m_displayed_node_name.assign (m_node_name);
    }
    
    return m_displayed_node_name.c_str (); 
} // GetDisplayName

const GUID& untrusted_files_page::getNodeType () 
{ 
    return m_this_guid; 
} // getNodeType

HRESULT untrusted_files_page::GetResultViewType (LPOLESTR *ppViewType, long *pViewOptions)
{
    *pViewOptions = MMC_VIEW_OPTIONS_MULTISELECT; // enable multi-selection
    *ppViewType = NULL;
       
    return S_OK; 
} // GetResultViewType

void untrusted_files_page::SetScopeItemValue (HSCOPEITEM hscopeitem) 
{ 
    m_parent_scope_item = hscopeitem; 
} // SetScopeItemValue

HSCOPEITEM untrusted_files_page::GetParentScopeItem () 
{ 
    return m_parent_scope_item; 
} // GetParentScopeItem

HRESULT untrusted_files_page::OnShow (IConsole* console, BOOL is_show, HSCOPEITEM scopeitem)
{
	locker_t sync_guard (m_sync);
	//
	// load from cache
	//
    if (NULL == m_untrusted_files_cache.get ())
    {
        m_untrusted_files_cache = ptr_to_untrusted_files_cache (new untrusted_files_cache_t (get_cache_file_name (), true));
        if (NULL != m_untrusted_files_cache.get ())
        {
            load_from_file_cache_no_sync ();
            check_cache_no_sync ();
        }
    }
    //
	// display
	//
    HRESULT      hr          = S_OK;
    IHeaderCtrl* header_ctrl = NULL;
    IResultData* result_data = NULL;
    
    m_console           = console;
    m_parent_scope_item = scopeitem;
    m_is_show           = (TRUE == is_show);
    
    m_sync.notifyAll ();
    
    if (false == m_is_show)
        return hr;
        
    hr = console->QueryInterface (IID_IHeaderCtrl, (void **)&header_ctrl);
    if (S_OK != hr)
        return hr;
        
    scope_guard header_finalizer = make_guard (header_ctrl, gswmmc::make_interface_finalizer (header_ctrl));
        
    hr = console->QueryInterface (IID_IResultData, (void **)&result_data);
    if (S_OK != hr)
        return hr;
        
    scope_guard result_finalizer = make_guard (result_data, gswmmc::make_interface_finalizer (result_data));
    
    hr = header_ctrl->InsertColumn (0, L"File",         0, MMCLV_AUTO);
    hr = header_ctrl->InsertColumn (1, L"Folder",         0, MMCLV_AUTO);
    hr = header_ctrl->InsertColumn (2, L"Application",  0, MMCLV_AUTO);
    hr = header_ctrl->InsertColumn (3, L"Date", 0, MMCLV_AUTO); // (yyyy/mm/dd hh:mm:ss)
    
    if (0 == m_destroy_started_flag.value ())
        show_cached_file_items_no_sync ();

    return hr;
} // OnShow

HRESULT untrusted_files_page::OnSelect (CComponent* pComponent, IConsole* pConsole, BOOL bScope, BOOL bSelect)
{
    // enable rename, refresh, and delete verbs
    IConsoleVerb* pConsoleVerb;

    HRESULT hr = pConsole->QueryConsoleVerb(&pConsoleVerb);
    _ASSERT(SUCCEEDED(hr));
    if (S_OK != hr)
        return hr;
    
    scope_guard result_finalizer = make_guard (pConsoleVerb, gswmmc::make_interface_finalizer (pConsoleVerb));

    hr = pConsoleVerb->SetVerbState(MMC_VERB_REFRESH, ENABLED, TRUE);

    return S_OK;
} // OnSelect

HRESULT untrusted_files_page::OnRefresh (IConsole *pConsole)
{
    //{
    //    locker_t sync_guard (m_sync);
    //    
    //    if (NULL == m_refresh_thread.get ())
    //        m_refresh_thread = ptr_to_work_thread (new work_thread (boost::bind (&untrusted_files_page::refresh_thread, boost::ref (*this))));
    //}
    
    IDataObject *dummy = NULL;
    HRESULT hr;

    hr = m_console->UpdateAllViews (dummy, m_parent_scope_item, UPDATE_SCOPEITEM);
    _ASSERT(S_OK == hr);
        
    return hr;
} // OnRefresh

HRESULT untrusted_files_page::OnAddMenuItems (IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed)
{
    //return CDelegationBase::OnAddMenuItems (pContextMenuCallback, pInsertionsAllowed);
    
    HRESULT         hr = S_OK;
    CONTEXTMENUITEM menu_items[] = {
            {
                L"Start scan...", 
                L"Start scan",
                ID_START_SCAN, 
                CCM_INSERTIONPOINTID_PRIMARY_TOP, 
                0, 
                CCM_SPECIAL_DEFAULT_ITEM
            },
            { NULL, NULL, 0, 0, 0, 0 }
        };
    //
    // Loop through and add each of the menu items
    if (CCM_INSERTIONALLOWED_NEW == (*pInsertionsAllowed & CCM_INSERTIONALLOWED_NEW))
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

INT_PTR CALLBACK ScanDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static untrusted_files_page *This = NULL;

    switch ( uMsg ) {

		case WM_INITDIALOG:
			{
				This = (untrusted_files_page *)lParam;
				This->m_hwndScanDlg = hwndDlg;
				SendDlgItemMessage(hwndDlg, IDC_PROGRESS_SCAN, PBM_SETRANGE, 0, MAKELPARAM(0, 10000));
				/*
				ShowWindow(hwndDlg, SW_SHOW);
				SetForegroundWindow(hwndDlg);
				EnableWindow(hwndDlg, TRUE);
				*/
				This->start_scan_thread ();
			}
			break;

		case WM_COMMAND:
			switch ( LOWORD(wParam) ) {
				case IDSTOP:
					if ( This != NULL ) {
						This->stop_scan_thread ();
						This->m_hwndScanDlg = NULL;
						This->m_Pos = 0;
						This = NULL;
					}
					EndDialog(hwndDlg, 0);
					break;

				default:
					return FALSE;
			}
			break;
    }

	return FALSE;
	//return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}	

HRESULT untrusted_files_page::OnMenuCommand (IConsole* pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData)
{
    //return CDelegationBase::OnMenuCommand (pConsole, lCommandID, piDataObject, pComData);
    switch (lCommandID)
    {
        case ID_START_SCAN:
		{
			HWND hwndMainWindow;
			pConsole->GetMainWindow(&hwndMainWindow);

			DialogBoxParam(g_hinst, MAKEINTRESOURCE(IDD_DIALOG_SCAN), GetForegroundWindow() /* hwndMainWindow */, ScanDialogProc, (LPARAM)this);
			OnRefresh(pConsole);
		}
        break;
    }
    
    return S_OK;
} // OnMenuCommand

HRESULT untrusted_files_page::on_delete_file_item (const untrusted_file_item& file_item)
{
	//
	// refresh  view
	//
    IResultData* pResultData = NULL;

    HRESULT hr = /*pConsoleComp*/m_console->QueryInterface(IID_IResultData, (void **)&pResultData);
    _ASSERT( SUCCEEDED(hr) );
    if (false == SUCCEEDED (hr))
        return hr;
        
    scope_guard data_finalizer = make_guard (pResultData, gswmmc::make_interface_finalizer (pResultData));

    HRESULTITEM myhresultitem;  
        
    //lparam == &file_item
    hr = pResultData->FindItemByLParam ((LPARAM) &file_item, &myhresultitem);
    if (FAILED (hr))
    {
        hr = S_FALSE;
    } 
    else
    {
        hr = pResultData->DeleteItem (myhresultitem, 0);
        _ASSERT( SUCCEEDED(hr) );
    }

	//
	// delete from cache and display list
	//
    {
        locker_t sync_guard (m_sync);
        
        wstring object_name = file_item.get_directory_name () + file_item.get_file_name ();
        untrusted_file_items_t::iterator i = m_file_items.find (object_name);
        if (i != m_file_items.end ())
            remove_file_item_no_sync (i);
    }

    return hr;
} // on_delete_file_item

void untrusted_files_page::refresh_drives_list (string_list& drives_list)
{
    drives_list.clear ();
    
    DWORD length = ::GetLogicalDriveStringsW (0, NULL);
    
    if (0 == length)
        return;
        
    ptr_to_wchar_array drives = ptr_to_wchar_array (new wchar_t [length + 1]);
    if (NULL == drives.get ())
        return;
        
    length = ::GetLogicalDriveStringsW (length, drives.get ());
    if (0 == length)
        return;
    
    wchar_t* p = drives.get ();
    
    while (0 != *p) 
    {
        if (DRIVE_FIXED == ::GetDriveType (p) && true == is_ntfs_volume (p))
            drives_list.push_back (ptr_to_wstring (new wstring (p)));
        
        p += wcslen (p) + 1;
    }
} // refresh_drives_list

bool untrusted_files_page::is_ntfs_volume (wchar_t* volume_root_path)
{
    wchar_t fs_name[MAX_PATH];
    DWORD   sys_flags;
    
    fs_name[0] = 0;
    
    ::GetVolumeInformationW (
        volume_root_path, 
        NULL, 0, NULL, NULL,
        &sys_flags, 
        fs_name, 
        MAX_PATH
    );
    
    return (0 == wcscmp (fs_name, L"NTFS"));
} // is_ntfs_volume

void untrusted_files_page::scan_files ()
{
    HRESULT      hr          = S_OK;
    IResultData* result_data = NULL;
    
//    hr = m_console->QueryInterface (IID_IResultData, (void **)&result_data);
//    if (S_OK != hr)
//        return;
        
//    scope_guard result_finalizer = make_guard (result_data, gswmmc::make_interface_finalizer (result_data));    

    // gs: commented for tests only, remove
    for (string_list::iterator i = m_drives_list.begin (); (i != m_drives_list.end ()) && (0 == m_destroy_started_flag.value ()); ++i)
    {
        scan_directory (*(*i), result_data);
		//scan_directory (L"c:\\temp\\", result_data);
        {
            locker_t sync_guard (m_sync);
            
            if (0 == m_destroy_started_flag.value ())
                check_cache_no_sync ();
        }
    }
    
} // scan_files

typedef struct _FILE_STREAM_INFORMATION {
	ULONG NextEntryOffset;
	ULONG StreamNameLength;
	LARGE_INTEGER EndOfStream;
	LARGE_INTEGER AllocationSize;
	WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
    union {
        int Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef int (NTAPI *_ZwQueryInformationFile)(
    IN HANDLE  FileHandle,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  FileInformation,
    IN ULONG  Length,
    IN int FileInformationClass
    );


PFILE_STREAM_INFORMATION GetStreamInfo(const wchar_t *FileName, bool IsDir)
{
	static _ZwQueryInformationFile ZwQueryInformationFile = NULL;

	if ( ZwQueryInformationFile == NULL ) {
		HMODULE hModule = GetModuleHandle(L"ntdll.dll");
		ZwQueryInformationFile = (_ZwQueryInformationFile) GetProcAddress(hModule, "ZwQueryInformationFile");
		if ( ZwQueryInformationFile == NULL )
			return NULL;
	}

	HANDLE hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, IsDir ? FILE_FLAG_BACKUP_SEMANTICS : 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE )
		return NULL;

	IO_STATUS_BLOCK ios;
	byte Buf[512];
	int rc = ZwQueryInformationFile(hFile, &ios, Buf, sizeof Buf, 22 /* FileStreamInformation */);
	if ( rc == 0 && ios.Information != 0 ) {
		CloseHandle(hFile);
		if ( PFILE_STREAM_INFORMATION(Buf)->NextEntryOffset == NULL && IsDir == false )
			return NULL;
		
		PFILE_STREAM_INFORMATION Info = (PFILE_STREAM_INFORMATION) malloc(ios.Information);
		if ( Info == NULL )
			return NULL;

		memcpy(Info, Buf, ios.Information);
		return Info;
	}

	ULONG Length = 1024;
	while ( rc == 0xC0000004 || rc == 0x80000005 || rc == 0xC0000023 ) {
		PFILE_STREAM_INFORMATION Info = (PFILE_STREAM_INFORMATION) malloc(Length);
		if ( Info == NULL ) {
			CloseHandle(hFile);
			return NULL;
		}

		rc = ZwQueryInformationFile(hFile, &ios, Info, Length, 22 /* FileStreamInformation */);
		if ( rc == 0 ) {
			CloseHandle(hFile);
			return Info;
		}
	}

	CloseHandle(hFile);

	return NULL;
}


void untrusted_files_page::scan_directory (const wstring& directory, IResultData* result_page)
{
    struct   _wfinddata_t find_data;
    int      res         = 0;
    wstring  mask        = directory;
    
    mask.append (L"*.*");
    intptr_t handle_dir = ::_wfindfirst (const_cast <wchar_t*> (mask.c_str ()), &find_data);
    
    if (0 > handle_dir)
        return;
    scope_guard dir_finalizer = make_guard (handle_dir, &::_findclose);    
    
    while ((0 <= res) && (0 == m_destroy_started_flag.value ()))
    {
        sleep (0); // safe cpu time
        
        if ((L'.' == find_data.name [0]) &&  (L'\0' == find_data.name [1] || (L'.' == find_data.name [1] && L'\0' == find_data.name [2])))
        {
            ; // skip
        }
        else
        {
            wstring object_name = directory + find_data.name;
			bool IsDir = _A_SUBDIR == (find_data.attrib & _A_SUBDIR);
			// enum streams
			FILE_STREAM_INFORMATION *Info = GetStreamInfo((directory + L"\\" + find_data.name).c_str(), IsDir);
			if ( Info != NULL ) {
				FILE_STREAM_INFORMATION *Stream = Info;
				while ( true ) {

					wstring StreamName;
					StreamName.assign(Stream->StreamName, Stream->StreamNameLength / sizeof wchar_t);
					StreamName.insert(0, find_data.name);

					check_file (directory, StreamName, result_page);

					if ( Stream->NextEntryOffset == 0 )
						break;

					Stream = (FILE_STREAM_INFORMATION *) ( (byte *)Stream + Stream->NextEntryOffset);
				};

				free(Info);

				if ( IsDir == true )
				{
					scan_directory (object_name + L"\\", result_page);
				}
			} else
			if ( IsDir == true )
            {
                scan_directory (object_name + L"\\", result_page);
            }
            else
            {
				check_file (directory, find_data.name, result_page);
            }
        }
        
        res = ::_wfindnext (handle_dir, &find_data);
    } // while (0 <= res)
} // scan_directory

void untrusted_files_page::check_file (const wstring& directory_name, const wstring& file_name, IResultData* result_page)
{
#ifdef _CB_TEST_DEBUG_
    static int ct = 0;
#endif // _CB_TEST_DEBUG_    
    
    wstring          modify_time;
    EntityAttributes attrs;
    wstring          object_name = directory_name + file_name;
    
    {
        locker_t sync_guard (m_sync);
        
        untrusted_file_items_t::iterator i = m_file_items.find (object_name);
        if (i != m_file_items.end ())
            return;
    }
                
#ifndef _CB_TEST_DEBUG_                
    if (true == get_aci_attributes (object_name, attrs, modify_time))
#else    
    sleep (1000); 
    if (false == get_aci_attributes (object_name, attrs, modify_time) && 100 > ++ct)
#endif // _CB_TEST_DEBUG_    
    {
        ptr_to_untrusted_file_item file_item (new untrusted_file_item (*this, directory_name, file_name, attrs, modify_time));
        if (NULL != file_item.get ())
        {
            {
                locker_t sync_guard (m_sync);
                add_file_item_no_sync (object_name, file_item);
            }
        }
    }
	//
	// update progress
	//
	if ( ++m_Pos > 10000 ) m_Pos = 0;
	PostMessage(GetDlgItem(m_hwndScanDlg, IDC_PROGRESS_SCAN), PBM_SETPOS, m_Pos, 0);

} // check_file

bool untrusted_files_page::get_aci_attributes (const wstring& file_name, EntityAttributes& attrs, wstring& modify_time)
{
    HANDLE handle_object = open_file (file_name);
        
    if (INVALID_HANDLE_VALUE == handle_object) 
        return false;

    scope_guard object_finalizer = make_guard (handle_object, &untrusted_files_page::close_file);    

	bool Result = m_gswdrv.GetObjectAttributes(handle_object, nttFile, 0, &attrs) && 
				  attrs.Param[GesRule::attIntegrity] < GesRule::modTCB && attrs.Param[GesRule::attIntegrity] > GesRule::modUntrusted;
	// gs: added for test only, remove
	//Result = true;
	//attrs.Param[0] = 17; attrs.Param[1] = 17; attrs.Param[2] = 0; attrs.Param[3] = 2; attrs.Param[4] = 0; attrs.Param[5] = 0;
	//
	if ( Result == true )
	{
		FILETIME last_modify_time;
		if (TRUE == ::GetFileTime (handle_object, NULL, NULL, &last_modify_time))
		{
			SYSTEMTIME utc_time;
			SYSTEMTIME local_time;
	        
			::FileTimeToSystemTime (&last_modify_time, &utc_time);
			::SystemTimeToTzSpecificLocalTime(NULL, &utc_time, &local_time);

			wchar_t buf[256];
			swprintf (
				buf, 
				L"%d/%02d/%02d  %02d:%02d:%02d", 
				local_time.wYear,
				local_time.wMonth,
				local_time.wDay,
				local_time.wHour,
				local_time.wMinute,
				local_time.wSecond
			);
	        
			modify_time.assign (buf);
		}
	}
    
	return Result;
} // get_aci_attributes

void untrusted_files_page::scan_thread ()
{
    if (0 == m_destroy_started_flag.value ())
    {
        {
            locker_t sync_guard (m_sync);
            refresh_drives_list (m_drives_list);
        }
        
        scan_files ();
    }

	PostMessage(m_hwndScanDlg, WM_COMMAND, IDSTOP, 0);
} // scan_thread

void untrusted_files_page::refresh_thread ()
{
    if (NULL != m_work_thread.get ())
    {
        {
            locker_t sync_guard (m_sync);
            
            m_destroy_started_flag.increment ();
            m_sync.notifyAll ();
        }
        
        m_work_thread->join ();
        m_work_thread.reset ();
        
        m_destroy_started_flag.decrement ();
    }
    
//    IDataObject *dummy = NULL;
//    HRESULT hr;

//    hr = m_console->UpdateAllViews (dummy, m_parent_scope_item, UPDATE_SCOPEITEM);
//    _ASSERT( S_OK == hr);
//    if (S_OK == hr)
        m_work_thread = ptr_to_work_thread (new work_thread (boost::bind (&untrusted_files_page::scan_thread, boost::ref (*this))));
    
    {
        locker_t sync_guard (m_sync);
        
        m_refresh_thread.reset ();
    }
} // refresh_thread

void untrusted_files_page::check_cache ()
{
    locker_t sync_guard (m_sync);
    check_cache_no_sync ();
} // check_cache

void untrusted_files_page::load_from_file_cache_no_sync ()
{
    size_t                       size_array;
    ptr_to_untrusted_files_array files_array = m_untrusted_files_cache->get_items (size_array);
    
    for (size_t i = 0; i < size_array; ++i)
    {
        ptr_to_untrusted_file_item file_item (new untrusted_file_item (*this, files_array[i]));
        if (NULL != file_item.get ())
            m_file_items[files_array[i]->get_directory_name () + files_array[i]->get_file_name ()] = file_item; // add file to list
    }
} // load_from_file_cache_no_sync

void untrusted_files_page::check_cache_no_sync ()
{
    for (untrusted_file_items_t::iterator i = m_file_items.begin (); (i != m_file_items.end ()) && (0 == m_destroy_started_flag.value ()); ++i)
    {
        ptr_to_untrusted_file_item file_item = (*i).second;
        wstring object_name = file_item->get_directory_name () + file_item->get_file_name ();
        
#ifndef _CB_TEST_DEBUG_        
        wstring          modify_time;
        EntityAttributes attrs;
        
        if (false == get_aci_attributes (object_name, attrs, modify_time))
#else
        HANDLE handle_object = open_file (object_name);
        untrusted_files_page::close_file (handle_object);
        if (INVALID_HANDLE_VALUE == handle_object) 
#endif // _CB_TEST_DEBUG_        
        {
            remove_file_item_no_sync (i);
            check_cache_no_sync ();
            break;
        }
    } // for (...)
} // check_cache_no_sync

void untrusted_files_page::show_cached_file_items_no_sync ()
{
    HRESULT      hr          = S_OK;
    IResultData* result_data = NULL;
    
    hr = m_console->QueryInterface (IID_IResultData, (void **)&result_data);
    if (S_OK != hr)
        return;
        
    scope_guard result_finalizer = make_guard (result_data, gswmmc::make_interface_finalizer (result_data));    
    
    RESULTDATAITEM   rdi;
    
    for (untrusted_file_items_t::iterator i = m_file_items.begin (); i != m_file_items.end (); ++i)
    {
        ptr_to_untrusted_file_item file_item = (*i).second;
        
        memset (&rdi, 0, sizeof (rdi));
        
        rdi.mask       = RDI_STR | RDI_PARAM;   
        rdi.str         = MMC_CALLBACK;
        rdi.nCol        = 0;
        rdi.lParam      = reinterpret_cast<LPARAM> (file_item.get ());

        hr = result_data->InsertItem (&rdi);
    } 
} // show_cached_file_items_no_sync

void untrusted_files_page::add_file_item_no_sync (const wstring& object_name, ptr_to_untrusted_file_item& file_item)
{
    if (NULL != m_untrusted_files_cache.get ())
        m_untrusted_files_cache->add_item (file_item->get_file_name (), file_item->get_directory_name (), file_item->get_app_name (), file_item->get_attrs(), file_item->get_modify_time ());
    m_file_items[object_name] = file_item; // add file to list
	
} // add_file_item_no_sync

void untrusted_files_page::remove_file_item_no_sync (untrusted_file_items_t::iterator& i)
{
    ptr_to_untrusted_file_item file_item = (*i).second;
    m_file_items.erase (i);
    
    if (NULL != m_untrusted_files_cache.get ())
        m_untrusted_files_cache->remove_item (file_item->get_untrusted_file ()->get_directory_name () + file_item->get_untrusted_file ()->get_file_name ());
} // remove_file_item_no_sync

void untrusted_files_page::sleep (int timeout)
{
    locker_t sync_guard (m_sync);
        
    m_sync.wait_noexc (timeout); 
} // sleep

HANDLE untrusted_files_page::open_file (const wstring& file_name)
{
    return 
        ::CreateFileW (
            file_name.c_str (), 
            FILE_READ_ATTRIBUTES, 
            FILE_SHARE_READ | FILE_SHARE_WRITE, 
            NULL, 
            OPEN_EXISTING, 
            0, 
            NULL
        );
} // open_file

void untrusted_files_page::close_file (HANDLE file_handle)
{
    ::CloseHandle (file_handle);
} // close_file

wstring untrusted_files_page::get_cache_file_name ()
{
    wstring cache_file_name;
    
    //config::Configurator::PtrToINode srv_node = config::Configurator::getServiceNode ();
   // if (NULL != srv_node.get ())
   //   cache_file_name.assign (srv_node->getString (L"InstallDir"));
      
    //if (0 >= cache_file_name.size ())
    //    cache_file_name.assign (get_module_directory ());
	wchar_t TempFolder[MAX_PATH];
	GetTempPath(sizeof TempFolder / sizeof TempFolder[0], TempFolder);
	cache_file_name = TempFolder;
      
    cache_file_name.append (L"\\gswmcc_untrusted_cache.history");
    
    return cache_file_name;
} // get_cache_file_name

wstring untrusted_files_page::get_module_directory ()
{
    wstring module_dir = L".";
    
    HMODULE     module_handle = ::LoadLibraryW (L"gswmmc.dll");
    scope_guard module_handle_finalizer = make_guard (module_handle, &::FreeLibrary);    
    
    wchar_t     fixed_buffer_for_gmfn_bug [2 * MAX_PATH];

    DWORD length = ::GetModuleFileNameW (module_handle, fixed_buffer_for_gmfn_bug, sizeof (fixed_buffer_for_gmfn_bug) - 1);
    if (0 != length)
    {
        module_dir.assign (fixed_buffer_for_gmfn_bug);
        
        size_t end_index = 0;
        if (wstring::npos != (end_index = module_dir.rfind (L'\\')))
            module_dir.erase (end_index);
    }
    
    return module_dir;
} // get_module_directory