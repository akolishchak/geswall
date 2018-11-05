//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include "untrusted_files_cache.h"

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

typedef commonlib::PtrToWcharArray ptr_to_wchar_array;

const wchar_t untrusted_files_cache_t::ITEM_STATUS_ACTIVE  = L'a';
const wchar_t untrusted_files_cache_t::ITEM_STATUS_DELETED = L'd';
const wchar_t untrusted_files_cache_t::ITEM_STATUS_SKIPPED = L's';

//
// cache item format
// [X];file_name;dir_name;app_name;modify_time;
//  X: a - active
//     d - deleted
//     s - skipped
//

untrusted_files_cache_t::untrusted_files_cache_t (const wstring& file_name, bool create_new_if_not_exists)
    : m_file_name (file_name),
      m_file (::_wfopen (file_name.c_str (), L"r+b")) // open existing
{
    if (NULL == m_file && true == create_new_if_not_exists)
        m_file = ::_wfopen (file_name.c_str (), L"w+b"); // create new
        
    fill_cache_from_file ();
} // untrusted_files_cache_t

untrusted_files_cache_t::~untrusted_files_cache_t ()
{
    try
    {
        if (NULL != m_file)
            ::fclose (m_file);
    }
    catch (...)
    {
    }
} // ~untrusted_files_cache_t

const wstring& untrusted_files_cache_t::get_file_name () const
{
    return m_file_name;
} // get_file_name

ptr_to_untrusted_files_array untrusted_files_cache_t::get_items (size_t& result_size_array) const
{
    result_size_array = 0;
    
    locker_t sync_guard (m_sync);
    
    if (0 >= m_chache_items.size ())
        ptr_to_untrusted_files_array ();
    
    ptr_to_untrusted_files_array files_array (new ptr_to_untrusted_file[m_chache_items.size ()]);
    
    for (cache_items_t::const_iterator i = m_chache_items.begin (); i != m_chache_items.end (); ++i, ++result_size_array)
    {
        files_array[result_size_array] = (*i).second;
    }
    
    return files_array;
} // get_items

bool untrusted_files_cache_t::add_item (const wstring& file_name, const wstring& dir_name, const wstring& app_name, const EntityAttributes &attrs, const wstring& modify_time)
{
    locker_t sync_guard (m_sync);
    wstring  full_item_name = dir_name + file_name;
    
    cache_items_t::iterator i = m_chache_items.find (full_item_name);
    if (i != m_chache_items.end ())
        return true;
        
    if (NULL != m_file && 0 == ::fseek (m_file, 0, SEEK_END))    
    {
        size_t  pos = ::ftell (m_file);
        
        ptr_to_cache_item item (new cache_item_t (pos, L"[a]", dir_name, file_name, app_name, attrs, modify_time));
        if (NULL != item.get ())
        {
            wstring cache_item;
            
            cache_item.assign (L"\n");
            
            cache_item
                .append (item->m_status)
                .append (L";")
                .append (item->get_file_name ())
                .append (L";")
                .append (item->get_directory_name ())
                .append (L";")
                .append (item->get_app_name ())
                .append (L";")
                .append (item->get_modify_time ())
                .append (L";");
            
            if (0 <= ::fputws (cache_item.c_str (), m_file))
            {
                m_chache_items[full_item_name] = item;
                return true;
            }    
        }
    }
    
    return false;
} // add_item

void untrusted_files_cache_t::remove_item (const wstring& full_item_name)
{
    locker_t sync_guard (m_sync);
    
    cache_items_t::iterator i = m_chache_items.find (full_item_name);
    if (i == m_chache_items.end ())
        return;
    
    ptr_to_cache_item item = (*i).second;
    
    if (NULL != m_file && 0 == ::fseek (m_file, static_cast <long> (item->m_file_offset), SEEK_SET))
    {
        item->m_status[1] = ITEM_STATUS_DELETED;
        ::fwrite (item->m_status.c_str (), sizeof (wchar_t), item->m_status.size (), m_file);
        ::fflush (m_file);
    }
    
    m_chache_items.erase (i);    
} // remove_item

void untrusted_files_cache_t::fill_cache_from_file ()
{
    if (NULL == m_file)
        return;

    ptr_to_wchar_array string_array (new wchar_t[64*1024]);
    
    if (NULL == string_array.get ())
        return;
    
    size_t  item_pos;
    wstring status;
    wstring file_name;
    wstring dir_name;
    wstring app_name;
    wstring modify_time;
    
    size_t pos = ::ftell (m_file);
    while (NULL != ::fgetws (string_array.get (), 64*1024, m_file))
    {
        status.clear ();
        file_name.clear ();
        dir_name.clear ();
        app_name.clear ();
        modify_time.clear ();
		EntityAttributes attrs =  { 0 };
        
        parse_cache_item (string_array.get (), status, file_name, dir_name, app_name, modify_time);
        item_pos = pos;
        
        pos = ::ftell (m_file);
        
        if (true == is_item_valid (status))
            add_item (item_pos, status, file_name, dir_name, app_name, attrs, modify_time);
    }
    
} // fill_cache_from_file

void untrusted_files_cache_t::add_item (size_t item_file_pos, const wstring& status, const wstring& file_name, const wstring& dir_name, const wstring& app_name, const EntityAttributes &attrs, const wstring& modify_time)
{
    locker_t sync_guard (m_sync);
    wstring  full_item_name = dir_name + file_name;
    
    cache_items_t::iterator i = m_chache_items.find (full_item_name);
    if (i != m_chache_items.end ())
        return;
        
    ptr_to_cache_item item (new cache_item_t (item_file_pos, status, dir_name, file_name, app_name, attrs, modify_time));
    if (NULL != item.get ())
        m_chache_items[full_item_name] = item;
} // add_item

bool untrusted_files_cache_t::is_item_valid (const wstring& status) const
{
    return (3 <= status.size () && ITEM_STATUS_ACTIVE == status[1]);
} // is_item_valid

void untrusted_files_cache_t::parse_cache_item (wchar_t* cache_item, wstring& status, wstring& file_name, wstring& dir_name, wstring& app_name, wstring& modify_time)
{
    wchar_t* token = wcstok (cache_item, L";");
    size_t   index = 0;
    
    while (NULL != token && 5 > index)
    {
         switch (index)
         {
            case 0:
                status.assign (token);
                break;
            case 1:
                file_name.assign (token);
                break;
            case 2:
                dir_name.assign (token);
                break;
            case 3:
                app_name.assign (token);
                break;
            case 4:
                modify_time.assign (token);
                break;
         }
         
         token = wcstok (NULL, L";");
         ++index;
    }
} // parse_cache_item