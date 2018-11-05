//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswmmc_untrusted_files_cache_h_
 #define _gswmmc_untrusted_files_cache_h_

#include "commonlib/commondefs.h"

#include "untrusted_file.h"

#include <stdio.h>
#include <io.h>
#include <string>
#include <hash_map>

class untrusted_files_cache_t;
//****************************************************************************************//

typedef boost::shared_array<ptr_to_untrusted_file> ptr_to_untrusted_files_array;

class untrusted_files_cache_t
{
  protected:
    typedef commonlib::sync::SyncObject                       sync_object;
    typedef commonlib::sync::SyncObject::Locker               locker_t;
    typedef std::wstring                                      wstring;
    typedef boost::shared_ptr<wstring>                        ptr_to_wstring;
  
    struct cache_item_t : public untrusted_file_t
    {
        cache_item_t (size_t file_offset, const wstring& status, const wstring& directory_name, const wstring& file_name, const wstring& app_name, const EntityAttributes &attrs, const wstring& modify_time)
            : untrusted_file_t (directory_name, file_name, app_name, attrs, modify_time),
              m_status (status),
              m_file_offset (file_offset)
        {
        
        }
        
        wstring m_status;
        size_t  m_file_offset;
    }; // struct cache_item_t
  
    typedef boost::shared_ptr<cache_item_t>                   ptr_to_cache_item;
    typedef stdext::hash_map <wstring, ptr_to_cache_item>     cache_items_t;
    
  public:
    untrusted_files_cache_t (const wstring& cache_file_name, bool create_new_if_not_exists);
    virtual ~untrusted_files_cache_t ();

             const wstring& get_file_name () const;
             ptr_to_untrusted_files_array get_items (size_t& result_size_array) const;
             bool           add_item (const wstring& file_name, const wstring& dir_name, const wstring& app_name, const EntityAttributes &attrs, const wstring& modify_time);
             void           remove_item (const wstring& full_item_name);
    
  protected:
             void           fill_cache_from_file ();
             void           add_item (size_t item_file_pos, const wstring& status, const wstring& file_name, const wstring& dir_name, const wstring& app_name, const EntityAttributes &attrs, const wstring& modify_time);
             bool           is_item_valid (const wstring& status) const;
             void           parse_cache_item (wchar_t* cache_item, wstring& status, wstring& file_name, wstring& dir_name, wstring& app_name, wstring& modify_time);
  private:
    
  private:
    static const wchar_t ITEM_STATUS_ACTIVE;
    static const wchar_t ITEM_STATUS_DELETED;
    static const wchar_t ITEM_STATUS_SKIPPED;
  
    mutable sync_object     m_sync;
  
    wstring         m_file_name;
    FILE*           m_file;
    
    cache_items_t   m_chache_items;
}; // class untrusted_files_cache_t

typedef boost::shared_ptr <untrusted_files_cache_t>      ptr_to_untrusted_files_cache;

#endif // _gswmmc_untrusted_files_cache_h_

