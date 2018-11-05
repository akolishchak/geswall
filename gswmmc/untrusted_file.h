//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswmmc_untrusted_file_h_
 #define _gswmmc_untrusted_file_h_

#include "commonlib/commondefs.h"
#include "gsw/gswioctl.h"

#include <string>

class untrusted_file_t;
//****************************************************************************************//

class untrusted_file_t
{
  protected:
    typedef commonlib::sync::SyncObject      sync_object;
    typedef commonlib::sync::SyncObject::Locker locker_t;
    typedef std::wstring                     wstring;
    typedef boost::shared_ptr<wstring>       ptr_to_wstring;
    
  public:
    untrusted_file_t (const wstring& directory_name, const wstring& file_name, const EntityAttributes &attrs, const wstring& modify_time);
	untrusted_file_t (const wstring& directory_name, const wstring& file_name, const wstring& app_name, const EntityAttributes &attrs, const wstring& modify_time);
    untrusted_file_t (const untrusted_file_t& right);
    virtual ~untrusted_file_t ();
    
            untrusted_file_t& operator= (const untrusted_file_t& right);
            
            const wstring& get_directory_name () const;
            const wstring& get_file_name () const;
			const EntityAttributes& get_attrs () const;
            const wstring& get_app_name () const;
            const wstring& get_modify_time () const;

  protected:
    void swap (untrusted_file_t& right)
    {
        m_directory_name.swap (right.m_directory_name);
        m_file_name.swap (right.m_file_name);
        m_app_name.swap (right.m_app_name);
        m_modify_time.swap (right.m_modify_time);
    } // swap

  private:
    wstring        query_app_name (const wstring& file_name, const EntityAttributes &attributes);
    
    static HANDLE  open_file (const wstring& file_name);
    static void    close_file (HANDLE file_handle);
    
  private:
    wstring         m_directory_name;
    wstring         m_file_name;
	EntityAttributes m_attrs;
    wstring         m_app_name;
    wstring         m_modify_time;
}; // class untrusted_file_t

typedef boost::shared_ptr <untrusted_file_t>      ptr_to_untrusted_file;

#endif // _gswmmc_untrusted_file_h_

