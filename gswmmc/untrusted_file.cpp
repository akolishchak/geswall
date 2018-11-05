//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include "untrusted_file.h"

#include "app/application.h"
#include "gswdrv.h"

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

typedef commonlib::PtrToWcharArray ptr_to_wchar_array;

untrusted_file_t::untrusted_file_t (const wstring& directory_name, const wstring& file_name, const EntityAttributes &attrs, const wstring& modify_time)
    : m_directory_name (directory_name), 
      m_file_name (file_name),
	  m_attrs (attrs),
      m_app_name (query_app_name (directory_name + file_name, attrs)),
      m_modify_time (modify_time)
{

} // untrusted_file_t

untrusted_file_t::untrusted_file_t (const wstring& directory_name, const wstring& file_name, const wstring& app_name, const EntityAttributes &attrs, const wstring& modify_time)
    : m_directory_name (directory_name), 
      m_file_name (file_name),
	  m_attrs (attrs),
      m_app_name (app_name),
      m_modify_time (modify_time)
{

}

untrusted_file_t::untrusted_file_t (const untrusted_file_t& right)
    : m_directory_name (right.get_directory_name ()), 
      m_file_name (right.get_file_name ()),
	  m_attrs (right.get_attrs ()),
      m_app_name (right.get_app_name ()),
      m_modify_time (right.get_modify_time ())
{
    
} // untrusted_file_t

untrusted_file_t::~untrusted_file_t ()
{
    try
    {
    }
    catch (...)
    {
    }
} // ~untrusted_file_t

untrusted_file_t& untrusted_file_t::operator= (const untrusted_file_t& right)
{
    if (this != &right)
        untrusted_file_t (right).swap (*this);
  
    return *this;
} // operator=

const wstring& untrusted_file_t::get_directory_name () const
{
    return m_directory_name;
} // get_directory_name

const wstring& untrusted_file_t::get_file_name () const
{
    return m_file_name;
} // get_file_name

const EntityAttributes& untrusted_file_t::get_attrs () const
{
	return m_attrs;
}
const wstring& untrusted_file_t::get_app_name () const
{
    return m_app_name;
} // get_app_name

const wstring& untrusted_file_t::get_modify_time () const
{
    return m_modify_time;
} // get_modify_time

wstring untrusted_file_t::query_app_name (const wstring& file_name, const EntityAttributes& attributes)
{
    if (attributes.Param[GesRule::attIntegrity] < GesRule::modTCB && attributes.Param[GesRule::attIntegrity] > GesRule::modUndefined ) 
    {
        // 
        int AppId = attributes.Param[GesRule::attObjectId];
        int RuleId = AppId < 0 ? 0 : 1;
        //
        // 2. 
        //
        App::Application app_item;
        App::Application::GetAppItem (AppId, RuleId, L"Unknown", app_item);
        return app_item.GetDisplayName();
        //return L"todo_real_display_name";
    }
    
    return L"trusted app";
} // query_app_name

HANDLE untrusted_file_t::open_file (const wstring& file_name)
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

void untrusted_file_t::close_file (HANDLE file_handle)
{
    ::CloseHandle (file_handle);
} // close_file