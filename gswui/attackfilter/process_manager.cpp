//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"

#include <aclapi.h>

#include "process_manager.h"
#include "gswui/gswclient_helper.h"

namespace gswui {
namespace attackfilter {

#pragma message (__WARNING__"process_manager check max size process list???")

namespace API123 {
BOOL SlayProcess( IN DWORD PID);
}

process_manager::process_manager ()
    : m_max_queue_size (20)
{

} // process_manager

process_manager::~process_manager ()
{
    try
    {
        m_processes.clear ();
        m_process_queue.clear ();
    }
    catch (...)
    {
    }
} // ~process_manager

void process_manager::add_process (const wstring& name, unsigned long process_id)
{
    locker sync_guard (m_sync);

    remove_process_impl (process_id);

    ptr_to_process_info proc_info (new process_info_t (name, process_id));
    if (NULL != proc_info.get ())
    {
        m_processes [process_id] = proc_info;
        m_process_queue.push_back (proc_info);
        
        check_queue_size ();
    }
} // add_process

void process_manager::remove_process (const wstring& name)
{
    locker sync_guard (m_sync);

    remove_process_impl (name);
} // remove_process

void process_manager::remove_process (unsigned long process_id)
{
    locker sync_guard (m_sync);

    remove_process_impl (process_id);
} // remove_process

void process_manager::remove_all_processes ()
{
    locker sync_guard (m_sync);
    
    m_processes.clear ();
    m_process_queue.clear ();
} // remove_all_processes

void process_manager::kill_process (const wstring& name)
{
    locker sync_guard (m_sync);
    
    kill_process_impl (name);
} // kill_process

bool process_manager::kill_process (unsigned long process_id)
{
    locker sync_guard (m_sync);
    
    process_map::iterator i = m_processes.find (process_id);
    if (i != m_processes.end ())
    {
        if (true == kill_process ((*i).second))
        {
            remove_process_impl (i);
            return true;
        }
    }
    
    return false;
} // kill_process

void process_manager::kill_all_processes ()
{
    locker sync_guard (m_sync);
    
    for (process_map::iterator i = m_processes.begin (); i != m_processes.end (); ++i)
    {
        ptr_to_process_info proc_info = (*i).second;
        kill_process (proc_info);
    }
    
    m_processes.clear ();
    m_process_queue.clear ();
} // kill_all_processes

ptr_to_process_array process_manager::get_processes ()
{
    locker sync_guard (m_sync);

    ptr_to_process_array proc_array (new ptr_to_process_info[m_processes.size () + 1]);

    if (NULL != proc_array.get ())
    {
        size_t index = 0;
        for (process_map::iterator i = m_processes.begin (); i != m_processes.end (); ++i)
        {
            ptr_to_process_info proc_info = (*i).second;
            proc_array [index++] = proc_info;
        } 
    } // if (NULL != proc_array.get ())

    return proc_array;
} // get_processes

ptr_to_process_array process_manager::get_processes (const wstring& name)
{
    locker sync_guard (m_sync);

    ptr_to_process_array proc_array (new ptr_to_process_info[get_process_count (name) + 1]);
    if (NULL != proc_array.get ())
    {
        size_t index = 0;
        for (process_map::iterator i = m_processes.begin (); i != m_processes.end (); ++i)
        {
            ptr_to_process_info proc_info = (*i).second;
            if (0 == name.compare (proc_info->name ()))
                proc_array [index++] = proc_info;
        } 
    } // if (NULL != proc_array.get ())

    return proc_array;
} // get_processes

ptr_to_process_info process_manager::get_process (unsigned long process_id)
{
    locker sync_guard (m_sync);

    process_map::iterator i = m_processes.find (process_id);
    if (i != m_processes.end ())
        return (*i).second;

    return ptr_to_process_info ();
} // get_process

void process_manager::set_max_queue_size (size_t max_queue_size)
{
    locker sync_guard (m_sync);
    
    m_max_queue_size = max_queue_size;
    
    check_queue_size ();
} // set_max_queue_size

size_t process_manager::get_max_queue_size ()
{
    return m_max_queue_size;
} // get_max_queue_size

size_t process_manager::get_process_count (const wstring& name)
{
    size_t index = 0;
    
    for (process_map::iterator i = m_processes.begin (); i != m_processes.end (); ++i)
    {
        ptr_to_process_info proc_info = (*i).second;
        if (0 == name.compare (proc_info->name ()))
            ++index;
    } 
    
    return index;
} // get_process_count

void process_manager::cleanup_finished_processes ()
{
    for (process_map::iterator i = m_processes.begin (); i != m_processes.end (); ++i)
    {
        ptr_to_process_info proc_info = (*i).second;
        // check it
        #pragma message (__WARNING__"process_manager::cleanup_finished_processes need implement")
    } 
} // cleanup_finished_processes

void process_manager::remove_process_impl (const wstring& name)
{
    for (process_map::iterator i = m_processes.begin (); i != m_processes.end (); ++i)
    {
        ptr_to_process_info proc_info = (*i).second;
        if (0 == name.compare (proc_info->name ()))
        {
            remove_process_impl (i);
            remove_process_impl (name); // recursively call for remove all processes with same name
            break;
        }
    }
} // remove_process_impl

void process_manager::kill_process_impl (const wstring& name)
{
    for (process_map::iterator i = m_processes.begin (); i != m_processes.end (); ++i)
    {
        ptr_to_process_info proc_info = (*i).second;
        if (0 == name.compare (proc_info->name ()))
        {
            if (true == kill_process (proc_info))
            {
                remove_process_impl (i);
                kill_process_impl (name); // recursively call for remove all processes with same name
                break;
            }
        }
    }
} // remove_process_impl

bool process_manager::kill_process (ptr_to_process_info& proc_info)
{
    return (TRUE == API123::SlayProcess (proc_info->process_id ()));
} // kill_process

void process_manager::remove_process_impl (unsigned long process_id)
{
    process_map::iterator i = m_processes.find (process_id);
    if (i != m_processes.end ())
    {
        m_process_queue.remove ((*i).second);
        m_processes.erase (i);
    }    
} // remove_process_impl

void process_manager::remove_process_impl (process_map::iterator& i)
{
    m_process_queue.remove ((*i).second);
    m_processes.erase (i);
} // remove_process_impl

void process_manager::check_queue_size ()
{
    if (m_max_queue_size < m_process_queue.size ())
    {
        process_list::iterator i;
        while (true)
        {
            i = m_process_queue.begin ();
            if (i == m_process_queue.end () || m_max_queue_size >= m_process_queue.size ())
                break;
               
            ptr_to_process_info pi = (*i);
            remove_process_impl (pi->process_id ());
        }
    }
} // check_queue_size

namespace API123 {

BOOL EnableTokenPrivilege( IN HANDLE htok, IN LPCTSTR szPrivilege, IN OUT TOKEN_PRIVILEGES &tpOld)
{
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if( LookupPrivilegeValue( NULL, szPrivilege, &tp.Privileges[0].Luid))
    {
        // htok must have been opened with the following permissions:
        // TOKEN_QUERY (to get the old priv setting)
        // TOKEN_ADJUST_PRIVILEGES (to adjust the priv)
        DWORD cbOld = sizeof( tpOld);
        if( AdjustTokenPrivileges( htok, FALSE, &tp, cbOld, &tpOld, &cbOld))
        // Note that AdjustTokenPrivileges may succeed, and yet
        // some privileges weren't actually adjusted.
        // You've got to check GetLastError() to be sure!
            return ( ERROR_NOT_ALL_ASSIGNED != GetLastError());
        else
            return FALSE;
    }
    return FALSE;
}

BOOL RestoreTokenPrivilege( IN HANDLE htok, IN const TOKEN_PRIVILEGES &tpOld)
{
    return AdjustTokenPrivileges( htok, FALSE, const_cast<TOKEN_PRIVILEGES*>(&tpOld), 0, 0, 0);
}

BOOL EnablePrivilege( IN LPCTSTR szPrivilege)
{
    HANDLE hToken;
    if( !::OpenProcessToken( ::GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tpOld;
    BOOL bReturn = EnableTokenPrivilege( hToken, szPrivilege, tpOld);
    ::CloseHandle(hToken);
    return bReturn;
}


BOOL AdjustDacl( IN HANDLE h, IN DWORD DesiredAccess)
{
    // the WORLD Sid is trivial to form programmatically (S-1-1-0)
    SID world = { SID_REVISION, 1, SECURITY_WORLD_SID_AUTHORITY, 0 };

    EXPLICIT_ACCESS ea =
    {
        DesiredAccess,
        SET_ACCESS,
        NO_INHERITANCE,
        {
            0, NO_MULTIPLE_TRUSTEE,
            TRUSTEE_IS_SID,
            TRUSTEE_IS_USER,
            reinterpret_cast<LPTSTR>(&world)
        }
    };
    PACL pdacl = NULL;
    DWORD err = SetEntriesInAcl( 1, &ea, 0, &pdacl);
    if( err == ERROR_SUCCESS)
    {
        err = SetSecurityInfo( h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, pdacl, 0);
        LocalFree( pdacl);
        return err == ERROR_SUCCESS;
    }
    return FALSE;
}

HANDLE GetProcessHandleWithEnoughRights( IN DWORD PID, IN DWORD AccessRights)
{
    HANDLE hProcess = ::OpenProcess( AccessRights, FALSE, PID);
    if( !hProcess)
    {
        HANDLE hpWriteDAC = OpenProcess( WRITE_DAC, FALSE, PID);
        if( !hpWriteDAC)
        {
            // hmm, we don't have permissions to modify the DACL...
            // time to take ownership...
            HANDLE htok;
            if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &htok))
                return FALSE;

            TOKEN_PRIVILEGES tpOld;
            if( EnableTokenPrivilege( htok, SE_TAKE_OWNERSHIP_NAME, tpOld))
            {
                // SeTakeOwnershipPrivilege allows us to open objects with
                // WRITE_OWNER, but that's about it, so we'll update the owner,
                // and dup the handle so we can get WRITE_DAC permissions.
                HANDLE hpWriteOwner = OpenProcess( WRITE_OWNER, FALSE, PID);
                if( hpWriteOwner)
                {
                    BYTE buf[512]; // this should always be big enough
                    DWORD cb = sizeof( buf);
                    if( GetTokenInformation( htok, TokenUser, buf, cb, &cb))
                    {
                        DWORD err = SetSecurityInfo( 
                                hpWriteOwner, 
                                SE_KERNEL_OBJECT,
                                OWNER_SECURITY_INFORMATION,
                                reinterpret_cast<TOKEN_USER*>(buf)->User.Sid,
                                0, 0, 0);
                        if( err == ERROR_SUCCESS)
                        {
                            // now that we're the owner, we've implicitly got WRITE_DAC
                            // permissions, so ask the system to reevaluate our request,
                            // giving us a handle with WRITE_DAC permissions
                            if ( !DuplicateHandle( 
                                    GetCurrentProcess(), 
                                    hpWriteOwner,
                                    GetCurrentProcess(), 
                                    &hpWriteDAC,
                                    WRITE_DAC, FALSE, 0) 
                                )
                            { hpWriteDAC = NULL; }
                        }
                    }
                    ::CloseHandle( hpWriteOwner);
                }
                // not truly necessary in this app,
                // but included for completeness
                RestoreTokenPrivilege( htok, tpOld);
            }
            ::CloseHandle( htok);
        }

        if( hpWriteDAC)
        {
            // we've now got a handle that allows us WRITE_DAC permission
            AdjustDacl( hpWriteDAC, AccessRights);

            // now that we've granted ourselves permission to access 
            // the process, ask the system to reevaluate our request,
            // giving us a handle with right permissions
            if ( !DuplicateHandle( 
                    GetCurrentProcess(), 
                    hpWriteDAC,
                    GetCurrentProcess(), 
                    &hProcess,
                    AccessRights, 
                    FALSE, 
                    0) 
                )
            { hProcess = NULL; }
            CloseHandle(hpWriteDAC);
        }
    }
    return hProcess;
}

BOOL SlayProcess( IN DWORD PID)
{
    HANDLE hp = GetProcessHandleWithEnoughRights( PID, PROCESS_TERMINATE);
    if( hp)
    {
        // if all went well, we've now got a handle to the process
        // that grants us PROCESS_TERMINATE permissions
        BOOL bReturn = TerminateProcess( hp, 1);
        ::CloseHandle(hp);
        return bReturn;
    }
    return FALSE;
}

} // namespace API123 {

} // namespace attackfilter {
} // namespace gswui {
