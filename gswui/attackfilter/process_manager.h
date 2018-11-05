//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswui_attackfilter_process_manager_h_
 #define _gswui_attackfilter_process_manager_h_

#include <string>
#include <hash_map>
#include <list>

#include <boost/smart_ptr.hpp>

#include "commonlib/commondefs.h"
 
namespace gswui {
namespace attackfilter {

class process_manager;

typedef std::wstring  wstring;

class process_manager
{
  //
  // types
  //
  public:
    struct process_info_t
    {
        process_info_t (const wstring& name, unsigned long process_id)
            : m_name (name),
              m_process_id (process_id)
        {
        }

        const wstring& name () const
        {
            return m_name;
        } // name

        const unsigned long process_id () const
        {
            return m_process_id;
        } // process_id

        const wstring       m_name;
        const unsigned long m_process_id;
    }; // struct process_info_t

    typedef boost::shared_ptr<process_info_t>              ptr_to_process_info;
    typedef boost::shared_array<ptr_to_process_info>       ptr_to_process_array;
  
  protected:
    typedef commonlib::sync::SyncObject::Locker  locker;
    typedef commonlib::sync::SyncObject          sync_object;

    typedef stdext::hash_map <unsigned long, ptr_to_process_info> process_map;
    typedef std::list <ptr_to_process_info>                       process_list;

  private:
  
  //
  // methods
  //
  public:
             process_manager ();
    virtual ~process_manager ();
    
    void     add_process (const wstring& name, unsigned long process_id);
    void     remove_process (const wstring& name);
    void     remove_process (unsigned long process_id);
    void     remove_all_processes ();
    
    void     kill_process (const wstring& name);
    bool     kill_process (unsigned long process_id);
    void     kill_all_processes ();

    ptr_to_process_array get_processes ();
    ptr_to_process_array get_processes (const wstring& name);

    ptr_to_process_info  get_process (unsigned long process_id);
    
    void     set_max_queue_size (size_t max_queue_size);
    size_t   get_max_queue_size ();
  
  protected:
                process_manager (const process_manager& right) {};
    process_manager& operator= (const process_manager& right) { return *this; }
  
  private:
    size_t   get_process_count (const wstring& name);
    void     cleanup_finished_processes ();
    
    void     remove_process_impl (const wstring& name);
    void     kill_process_impl (const wstring& name);
    bool     kill_process (ptr_to_process_info& proc_info);
    
    void     remove_process_impl (unsigned long process_id);
    void     remove_process_impl (process_map::iterator& i);
    
    void     check_queue_size ();
  
  //
  // data
  //
  public:
  protected:
    sync_object  m_sync;
    process_map  m_processes;
    process_list m_process_queue;
    
    size_t       m_max_queue_size;

  private:
}; // class process_manager

typedef boost::shared_ptr<process_manager>     ptr_to_process_manager;
typedef process_manager::ptr_to_process_info   ptr_to_process_info;
typedef process_manager::ptr_to_process_array  ptr_to_process_array;

} // namespace attackfilter {
} // namespace gswui {

#endif // _gswui_attackfilter_process_manager_h_