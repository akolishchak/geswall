//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_attack_wnd_h__
 #define __gswui_attack_wnd_h__

#include "commonlib/commondefs.h"
#include "log_wnd.h"

#include "gswui/attackfilter/process_manager.h"

namespace gswui {
namespace logwnd {

class attack_wnd;

//****************************************************************************************//

class attack_wnd : public log_wnd
{
  public:
    typedef gswui::attackfilter::ptr_to_process_manager  ptr_to_process_manager;
    
    enum termination_type_t
    {
        termination_type_none = 0,
        termination_type_auto,
        termination_type_interactive_ignore,
        termination_type_interactive_terminate
    }; // enum termination_type_t
    
  protected:
    typedef commonlib::IntrusiveAtomicCounter            atomic_counter_t;
    
  private:

  public:
    attack_wnd (HINSTANCE global_instance, ptr_to_process_manager& process_manager);
    virtual ~attack_wnd ();
    
    virtual void      add_message (const wstring& app_name, const wstring& message);
    virtual void      clean ();
    
    termination_type_t get_process_termination_type ();
    void     set_process_termination_type (termination_type_t term_type);

  protected:
    virtual void    reload_setting (ptr_to_config_node& params);
  
    virtual LRESULT wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    virtual LRESULT on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify);
  
  private:
    bool    check_mouse_button_clicked (HWND hwnd, int x, int y);
    bool    check_click_on_button (HWND hwnd, unsigned int bitmap_resource_id);
    void    refresh_termination_skin ();
    void    check_process_termination ();
    void    kill_processes ();

  public:
  protected:
  private:
    ptr_to_process_manager m_process_manager;
    atomic_counter_t       m_kill_started;
    atomic_counter_t       m_button_state;
    int                    m_mouse_key_pressed_x;
    int                    m_mouse_key_pressed_y;
    int                    m_mouse_key_released_x;
    int                    m_mouse_key_released_y;
    
    termination_type_t     m_termination_type;
}; // class attack_wnd

} // namespace logwnd {
} // namespace gswui {

#endif // __gswui_attack_wnd_h__