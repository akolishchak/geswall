//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"

#include <windowsx.h>

#include "attack_wnd.h"

#include "resource1.h"

#include "commonlib/debug.h"
 
namespace gswui {
namespace logwnd {

attack_wnd::attack_wnd (HINSTANCE global_instance, ptr_to_process_manager& process_manager)
    : log_wnd (
          global_instance, 
          L"AttackDetection", 
          L"GeSWall's Attacks Prevention",
          RGB (255, 128, 0),
          5000,
          500,
          110,
          RGB (0, 0, 0),
          IDB_BITMAP_DETECTOR_SKIN_MASK,
          IDB_BITMAP_DETECTOR_SKIN
      ),
      m_process_manager (process_manager),
      m_termination_type (termination_type_interactive_ignore),
      m_mouse_key_pressed_x (0),
      m_mouse_key_pressed_y (0),
      m_mouse_key_released_x (0),
      m_mouse_key_released_y (0)
{
    add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TOP_LEFT, skin_align_top_left);
    add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TOP_RIGHT, skin_align_top_right);
    //add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TERMINATE, skin_align_bottom_right, -5, skin_shift_pixels);
    //add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_IGNORE, skin_align_bottom_center, -30, skin_shift_pixels);
} // notify_wnd

attack_wnd::~attack_wnd ()
{
    try
    {
        destroy ();
    }
    catch (...)
    {
    }
} // ~attack_wnd

void attack_wnd::add_message (const wstring& app_name, const wstring& message)
{
    log_wnd::add_message (app_name, message);
    
//    if (true == is_auto_process_terminate ())
//        kill_processes ();
} // add_message

void attack_wnd::clean ()
{
    check_process_termination ();
    
    log_wnd::clean ();
    m_process_manager->remove_all_processes ();
} // clean

attack_wnd::termination_type_t attack_wnd::get_process_termination_type ()
{
    check_reload_setting ();
    
    return m_termination_type;
} // get_process_termination_type

void attack_wnd::set_process_termination_type (termination_type_t term_type)
{
    m_termination_type = term_type;
    refresh_termination_skin ();
    
    ptr_to_config_node params = get_config_node ();
    if (NULL != params.get ())
        params->setUInt (L"AutomaticProcessTermination", m_termination_type);
} // set_process_termination_type

void attack_wnd::reload_setting (ptr_to_config_node& params)
{
    if (NULL == params.get ())
        return;
    
    log_wnd::reload_setting (params);
    
    unsigned int term_type = params->getUInt (L"AutomaticProcessTermination");
    
    switch (static_cast <termination_type_t> (term_type))
    {
        case termination_type_none:
            m_termination_type = termination_type_none;
            break;
        case termination_type_auto:
            m_termination_type = termination_type_auto;
            break;
        case termination_type_interactive_ignore:
            m_termination_type = termination_type_interactive_ignore;
            break;
        case termination_type_interactive_terminate:
            m_termination_type = termination_type_interactive_terminate;
            break;
        default:
            m_termination_type = termination_type_none;
            break;
    }
    
    refresh_termination_skin ();
} // reload_setting

LRESULT attack_wnd::wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_NCHITTEST:
            if (true == check_mouse_button_clicked (hwnd, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)))
            {
                if (true == check_click_on_button (hwnd, IDB_BITMAP_DETECTOR_SKIN_TERMINATE))
                {
                    if (1 == m_kill_started.increment ())
                    {
                        kill_processes ();
                        hide ();
                        m_kill_started.decrement ();
                    }
                } 
                else if (true == check_click_on_button (hwnd, IDB_BITMAP_DETECTOR_SKIN_IGNORE))
                {
                    m_process_manager->remove_all_processes ();
                    hide ();
                }
            }
            break;
    }
    
    return log_wnd::wnd_proc (hwnd, message, wParam, lParam);
} // wnd_proc

LRESULT attack_wnd::on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify)
{
    //switch (idCommand)
    //{
    //}
    
    return log_wnd::on_command (hwnd, idCommand, hwndCtl, codeNotify);
} // on_command

bool attack_wnd::check_mouse_button_clicked (HWND hwnd, int x, int y)
{
    bool bt_down = (0 != (::GetAsyncKeyState (VK_LBUTTON) & 0x8000));
    int  state   = -1;
    
    if (true == bt_down)
    {
        state = m_button_state.increment ();
        if (1 == state)
        {
            m_mouse_key_pressed_x = x;
            m_mouse_key_pressed_y = y;
            m_mouse_key_released_x = 0;
            m_mouse_key_released_y = 0;
            // ::SetCapture (hwnd);
        }    
        else
        {
            m_button_state.decrement ();
        }    
//        debugString ((L"\n+state = %u", state));
    }
    else    
    {
        state = m_button_state.decrement ();
        if (0 == state)
        {
            m_mouse_key_released_x = x;
            m_mouse_key_released_y = y;
            // ::ReleaseCapture ();
        }    
        else
        {
            m_button_state.increment ();
        }    
//        debugString ((L"\n-state = %u", state));            
    }
    
    return (0 == state);
} // check_mouse_button_clicked 

bool attack_wnd::check_click_on_button (HWND hwnd, unsigned int bitmap_resource_id)
{
    bool result  = false;
    
    ptr_to_skin_bitmap bitmap_info = get_skin_bitmap_info (bitmap_resource_id);
    if (NULL != bitmap_info.get ())
    {
        RECT wnd_rect    = { 0 };
    
        ::GetWindowRect (hwnd, &wnd_rect);
        
        wnd_rect.left   = wnd_rect.left + bitmap_info->m_placement.left;
        wnd_rect.right  = wnd_rect.left + (bitmap_info->m_placement.right - bitmap_info->m_placement.left);
        wnd_rect.top    = wnd_rect.top + bitmap_info->m_placement.top;
        wnd_rect.bottom = wnd_rect.top + (bitmap_info->m_placement.bottom - bitmap_info->m_placement.top);
        
        if (
               m_mouse_key_pressed_x > wnd_rect.left && m_mouse_key_pressed_x < wnd_rect.right 
            && m_mouse_key_pressed_y > wnd_rect.top && m_mouse_key_pressed_y < wnd_rect.bottom
            && m_mouse_key_released_x > wnd_rect.left && m_mouse_key_released_x < wnd_rect.right 
            && m_mouse_key_released_y > wnd_rect.top && m_mouse_key_released_y < wnd_rect.bottom
           )
        {
            result = true;
        }
    }   
    
    return result;
} // check_click_on_button

void attack_wnd::refresh_termination_skin ()
{
    switch (m_termination_type)
    {
        case termination_type_none:
            remove_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TERMINATE);
            remove_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_IGNORE);
            break;
        case termination_type_auto:
            remove_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TERMINATE);
            remove_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_IGNORE);
            break;
        case termination_type_interactive_ignore:
            add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TERMINATE, skin_align_bottom_right, -5, skin_shift_pixels);
            add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_IGNORE, skin_align_bottom_center, -30, skin_shift_pixels);
            break;
        case termination_type_interactive_terminate:
            add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TERMINATE, skin_align_bottom_right, -5, skin_shift_pixels);
            add_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_IGNORE, skin_align_bottom_center, -30, skin_shift_pixels);
            break;
        default:
            remove_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_TERMINATE);
            remove_skin_bitmap (IDB_BITMAP_DETECTOR_SKIN_IGNORE);
            break;
    }
    
    if (true == is_visible ())
        log_wnd::refresh_logwnd ();
} // refresh_termination_skin

void attack_wnd::check_process_termination ()
{
    switch (m_termination_type)
    {
        case termination_type_none:
            break;
        case termination_type_auto:
            kill_processes ();
            break;
        case termination_type_interactive_ignore:
            break;
        case termination_type_interactive_terminate:
            kill_processes ();
            break;
    }
} // check_process_termination

void attack_wnd::kill_processes ()
{
    gswui::attackfilter::ptr_to_process_array proc_array = m_process_manager->get_processes ();
    
    if (NULL != proc_array.get ())
    {
        for (int i = 0; NULL != proc_array[i].get (); ++i)
        {
//debugString ((L"\nprocess_info: name = %s, process_id = %u", proc_array[i]->name ().c_str (), proc_array[i]->process_id ()));        

#ifdef _CB_TEST_DEBUG_
            if (true == m_process_manager->kill_process (proc_array[i]->process_id ()))
                log_wnd::add_message (proc_array[i]->name (), L" - killed");
            else    
                log_wnd::add_message (proc_array[i]->name (), L" - don`t killed, access denied.");
#else                
            m_process_manager->kill_process (proc_array[i]->process_id ());
#endif _CB_TEST_DEBUG_                
        }
    }
} // kill_processes

} // namespace logwnd {
} // namespace gswui {

