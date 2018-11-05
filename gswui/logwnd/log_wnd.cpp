//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "richedit.h"

#include "log_wnd.h"

#include "commonlib/debug.h"

#include "gswui/gui_helper.h"

#include "../resource1.h"

#include <commctrl.h>
#include <windowsx.h>

#include <stdlib.h>
#include <time.h>


namespace gswui {
namespace logwnd {

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

#define  IDC_PAINT_ALGO_FALLTO_010    1100
#define  IDC_PAINT_ALGO_FALLTO_020    1101
#define  IDC_PAINT_ALGO_FALLTO_040    1102
#define  IDC_PAINT_ALGO_FALLTO_060    1103
#define  IDC_PAINT_ALGO_FALLTO_080    1104

#define  ID_LIST_CONTROL              2000

#define  IDC_EXIT                     9999

log_wnd::atomic_counter log_wnd::m_instance_counter;

log_wnd::
    log_wnd (
        HINSTANCE       global_instance, 
        const wstring&  name, 
        const wstring&  wnd_name,
        COLORREF        bkg_color,
        int             stable_time,
        int             visible_time,
        int             font_size,
        COLORREF        font_color,
        int             skin_mask_resource_id,   // IDB_BITMAP_DETECTOR_SKIN_MASK
        int             skin_bitmap_resource_id
    )
    : m_instance_id (m_instance_counter.increment ()),
      m_name (name),
      m_wnd_name (wnd_name), 
      m_global_instance (global_instance),
      m_init_complete (false),
      m_init_result (false),
      m_need_reload_setting (true),
      m_hwnd_log_window (NULL),
      m_view_control (new redit_log_view (global_instance)),
      m_current_alpha (255),
      m_repaint_timer_id (1),
      m_repaint_timer_resolution (50),
      m_bkg_color_default (RGB (192, 192, 192)),
      m_bkg_color (bkg_color),
      m_bkg_brush (NULL),
      m_refresh_bkg_brush (true),
      m_stable_time (stable_time),
      m_visible_time (visible_time),
      m_font_size_percent (font_size),
      m_font_color (font_color),
      m_window_size_x (25),
      m_window_size_y (20),
      m_window_size_x_min (300),
      m_window_size_y_min (150),
      m_window_size_x_max (600),
      m_window_size_y_max (512),
      m_logwnd_prev_height (0),
      m_list_control_req_height (0),
      m_current_paint_algo (IDC_PAINT_ALGO_FALLTO_010),
      m_current_stable_time (1),
      m_current_visible_time (1),
      m_current_direction (-1),
      m_skin_mask_resource_id (skin_mask_resource_id),
      m_skin_bitmap_resource_id (skin_bitmap_resource_id),
      m_skin_bitmap (NULL),
      m_skin_mask_bitmap (NULL),
      m_caption_height (-1),
      m_bottom_height (-1),
      m_compatible_hdc_1 (NULL),
      m_compatible_hdc_2 (NULL)
      
{
    m_gui_thread = ptr_to_work_thread (new work_thread (thread_stub (*this)));
} // log_wnd


log_wnd::~log_wnd ()
{
    try
    {
        destroy ();
    }
    catch (...)
    {
    }
} // ~log_wnd

void log_wnd::destroy ()
{
    if (NULL != m_hwnd_log_window)
    {
        ::PostMessage (m_hwnd_log_window, WM_COMMAND, IDC_EXIT, 0);
        //DestroyWindow (m_hwndToolWindow);
    }  
      
    if (NULL != m_gui_thread.get ())  
        m_gui_thread->join ();

    if (NULL != m_compatible_hdc_1)
        ::DeleteDC (m_compatible_hdc_1);
    if (NULL != m_compatible_hdc_2)
        ::DeleteDC (m_compatible_hdc_2);
    m_compatible_hdc_1 = m_compatible_hdc_2 = NULL;    
        
    if (NULL != m_skin_bitmap)
        ::DeleteObject (m_skin_bitmap);
    m_skin_bitmap = NULL;    
        
    if (NULL != m_skin_mask_bitmap)    
        ::DeleteObject (m_skin_mask_bitmap);
    m_skin_mask_bitmap = NULL;    
        
    m_skin_bitmaps.clear ();    
    
    if (NULL != m_bkg_brush)
        ::DeleteObject (m_bkg_brush);
    m_bkg_brush = NULL;    
    
    m_refresh_bkg_brush   = true;
    m_init_result         = false;
    m_init_complete       = false;
    m_need_reload_setting = true;
} // destroy

void log_wnd::add_skin_bitmap (int bitmap_resource_id, skin_align_t align, unsigned int shift_persents, skin_shift_t shift_type)
{
    m_skin_bitmaps.erase (bitmap_resource_id);
    
    ptr_to_skin_bitmap skin_bitmap (new skin_bitmap_t (m_global_instance, bitmap_resource_id, align, shift_persents, shift_type));
    if (NULL != skin_bitmap.get ())
    {
        if (
                skin_align_top_left   == align
             || skin_align_top_right  == align
             || skin_align_top_center == align
            )
        {
            if (m_caption_height < (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight))
                m_caption_height = (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight);
        }
        else
        {
            if (
                   skin_align_bottom_center == align
                || skin_align_bottom_right  == align
                || skin_align_bottom_center == align
               )
            {
                if (m_bottom_height < (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight))
                    m_bottom_height = (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight);
            }
        }
        
        m_skin_bitmaps [bitmap_resource_id] = skin_bitmap;
    }
} // add_skin_bitmap

void log_wnd::remove_skin_bitmap (int bitmap_resource_id)
{
    m_skin_bitmaps.erase (bitmap_resource_id);
    recalc_skin_params ();
} // remove_skin_bitmap

log_wnd::ptr_to_skin_bitmap log_wnd::get_skin_bitmap_info (int bitmap_resource_id)
{
    skin_bitmap_map::iterator i = m_skin_bitmaps.find (bitmap_resource_id);
    if (i != m_skin_bitmaps.end ())
        return (*i).second;
        
    return ptr_to_skin_bitmap ();
} // get_skin_bitmap_info

void log_wnd::hide ()
{
    if (false == m_init_result)
        return;
        
    hide_log_window (m_hwnd_log_window);
} // hide

bool log_wnd::is_visible ()
{
    return (TRUE == ::IsWindowVisible (m_hwnd_log_window));
} // is_visible

void log_wnd::add_message (const wstring& app_name, const wstring& message)
{
debugString ((L"\nadd_message (): [0]"));
    if (false == m_init_complete)
    {
debugString ((L"\nadd_message (): [wait for init completed]"));    
        commonlib::sync::SyncObject::Locker locker (m_init_complete_sync);
        if (false == m_init_complete)
            m_init_complete_sync.wait (-1);
debugString ((L"\nadd_message (): [end of wait for init completed]"));
    }
    
    if (false == m_init_result)
        return;
    
    check_reload_setting ();
    
    COLORREF font_color        = RGB (0, 0, 0);
    
//    clean ();
    
    m_view_control->add_message (app_name, message, m_font_size_percent, m_font_color);    
        
    refresh_logwnd ();
debugString ((L"\nadd_message (): [X]"));    
} // add_message

void log_wnd::clean ()
{
    if (false == m_init_result)
        return;
        
//    m_logwnd_prev_height      = 0;
    m_list_control_req_height = 0;
    
    m_view_control->clean ();
    
//    refresh_logwnd ();
} // clean

log_wnd::PaintAlgo log_wnd::get_paint_algo ()
{
    PaintAlgo result = PaintAlgoFallTo60;
  
    switch (m_current_paint_algo)
    {
      case IDC_PAINT_ALGO_FALLTO_010:
           result = PaintAlgoFallTo10;
           break;
      case IDC_PAINT_ALGO_FALLTO_020:
           result = PaintAlgoFallTo20;
           break;
      case IDC_PAINT_ALGO_FALLTO_040:
           result = PaintAlgoFallTo40;
           break;
      case IDC_PAINT_ALGO_FALLTO_060:
           result = PaintAlgoFallTo60;
           break;
      case IDC_PAINT_ALGO_FALLTO_080:
           result = PaintAlgoFallTo80;
           break;
    }
    
    return result;
} // get_paint_algo

void log_wnd::set_paint_algo (PaintAlgo algo)
{
    if (true == refresh_paint_algo (algo))
        get_config_node ()->setInt (L"PaintAlgorithm", algo);
} // set_paint_algo

int log_wnd::get_stable_time ()
{
    return m_stable_time;
} // get_stable_time

void log_wnd::set_stable_time (int stable_time)
{
    get_config_node ()->setInt (L"StableTime", stable_time);
    m_stable_time = stable_time;
    //m_stable_time = stable_time;
    //refresh_paint (m_current_paint_algo);
} // set_stable_time

int log_wnd::get_visible_time ()
{
    return m_visible_time;
} // get_visible_time

void log_wnd::set_visible_time (int visible_time)
{
    get_config_node ()->setInt (L"VisibleTime", visible_time);
    m_visible_time = visible_time;
    //m_visible_time = visible_time;
    //refresh_paint (m_current_paint_algo);
} // set_visible_time

COLORREF log_wnd::get_bkg_color ()
{
    return m_bkg_color;
} // get_bkg_color

void log_wnd::set_bkg_color (COLORREF bkg_color)
{
    m_bkg_color         = bkg_color;
    m_refresh_bkg_brush = true;
    get_config_node ()->setUInt (L"BackgroundColor", bkg_color);
//    refresh_paint (m_current_paint_algo);
} // set_bkg_color

void log_wnd::select_bkg_color (HWND hwnd)
{
    set_bkg_color (gui_helper::select_color (hwnd, get_bkg_color ()));
    
    if (true == is_visible ())
        refresh_logwnd ();
} // select_bkg_color

COLORREF log_wnd::get_font_color ()
{
    return m_font_color;
} // get_font_color

void log_wnd::set_font_color (COLORREF font_color)
{
    m_font_color = font_color;
    get_config_node ()->setUInt (L"FontColor", m_font_color);
} // set_font_color
    
int log_wnd::get_font_size ()
{
    return m_font_size_percent;
} // get_font_size

void log_wnd::set_font_size (int size)
{
    m_font_size_percent = size;
    get_config_node ()->setInt (L"FontSizePercent", m_font_size_percent);
} // set_font_size
    
void log_wnd::set_repaint_timer_resolution (unsigned int resolution)
{
    if (50 >  resolution)
        resolution = 50;
    if (5000 < resolution)
        resolution = 5000;
    
    m_repaint_timer_resolution = resolution;
    get_config_node ()->setUInt (L"RepaintTimerResolution", resolution);
    
    kill_repaint_timer ();
    create_repaint_timer ();
} // set_repaint_timer_resolution

//
// protected methods
//
struct init_finalizer_t
{
    init_finalizer_t (log_wnd::sync_object& init_complete_sync, bool& init_complete, bool& init_result)
        : m_init_complete_sync (init_complete_sync),
          m_init_complete (init_complete),
          m_init_result (init_result)
    {
    }
    
    void operator () (bool* result)
    {
        log_wnd::sync_object::Locker locker (m_init_complete_sync);
        m_init_result   = *result;
        m_init_complete = true;
        m_init_complete_sync.notifyAll ();
debugString ((L"\nlog_wnd::init_finalizer_t: [init completed]"));    
    } // operator ()
    
    log_wnd::sync_object&  m_init_complete_sync;
    bool&                  m_init_complete;
    bool&                  m_init_result;
}; // struct init_finalizer_t

int log_wnd::gui_thread_proc ()
{
debugString ((L"\nlog_wnd::gui_thread_proc: [0]"));
    bool        init_result = false;
    scope_guard init_finalizer = make_guard (&init_result, init_finalizer_t (m_init_complete_sync, m_init_complete, m_init_result));
    
    if (NULL == m_view_control.get ())
    {
debugString ((L"\nlog_wnd::gui_thread_proc: [0.5]"));
        return -1;
    }
    
//    HMODULE module_riched32 = ::LoadLibraryW (L"riched32.dll");
    HMODULE module_riched32 = ::LoadLibraryW (L"riched20.dll");
    if (NULL == module_riched32)
    {
debugString ((L"\nlog_wnd::gui_thread_proc: [1]"));
        return -1;
    }

debugString ((L"\nlog_wnd::gui_thread_proc: [2]"));
    scope_guard module_riched32_finalizer = make_guard (module_riched32, &::FreeLibrary);    
    
    InitCommonControls ();
debugString ((L"\nlog_wnd::gui_thread_proc: [3]"));    
    
    wstring     class_name_prefix = L"GsWUILogWindow_";
    wchar_t     postfix [32];
    
    srand (((unsigned) time (NULL)) * m_instance_id);
    swprintf (postfix, L"%08x", rand ()); //m_instance_id);
    class_name_prefix.append (postfix);
  
    WNDCLASS    wndclass;
    
    ZeroMemory (&wndclass, sizeof(wndclass));
    wndclass.style         = CS_SAVEBITS | CS_DBLCLKS;
    wndclass.lpfnWndProc   = &wnd_callback;
    wndclass.cbClsExtra    = 0;
    wndclass.cbWndExtra    = sizeof (void*);
    wndclass.hInstance     = m_global_instance;
    wndclass.hIcon         = NULL;
    wndclass.hCursor       = LoadCursor (NULL, IDC_ARROW);
    wndclass.hbrBackground = (HBRUSH) COLOR_BACKGROUND;
    wndclass.lpszMenuName  = NULL;
    wndclass.lpszClassName = class_name_prefix.c_str ();
    
    if (0 != ::RegisterClassW (&wndclass))
    {
debugString ((L"\nlog_wnd::gui_thread_proc: [4]"));
        m_hwnd_log_window = 
            create_window (
                /*WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW |*/ WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_NOACTIVATE,// | WS_VISIBLE, 
                WS_SYSMENU | WS_BORDER | WS_POPUP | WS_CAPTION/* | WS_CLIPCHILDREN*/, // | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME
                m_wnd_name, 
                class_name_prefix
            );
        if (NULL != m_hwnd_log_window)
        {
debugString ((L"\nlog_wnd::gui_thread_proc: [5]"));        
            //::SendMessageW (m_hwnd_log_window, WM_SETTEXT, 0, (LPARAM) m_wnd_name.c_str ());
            ::SetLayeredWindowAttributes (m_hwnd_log_window, RGB (0x80, 0x80, 0x80), m_current_alpha, LWA_ALPHA);
            init_skin ();
            
            init_result = true;
            init_finalizer.free ();

debugString ((L"\nlog_wnd::gui_thread_proc: [6]"));
            
            ::MSG  msg;
            while (TRUE == ::GetMessage (&msg, 0, 0, 0))
            {
                ::TranslateMessage (&msg);
                ::DispatchMessage (&msg);
            } // while (TRUE == GetMessage (&msg, 0, 0, 0))
            
            ::DestroyWindow (m_hwnd_log_window);
            
            m_hwnd_log_window   = NULL;
            
            return 0;
        } // if (NULL != m_hwnd_log_window)
    } // if (0 != ::RegisterClassW (&wndclass))
    
debugString ((L"\nlog_wnd::gui_thread_proc: [X]"));
    return -1;
} // gui_thread_proc

HWND log_wnd::create_window (DWORD ex_style, DWORD style, const wstring& wnd_name, const wstring& class_name)
{
    return 
        ::CreateWindowExW (
                    ex_style, 
                    class_name.c_str (), 
                    wnd_name.c_str (), 
                    style,
                    0, 0, 250, 50, 
                    NULL, 
                    NULL, 
                    m_global_instance, 
                    this
                );
} // create_window

void log_wnd::init_skin ()
{
    if (0 <= m_skin_bitmap_resource_id && NULL == m_skin_bitmap)
    {   
        m_skin_bitmap = ::LoadBitmapW (m_global_instance, MAKEINTRESOURCE(m_skin_bitmap_resource_id));
        ::GetObjectW (m_skin_bitmap, sizeof (m_skin_bitmap_info), &m_skin_bitmap_info);
    }
    
    refresh_region ();
} // init_skin

void log_wnd::refresh_region ()
{
    if (0 > m_skin_mask_resource_id)
        return;
        
    if (NULL == m_skin_mask_bitmap)
    {   
        m_skin_mask_bitmap = ::LoadBitmapW (m_global_instance, MAKEINTRESOURCE(m_skin_mask_resource_id));
        ::GetObjectW (m_skin_mask_bitmap, sizeof (m_skin_mask_bitmap_info), &m_skin_mask_bitmap_info);
    }
        
    if (NULL == m_compatible_hdc_1 || NULL == m_compatible_hdc_2)
    {
        HDC         wnd_hdc       = ::GetWindowDC (m_hwnd_log_window);
        scope_guard wnd_hdc_guard = make_guard (wnd_hdc, gui_helper::hdc_finalizer (m_hwnd_log_window));
        
        m_compatible_hdc_1 = ::CreateCompatibleDC (wnd_hdc); 
        m_compatible_hdc_2 = ::CreateCompatibleDC (wnd_hdc); 
    }
    
    if (NULL != m_compatible_hdc_1 && NULL != m_compatible_hdc_2)
    {
        RECT wnd_rect = { 0 };
        ::GetWindowRect (m_hwnd_log_window, &wnd_rect);
        
        HBITMAP     new_mask_bitmap       = CreateCompatibleBitmap (m_compatible_hdc_1, (wnd_rect.right - wnd_rect.left), (wnd_rect.bottom - wnd_rect.top));
        scope_guard new_mask_bitmap_guard = make_guard (new_mask_bitmap, &::DeleteObject);
        
        HGDIOBJ     prev_obj_1       = ::SelectObject (m_compatible_hdc_1, new_mask_bitmap);
        scope_guard prev_obj_1_guard = make_guard (prev_obj_1, gui_helper::selobj_finalizer (m_compatible_hdc_1));
        
        HGDIOBJ     prev_obj_2       = ::SelectObject (m_compatible_hdc_2, m_skin_mask_bitmap);
        scope_guard prev_obj_2_guard = make_guard (prev_obj_2, gui_helper::selobj_finalizer (m_compatible_hdc_2));
        
        //int         caption_height   = (NULL == m_skin_top_bitmap) ? gui_helper::get_wnd_caption_height (m_hwnd_log_window) : ((BITMAPINFO*) &m_skin_top_bitmap_info)->bmiHeader.biHeight;
        int         caption_height   = (0 >= m_caption_height) ? gui_helper::get_wnd_caption_height (m_hwnd_log_window) : m_caption_height;
        int         bottom_height    = (0 >= m_bottom_height) ? caption_height : m_bottom_height;
        
        ::StretchBlt (
            m_compatible_hdc_1, 
            0, 
            0, 
            (wnd_rect.right - wnd_rect.left),
            caption_height,
            m_compatible_hdc_2,
            0, 
            0, 
            ((BITMAPINFO*) &m_skin_mask_bitmap_info)->bmiHeader.biWidth,
            caption_height,
            SRCCOPY
        );
        
        ::StretchBlt (
            m_compatible_hdc_1, 
            0, 
            caption_height, 
            (wnd_rect.right - wnd_rect.left),
            (wnd_rect.bottom - wnd_rect.top) - (caption_height + bottom_height),
            m_compatible_hdc_2,
            0, 
            caption_height, 
            ((BITMAPINFO*) &m_skin_mask_bitmap_info)->bmiHeader.biWidth,
            ((BITMAPINFO*) &m_skin_mask_bitmap_info)->bmiHeader.biHeight - (caption_height + bottom_height),
            SRCCOPY
        );
        
        ::StretchBlt (
            m_compatible_hdc_1, 
            0, 
            (wnd_rect.bottom - wnd_rect.top) - bottom_height, 
            (wnd_rect.right - wnd_rect.left),
            bottom_height,
            m_compatible_hdc_2,
            0, 
            ((BITMAPINFO*) &m_skin_mask_bitmap_info)->bmiHeader.biHeight - bottom_height, 
            ((BITMAPINFO*) &m_skin_mask_bitmap_info)->bmiHeader.biWidth,
            bottom_height,
            SRCCOPY
        );
        
        ::SetWindowRgn (m_hwnd_log_window, gui_helper::scan_region (new_mask_bitmap, 0, 0, 0), TRUE);
    }
} // init_region

LRESULT CALLBACK log_wnd::wnd_callback (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_NCCREATE:
        case WM_CREATE:
        {
            ::CREATESTRUCTW* create_info = reinterpret_cast <::CREATESTRUCTW*> (lParam);
            ::SetWindowLongPtrW (hwnd, GWLP_USERDATA, PtrToUlong (create_info->lpCreateParams));
            break;
        }
    } // switch (message)
    
    log_wnd* _this = reinterpret_cast <log_wnd*> (ULongToPtr (::GetWindowLongPtrW (hwnd, GWLP_USERDATA)));
    
    if (NULL != _this)
        return _this->wnd_proc (hwnd, message, wParam, lParam);
        
    return ::DefWindowProc (hwnd, message, wParam, lParam);
} // wnd_callback

LRESULT log_wnd::wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_CREATE:
        {
            init_log_control (hwnd);
            create_repaint_timer ();
            break;
        }
        case WM_ENDSESSION:
            ::PostQuitMessage (0);
            break;
        case WM_CLOSE:
            hide_log_window (hwnd);
            return 0;
        case WM_DESTROY:
            kill_repaint_timer ();
            m_view_control->destroy ();
            break;
            
        case WM_TIMER:     
            if (static_cast <UINT_PTR> (wParam) == m_repaint_timer_id)
                return repaint_log_window (hwnd);
            break;
        case WM_SIZE:
            m_view_control->resize (0, 0, LOWORD (lParam), HIWORD (lParam));
            refresh_region ();
            return 0;
        case WM_NOTIFY:
        {
            NMHDR* nm_hdr = reinterpret_cast <NMHDR*> (lParam);
            if (ID_LIST_CONTROL == nm_hdr->idFrom)// && nm_hdr->hwndFrom == m_hwnd_list_control)
                on_rich_edit_notify (hwnd, nm_hdr);
            return 0;     
        }
        
////////////////////////////////// workaround for disable tooltips on caption buttons
        case WM_NCHITTEST:
        {
            bool bt_down = false;
            
            bt_down = bt_down || (0 != (::GetAsyncKeyState (VK_LBUTTON) & 0x8000));
            bt_down = bt_down || (0 != (::GetAsyncKeyState (VK_RBUTTON) & 0x8000));
            bt_down = bt_down || (0 != (::GetAsyncKeyState (VK_MBUTTON) & 0x8000));
            
            LRESULT res = ::DefWindowProc (hwnd, message, wParam, lParam);
            if (false == bt_down && HTCLOSE == res)
                res = 0;
            
            return res;
        }
//////////////////////////////////        
        
        case WM_NCLBUTTONDOWN:
        case WM_NCRBUTTONDOWN:
        case WM_NCMBUTTONDOWN:
        {
            switch (wParam)
            {
                case HTCLOSE:
                    hide_log_window (hwnd);
                    return 0;
            }
            break;
        }
        
        case WM_NCACTIVATE:
        {
            if (NULL != m_skin_bitmap)
                return 0;
            break;
        }
        case WM_NCPAINT:
        {
            if (true == draw_skin (hwnd))
                return 0;
            break;
        }
        
        case WM_NCCALCSIZE:
        {
            BOOL is_client_processing = static_cast <BOOL> (wParam);
            if (TRUE == is_client_processing)
            {
                NCCALCSIZE_PARAMS* calc_size_params = reinterpret_cast <NCCALCSIZE_PARAMS*> (lParam);
                int                top              = calc_size_params->rgrc[0].top;
                int                bottom           = calc_size_params->rgrc[0].bottom;
                LRESULT result = ::DefWindowProc (hwnd, message, wParam, lParam);
                
                if (0 < m_caption_height && m_caption_height > (calc_size_params->rgrc[0].top - top))
                    calc_size_params->rgrc[0].top = top + m_caption_height;
                    
                if (0 < m_bottom_height && m_bottom_height > (bottom - calc_size_params->rgrc[0].bottom))
                    calc_size_params->rgrc[0].bottom = bottom - m_bottom_height;
                
                return result;
            }
            break;
        }

        case WM_PAINT:
        {
            ::DefWindowProc (hwnd, message, wParam, lParam);
            m_view_control->repaint ();
            return 0;
        }

        case WM_SYSCOMMAND:
        	return on_sys_command (hwnd, message, wParam, lParam);

        HANDLE_MSG (hwnd, WM_COMMAND, on_command);
    } // switch (message)
    
    return ::DefWindowProc (hwnd, message, wParam, lParam);
} // wnd_proc

LRESULT log_wnd::on_rich_edit_notify (HWND hwnd, NMHDR* nm_hdr)
{
#pragma message (__WARNING__"redevelop log_wnd::on_rich_edit_notify - move it to view implementation")
    switch (nm_hdr->code)
    {
        case EN_MSGFILTER:
        {
            MSGFILTER* msg_filter = reinterpret_cast <MSGFILTER*> (nm_hdr);
            if (WM_LBUTTONDOWN == msg_filter->msg)
                hide_log_window (hwnd);
            break;
        }
        case EN_REQUESTRESIZE:
        {
            REQRESIZE* req_size = reinterpret_cast <REQRESIZE*> (nm_hdr);
debugString ((L"\nlog_wnd::on_rich_edit_notify (): req_size = %u, prev_req_size = %u", (req_size->rc.bottom - req_size->rc.top), m_list_control_req_height));
            //if ((req_size->rc.bottom - req_size->rc.top) > m_list_control_req_height)
                m_list_control_req_height = req_size->rc.bottom - req_size->rc.top;
            break;
        }
    } // switch (nm_hdr->code)

    return 0;
} // on_rich_edit_notify

LRESULT log_wnd::on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify)
{
    switch (idCommand)
    {
        case IDC_EXIT:
            //kill_repaint_timer ();
            ::PostQuitMessage (0);
            break;
    }
    return 0;
} // on_command

LRESULT log_wnd::on_sys_command (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (wParam)
	{
		case SC_CLOSE:
			hide_log_window (hwnd);
			return 0;
	}
	
	return ::DefWindowProc (hwnd, message, wParam, lParam);
} // on_sys_command

log_wnd::ptr_to_config_node log_wnd::get_config_node ()
{
    ptr_to_config_node root_params = config::Configurator::getLogWindowNode ();

    if (NULL != root_params.get ())
        return root_params->getNode (m_name, true);
        
    return root_params;    
} // get_config_node

void log_wnd::check_reload_setting ()
{
#if (DEBUG || _CB_TEST_DEBUG_)
    reload_setting ();
    if (true == m_need_reload_setting)
    {
        m_need_reload_setting = false;
    }
#else
    if (true == m_need_reload_setting)
    {
        reload_setting ();
        m_need_reload_setting = false;
    }
#endif // DEBUG || _CB_TEST_DEBUG_

} // check_reload_setting

void log_wnd::reload_setting ()
{
    reload_setting (get_config_node ());
} // reload_setting

void log_wnd::reload_setting (ptr_to_config_node& params)
{
    if (NULL != params.get ())
    {
        unsigned int uint_value;
        int          int_value;
        
        if (0 != (uint_value = params->getUInt (L"BackgroundColorDefault")))
            m_bkg_color_default = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"BackgroundColorDefault", m_bkg_color_default);
            
        if (0 != (uint_value = params->getUInt (L"BackgroundColor")))
            m_bkg_color = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"BackgroundColor", m_bkg_color);
        m_refresh_bkg_brush = true;
            
        if (0 < (int_value = params->getInt (L"VisibleTime")))  
            m_visible_time = int_value;
        else
            params->setInt (L"VisibleTime", m_visible_time);  
            
        if (0 < (int_value = params->getInt (L"StableTime")))
            m_stable_time = int_value;
        else
            params->setInt (L"StableTime", m_stable_time);
            
        if (0 < (int_value = params->getInt (L"PaintAlgorithm")))
        {
            refresh_paint_algo (static_cast <PaintAlgo> (int_value));
        }    
        else
        {
            params->setInt (L"PaintAlgorithm", get_paint_algo ());
            refresh_paint_algo (get_paint_algo ());
        }
        
        uint_value = params->getUInt (L"RepaintTimerResolution");
        if (0 != uint_value)
            set_repaint_timer_resolution (uint_value);
        else
            set_repaint_timer_resolution (50);    

        if (10 < (int_value = params->getInt (L"FontSizePercent")) && 1000 >= int_value)
            m_font_size_percent = int_value;
        else
            params->setInt (L"FontSizePercent", m_font_size_percent);
            
        if (0 != (uint_value = params->getUInt (L"FontColor")))
            m_font_color = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"FontColor", m_font_color);
            
/*            
        if (m_window_size_x_min < (int_value = params->getInt (L"WindowSizeX")) && m_window_size_x_max >= int_value)
            m_window_size_x = int_value;
        else
            params->setInt (L"WindowSizeX", m_window_size_x);
*/            
        if (m_window_size_y_min < (int_value = params->getInt (L"WindowSizeY")) && m_window_size_y_max >= int_value)
            m_window_size_y = int_value;
        else
            params->setInt (L"WindowSizeY", m_window_size_y);    
            
        if (NULL != m_view_control.get ())    
        {
            if (0 != (uint_value = params->getUInt (L"MessageQueueSize")))
                m_view_control->set_max_queue_size (uint_value);
            else
                params->setUInt (L"MessageQueueSize", static_cast <unsigned int> (m_view_control->get_max_queue_size ()));
        }
    } // if (NULL != params.get ())
} // reload_setting

void log_wnd::create_repaint_timer ()
{
    m_repaint_timer_id = ::SetTimer (m_hwnd_log_window, m_repaint_timer_id, m_repaint_timer_resolution, NULL);
} // create_repaint_timer

void log_wnd::kill_repaint_timer ()
{
    ::KillTimer (m_hwnd_log_window, m_repaint_timer_id);
} // kill_repaint_timer

void log_wnd::init_log_control (HWND parent_window)
{
    m_view_control->create (parent_window, ID_LIST_CONTROL);
} // init_log_control

bool log_wnd::draw_skin (HWND hwnd)
{
    if (NULL != m_skin_bitmap && NULL != m_compatible_hdc_1)
    {
        RECT wnd_rect    = { 0 };
        RECT client_rect = { 0 };
        
        ::GetWindowRect (hwnd, &wnd_rect);
        ::GetWindowRect (hwnd, &client_rect);
        
        client_rect.right  -= client_rect.left;
        client_rect.bottom -= client_rect.top;
        client_rect.left    = client_rect.top = 0;
        
        HDC         hdc       = ::GetWindowDC (hwnd); // ::GetDCEx (hWnd, (HRGN)wParam, DCX_WINDOW|DCX_INTERSECTRGN);
        scope_guard hdc_guard = make_guard (hdc, gui_helper::hdc_finalizer (hwnd));    
        
        ::FillRect (hdc, &client_rect, get_bkg_brush ());
        
        HGDIOBJ     prev_obj_1       = ::SelectObject (m_compatible_hdc_1, m_skin_bitmap);
        scope_guard prev_obj_1_guard = make_guard (prev_obj_1, gui_helper::selobj_finalizer (m_compatible_hdc_1));
        
        //int caption_height           = (NULL == m_skin_top_bitmap) ? gui_helper::get_wnd_caption_height (hwnd) : ((BITMAPINFO*) &m_skin_top_bitmap_info)->bmiHeader.biHeight;
        int         caption_height   = (0 >= m_caption_height) ? gui_helper::get_wnd_caption_height (hwnd) : m_caption_height;
        int         bottom_height    = (0 >= m_bottom_height) ? caption_height : m_bottom_height;
        
        ::TransparentBlt (
            hdc, 
            0, 
            0, 
            (wnd_rect.right - wnd_rect.left),
            caption_height,
            m_compatible_hdc_1,
            0, 
            0, 
            ((BITMAPINFO*) &m_skin_bitmap_info)->bmiHeader.biWidth,
            caption_height,
            0
        );
        
        ::TransparentBlt (
            hdc, 
            0, 
            caption_height, 
            (wnd_rect.right - wnd_rect.left),
            (wnd_rect.bottom - wnd_rect.top) - (caption_height + bottom_height),
            m_compatible_hdc_1,
            0, 
            caption_height, 
            ((BITMAPINFO*) &m_skin_bitmap_info)->bmiHeader.biWidth,
            ((BITMAPINFO*) &m_skin_bitmap_info)->bmiHeader.biHeight - (caption_height + bottom_height),
            0
        );

        ::TransparentBlt (
            hdc, 
            0, 
            //caption_height + (wnd_rect.bottom - wnd_rect.top) - 2 * caption_height, 
            (wnd_rect.bottom - wnd_rect.top) - bottom_height, 
            (wnd_rect.right - wnd_rect.left),
            bottom_height,
            m_compatible_hdc_1,
            0, 
            //caption_height + ((BITMAPINFO*) &m_skin_bitmap_info)->bmiHeader.biHeight - 2 * caption_height, 
            ((BITMAPINFO*) &m_skin_bitmap_info)->bmiHeader.biHeight - bottom_height,
            ((BITMAPINFO*) &m_skin_bitmap_info)->bmiHeader.biWidth,
            bottom_height,
            0
        );
        
        draw_skin_foreground (hdc, client_rect);
        
        return true;
    }
    return false;
} // draw_skin

void log_wnd::draw_skin_foreground (HDC destination_dc, const RECT& client_rect)
{
    if (NULL == m_compatible_hdc_2)
        return;
        
    for (skin_bitmap_map::iterator i = m_skin_bitmaps.begin () ; i != m_skin_bitmaps.end () ; ++i)
    {
        ptr_to_skin_bitmap info = (*i).second;
        
        if (NULL != info->m_skin_bitmap)
        {
            HGDIOBJ     prev_obj_2       = ::SelectObject (m_compatible_hdc_2, info->m_skin_bitmap);
            scope_guard prev_obj_2_guard = make_guard (prev_obj_2, gui_helper::selobj_finalizer (m_compatible_hdc_2));
            
            switch (info->m_align)
            {
                case skin_align_top_left:
                    info->m_placement.left   = 0;
                    info->m_placement.right  = info->m_placement.left + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth;
                    info->m_placement.top    = 0;
                    info->m_placement.bottom = info->m_placement.top + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    
                    calc_horizontal_shift (info, client_rect);
                    break;
                case skin_align_top_right:
                    info->m_placement.left   = client_rect.right - ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth;
                    info->m_placement.right  = info->m_placement.left + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth;
                    info->m_placement.top    = 0;
                    info->m_placement.bottom = info->m_placement.top + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    
                    calc_horizontal_shift (info, client_rect);
                    break;
                case skin_align_bottom_left:
                    info->m_placement.left   = 0;
                    info->m_placement.right  = info->m_placement.left + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth;
                    info->m_placement.top    = client_rect.bottom - ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    info->m_placement.bottom = info->m_placement.top + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    
                    calc_horizontal_shift (info, client_rect);
                    break;    
                case skin_align_bottom_center:    
                    info->m_placement.left   = client_rect.right / 2 - ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth / 2;
                    info->m_placement.right  = info->m_placement.left + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth;
                    info->m_placement.top    = client_rect.bottom - ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    info->m_placement.bottom = info->m_placement.top + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    
                    calc_horizontal_shift (info, client_rect);
                    break;
                case skin_align_bottom_right:
                    info->m_placement.left   = client_rect.right - ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth;
                    info->m_placement.right  = info->m_placement.left + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth;
                    info->m_placement.top    = client_rect.bottom - ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    info->m_placement.bottom = info->m_placement.top + ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight;
                    
                    calc_horizontal_shift (info, client_rect);
                    break;    
                default:
                    info->m_placement.left   = 0;
                    info->m_placement.right  = 0;
                    info->m_placement.top    = 0;
                    info->m_placement.bottom = 0;
                    break;    
            } // switch (info->m_align)
            
            if (0 < (info->m_placement.right - info->m_placement.left) && 0 < (info->m_placement.bottom - info->m_placement.top))
            {
                ::TransparentBlt (
                    destination_dc, // handle to destination DC
                    info->m_placement.left,   // x-coord of destination upper-left corner
                    info->m_placement.top,    // y-coord of destination upper-left corner
                    ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth,     // width of destination rectangle
                    ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight,    // height of destination rectangle
                    m_compatible_hdc_2,         // handle to source DC
                    0,          // x-coord of source upper-left corner
                    0,          // y-coord of source upper-left corner
                    ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biWidth,      // width of source rectangle
                    ((BITMAPINFO*) &info->m_skin_bitmap_info)->bmiHeader.biHeight,     // height of source rectangle
                    0           // color to make transparent
                );
            }
        } // if (NULL != info->m_skin_bitmap)
    } // for (...)

} // draw_skin_foreground

void log_wnd::calc_horizontal_shift (ptr_to_skin_bitmap& info, const RECT& client_rect)
{
    if (0 == info->m_shift)
        return;
    
    int shift = 0;
    
    switch (info->m_shift_type)
    {
        case skin_shift_percents:
            shift = info->m_shift * (client_rect.right - client_rect.left) / 100;
            info->m_placement.left  += shift;
            info->m_placement.right += shift;
            break;
        case skin_shift_pixels:
            shift = info->m_shift;
            info->m_placement.left  += shift;
            info->m_placement.right += shift;
            break; 
    }
} // calc_horizontal_shift

void log_wnd::calc_vertical_shift (ptr_to_skin_bitmap& info, const RECT& client_rect)
{
#pragma message (__WARNING__"log_wnd::calc_vertical_shift () - TODO")
} // calc_vertical_shift

void log_wnd::recalc_skin_params ()
{
    m_caption_height = -1;
    m_bottom_height  = -1;
    
    for (skin_bitmap_map::iterator i = m_skin_bitmaps.begin () ; i != m_skin_bitmaps.end () ; ++i)
    {
        ptr_to_skin_bitmap skin_bitmap = (*i).second;
        if (
               skin_align_top_left   == skin_bitmap->m_align
            || skin_align_top_right  == skin_bitmap->m_align
            || skin_align_top_center == skin_bitmap->m_align
           )
        {
            if (m_caption_height < (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight))
                m_caption_height = (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight);
        }
        else
        {
            if (
                   skin_align_bottom_center == skin_bitmap->m_align
                || skin_align_bottom_right  == skin_bitmap->m_align
                || skin_align_bottom_center == skin_bitmap->m_align
               )
            {
                if (m_bottom_height < (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight))
                    m_bottom_height = (int) (((BITMAPINFO*) &skin_bitmap->m_skin_bitmap_info)->bmiHeader.biHeight);
            }
        }
    }
} // recalc_skin_params

LRESULT log_wnd::repaint_log_window (HWND hwnd)
{
    if (FALSE == ::IsWindowVisible (hwnd))
        return 0;
        
    m_current_stable_time += m_repaint_timer_resolution;
    
    if (m_current_stable_time < m_stable_time)
        return 0;
        
    bool doUpdate  = (0 != m_current_direction);
    int  threshold = 0;
    
    switch (m_current_paint_algo)
    {
        case IDC_PAINT_ALGO_FALLTO_010:
             threshold = (int) ((float) 255 / (float) 100 * (float) 10);
             break;
        case IDC_PAINT_ALGO_FALLTO_020:
             threshold = (int) ((float) 255 / (float) 100 * (float) 20);
             break;
        case IDC_PAINT_ALGO_FALLTO_040:
             threshold = (int) ((float) 255 / (float) 100 * (float) 40);
             break;
        case IDC_PAINT_ALGO_FALLTO_060:
             threshold = (int) ((float) 255 / (float) 100 * (float) 60);
             break;
        case IDC_PAINT_ALGO_FALLTO_080:
             threshold = (int) ((float) 255 / (float) 100 * (float) 80);
             break;
    }
    
    m_current_alpha += 4 * m_current_direction;
    if (threshold >= m_current_alpha)
    {
        m_current_alpha     = threshold;
        m_current_direction = 0;
        m_current_visible_time += m_repaint_timer_resolution;
    }
    
    if (m_current_visible_time > m_visible_time)
    {
        hide_log_window (hwnd);
        refresh_paint (m_current_paint_algo);
        return 0;
    }    

    if (true == doUpdate)
        ::SetLayeredWindowAttributes (hwnd, RGB (0x80, 0x80, 0x80), m_current_alpha, LWA_ALPHA);

    return 0;
} // repaintWindow

void log_wnd::hide_log_window (HWND hwnd)
{
    clean ();
    ::ShowWindow (hwnd, SW_HIDE);
} // hide_log_window

void log_wnd::refresh_logwnd ()
{
    refresh_paint (m_current_paint_algo);
    
    RECT wnd_placement;
    get_log_window_placement (wnd_placement);
            
    UINT flags = SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_FRAMECHANGED;
    ::SetWindowPos (
        m_hwnd_log_window, 
        HWND_TOPMOST, 
        wnd_placement.left, 
        wnd_placement.top, 
        wnd_placement.right - wnd_placement.left, 
        wnd_placement.bottom - wnd_placement.top, 
        flags
    );

    refresh_window_background (get_bkg_color ());
    ::SendMessageW (m_hwnd_log_window, WM_NCPAINT, 1, 0);
    ::InvalidateRect (m_hwnd_log_window, NULL, TRUE);
} // refresh_logwnd 

void log_wnd::refresh_paint (int paint_algo)
{
    m_current_paint_algo   = paint_algo;
    m_current_visible_time = 0;
    m_current_stable_time  = 0;
    m_current_direction    = -1;
    m_current_alpha        = 255;
    
    ::SetLayeredWindowAttributes (m_hwnd_log_window, RGB (0x80, 0x80, 0x80), m_current_alpha, LWA_ALPHA);
    ::InvalidateRect (m_hwnd_log_window, NULL, TRUE);
} // refresh_paint

bool log_wnd::refresh_paint_algo (PaintAlgo algo)
{
    switch (algo)
    {
      case PaintAlgoFallTo10:
           refresh_paint (IDC_PAINT_ALGO_FALLTO_010);
           return true;
      case PaintAlgoFallTo20:
           refresh_paint (IDC_PAINT_ALGO_FALLTO_020);
           return true;
      case PaintAlgoFallTo40:
           refresh_paint (IDC_PAINT_ALGO_FALLTO_040);
           return true;
      case PaintAlgoFallTo60:
           refresh_paint (IDC_PAINT_ALGO_FALLTO_060);
           return true;
      case PaintAlgoFallTo80:
           refresh_paint (IDC_PAINT_ALGO_FALLTO_080);
           return true;
    }
    
    return false;
} // refresh_paint_algo

void log_wnd::get_log_window_placement (RECT& result)
{
    memset (&result, 0, sizeof (RECT));
    
    if (TRUE == SystemParametersInfo (SPI_GETWORKAREA, 0, &result, 0))
    {
        RECT client_rect = { 0 };
        GetClientRect (m_hwnd_log_window, &client_rect);
        
        //int y_min = (int) ((result.bottom - result.top) / 16);
        //int y_max = (int) ((result.bottom - result.top) / 8);
        
        //int x     = (int) ((result.right - result.left) / 2.5);
        //int y     = (m_logwnd_prev_height > y_min) ?  m_logwnd_prev_height : y_min; // y_min;
        
        int x_min = m_window_size_x_min;
        int x_max = m_window_size_x_max;
        int y_min = (int) ((result.bottom - result.top) / 16);
        //int y_max = (int) ((result.bottom - result.top) * m_window_size_y / 100 ); //(int) ((result.bottom - result.top) / 8);
        
        int x     = (int) ( (result.right - result.left) * m_window_size_x / 100 );
        int y     = (m_logwnd_prev_height > 0/*y_min*/) ?  m_logwnd_prev_height : y_min;
        
        //if ((client_rect.bottom - client_rect.top) < m_list_control_req_height)
            y += (m_list_control_req_height - (client_rect.bottom - client_rect.top));
            
        if (x_min > x)
            x = x_min;
        if (x_max < x)
            x = x_max;

        //if (y > y_max)
        //    y = y_max;
        
        if ((result.right - result.left) < x)
            x = (result.right - result.left);
        if ((result.bottom - result.top) < y)
            y = (result.bottom - result.top);
            
        
        result.left = result.right - x;
        result.top  = result.bottom - y;
        
debugString ((
    L"\ngswui::logwnd::get_log_window_placement (): \n\tm_list_control_req_height = %u, m_logwnd_prev_height = %u, y = %u, client_y = %u", 
    m_list_control_req_height, 
    m_logwnd_prev_height, 
    y,
    (client_rect.bottom - client_rect.top)
));
        m_logwnd_prev_height = y;
    }
} // get_log_window_placement

void log_wnd::refresh_window_background (COLORREF color)
{
    m_view_control->set_background_color (color);
    //get_bkg_brush ();
} // refresh_window_background

HBRUSH log_wnd::get_bkg_brush ()
{
    if (true == m_refresh_bkg_brush)
    {
        if (NULL != m_bkg_brush)
            ::DeleteObject (m_bkg_brush);
            
        m_bkg_brush         = ::CreateSolidBrush (m_bkg_color);
        m_refresh_bkg_brush = false;
    }
    
    return m_bkg_brush;
} // get_bkg_brush

} // namespace logwnd {
} // namespace gswui {

