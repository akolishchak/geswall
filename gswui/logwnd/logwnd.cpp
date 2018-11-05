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

#include "logwnd.h"

#include <commctrl.h>
#include <windowsx.h>

#include "commonlib/commondefs.h"
#include "commonlib/thread.h"
#include "commonlib/debug.h"

#include "config/configurator.h"

#include "gswui/gui_helper.h"

#include <list>

namespace gswui {
namespace logwnd {

typedef commonlib::thread                work_thread;
typedef boost::shared_ptr <work_thread>  ptr_to_work_thread;
typedef boost::shared_ptr <wstring>      ptr_to_wstring;
typedef std::list <ptr_to_wstring>       string_list;

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

#define  IDC_PAINT_ALGO_FALLTO_010    1100
#define  IDC_PAINT_ALGO_FALLTO_020    1101
#define  IDC_PAINT_ALGO_FALLTO_040    1102
#define  IDC_PAINT_ALGO_FALLTO_060    1103
#define  IDC_PAINT_ALGO_FALLTO_080    1104

#define  ID_LIST_CONTROL              2000

#define  IDC_EXIT                     9999

int      gui_thread_proc ();
LRESULT  CALLBACK log_wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

LRESULT  on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify);
LRESULT  on_rich_edit_notify (HWND hwnd, NMHDR* nm_hdr);

void     create_repaint_timer ();
void     kill_repaint_timer ();
//LRESULT  paint_log_window (HWND hwnd);
LRESULT  repaint_log_window (HWND hwnd);
void     hide_log_window (HWND hwnd);
HFONT    create_font (int orientation, BYTE charSet, BYTE italic, wchar_t* faceName, int height, int width);
//void     refresh_bkg_brush ();
void     get_log_window_placement (RECT& result);
void     refresh_paint (int paint_algo);
bool     refresh_paint_algo (PaintAlgo algo);
void     reload_setting ();
void     init_log_control (HWND parent_window);
void     refresh_logwnd ();
void     refresh_window_background (COLORREF color);
void     add_message (const wstring& app_name, const wstring& message, int font_size_percent, COLORREF font_color);

bool               m_need_reload_setting = true;

UINT_PTR           m_repaint_timer_id         = 1;
UINT               m_repaint_timer_resolution = 50; // msec
                                       
HINSTANCE          m_global_instance    = NULL;
HWND               m_hwnd_log_window    = NULL;
HWND               m_hwnd_list_control  = NULL;
COLORREF           m_bkg_color_default             = RGB (192, 192, 192);
COLORREF           m_bkg_color_notification        = RGB (192, 192, 192);
COLORREF           m_bkg_color_attack_notification = RGB (255, 128, 0);

//HFONT              m_log_font           = NULL;
//HBRUSH             m_bkg_brush          = NULL;

int                m_current_paint_algo      = IDC_PAINT_ALGO_FALLTO_010;
int                m_current_direction       = -1;
int                m_current_alpha           = 255;
int                m_stable_time             = 1;
int                m_visible_time            = 500;
int                m_current_stable_time     = 1;
int                m_current_visible_time    = 1;
int                m_list_control_req_height = 0;
int                m_logwnd_prev_height      = 0;

int                m_attack_stable_time      = 5000;
int                m_notify_stable_time      = 1;
int                m_attack_visible_time     = 500;
int                m_notify_visible_time     = 500;

int                m_attack_font_size_percent = 120;
int                m_notify_font_size_percent = 100;

COLORREF           m_attack_font_color       = RGB (255, 255, 255);
COLORREF           m_notify_font_color       = RGB (0, 0, 0);

int                m_window_size_x           = 25;
int                m_window_size_y           = 20;

int                m_window_size_x_min       = 300;
int                m_window_size_y_min       = 150;
int                m_window_size_x_max       = 600;
int                m_window_size_y_max       = 512;

size_t             m_log_queue_max_size      = 5;
string_list        m_log_queue;

MessageType        m_last_message_type  = MessageTypeText;


bool                        m_init_complete = false;
commonlib::sync::SyncObject m_init_complete_sync;
ptr_to_work_thread          m_gui_thread;

//commonlib::sync::SyncObject m_update_sync;

void create (HINSTANCE instance)
{
    destroy ();
    
    m_global_instance = instance;
    m_gui_thread      = ptr_to_work_thread (new work_thread (&gui_thread_proc));
} // create

void destroy ()
{
    if (NULL != m_hwnd_log_window)
    {
        ::PostMessage (m_hwnd_log_window, WM_COMMAND, IDC_EXIT, 0);
        //DestroyWindow (m_hwndToolWindow);
    }  
      
    if (NULL != m_gui_thread.get ())  
        m_gui_thread->join ();

    m_log_queue.clear ();
    
    m_init_complete       = false;
    m_need_reload_setting = true;
} // destroy

void add_message (MessageType message_type, const wstring& app_name, const wstring& message, const wstring& wnd_name)
{
debugString ((L"\nadd_message (): [0]"));
    if (false == m_init_complete)
    {
        commonlib::sync::SyncObject::Locker locker (m_init_complete_sync);
        if (false == m_init_complete)
            m_init_complete_sync.wait (-1);
    }
    
#if (DEBUG || _CB_TEST_DEBUG_)
    reload_setting ();
#else
    if (true == m_need_reload_setting)
    {
        reload_setting ();
        m_need_reload_setting = false;
    }
#endif // DEBUG || _CB_TEST_DEBUG_
    
    int      font_size_percent = 100;
    COLORREF font_color        = RGB (0, 0, 0);
    
    if (MessageTypeAttackNotification == message_type)
    {
        font_size_percent = m_attack_font_size_percent;
        font_color        = m_attack_font_color;
        m_stable_time     = m_attack_stable_time;
        m_visible_time    = m_attack_visible_time;
    }
    else if (MessageTypeNotification == message_type)
    {
        font_size_percent = m_notify_font_size_percent;
        font_color        = m_notify_font_color;
        m_stable_time     = m_notify_stable_time;
        m_visible_time    = m_notify_visible_time;
    }
    else
    {
        font_size_percent = m_notify_font_size_percent;
        font_color        = m_notify_font_color;
        m_stable_time     = m_notify_stable_time;
        m_visible_time    = m_notify_visible_time;
    }
    
    if (m_last_message_type > message_type)
    {
debugString ((L"\nadd_message (): [X0]"));
        return;
    }
    else if (m_last_message_type < message_type)
    {
        clean ();
    }
    
    m_last_message_type = message_type;
    
    refresh_window_background (get_bkg_color (message_type));
    ::SendMessageW (m_hwnd_log_window, WM_SETTEXT, 0, (LPARAM) wnd_name.c_str ());
    add_message (app_name, message, font_size_percent, m_notify_font_color);    
        
    refresh_logwnd ();
    
    ::SendMessageW (m_hwnd_list_control, WM_KILLFOCUS, NULL, 0);
    
debugString ((L"\nadd_message (): [X]"));    
} // add_message

void clean ()
{
    m_last_message_type       = MessageTypeText;
    m_logwnd_prev_height      = 0;
    m_list_control_req_height = 0;
    m_log_queue.clear ();
    
    ::SendMessageW (m_hwnd_list_control, WM_SETTEXT, 0, (LPARAM) L"");
    
    refresh_logwnd ();
} // clean

void refresh_logwnd ()
{
    refresh_paint (m_current_paint_algo);
    
    RECT wnd_placement;
    get_log_window_placement (wnd_placement);
            
    UINT flags = SWP_NOACTIVATE | SWP_SHOWWINDOW;
    ::SetWindowPos (
        m_hwnd_log_window, 
        HWND_TOPMOST, 
        wnd_placement.left, 
        wnd_placement.top, 
        wnd_placement.right - wnd_placement.left, 
        wnd_placement.bottom - wnd_placement.top, 
        flags
    );
} // refresh_logwnd 

PaintAlgo get_paint_algo ()
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

void set_paint_algo (PaintAlgo algo)
{
    if (true == refresh_paint_algo (algo))
        (config::Configurator::getLogWindowNode ())->setInt (L"PaintAlgorithm", algo);
} // set_paint_algo

int get_stable_time (MessageType message_type)
{
    if (MessageTypeAttackNotification == message_type)
        return m_attack_stable_time;
    if (MessageTypeNotification == message_type)    
        return m_notify_stable_time;
        
    return m_stable_time;
} // get_stable_time

void set_stable_time (MessageType message_type, int stable_time)
{
    if (MessageTypeAttackNotification == message_type)
    {
        (config::Configurator::getLogWindowNode ())->setInt (L"AttackStableTime", stable_time);
        m_attack_stable_time = stable_time;
    }
    else if (MessageTypeNotification == message_type)    
    {
        (config::Configurator::getLogWindowNode ())->setInt (L"NotifyStableTime", stable_time);
        m_notify_stable_time = stable_time;
    }    
    //m_stable_time = stable_time;
    //refresh_paint (m_current_paint_algo);
} // set_stable_time

int get_visible_time (MessageType message_type)
{
    if (MessageTypeAttackNotification == message_type)
        return m_attack_visible_time;
    if (MessageTypeNotification == message_type)    
        return m_notify_visible_time;
        
    return m_visible_time;
} // get_visible_time

void set_visible_time (MessageType message_type, int visible_time)
{
    if (MessageTypeAttackNotification == message_type)
    {
        (config::Configurator::getLogWindowNode ())->setInt (L"AttackVisibleTime", visible_time);
        m_attack_visible_time = visible_time;
    }
    else if (MessageTypeNotification == message_type)    
    {
        (config::Configurator::getLogWindowNode ())->setInt (L"NotifyVisibleTime", visible_time);
        m_notify_visible_time = visible_time;
    }    
    
    //m_visible_time = visible_time;
    //refresh_paint (m_current_paint_algo);
} // set_visible_time

COLORREF get_bkg_color (MessageType message_type)
{
    if (MessageTypeNotification == message_type)
    {
        return m_bkg_color_notification;
    }
    else if (MessageTypeAttackNotification == message_type)
    {
        return m_bkg_color_attack_notification;
    }
    
    return m_bkg_color_default;
} // get_bkg_color

void set_bkg_color (MessageType message_type, COLORREF bkg_color)
{
    if (MessageTypeNotification == message_type)
    {
        m_bkg_color_notification = bkg_color;
        (config::Configurator::getLogWindowNode ())->setUInt (L"BackgroundColorNotification", bkg_color);
    }
    else if (MessageTypeAttackNotification == message_type)
    {
        m_bkg_color_attack_notification = bkg_color;
        (config::Configurator::getLogWindowNode ())->setUInt (L"BackgroundColorAttackNotification", bkg_color);
    }
    else
    {
        m_bkg_color_default = bkg_color;
        (config::Configurator::getLogWindowNode ())->setUInt (L"BackgroundColorDefault", bkg_color);
    }
        
//    refresh_paint (m_current_paint_algo);
} // set_bkg_color

void select_bkg_color (MessageType message_type, HWND hwnd)
{
    set_bkg_color (message_type, gui_helper::select_color (hwnd, get_bkg_color (message_type)));
} // select_bkg_color

void set_repaint_timer_resolution (unsigned int resolution)
{
    if (50 >  resolution)
        resolution = 50;
    if (5000 < resolution)
        resolution = 5000;
    
    m_repaint_timer_resolution = resolution;
    (config::Configurator::getLogWindowNode ())->setUInt (L"RepaintTimerResolution", resolution);
    
    kill_repaint_timer ();
    create_repaint_timer ();
} // set_repaint_timer_resolution

int gui_thread_proc ()
{
    HMODULE module_riched32 = ::LoadLibraryW (L"riched32.dll");
    if (NULL == module_riched32)
        return -1;
        
    scope_guard module_riched32_finalizer = make_guard (module_riched32, &::FreeLibrary);    
    
    InitCommonControls ();

    wchar_t*    className  = L"GsWUILogWindow";
  
    WNDCLASS    wndclass;
    
    ZeroMemory (&wndclass, sizeof(wndclass));
    wndclass.style         = CS_SAVEBITS | CS_DBLCLKS;
    wndclass.lpfnWndProc   = log_wnd_proc;
    wndclass.cbClsExtra    = 0;
    wndclass.cbWndExtra    = 0;
    wndclass.hInstance     = m_global_instance;
    wndclass.hIcon         = NULL;
    wndclass.hCursor       = LoadCursor (NULL, IDC_ARROW);
    wndclass.hbrBackground = (HBRUSH) COLOR_BACKGROUND;
    wndclass.lpszMenuName  = NULL;
    wndclass.lpszClassName = className;
    
    if (0 != ::RegisterClassW (&wndclass))
    {
        m_hwnd_log_window = 
            ::CreateWindowExW (
                /*WS_EX_TRANSPARENT | */WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_NOACTIVATE,// | WS_VISIBLE, 
                className, 
                L"GeSWall logs window", 
                WS_SYSMENU | WS_BORDER | WS_POPUP | WS_CAPTION | WS_CLIPCHILDREN, // | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME
                0, 0, 250, 50, 
                NULL, 
                NULL, 
                m_global_instance, 
                NULL
            );
        if (NULL != m_hwnd_log_window)
        {
            ::SetLayeredWindowAttributes (m_hwnd_log_window, RGB (0x80, 0x80, 0x80), m_current_alpha, LWA_ALPHA);
            
            //
            // do not remove braces { ...sync... } !!!!!!!!!
            //
            {
                commonlib::sync::SyncObject::Locker locker (m_init_complete_sync);
                m_init_complete = true;
                m_init_complete_sync.notifyAll ();
            }
            
            ::MSG  msg;
            while (TRUE == ::GetMessage (&msg, 0, 0, 0))
            {
                ::TranslateMessage (&msg);
                ::DispatchMessage (&msg);
            } // while (TRUE == GetMessage (&msg, 0, 0, 0))
            
            ::DestroyWindow (m_hwnd_log_window);
            
            m_hwnd_list_control = NULL;
            m_hwnd_log_window   = NULL;
        } // if (NULL != m_hwnd_log_window)
    } // if (0 != ::RegisterClassW (&wndclass))

    return 0;
} // gui_thread_proc

LRESULT CALLBACK log_wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_CREATE:
//             refresh_bkg_brush ();
//             m_log_font         = create_font (0, DEFAULT_CHARSET, 0, L"Tahoma", 16, 0);
             create_repaint_timer ();
             init_log_control (hwnd);
             ::InvalidateRect (hwnd, NULL, TRUE);
             break;
        case WM_ENDSESSION:
        case WM_CLOSE:
             hide_log_window (hwnd);
             //kill_repaint_timer ();
             //::PostQuitMessage (message);
             return 0;
        case WM_DESTROY:
             kill_repaint_timer ();
             
             ::DestroyWindow (m_hwnd_list_control);
        
//             if (NULL != m_log_font)
//                 ::DeleteObject (m_log_font);
        
//             if (NULL != m_bkg_brush)
//                 ::DeleteObject (m_bkg_brush);
             break;
        case WM_TIMER:     
             if (static_cast <UINT_PTR> (wParam) == m_repaint_timer_id)
                 return repaint_log_window (hwnd);
             break;
        case WM_SIZE:
             ::MoveWindow (m_hwnd_list_control, 0, 0, LOWORD (lParam), HIWORD (lParam), TRUE);
             return 0;
//        case WM_PARENTNOTIFY:     
//             if (WM_LBUTTONDOWN == wParam)
//                 hide_log_window (hwnd);
//             return 0;
        case WM_NOTIFY:
        {
             NMHDR* nm_hdr = reinterpret_cast <NMHDR*> (lParam);
             if (ID_LIST_CONTROL == nm_hdr->idFrom && nm_hdr->hwndFrom == m_hwnd_list_control)
                 on_rich_edit_notify (hwnd, nm_hdr);
             return 0;     
        }
        //case WM_PAINT:
        //     return paint_log_window (hwnd);
        HANDLE_MSG (hwnd, WM_COMMAND, on_command);     
    }          
    
    return ::DefWindowProc (hwnd, message, wParam, lParam);
} // log_wnd_proc

LRESULT on_rich_edit_notify (HWND hwnd, NMHDR* nm_hdr)
{
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
            if ((req_size->rc.bottom - req_size->rc.top) > m_list_control_req_height)
                m_list_control_req_height = req_size->rc.bottom - req_size->rc.top;
            break;
        }
    } // switch (nm_hdr->code)

    return 0;
} // on_rich_edit_notify

LRESULT on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify)
{
    switch (idCommand)
    {
        case IDC_EXIT:
            kill_repaint_timer ();
            ::PostQuitMessage (0);
            break;
    }
    return 0;
} // on_command

void create_repaint_timer ()
{
    m_repaint_timer_id = ::SetTimer (m_hwnd_log_window, m_repaint_timer_id, m_repaint_timer_resolution, NULL);
} // create_repaint_timer

void kill_repaint_timer ()
{
    ::KillTimer (m_hwnd_log_window, m_repaint_timer_id);
} // kill_repaint_timer

//LRESULT paint_log_window (HWND hwnd)
//{
//    PAINTSTRUCT ps; 
//    HDC         hdc = ::BeginPaint (hwnd, &ps); 
//    
//    RECT        wndRect;
//
//    ::GetClientRect (hwnd, &wndRect);
//    ::FillRect (hdc, &wndRect, m_bkg_brush);
//    
//    HGDIOBJ     oldFont    = ::SelectObject (hdc, m_log_font);
//    int         prevBkMode = ::SetBkMode (hdc, TRANSPARENT);
//    
//    const wchar_t* captionToolWindow = m_log_text.c_str ();
//    
//    SIZE        textSize;
//    int         textLen = lstrlenW (captionToolWindow);
//  
//    ::GetTextExtentPoint32W (hdc, captionToolWindow, textLen, &textSize);
//    //::TextOutW (hdc, wndRect.right / 2 - textSize.cx / 2, wndRect.bottom / 2 - textSize.cy / 2, captionToolWindow, textLen);
//    ::DrawTextW (hdc, captionToolWindow, textLen, &wndRect, DT_LEFT | DT_WORDBREAK | DT_CALCRECT);
//    ::DrawTextW (hdc, captionToolWindow, textLen, &wndRect, DT_LEFT | DT_WORDBREAK);
//
//    
//    ::SetBkMode (hdc, prevBkMode);
//    ::SelectObject (hdc, oldFont);
//    
//    ::EndPaint (hwnd, &ps); 
//    
//    return 0;
//} // paint_log_window

LRESULT repaint_log_window (HWND hwnd)
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

void hide_log_window (HWND hwnd)
{
    clean ();
    ::ShowWindow (hwnd, SW_HIDE);
} // hide_log_window


HFONT create_font (int orientation, BYTE charSet, BYTE italic, wchar_t* faceName, int height, int width)
{
    ::LOGFONTW lf = { 0 };
    
    lstrcpy (lf.lfFaceName, faceName);
    
    lf.lfOrientation = lf.lfEscapement = orientation;
    lf.lfCharSet     = charSet;
    lf.lfItalic      = italic;
    lf.lfHeight      = height;
    lf.lfWidth       = width;
    
    return ::CreateFontIndirect (&lf);
} // create_font

//void refresh_bkg_brush ()
//{
//    if (NULL != m_bkg_brush)
//        ::DeleteObject (m_bkg_brush);
//
//    m_bkg_brush = ::CreateSolidBrush (m_bkg_color);
//} // refresh_bkg_brush

void get_log_window_placement (RECT& result)
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
        int y_max = (int) ((result.bottom - result.top) * m_window_size_y / 100 ); //(int) ((result.bottom - result.top) / 8);
        
        int x     = (int) ( (result.right - result.left) * m_window_size_x / 100 );
        int y     = (m_logwnd_prev_height > y_min) ?  m_logwnd_prev_height : y_min;
        
        if ((client_rect.bottom - client_rect.top) < m_list_control_req_height)
            y += (m_list_control_req_height - (client_rect.bottom - client_rect.top));
            
        if (x_min > x)
            x = x_min;
        if (x_max < x)
            x = x_max;

        if (y > y_max)
            y = y_max;
        
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

void refresh_paint (int paint_algo)
{
    m_current_paint_algo   = paint_algo;
    m_current_visible_time = 0;
    m_current_stable_time  = 0;
    m_current_direction    = -1;
    m_current_alpha        = 255;
    
    ::SetLayeredWindowAttributes (m_hwnd_log_window, RGB (0x80, 0x80, 0x80), m_current_alpha, LWA_ALPHA);
    ::InvalidateRect (m_hwnd_log_window, NULL, TRUE);
} // refresh_paint

bool refresh_paint_algo (PaintAlgo algo)
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

void reload_setting ()
{
    config::Configurator::PtrToINode params = config::Configurator::getLogWindowNode ();
    if (NULL != params.get ())
    {
        unsigned int uint_value;
        int          int_value;
        
        if (0 != (uint_value = params->getUInt (L"BackgroundColorDefault")))
            m_bkg_color_default = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"BackgroundColorDefault", m_bkg_color_default);
            
        if (0 != (uint_value = params->getUInt (L"BackgroundColorNotification")))
            m_bkg_color_notification = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"BackgroundColorNotification", m_bkg_color_notification);
            
        if (0 != (uint_value = params->getUInt (L"BackgroundColorAttackNotification")))
            m_bkg_color_attack_notification = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"BackgroundColorAttackNotification", m_bkg_color_attack_notification);
            
        if (0 < (int_value = params->getInt (L"AttackVisibleTime")))  
            m_attack_visible_time = int_value;
        else
            params->setInt (L"AttackVisibleTime", m_attack_visible_time);  
            
        if (0 < (int_value = params->getInt (L"NotifyVisibleTime")))  
            m_notify_visible_time = int_value;
        else
            params->setInt (L"NotifyVisibleTime", m_notify_visible_time);  
            
        if (0 < (int_value = params->getInt (L"AttackStableTime")))
            m_attack_stable_time = int_value;
        else
            params->setInt (L"AttackStableTime", m_attack_stable_time);
            
        if (0 < (int_value = params->getInt (L"NotifyStableTime")))
            m_notify_stable_time = int_value;
        else
            params->setInt (L"NotifyStableTime", m_notify_stable_time);
            
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

        if (10 < (int_value = params->getInt (L"AttackFontSizePercent")) && 1000 >= int_value)
            m_attack_font_size_percent = int_value;
        else
            params->setInt (L"AttackFontSizePercent", m_attack_font_size_percent);
            
        if (10 < (int_value = params->getInt (L"NotifyFontSizePercent")) && 1000 >= int_value)
            m_notify_font_size_percent = int_value;
        else
            params->setInt (L"NotifyFontSizePercent", m_notify_font_size_percent);    
            
        if (0 != (uint_value = params->getUInt (L"AttackFontColor")))
            m_attack_font_color = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"AttackFontColor", m_attack_font_color);
            
        if (0 != (uint_value = params->getUInt (L"NotifyFontColor")))
            m_notify_font_color = RGB (GetRValue (uint_value), GetGValue (uint_value), GetBValue (uint_value));
        else
            params->setUInt (L"NotifyFontColor", m_notify_font_color);    
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
    } // if (NULL != params.get ())
} // reload_setting

void init_log_control (HWND parent_window)
{
    m_hwnd_list_control = 
        ::CreateWindowW (
            //WS_EX_CLIENTEDGE, //WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR | LVS_EX_HEADERDRAGDROP,
            RICHEDIT_CLASSW, //WC_EDITW,
            L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 250, 50,
            parent_window,
            reinterpret_cast <HMENU> (ID_LIST_CONTROL),
            m_global_instance, 
            NULL
        );
        
    ::SendMessageW (m_hwnd_list_control, EM_SETSEL, 0, 0); 
    
    CHARFORMATW char_format_orig = { 0 };
    CHARFORMATW char_format = { 0 };
    
    char_format_orig.cbSize = sizeof (char_format);
    
    ::SendMessageW (m_hwnd_list_control, EM_GETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format_orig); 
    
    char_format = char_format_orig;
    
    char_format.dwMask    = CFM_FACE | CFM_BOLD | CFM_ITALIC;
    char_format.dwEffects = 0;
    
    wcsncpy (char_format.szFaceName, L"Verdana", LF_FACESIZE);
    
    ::SendMessageW (m_hwnd_list_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format); 
    
    LRESULT event_mask = ::SendMessageW (m_hwnd_list_control, EM_GETEVENTMASK, 0, 0);
    ::SendMessageW (m_hwnd_list_control, EM_SETEVENTMASK, 0, event_mask | ENM_MOUSEEVENTS | ENM_REQUESTRESIZE);
} // init_log_control

void refresh_window_background (COLORREF color)
{
    ::SendMessageW (m_hwnd_list_control, EM_SETBKGNDCOLOR, 0, color);
    // refresh_bkg_brush ();
} // refresh_window_background

//void add_message (const wstring& app_name, const wstring& message, bool increase_font) // int increase_font_percent, COLORREF font_color
void add_message (const wstring& app_name, const wstring& message, int font_size_percent, COLORREF font_color) // int increase_font_percent, COLORREF font_color
{
    if (m_log_queue.size () >= m_log_queue_max_size)
        m_log_queue.pop_back ();
        
    wstring log_text;
    log_text.append (app_name).append (L" ").append (message);
    
    m_log_queue.push_front (ptr_to_wstring (new wstring (log_text)));
    
    size_t log_text_length = 0;
    for (string_list::iterator i = m_log_queue.begin (); i != m_log_queue.end (); ++i)
    {
        log_text_length += (*i)->length () + 1;
    }
    
    log_text.append (L"\r\n");
    
    //refresh_logwnd ();
    
    CHARFORMAT char_format_orig = { 0 };
    
    char_format_orig.cbSize = sizeof (char_format_orig);
    
    ::SendMessageW (m_hwnd_list_control, EM_SETSEL, 0, 0); 
    ::SendMessageW (m_hwnd_list_control, EM_GETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format_orig); 
    
    CHARFORMAT mess_char_format = { 0 };
    
    mess_char_format = char_format_orig;
    mess_char_format.dwMask    = CFM_FACE | CFM_BOLD | CFM_ITALIC | CFM_UNDERLINE | CFM_STRIKEOUT | CFM_SIZE | CFM_COLOR;
    mess_char_format.dwEffects = 0;
    
    wcsncpy (mess_char_format.szFaceName, L"Verdana", LF_FACESIZE);
    
    //if (true == increase_font)
    //    mess_char_format.yHeight = mess_char_format.yHeight + (int) (mess_char_format.yHeight / 5.);
    mess_char_format.yHeight     = (int) (((float) mess_char_format.yHeight / 100.) * (float) font_size_percent);
    mess_char_format.crTextColor = font_color;
    
    // set char format
    ::SendMessageW (m_hwnd_list_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &mess_char_format); 
    
    // add message
    ::SendMessageW (m_hwnd_list_control, EM_REPLACESEL, FALSE, (LPARAM) log_text.c_str ()); 
    
    if (0 < app_name.length ())
    {
        // set bold font for app_name
        CHARFORMAT app_name_char_format = { 0 };

        app_name_char_format           = char_format_orig;
        app_name_char_format.dwMask    = CFM_BOLD;// | CFM_ITALIC;
        app_name_char_format.dwEffects = CFE_BOLD;// | CFE_ITALIC;
        
        ::SendMessageW (m_hwnd_list_control, EM_SETSEL, 0, app_name.length ()); 
        ::SendMessageW (m_hwnd_list_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &app_name_char_format); 
    }
    
    // delete finalize eol symbols
    GETTEXTLENGTHEX text_length;
    
    text_length.flags = GTL_NUMCHARS;
    LRESULT re_text_length = ::SendMessageW (m_hwnd_list_control, EM_GETTEXTLENGTHEX, (WPARAM) &text_length, 0);
    
    ::SendMessageW (m_hwnd_list_control, EM_SETSEL, (WPARAM) log_text_length, (LPARAM) re_text_length);
    ::SendMessageW (m_hwnd_list_control, EM_REPLACESEL, FALSE, (LPARAM) L""); 
    ::SendMessageW (m_hwnd_list_control, EM_SETSEL, 0, 0); 
    
    // restore original char format
    ::SendMessageW (m_hwnd_list_control, EM_SETSEL, 0, 0); 
    ::SendMessageW (m_hwnd_list_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format_orig); 
} // add_message

} // namespace logwnd {
} // namespace gswui {
