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

#include "redit_log_view.h"
 
namespace gswui {
namespace logwnd {

redit_log_view::redit_log_view (HINSTANCE global_instance)
    : m_global_instance (global_instance),
      m_parent_window (NULL),
      m_hwnd_control (NULL),
      m_max_queue_size (5)
{

} // redit_log_view

redit_log_view::~redit_log_view ()
{
    try
    {
        destroy ();
    }
    catch (...)
    {
    }
} // ~redit_log_view

//LRESULT OldEditProc; 
//LRESULT CALLBACK EditProc( HWND, UINT, WPARAM, LPARAM ); 

bool redit_log_view::create (HWND parent_window, int control_id) 
{
    m_parent_window = parent_window;

    //m_hwnd_control = 
    //    ::CreateWindowW (
    //        //WS_EX_CLIENTEDGE, //WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR | LVS_EX_HEADERDRAGDROP,
    //        RICHEDIT_CLASSW, //WC_EDITW,
    //        L"",
    //        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
    //        0, 0, 250, 50,
    //        parent_window,
    //        reinterpret_cast <HMENU> (IntToPtr (control_id)),
    //        m_global_instance, 
    //        NULL
    //    );
    m_hwnd_control = 
        ::CreateWindowExW (
            0, //WS_EX_TRANSPARENT,
            RICHEDIT_CLASSW, //WC_EDITW,
            L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 250, 50,
            parent_window,
            reinterpret_cast <HMENU> (IntToPtr (control_id)),
            m_global_instance, 
            NULL
        );

    if (NULL != m_hwnd_control)
    {
        //OldEditProc = ::SetWindowLongPtrW (m_hwnd_control, GWL_WNDPROC,(LONG) (WNDPROC) EditProc); 
        
        ::SendMessageW (m_hwnd_control, EM_SETSEL, 0, 0); 
    
        CHARFORMATW char_format_orig = { 0 };
        CHARFORMATW char_format = { 0 };
        
        char_format_orig.cbSize = sizeof (char_format);
        
        ::SendMessageW (m_hwnd_control, EM_GETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format_orig); 
        
        char_format = char_format_orig;
        
        char_format.dwMask    = CFM_FACE | CFM_BOLD | CFM_ITALIC;
        char_format.dwEffects = 0;
        
        wcsncpy (char_format.szFaceName, L"Verdana", LF_FACESIZE);
        
        ::SendMessageW (m_hwnd_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format); 
        
        LRESULT event_mask = ::SendMessageW (m_hwnd_control, EM_GETEVENTMASK, 0, 0);
        ::SendMessageW (m_hwnd_control, EM_SETEVENTMASK, 0, event_mask | ENM_MOUSEEVENTS | ENM_REQUESTRESIZE);

        return true;
    }

    return false;
} // create

//LRESULT CALLBACK EditProc (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) 
//{ 
//    switch (uMsg) 
//    { 
//        case WM_CHAR: 
//        { 
//            RECT rect; 
//            GetClientRect(hWnd, &rect); 
//            ClientToScreen(hWnd, (LPPOINT)&rect); 
//            ScreenToClient(GetParent(hWnd),(LPPOINT) &rect); 
//            InvalidateRect(GetParent(hWnd), &rect, TRUE); 
//        } 
//        break; 
//    } 
//    return(CallWindowProc((WNDPROC)OldEditProc, hWnd, uMsg, wParam, lParam )); 
//}        

void redit_log_view::destroy ()
{
    if (NULL != m_hwnd_control)
        ::DestroyWindow (m_hwnd_control);

    m_hwnd_control  = NULL;
    m_parent_window = NULL;
} // destroy

void redit_log_view::resize (int x, int y, int width, int height)
{
    ::MoveWindow (m_hwnd_control, x, y, width, height, TRUE);
} // resize

void redit_log_view::repaint ()
{
    ::InvalidateRect (m_hwnd_control, NULL, TRUE);
} // repaint

void redit_log_view::set_background_color (COLORREF color)
{
    ::SendMessageW (m_hwnd_control, EM_SETBKGNDCOLOR, 0, color);
} // set_background_color

void redit_log_view::set_max_queue_size (size_t max_queue_size)
{
    m_max_queue_size = max_queue_size;
} // set_max_queue_size

size_t redit_log_view::get_max_queue_size ()
{
    return m_max_queue_size;
} // get_max_queue_size

void redit_log_view::add_message (const wstring& app_name, const wstring& message, int font_size_percent, COLORREF font_color)
{
    while (m_log_queue.size () >= m_max_queue_size)
    {
        m_log_queue.pop_back ();
    }
        
    wstring log_text;
    log_text.append (app_name).append (L" ").append (message);
    
    m_log_queue.push_front (ptr_to_wstring (new wstring (log_text)));
    
    size_t log_text_length = 0;
    for (string_list::iterator i = m_log_queue.begin (); i != m_log_queue.end (); ++i)
    {
        log_text_length += (*i)->length () + 1;
    }
    
    log_text.append (L"\r\n");

    CHARFORMAT char_format_orig = { 0 };
    
    char_format_orig.cbSize = sizeof (char_format_orig);
    
    ::SendMessageW (m_hwnd_control, EM_SETSEL, 0, 0); 
    ::SendMessageW (m_hwnd_control, EM_GETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format_orig); 
    
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
    ::SendMessageW (m_hwnd_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &mess_char_format); 
    
    // add message
    ::SendMessageW (m_hwnd_control, EM_REPLACESEL, FALSE, (LPARAM) log_text.c_str ()); 
    
    if (0 < app_name.length ())
    {
        // set bold font for app_name
        CHARFORMAT app_name_char_format = { 0 };

        app_name_char_format           = char_format_orig;
        app_name_char_format.dwMask    = CFM_BOLD;// | CFM_ITALIC;
        app_name_char_format.dwEffects = CFE_BOLD;// | CFE_ITALIC;
        
        ::SendMessageW (m_hwnd_control, EM_SETSEL, 0, app_name.length ()); 
        ::SendMessageW (m_hwnd_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &app_name_char_format); 
    }
    
    // delete finalize eol symbols
    GETTEXTLENGTHEX text_length;
    
    text_length.flags = GTL_NUMCHARS;
    LRESULT re_text_length = ::SendMessageW (m_hwnd_control, EM_GETTEXTLENGTHEX, (WPARAM) &text_length, 0);
    
    ::SendMessageW (m_hwnd_control, EM_SETSEL, (WPARAM) log_text_length, (LPARAM) re_text_length);
    ::SendMessageW (m_hwnd_control, EM_REPLACESEL, FALSE, (LPARAM) L""); 
    ::SendMessageW (m_hwnd_control, EM_SETSEL, 0, 0); 
    
    // restore original char format
    ::SendMessageW (m_hwnd_control, EM_SETSEL, 0, 0); 
    ::SendMessageW (m_hwnd_control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &char_format_orig); 

    ::SendMessageW (m_hwnd_control, WM_KILLFOCUS, NULL, 0);
} // add_message

void redit_log_view::clean ()
{
    m_log_queue.clear ();
    ::SendMessageW (m_hwnd_control, WM_SETTEXT, 0, (LPARAM) L"");
} // clean

LRESULT redit_log_view::on_notify (HWND hwnd_parent, NMHDR* nm_hdr)
{
    return 0;
} // on_notify

} // namespace logwnd {
} // namespace gswui {

