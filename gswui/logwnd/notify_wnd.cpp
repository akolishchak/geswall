//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "notify_wnd.h"

#include "../notificator.h"

#include "resource1.h"
 
namespace gswui {
namespace logwnd {

notify_wnd::notify_wnd (HINSTANCE global_instance)
    : log_wnd (
          global_instance, 
          L"Notification", 
          L"GeSWall's Policy Notifications",
          RGB (255, 255, 202),
          1,
          500,
          100,
          RGB (0, 0, 0),
          IDB_BITMAP_NOTIFY_SKIN_MASK,
          IDB_BITMAP_NOTIFY_SKIN
      )
{
    add_skin_bitmap (IDB_BITMAP_NOTIFY_SKIN_TOP_LEFT, skin_align_top_left);
    add_skin_bitmap (IDB_BITMAP_NOTIFY_SKIN_TOP_RIGHT, skin_align_top_right);
} // notify_wnd

notify_wnd::~notify_wnd ()
{
    try
    {
        destroy ();
    }
    catch (...)
    {
    }
} // ~notify_wnd

HWND notify_wnd::create_window (DWORD ex_style, DWORD style, const wstring& wnd_name, const wstring& class_name)
{
    return log_wnd::create_window (ex_style, WS_MAXIMIZEBOX | style, wnd_name, class_name);
} // create_window

LRESULT notify_wnd::wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
////////////////////////////////// workaround for disable tooltips on caption buttons    
        case WM_NCHITTEST:
        {
            bool bt_down = false;
            
            bt_down = bt_down || (0 != (::GetAsyncKeyState (VK_LBUTTON) & 0x8000));
            bt_down = bt_down || (0 != (::GetAsyncKeyState (VK_RBUTTON) & 0x8000));
            bt_down = bt_down || (0 != (::GetAsyncKeyState (VK_MBUTTON) & 0x8000));

            LRESULT res = log_wnd::wnd_proc (hwnd, message, wParam, lParam);
            if (0 == res)
                return res;

            if (false == bt_down && HTMAXBUTTON == res)
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
                case HTMAXBUTTON: // use as permanent close command
                    gswui::notificator::set_notification_filter (0);
                    hide_log_window (hwnd);
                    return 0;
            }
            break;
        }
    }
    
    return log_wnd::wnd_proc (hwnd, message, wParam, lParam);
} // wnd_proc

} // namespace logwnd {
} // namespace gswui {

