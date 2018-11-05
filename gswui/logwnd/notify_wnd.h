//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_notify_wnd_h__
 #define __gswui_notify_wnd_h__

#include "commonlib/commondefs.h"
#include "log_wnd.h"

namespace gswui {
namespace logwnd {

class notify_wnd;

//****************************************************************************************//

class notify_wnd : public log_wnd
{
  public:
  protected:
  private:

  public:
    explicit notify_wnd (HINSTANCE global_instance);
    virtual ~notify_wnd ();

  protected:
    virtual HWND    create_window (DWORD ex_style, DWORD style, const wstring& wnd_name, const wstring& class_name);
    virtual LRESULT wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    
  private:

  public:
  protected:
  private:
}; // class notify_wnd

} // namespace logwnd {
} // namespace gswui {

#endif // __gswui_notify_wnd_h__