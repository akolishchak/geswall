//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_logwnd_h__
 #define __gswui_logwnd_h__

#include <string>

namespace gswui {
namespace logwnd {

typedef std::wstring  wstring;

void create (HINSTANCE instance);
void destroy ();

enum PaintAlgo
{
    PaintAlgoFallTo10 = 1,
    PaintAlgoFallTo20,
    PaintAlgoFallTo40,
    PaintAlgoFallTo60,
    PaintAlgoFallTo80
};

enum MessageType
{
    MessageTypeText = 1,
    MessageTypeNotification,
    MessageTypeAttackNotification
};

void      add_message (MessageType message_type, const wstring& app_name, const wstring& message, const wstring& wnd_name);
void      clean ();

PaintAlgo get_paint_algo ();
void      set_paint_algo (PaintAlgo algo);

int       get_stable_time (MessageType message_type);
void      set_stable_time (MessageType message_type, int stable_time);
int       get_visible_time (MessageType message_type);
void      set_visible_time (MessageType message_type, int visible_time);

COLORREF  get_bkg_color (MessageType message_type);
void      set_bkg_color (MessageType message_type, COLORREF bkg_color);
void      select_bkg_color (MessageType message_type, HWND hwnd);

void      set_repaint_timer_resolution (unsigned int resolution); // msec

} // namespace logwnd {
} // namespace gswui {

#endif // __gswui_logwnd_h__