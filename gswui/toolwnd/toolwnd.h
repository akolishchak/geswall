//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_toolwnd_h__
 #define __gswui_toolwnd_h__

namespace gswui {
namespace toolwnd {

void create (HINSTANCE instance);
void destroy ();

enum BlinkAlgo
{
  BlinkAlgoCyclic,
  BlinkAlgoFallTo20,
  BlinkAlgoFallTo40,
  BlinkAlgoFallTo60,
  BlinkAlgoFallTo80,
  BlinkAlgoDisable
};

BlinkAlgo get_blink_algo ();
void      set_blink_algo (BlinkAlgo algo);

void      set_untrasted_color (HWND hwnd);
void      set_isolated_color (HWND hwnd);
void      show_isolated_dir (HWND hwnd);
void      set_enable_caption_button (bool enable);
bool      is_caption_button_enabled ();

} // namespace toolwnd {
} // namespace gswui {

#endif // __gswui_toolwnd_h__