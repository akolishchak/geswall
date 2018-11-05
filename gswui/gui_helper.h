//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_gui_helper_h__
 #define __gswui_gui_helper_h__

#include "stdafx.h"

namespace gswui {
namespace gui_helper {

struct hdc_finalizer
{
    hdc_finalizer (HWND hwnd) : m_hwnd (hwnd) {}
    
    void operator () (HDC hdc)
    {
        ::ReleaseDC (m_hwnd, hdc);
    }
    
    HWND m_hwnd;
}; // hdc_finalizer

struct selobj_finalizer
{
    selobj_finalizer (HDC hdc) : m_hdc (hdc) {}
    
    void operator () (HGDIOBJ obj)
    {
        ::SelectObject (m_hdc, obj);
    }
    
    HDC m_hdc;
}; // selobj_finalizer


COLORREF select_color (HWND hwnd, COLORREF defaultColor);
HRGN     scan_region (HBITMAP pBitmap, BYTE jTranspR, BYTE jTranspG, BYTE jTranspB);
int      get_wnd_caption_height (HWND hwnd);

} // namespace gui_helper {
} // namespace gswui {

#endif // __gswui_gui_helper_h__