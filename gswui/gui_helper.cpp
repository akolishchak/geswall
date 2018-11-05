//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "gui_helper.h"
#include "commonlib/commondefs.h"

namespace gswui {
namespace gui_helper {

typedef commonlib::PtrToByte    ptr_to_byte;

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

ptr_to_byte get24_bits (HBITMAP pBitmap, WORD *pwWidth, WORD *pwHeight);

UINT_PTR CALLBACK color_hook_proc (HWND hdlg, UINT uiMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uiMsg)
    {
        case WM_INITDIALOG:
        {    
            RECT  dlg_rect;
            POINT cursor_pos;
            
            if (TRUE == ::GetWindowRect (hdlg, &dlg_rect) && TRUE == ::GetCursorPos (&cursor_pos))
            {
                int x = cursor_pos.x - (dlg_rect.right - dlg_rect.left);
                int y = cursor_pos.y - (dlg_rect.bottom - dlg_rect.top);
                
                if (0 > x)
                    x = 0;
                if (0 > y)
                    y = 0;    
                
                ::SetWindowPos (hdlg, NULL, x, y, 0, 0, SWP_ASYNCWINDOWPOS | SWP_NOSIZE | SWP_NOOWNERZORDER);
            }
            break;
        }
    }
    
    return 0;
} // color_hook_proc


COLORREF select_color (HWND hwnd, COLORREF defaultColor)
{
  CHOOSECOLORW    chooseColor;
  BOOL            result;        
  COLORREF        aclrCust[16] = {
    RGB(255, 255, 255), RGB(255, 255,   0),
    RGB(255,   0, 255), RGB(  0, 255, 255),
    RGB(255,   0,   0), RGB(  0, 255,   0),
    RGB(  0,   0, 255), RGB(192, 192, 192),
    RGB(127, 127, 127), RGB(127, 127,   0),
    RGB(127,  0 , 127), RGB(  0, 127, 127),
    RGB(127,   0,   0), RGB(  0, 127,   0),
    RGB(  0,   0, 127), RGB(  0,   0,   0) 
  };
  
  ZeroMemory (&chooseColor, sizeof (CHOOSECOLOR));
  
  chooseColor.lStructSize    = sizeof (CHOOSECOLOR); 
  chooseColor.hwndOwner      = hwnd; 
  chooseColor.hInstance      = NULL;   
  chooseColor.rgbResult      = defaultColor; 
  chooseColor.lpCustColors   = aclrCust; 
  chooseColor.Flags          = CC_ANYCOLOR | CC_ENABLEHOOK; // | CC_ENABLETEMPLATE; 
  chooseColor.lCustData      = NULL; 
  chooseColor.lpfnHook       = color_hook_proc; 
  chooseColor.lpTemplateName = NULL;//L"Sinus"; 
  
  result = ChooseColorW (&chooseColor);

  return chooseColor.rgbResult;
} // select_color

// -------------------------------------------------------------------------------------
// Return bitmap pixels in 24bits format.
// The caller must release the memory...
// -------------------------------------------------------------------------------------
ptr_to_byte get24_bits (HBITMAP pBitmap, WORD *pwWidth, WORD *pwHeight)
{
    // a bitmap object just to get bitmap width and height
    BITMAP bmpBmp;

    // pointer to original bitmap info
    LPBITMAPINFO pbmiInfo;

    // bitmap info will hold the new 24bit bitmap info
    BITMAPINFO bmiInfo;

    // width and height of the bitmap
    WORD wBmpWidth, wBmpHeight;

    // ---------------------------------------------------------
    // get some info from the bitmap
    // ---------------------------------------------------------
    GetObjectW (pBitmap, sizeof(bmpBmp),&bmpBmp);
    pbmiInfo   = (LPBITMAPINFO)&bmpBmp;

    // get width and height
    wBmpWidth  = (WORD)pbmiInfo->bmiHeader.biWidth;
    wBmpWidth -= (wBmpWidth%4);                       // width is 4 byte boundary aligned.
    wBmpHeight = (WORD)pbmiInfo->bmiHeader.biHeight;

    // copy to caller width and height parms
    *pwWidth  = wBmpWidth;
    *pwHeight = wBmpHeight;
    // ---------------------------------------------------------

    // allocate width * height * 24bits pixels
    ptr_to_byte pixels (new BYTE[wBmpWidth*wBmpHeight*3]);
    if (NULL == pixels.get ()) 
        return pixels;

    // get user desktop device context to get pixels from
    HDC hDC = GetWindowDC (NULL);
    if (NULL == hDC)
    {
        pixels.reset ();
        return pixels;
    }
    
    scope_guard hdc_guard = make_guard (hDC, hdc_finalizer (NULL));    

    // fill desired structure
    bmiInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmiInfo.bmiHeader.biWidth = wBmpWidth;
    bmiInfo.bmiHeader.biHeight = -wBmpHeight;
    bmiInfo.bmiHeader.biPlanes = 1;
    bmiInfo.bmiHeader.biBitCount = 24;
    bmiInfo.bmiHeader.biCompression = BI_RGB;
    bmiInfo.bmiHeader.biSizeImage = wBmpWidth*wBmpHeight*3;
    bmiInfo.bmiHeader.biXPelsPerMeter = 0;
    bmiInfo.bmiHeader.biYPelsPerMeter = 0;
    bmiInfo.bmiHeader.biClrUsed = 0;
    bmiInfo.bmiHeader.biClrImportant = 0;

    // get pixels from the original bitmap converted to 24bits
    int iRes = GetDIBits (hDC, pBitmap, 0, wBmpHeight, (LPVOID)pixels.get (), &bmiInfo, DIB_RGB_COLORS);

    // release the device context
    hdc_guard.free ();

    // if failed, cancel the operation.
    if (0 >= iRes)
        pixels.reset ();

    // return the pixel array
    return pixels;
} // get24_bits

HRGN scan_region (HBITMAP pBitmap, BYTE jTranspR, BYTE jTranspG, BYTE jTranspB)
{
    // bitmap width and height
    WORD wBmpWidth,wBmpHeight;

    // the final region and a temporary region
    HRGN hRgn, hTmpRgn;

    // 24bit pixels from the bitmap
    ptr_to_byte pixels = get24_bits (pBitmap, &wBmpWidth, &wBmpHeight);
    if (NULL == pixels.get ()) 
        return NULL;

    // create our working region
    hRgn = CreateRectRgn(0,0,wBmpWidth,wBmpHeight);
    if (!hRgn) 
        return NULL;

    // ---------------------------------------------------------
    // scan the bitmap
    // ---------------------------------------------------------
    DWORD p=0;
    for (WORD y=0; y<wBmpHeight; y++)
    {
        for (WORD x=0; x<wBmpWidth; x++)
        {
            BYTE jRed   = pixels.get () [p+2];
            BYTE jGreen = pixels.get () [p+1];
            BYTE jBlue  = pixels.get () [p+0];

            if (jRed == jTranspR && jGreen == jTranspG && jBlue == jTranspB)
            {
                // remove transparent color from region
                hTmpRgn = CreateRectRgn (x,y,x+1,y+1);
                CombineRgn (hRgn, hRgn, hTmpRgn, RGN_XOR);
                DeleteObject (hTmpRgn);
            }

            // next pixel
            p+=3;
        }
    }

    // return the region
    return hRgn;
} // scan_region

int get_wnd_caption_height (HWND hwnd)
{
   LONG style  = GetWindowLongW (hwnd, GWL_STYLE);
   int  height = 0;
   
   if (
          WS_THICKFRAME == (style & WS_THICKFRAME)
       || DS_MODALFRAME == (style & DS_MODALFRAME)
      )
     height += GetSystemMetrics (SM_CYSIZEFRAME);
     
   if (WS_BORDER == (style & WS_BORDER))
     height += GetSystemMetrics (SM_CYBORDER);
     
   if (WS_CAPTION == (style & WS_CAPTION))
     height += GetSystemMetrics (SM_CYCAPTION);

   return height;
} // get_wnd_caption_height


} // namespace gui_helper {
} // namespace gswui {

