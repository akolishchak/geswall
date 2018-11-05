// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//
// WINDOWS SKINNING TUTORIAL - by Vander Nunes - virtware.net
// This is the source-code that shows what is discussed in the tutorial.
// The code is simplified for the sake of clarity, but all the needed
// features for handling skinned windows is present. Please read
// the article for more information.
//
// skin.cpp   : CSkin class implementation
// 28/02/2002 : initial release.
//
// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


#include "skin.h"

namespace gswui {
namespace logwnd {

// ----------------------------------------------------------------------------
// constructor 1 - use it when you have not already created the app window.
// this one will not subclass automatically, you must call Hook() and Enable()
// to subclass the app window and enable the skin respectively.
// will throw an exception if unable to initialize skin from resource.
// ----------------------------------------------------------------------------

CSkin::CSkin(int iSkinRegion, int iSkinBitmap)
{
  init (iSkinRegion, iSkinBitmap);
} // CSkin



// ----------------------------------------------------------------------------
// constructor 2 - use it when you have already created the app window.
// this one will subclass the window and enable the skin automatically.
// will throw an exception if unable to initialize skin from resource.
// ----------------------------------------------------------------------------
CSkin::CSkin(HWND hWnd, int iSkinRegion, int iSkinBitmap)
{
  // default starting values
  m_bHooked = false;
  m_OldWndProc = NULL;

  // initialize
  init (iSkinRegion, iSkinBitmap);

  // subclass
  Hook(hWnd);

  // enable
  Enable(true);
}

void CSkin::init (int iSkinRegion, int iSkinBitmap)
{
    // default starting values
  m_bHooked = false;
  m_OldWndProc = NULL;

  // try to retrieve the skin data from resource.
  if ( !GetSkinData(iSkinRegion, iSkinBitmap) )
    throw ("Unable to retrieve the skin.");
}

// ----------------------------------------------------------------------------
// destructor - just call the destroyer
// ----------------------------------------------------------------------------
CSkin::~CSkin()
{
  Destroy();
}



// ----------------------------------------------------------------------------
// destroy skin resources and free allocated resources
// ----------------------------------------------------------------------------
void CSkin::Destroy()
{
  // unhook the window
  UnHook();

  // free bitmaps and device context
  if (m_dcSkin) { SelectObject(m_dcSkin, m_hOldBmp); DeleteDC(m_dcSkin); m_dcSkin = NULL; }
  if (m_hBmp) { DeleteObject(m_hBmp); m_hBmp = NULL; }

  // free skin region
  if (m_rgnSkin) { DeleteObject(m_rgnSkin); m_rgnSkin = NULL; }
}



// ----------------------------------------------------------------------------
// toggle skin on/off - must be Hooked() before attempting to enable skin.
// ----------------------------------------------------------------------------
bool CSkin::Enable(bool bEnable)
{
  // refuse to enable if there is no window subclassed yet.
  if (!Hooked()) return false;

  // toggle
  m_bEnabled = bEnable;

  // force window repainting
  InvalidateRect(m_hWnd, NULL, TRUE);

  return true;
}



// ----------------------------------------------------------------------------
// tell if the skinning is enabled
// ----------------------------------------------------------------------------
bool CSkin::Enabled()
{
  return m_bEnabled;
}



// ----------------------------------------------------------------------------
// hook a window
// ----------------------------------------------------------------------------
bool CSkin::Hook(HWND hWnd)
{
  // unsubclass any other window
  if (Hooked()) UnHook();

  // this will be our new subclassed window
  m_hWnd = hWnd;

  // set the skin region to the window
  SetWindowRgn(m_hWnd, m_rgnSkin, true);
  
//  DWORD dwStyle = ::GetWindowLongW (m_hWnd, GWL_STYLE);
//  dwStyle &= ~(WS_CAPTION|WS_SIZEBOX);
//  ::SetWindowLongW (m_hWnd, GWL_STYLE, dwStyle);

  // subclass the window procedure
  m_OldWndProc = (WNDPROC) UlongToPtr (::SetWindowLong(m_hWnd, GWL_WNDPROC, PtrToUlong (SkinWndProc)));

  // store a pointer to our class instance inside the window procedure.
  if (!::SetPropW (m_hWnd, L"skin", (void*)this))
  {
    // if we fail to do so, we just can't activate the skin.
    UnHook();
    return false;
  }

  // update flag
  m_bHooked = ( m_OldWndProc ? true : false );

  // force window repainting
  InvalidateRect(m_hWnd, NULL, TRUE);

  // successful return if we're hooked.
  return m_bHooked;
}



// ----------------------------------------------------------------------------
// unhook the window
// ----------------------------------------------------------------------------
bool CSkin::UnHook()
{
  // just to be safe we'll check this
  WNDPROC OurWnd;

  // cannot unsubclass if there is no window subclassed
  // returns true anyways.
  if (!Hooked()) return true;

  // remove the skin region from the window
  SetWindowRgn(m_hWnd, NULL, true);

  // unsubclass the window procedure
  OurWnd = (WNDPROC) UlongToPtr (::SetWindowLongW (m_hWnd, GWL_WNDPROC, PtrToUlong (m_OldWndProc)));

  // remove the pointer to our class instance, but if we fail we don't care.
  ::RemovePropW (m_hWnd, L"skin");

  // update flag - if we can't get our window procedure address again,
  // we failed to unhook the window.
  m_bHooked = ( OurWnd ? false : true );

  // force window repainting
  InvalidateRect(m_hWnd, NULL, TRUE);

  // successful return if we're unhooked.
  return !m_bHooked;
}



// ----------------------------------------------------------------------------
// tell us if there is a window subclassed
// ----------------------------------------------------------------------------
bool CSkin::Hooked()
{
  return m_bHooked;
}



// ----------------------------------------------------------------------------
// return the skin bitmap width
// ----------------------------------------------------------------------------
int CSkin::Width()
{
  return m_iWidth;
}



// ----------------------------------------------------------------------------
// return the skin bitmap height
// ----------------------------------------------------------------------------
int CSkin::Height()
{
  return m_iHeight;
}



// ----------------------------------------------------------------------------
// return the skin device context
// ----------------------------------------------------------------------------
HDC CSkin::HDC()
{
  return m_dcSkin;
}



// ----------------------------------------------------------------------------
// skin retrieval helper
// ----------------------------------------------------------------------------
bool CSkin::GetSkinData(int iSkinRegion, int iSkinBitmap)
{
  // get app instance handle
  HINSTANCE hInstance = GetModuleHandle(NULL);

  // -------------------------------------------------
  // retrieve the skin bitmap from resource.
  // -------------------------------------------------

  m_hBmp = LoadBitmap(hInstance, MAKEINTRESOURCE(iSkinBitmap));
  if (!m_hBmp) return false;

  // get skin info
  BITMAP bmp;
  GetObject(m_hBmp, sizeof(bmp), &bmp);

  // get skin dimensions
  m_iWidth = bmp.bmWidth;
  m_iHeight = bmp.bmHeight;


  // -------------------------------------------------
  // then, we retrieve the skin region from resource.
  // -------------------------------------------------

  // ask resource for our skin.
  HRSRC hrSkin = ::FindResourceW(hInstance, MAKEINTRESOURCE(iSkinRegion), L"Binary");
  if (!hrSkin) return false;

  // this is standard "BINARY" retrieval.
  LPRGNDATA pSkinData = (LPRGNDATA)LoadResource(hInstance, hrSkin);
  if (!pSkinData) return false;

  // create the region using the binary data.
  m_rgnSkin = ExtCreateRegion(NULL, SizeofResource(NULL,hrSkin), pSkinData);

  // free the allocated resource
  FreeResource(pSkinData);

  // check if we have the skin at hand.
  if (!m_rgnSkin) return false;


  // -------------------------------------------------
  // well, things are looking good...
  // as a quick providence, just create and keep
  // a device context for our later blittings.
  // -------------------------------------------------

  // create a context compatible with the user desktop
  m_dcSkin = CreateCompatibleDC(0);
  if (!m_dcSkin) return false;

  // select our bitmap
  m_hOldBmp = (HBITMAP)SelectObject(m_dcSkin, m_hBmp);


  // -------------------------------------------------
  // done
  // -------------------------------------------------
  return true;
}



// ------------------------------------------------------------------------
// Default skin window procedure.
// Here the class will handle WM_PAINT and WM_LBUTTONDOWN, originally sent
// to the application window, but now subclassed. Any other messages will
// just pass through the procedure and reach the original app procedure.
// ------------------------------------------------------------------------
LRESULT CALLBACK SkinWndProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam)
{
  // we will need a pointer to the associated class instance
  // (it was stored in the window before, remember?)
  CSkin *pSkin = (CSkin*)::GetPropW (hWnd, L"skin");

  // to handle WM_PAINT
	PAINTSTRUCT ps;

  // if we fail to get our class instance, we can't handle anything.
  if (!pSkin) return DefWindowProc(hWnd,uMessage,wParam,lParam);

  switch(uMessage)
  {
    //case WM_NCACTIVATE:
    //     CallWindowProc(pSkin->m_OldWndProc, hWnd, uMessage, wParam, lParam);
    case WM_NCPAINT:
    {
        RECT wnd_rect = { 0 };
        ::GetWindowRect (hWnd, &wnd_rect);
      
        HDC hdc;
        hdc = ::GetWindowDC (hWnd); // ::GetDCEx (hWnd, (HRGN)wParam, DCX_WINDOW|DCX_INTERSECTRGN);
        
        ::StretchBlt (
            hdc, 
            0, 
            0, 
            wnd_rect.right - wnd_rect.left,
            wnd_rect.bottom - wnd_rect.top,
            pSkin->HDC (),
            0, 
            0, 
            pSkin->Width(),
            pSkin->Height(),
            SRCCOPY
        );
        
        SetBkMode (hdc,TRANSPARENT);
        
        ::ReleaseDC (hWnd, hdc);
        return 0;
    }
    //case WM_PAINT:
    //{
    //  RECT wnd_rect = { 0 };
    //  ::GetWindowRect (hWnd, &wnd_rect);
    //    
    //  // ---------------------------------------------------------
    //  // here we just need to blit our skin
    //  // directly to the device context
    //  // passed by the painting message.
    //  // ---------------------------------------------------------
    //  BeginPaint(hWnd,&ps);

    //  // blit the skin
    //  //BitBlt(ps.hdc,0,0,pSkin->Width(),pSkin->Height(),pSkin->HDC(),0,0,SRCCOPY);
    //  ::StretchBlt (
    //    ps.hdc, 
    //    0, 
    //    0, 
    //    wnd_rect.right - wnd_rect.left,
    //    wnd_rect.bottom - wnd_rect.top,
    //    pSkin->HDC (),
    //    0, 
    //    0, 
    //    pSkin->Width(),
    //    pSkin->Height(),
    //    SRCCOPY
    //  );
    //  
    //  SetBkMode (ps.hdc,TRANSPARENT);

    //  EndPaint(hWnd,&ps);
    //  return 0;
    //}

    //case WM_LBUTTONDOWN:
    //{
    //  // ---------------------------------------------------------
    //  // this is a common trick for easy dragging of the window.
    //  // this message fools windows telling that the user is
    //  // actually dragging the application caption bar.
    //  // ---------------------------------------------------------
    //  SendMessage(hWnd, WM_NCLBUTTONDOWN, HTCAPTION,NULL);
    //  break;
    //}

  }

  // ---------------------------------------------------------
  // call the default window procedure to keep things going.
  // ---------------------------------------------------------
  return CallWindowProc(pSkin->m_OldWndProc, hWnd, uMessage, wParam, lParam);
}

} // namespace logwnd {
} // namespace gswui {
