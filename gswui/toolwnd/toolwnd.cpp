//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "toolwnd.h"

#include <commctrl.h>
#include <windowsx.h>
#include <shtypes.h>
#include <shlobj.h>
#include <objbase.h>
#include <objidl.h>
#include <tlhelp32.h>

#include "resource1.h"

#include "commonlib/commondefs.h"
#include "commonlib/thread.h"
#include "commonlib/tools.h"
#include "commonlib/commonlib.h"
#include "commonlib/nttools/nttools.h"
#include "colors.h"
#include "gswdrv.h"

#include "gswui/gui_helper.h"
#include "gswui/gswclient_helper.h"

#include <map>

namespace gswui {
namespace toolwnd {

#ifdef _CB_TEST_DEBUG_
 #pragma message (__WARNING__"this is cb.test.debug configurations")
#endif // _CB_TEST_DEBUG_ 

#ifndef _CB_TEST_DEBUG_
 #define _USE_GSWDRV_
#endif // _CB_TEST_DEBUG_ 

typedef commonlib::IntrusiveAtomicCounter  AtomicCounter;
typedef commonlib::thread                  WorkThread;
typedef boost::shared_ptr <WorkThread>     PtrToWorkThread;
typedef boost::shared_ptr <CGswDrv>        PtrToCGswDrv;

struct destroy_menu
{
  BOOL operator () (HMENU hMenu)
  {
    if (NULL != hMenu)
      return ::DestroyMenu (hMenu);
    return FALSE;  
  } // operator ()
}; // destroy_menu

struct disable_menu
{
  disable_menu (AtomicCounter& counter)
   : m_counter (counter), 
     m_prevValue (m_counter.increment () - 1)
  {

  } // disable_menu
  
  ~disable_menu ()
  {
    m_counter.decrement ();
  } // ~disable_menu
  
  AtomicCounter&                  m_counter;
  const AtomicCounter::value_type m_prevValue;
}; // disable_menu

#define  IDC_SHOW_MENU                998

#define IDC_MENU_RESTART			  999

#define  IDC_SET_UNTRUSTED_COLOR      1000
#define  IDC_SET_ISOLATED_COLOR       1001
#define  IDC_SET_BLINK_ALGO           1002
#define  IDC_SET_ISOLATED_DIR         1003
#define  IDC_BLINK_ALGO_CYCLIC        1103
#define  IDC_BLINK_ALGO_FALLTO_020    1104
#define  IDC_BLINK_ALGO_FALLTO_040    1105
#define  IDC_BLINK_ALGO_FALLTO_060    1106
#define  IDC_BLINK_ALGO_FALLTO_080    1107
#define  IDC_BLINK_ALGO_DISABLE       1108
#define  IDC_CLOSE_WINDOW             1999

int      guiThreadProc ();
int      statusThreadProc ();

LRESULT  on_reexec_button_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify);
LRESULT  onCommand (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify);
LRESULT  showLocalMenu (HWND hwnd);
LRESULT  trackLocalMenu (HWND hwnd);
LRESULT  repaintWindow (HWND hwnd);
LRESULT  paintWindow (HWND hwnd);
LRESULT  checkForegroundWindow ();

//LRESULT  passThoughtMessage (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
void     refreshBrush ();
wchar_t* getCaptionText ();
int      getWindowHeight (HWND hwnd);
int      getFrameHeight (HWND hwnd);
HFONT    createAnyFont (int orientation, BYTE charSet, BYTE italic, wchar_t* faceName, int height, int width);
void     onShowIsolatedDirectory (HWND hwnd);
void     onSelectIsolatedDirectory (HWND hwnd);
BOOL     showDirInitDialog (HWND hwnd);
void     showDirCloseDialog (HWND hwnd);
void     resetCurrentMarkedObjects ();
void     refreshBlink (int command);
bool     RestartAsNonIsolated(DWORD ProcessId);
LONG     get_window_long (HWND hwnd, int index);
int      get_caption_button_count (HWND hwnd);
void     create_reexec_button (HWND parent_hwnd);
LRESULT  paint_reexec_button_window (HWND hwnd);
void     paint_reexec_button (LPDRAWITEMSTRUCT draw_info);
HBITMAP  get_bitmap_info (int wnd_height, POINT& bitmap_size);
bool     refresh_blink_algo (BlinkAlgo algo);


static   LRESULT CALLBACK reexec_button_wndproc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
static   LRESULT CALLBACK toolWndProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
static   BOOL CALLBACK showDirDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

Colors    m_colors;
DWORD     m_currentMarkedProcessId = -1;

HINSTANCE m_globalInstance     = NULL;
UINT_PTR  m_foregroundTimerId  = 1;
UINT_PTR  m_repaintTimerId     = 2;
UINT_PTR  m_menuTimerId        = 3;
RECT      m_currentWndRect     = { 0 };
HWND      m_hwndToolWindow     = NULL;
HWND      m_hwndButtonWindow   = NULL;
HWND      m_hwndButton         = NULL;
HWND      m_hwndForeground     = NULL;
HFONT     m_toolFont           = NULL; 

HBITMAP   m_menu_button_picture = NULL;
HBITMAP   m_menu_button_picture_small = NULL;
POINT     m_button_size        = { 0 };
POINT     m_button_small_size  = { 0 };

bool      m_need_reload_setting   = true;
bool      m_enable_caption_menu   = false;
bool      m_enable_caption_button = true;

int       m_currentBlinkAlgo   = IDC_BLINK_ALGO_FALLTO_060;
int       m_currentDir         = -1;
int       m_currentAlpha       = 255;

COLORREF  m_currentColor       = NULL;
HBRUSH    m_bkgBrush           = NULL;

AtomicCounter m_disableMenu;
DWORD     m_timeMouseOver      = 3000;
LONG      m_isMouseOver        = 0;
DWORD     m_startTimeMouseOver = 0;

bool      m_comInitialized     = false;

PtrToWorkThread m_guiThread;
PtrToWorkThread m_statusThread;
PtrToCGswDrv    m_gswDrv;

static wchar_t* trustedCaption   = L"Trusted";
static wchar_t* untrustedCaption = L"Untrusted";
static wchar_t* isolatedCaption  = L"";//L"Isolated";

void create (HINSTANCE instance)
{
  destroy ();
  
  m_globalInstance = instance;
  //m_colors.reloadSetting ();
  //config::Configurator::PtrToINode Node = config::Configurator::getProcessMarkerNode();
  //m_enable_caption_button = Node->getBool(L"CaptionMenu16");
  
#ifdef _USE_GSWDRV_
  m_gswDrv = PtrToCGswDrv (new CGswDrv ());
  if (NULL != m_gswDrv.get ())
#endif // _USE_GSWDRV_  
  {
    m_guiThread      = PtrToWorkThread (new WorkThread (&guiThreadProc));
    //m_statusThread   = PtrToWorkThread (new WorkThread (&statusThreadProc));
  }  
} // create

void destroy ()
{
  if (NULL != m_hwndToolWindow)
  {
    PostMessage (m_hwndToolWindow, WM_CLOSE, 0, 0);
    //DestroyWindow (m_hwndToolWindow);
  }  
    
  if (NULL != m_statusThread.get ())
    m_statusThread->join ();
  
  if (NULL != m_guiThread.get ())  
    m_guiThread->join ();
    
  m_need_reload_setting = true;  
} // destroy

BlinkAlgo get_blink_algo ()
{
  BlinkAlgo result = BlinkAlgoFallTo60;
  
  switch (m_currentBlinkAlgo)
  {
    case IDC_BLINK_ALGO_CYCLIC:
         result = BlinkAlgoCyclic;
         break;
    case IDC_BLINK_ALGO_FALLTO_020:
         result = BlinkAlgoFallTo20;
         break;
    case IDC_BLINK_ALGO_FALLTO_040:
         result = BlinkAlgoFallTo40;
         break;
    case IDC_BLINK_ALGO_FALLTO_060:
         result = BlinkAlgoFallTo60;
         break;
    case IDC_BLINK_ALGO_FALLTO_080:
         result = BlinkAlgoFallTo80;
         break;
    case IDC_BLINK_ALGO_DISABLE:
         result = BlinkAlgoDisable;
         break;     
  }
  
  return result;
} // get_blink_algo

void set_blink_algo (BlinkAlgo algo)
{
  if (true == refresh_blink_algo (algo))
      (config::Configurator::getProcessMarkerNode ())->setInt (L"BlinkAlgorithm", algo);
} // set_blink_algo

void set_untrasted_color (HWND hwnd)
{
  m_colors.setUntrustedColor (gui_helper::select_color (hwnd, m_colors.getUntrustedColor ()));
} // set_untrasted_color

void set_isolated_color (HWND hwnd)
{
  m_colors.setIsolatedColor (gui_helper::select_color (hwnd, m_colors.getIsolatedColor ()));
} // set_isolated_color

void set_enable_caption_button (bool enable)
{
  m_enable_caption_button = enable;
  config::Configurator::PtrToINode Node = config::Configurator::getProcessMarkerNode();
  Node->setBool(L"CaptionMenu16", m_enable_caption_button);
  
  if (false == enable)
      ShowWindow (m_hwndButtonWindow, SW_HIDE);
} // set_enable_caption_button

bool is_caption_button_enabled ()
{
  return m_enable_caption_button;
} // is_caption_button_enabled

void show_isolated_dir (HWND hwnd)
{
  onShowIsolatedDirectory (hwnd);
} // show_isolated_dir

int guiThreadProc ()
{
debugString ((L"\ngswui::toolwnd::guiThreadProc (): start"));  
  InitCommonControls ();

  wchar_t*    className  = L"GsWUIToolWindow";
  
  WNDCLASS    wndclass;

  ZeroMemory (&wndclass, sizeof(wndclass));
  wndclass.style         = CS_SAVEBITS | CS_DBLCLKS;
  wndclass.lpfnWndProc   = toolWndProc;
  wndclass.cbClsExtra    = 0;
  wndclass.cbWndExtra    = 0;
  wndclass.hInstance     = m_globalInstance;
  wndclass.hIcon         = NULL;
  wndclass.hCursor       = LoadCursor (NULL, IDC_ARROW);
  wndclass.hbrBackground = (HBRUSH) COLOR_BACKGROUND;
  wndclass.lpszMenuName  = NULL;
  wndclass.lpszClassName = className;

  if (0 != ::RegisterClassW (&wndclass))
  {
    m_hwndToolWindow = CreateWindowExW (WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_NOACTIVATE, className, L"", WS_BORDER | WS_POPUP, 0, 0, 250, 25, NULL, NULL, m_globalInstance, NULL);
    if (NULL != m_hwndToolWindow)
    {
      SetLayeredWindowAttributes (m_hwndToolWindow, RGB (0x80, 0x80, 0x80), m_currentAlpha, LWA_ALPHA);
      create_reexec_button (m_hwndToolWindow);
      
      MSG  msg;
      while (TRUE == GetMessage (&msg, 0, 0, 0))
      {
        TranslateMessage (&msg);
        DispatchMessage (&msg);
      } // while (TRUE == GetMessage (&msg, 0, 0, 0))
      
      DestroyWindow (m_hwndButtonWindow);
      m_hwndButtonWindow = NULL;
      
      DestroyWindow (m_hwndToolWindow);
      m_hwndToolWindow = NULL;
    } // if (NULL != hwndToolWindow)
  } // if (0 != ::RegisterClassW (&wndclass))
debugString ((L"\ngswui::toolwnd::guiThreadProc (): end, %08x", m_hwndToolWindow));  
  
  return 0;
} // guiThreadProc

int statusThreadProc ()
{
  return 0;
} // statusThreadProc

LRESULT CALLBACK reexec_button_wndproc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  switch (message)
  {
    //case WM_PAINT:
    //     return paint_reexec_button_window (hwnd); 
    //case WM_LBUTTONDOWN:
    //     trackLocalMenu (m_hwndToolWindow);
    //     return 0;
    case WM_DRAWITEM:
         paint_reexec_button (reinterpret_cast <LPDRAWITEMSTRUCT> (lParam));
         break;
    HANDLE_MSG (hwnd, WM_COMMAND, on_reexec_button_command);
  }
  
  return DefWindowProc (hwnd, message, wParam, lParam);
} // reexec_button_wndproc

LRESULT on_reexec_button_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify)
{
  switch (idCommand)
  {
    case IDC_SHOW_MENU:
         trackLocalMenu (m_hwndToolWindow);
         break;
  }
  
  return 0;
} // on_reexec_button_command

LRESULT CALLBACK toolWndProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
//debugString ((L"\nGsWui::wndProc(): message = %08x", message));  
  switch (message)
  {
    case WM_CREATE:
         refreshBrush ();
         m_toolFont              = createAnyFont (0, DEFAULT_CHARSET, 0, L"Tahoma", 16, 0); // 8
         m_foregroundTimerId     = SetTimer (hwnd, m_foregroundTimerId, 50, NULL);
         m_repaintTimerId        = SetTimer (hwnd, m_repaintTimerId, 100, NULL);
//         m_menuTimerId           = SetTimer (hwnd, m_menuTimerId, 100, NULL);
         break;
    case WM_ENDSESSION:
    case WM_CLOSE:
         KillTimer (hwnd, m_foregroundTimerId);
         KillTimer (hwnd, m_repaintTimerId);
//         KillTimer (hwnd, m_menuTimerId);
         PostQuitMessage (message);
         break;
    case WM_DESTROY:
         KillTimer (hwnd, m_foregroundTimerId);
         KillTimer (hwnd, m_repaintTimerId);
//         KillTimer (hwnd, m_menuTimerId);

         if (NULL != m_toolFont)
           DeleteObject (m_toolFont);

         if (NULL != m_bkgBrush)
           DeleteObject (m_bkgBrush);
         break;
    case WM_TIMER:     
         if (static_cast <UINT_PTR> (wParam) == m_foregroundTimerId)
           return checkForegroundWindow ();
           
         if (static_cast <UINT_PTR> (wParam) == m_repaintTimerId)
           return repaintWindow (hwnd);
           
//         if (static_cast <UINT_PTR> (wParam) == m_menuTimerId)  
//           return showLocalMenu (hwnd);
         break;
    case WM_PAINT:
         return paintWindow (hwnd);
    //case WM_LBUTTONDOWN:
    //case WM_LBUTTONDBLCLK:
    //{
    //     HWND hwndForeground = m_hwndForeground;
    //     ShowWindow (m_hwndToolWindow, SW_HIDE);
    //     SetForegroundWindow (hwndForeground);
    //     return 0;
    //}     
    //case WM_RBUTTONDOWN:
    //     return trackLocalMenu (hwnd);
    //case WM_NCHITTEST:
    //     return passThoughtMessage (hwnd, message, wParam, lParam);
    //case WM_NCLBUTTONDOWN:
    //case WM_NCLBUTTONUP:
    //case WM_NCLBUTTONDBLCLK:
    //case WM_LBUTTONUP:
    //case WM_LBUTTONDOWN:
    //case WM_LBUTTONDBLCLK:
    //     return passThoughtMessage (hwnd, message, wParam, lParam);
    //     break;
    HANDLE_MSG (hwnd, WM_COMMAND, onCommand);     
  }          

  return DefWindowProc (hwnd, message, wParam, lParam);
} // toolWndProc

LRESULT onCommand (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify)
{
  switch (idCommand)
  {
    case IDC_MENU_RESTART:
	{
		RestartAsNonIsolated(m_currentMarkedProcessId);
		break;
	}
    case IDC_SET_UNTRUSTED_COLOR:
    {
         HWND hwndForeground = m_hwndForeground;
         set_untrasted_color (hwnd);
         SetForegroundWindow (hwndForeground);
         break;
    }     
    case IDC_SET_ISOLATED_COLOR:
    {
         HWND hwndForeground = m_hwndForeground;
         set_isolated_color (hwnd);
         SetForegroundWindow (hwndForeground);
         break;
    }    
    case IDC_SET_ISOLATED_DIR:
    {
         HWND hwndForeground = m_hwndForeground;
         show_isolated_dir (hwnd);
         SetForegroundWindow (hwndForeground);
         break;
    }    
    case IDC_BLINK_ALGO_CYCLIC:
         set_blink_algo (BlinkAlgoCyclic);
         m_hwndForeground = NULL;
         break;
    case IDC_BLINK_ALGO_FALLTO_020:
         set_blink_algo (BlinkAlgoFallTo20);
         m_hwndForeground = NULL;
         break;
    case IDC_BLINK_ALGO_FALLTO_040:
         set_blink_algo (BlinkAlgoFallTo40);
         m_hwndForeground = NULL;
         break;
    case IDC_BLINK_ALGO_FALLTO_060:
         set_blink_algo (BlinkAlgoFallTo60);
         m_hwndForeground = NULL;
         break;
    case IDC_BLINK_ALGO_FALLTO_080:
         set_blink_algo (BlinkAlgoFallTo80);
         m_hwndForeground = NULL;
         break;
    case IDC_BLINK_ALGO_DISABLE:
         set_blink_algo (BlinkAlgoDisable);
         m_hwndForeground = NULL;
         break;     
    case IDC_CLOSE_WINDOW:
    {
         //HWND hwndForeground = m_hwndForeground;
         //ShowWindow (m_hwndToolWindow, SW_HIDE);
         //SetForegroundWindow (hwndForeground);
         break;     
    }     
  } // switch (idCommand)
  
  return 0;
} // onCommand

LRESULT showLocalMenu (HWND hwnd)
{
  if (
         NULL == m_hwndForeground 
      || FALSE == IsWindowVisible (m_hwndForeground) 
      || FALSE == IsWindowVisible (hwnd)
     )
    return 0;
    
  POINT mousePos;
  if (FALSE == GetCursorPos (&mousePos))
    return 0;
  
  RECT wndRect;
  
  if (FALSE == GetWindowRect (hwnd, &wndRect))
    return 0;
    
  if (
          wndRect.left < mousePos.x && wndRect.right > mousePos.x
       && wndRect.top < mousePos.y && wndRect.bottom > mousePos.y
     )
  {
    SHORT keyState = 0;
    
    keyState |= GetAsyncKeyState (VK_LBUTTON);
    keyState |= GetAsyncKeyState (VK_RBUTTON);
    keyState |= GetAsyncKeyState (VK_MBUTTON);
    keyState |= GetAsyncKeyState (VK_XBUTTON1);
    keyState |= GetAsyncKeyState (VK_XBUTTON2);
  
    if (keyState >= 0)
    {
      DWORD currentTime = GetTickCount ();  
    
      if (0 == InterlockedExchange (&m_isMouseOver, 1))
      {
        m_startTimeMouseOver = currentTime;
      }  
      else
      {
        if (m_timeMouseOver <= (currentTime - m_startTimeMouseOver))
        {
          InterlockedExchange (&m_isMouseOver, 0);
          m_startTimeMouseOver = 0;
          if (true == m_enable_caption_menu)
            trackLocalMenu (hwnd);
        }
      }  
    }
    else
    {
      InterlockedExchange (&m_isMouseOver, 0);
      m_startTimeMouseOver = 0;
    }
  }   
  else
  {
    InterlockedExchange (&m_isMouseOver, 0);
    m_startTimeMouseOver = 0;
  }
  
  return 0;
} // showLocalMenu

LRESULT trackLocalMenu (HWND hwnd)
{
  disable_menu disableMenu (m_disableMenu);
  if (0 != disableMenu.m_prevValue)
    return 0;
   
  commonlib::sguard::object<HMENU, destroy_menu> menu (CreatePopupMenu (), destroy_menu ());
  if (NULL == menu.get ())
    return 0;
  
  POINT mousePos;
  if (FALSE == GetCursorPos (&mousePos))
    return 0;
  
  //AppendMenuW (menu, MF_STRING | MF_GRAYED,    IDC_SET_ISOLATED_DIR,    L"Grant Access to Folder...");
  AppendMenuW (menu, MF_STRING,    IDC_SET_ISOLATED_COLOR,  L"Isolated Window Color...");
  //AppendMenuW (menu, MF_STRING,    IDC_SET_UNTRUSTED_COLOR, L"Untrusted Color...");
  AppendMenuW (menu, MF_STRING,    IDC_SET_BLINK_ALGO,      L"Blink Effect");
  AppendMenuW (menu, MF_SEPARATOR, 0,                       NULL);
  AppendMenuW (menu, MF_STRING, IDC_MENU_RESTART,         L"Restart as Non-Isolated");
  AppendMenuW (menu, MF_SEPARATOR, 0,                       NULL);
  AppendMenuW (menu, MF_STRING,    IDC_CLOSE_WINDOW,        L"Hide Menu");
  
  commonlib::sguard::object<HMENU, destroy_menu> blinkMenu (CreatePopupMenu (), destroy_menu ());
  if (NULL == blinkMenu.get ())
    return 0;
    
  AppendMenuW (blinkMenu, MF_STRING, IDC_BLINK_ALGO_CYCLIC,     L"Cyclic");
  AppendMenuW (blinkMenu, MF_STRING, IDC_BLINK_ALGO_FALLTO_020, L"Fall to 20%");
  AppendMenuW (blinkMenu, MF_STRING, IDC_BLINK_ALGO_FALLTO_040, L"Fall to 40%");
  AppendMenuW (blinkMenu, MF_STRING, IDC_BLINK_ALGO_FALLTO_060, L"Fall to 60%");
  AppendMenuW (blinkMenu, MF_STRING, IDC_BLINK_ALGO_FALLTO_080, L"Fall to 80%");
  AppendMenuW (blinkMenu, MF_STRING, IDC_BLINK_ALGO_DISABLE,    L"Disable");
  
  CheckMenuItem (blinkMenu, m_currentBlinkAlgo, MF_BYCOMMAND | MF_CHECKED);
  ModifyMenuW (menu, IDC_SET_BLINK_ALGO, MF_POPUP, HandleToLong (blinkMenu.get ()), L"Blink Effect");
  
  HWND hwndForeground = m_hwndForeground;
  SetWindowLong (hwnd, GWL_EXSTYLE, GetWindowLong (hwnd, GWL_EXSTYLE) & ~WS_EX_TRANSPARENT);

//debugString ((L"\nGsWui::TrackPopupMenu (): menu = %08x", menu.get ()));    
  SetForegroundWindow (hwnd);
  
  TrackPopupMenu (menu, 0, mousePos.x, mousePos.y, 0, hwnd, NULL);
  
  SetWindowLong (hwnd, GWL_EXSTYLE, GetWindowLong (hwnd, GWL_EXSTYLE) | WS_EX_TRANSPARENT);
  SetForegroundWindow (hwndForeground);
  
  blinkMenu.release ();
  //menu.free (); //release ();
  
  return 0;
} // trackLocalMenu

LRESULT repaintWindow (HWND hwnd)
{
  if (FALSE == IsWindowVisible (hwnd))
    return 0;
    
  bool doUpdate = (0 != m_currentDir);
  
  if (IDC_BLINK_ALGO_DISABLE == m_currentBlinkAlgo)
  {
    m_currentAlpha = 0;
    doUpdate       = true;
  }
  else if (IDC_BLINK_ALGO_CYCLIC == m_currentBlinkAlgo)
  {
    m_currentAlpha += 8 * m_currentDir;
    if (0 >= m_currentAlpha)
    {
      m_currentDir  *= -1;
      m_currentAlpha = 0;
    }
    else
    {
      if (255 < m_currentAlpha)
      {
        m_currentDir   = -1;
        m_currentAlpha = 255;
      }  
    }
  } // if (IDC_CYCLIC == m_currentBlinkAlgo)
  else
  {
    int threshold = 0;
    
    switch (m_currentBlinkAlgo)
    {
      case IDC_BLINK_ALGO_FALLTO_020:
           threshold = (int) ((float) 255 / (float) 100 * (float) 20);
           break;
      case IDC_BLINK_ALGO_FALLTO_040:
           threshold = (int) ((float) 255 / (float) 100 * (float) 40);
           break;
      case IDC_BLINK_ALGO_FALLTO_060:
           threshold = (int) ((float) 255 / (float) 100 * (float) 60);
           break;
      case IDC_BLINK_ALGO_FALLTO_080:
           threshold = (int) ((float) 255 / (float) 100 * (float) 80);
           break;
    }
    
    m_currentAlpha += 8 * m_currentDir;
    if (threshold >= m_currentAlpha)
    {
      m_currentAlpha = threshold;
      m_currentDir   = 0;
    }  
  }

  if (true == doUpdate)
    SetLayeredWindowAttributes (m_hwndToolWindow, RGB (0x80, 0x80, 0x80), m_currentAlpha, LWA_ALPHA);
    
  return 0;  
} // repaintWindow

LRESULT paintWindow (HWND hwnd)
{
  PAINTSTRUCT ps; 
  HDC         hdc = BeginPaint (hwnd, &ps); 
  
  RECT        wndRect;
  
  GetClientRect (hwnd, &wndRect);
  FillRect (hdc, &wndRect, m_bkgBrush);
  
  HGDIOBJ     oldFont    = SelectObject (hdc, m_toolFont);
  int         prevBkMode = SetBkMode (hdc, TRANSPARENT);
  
  wchar_t*    captionToolWindow = getCaptionText ();
  
  SIZE        textSize;
  int         textLen = lstrlenW (captionToolWindow);
  GetTextExtentPoint32W (hdc, captionToolWindow, textLen, &textSize);
  TextOutW (hdc, wndRect.right / 2 - textSize.cx / 2, wndRect.bottom / 2 - textSize.cy / 2, captionToolWindow, textLen);
  
  SetBkMode (hdc, prevBkMode);
  SelectObject (hdc, oldFont);
  
  EndPaint (hwnd, &ps); 
  
  return 0;
} // paintWindow

LRESULT checkForegroundWindow ()
{
  HWND hwnd = GetForegroundWindow ();
  if (hwnd == m_hwndToolWindow || hwnd == m_hwndButtonWindow)
  {
    if (FALSE == IsWindowVisible (m_hwndForeground))
      resetCurrentMarkedObjects ();

    return 0;
  }  
//debugString ((L"\nGsWui::checkForegroundWindow (): foreground wnd = %08x", hwnd));    
  if (NULL != hwnd && TRUE == IsWindowVisible (hwnd))
  {
    if (0 == m_disableMenu.value ())
    {
      SetWindowPos (m_hwndToolWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
      SetWindowPos (m_hwndButtonWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
    }  
    
    RECT wndRect;
    BOOL result = GetWindowRect (hwnd, &wndRect);
        
    GesRule::ModelType processState = GesRule::modThreatPoint;
    DWORD threadId  = GetWindowThreadProcessId (hwnd, &m_currentMarkedProcessId);
    
    if (true == m_need_reload_setting && false == m_colors.is_trusted_state (processState))
    {
      m_need_reload_setting = false;
      m_colors.reloadSetting ();
      
      config::Configurator::PtrToINode node = config::Configurator::getProcessMarkerNode();
	  
	  if (node->checkValue(L"CaptionMenu16") == false)
		m_enable_caption_button = true;
	  else
		m_enable_caption_button = node->getBool(L"CaptionMenu16");

      int algo;
	  if (0 <= (algo = node->getInt (L"BlinkAlgorithm")))
	    refresh_blink_algo (static_cast <BlinkAlgo> (algo));
	  else
	    node->setInt (L"BlinkAlgorithm", get_blink_algo ());
    }
    
    
#ifdef _USE_GSWDRV_    
    processState = m_gswDrv->GetSubjIntegrity (m_currentMarkedProcessId); // get process state
#endif // _USE_GSWDRV_    
    
    m_colors.refreshCurrentColor (processState);
    
    COLORREF currentColor = m_colors.getCurrentColor ();
    if (
           m_hwndForeground        != hwnd 
//        || currentColor            != m_currentColor
        || m_currentWndRect.bottom != wndRect.bottom
        || m_currentWndRect.left   != wndRect.left
        || m_currentWndRect.right  != wndRect.right
        || m_currentWndRect.top    != wndRect.top
       )
    {
      m_currentWndRect = wndRect;
      
//debugString ((L"\nGsWui::checkForegroundWindow (): foreground wnd = %08x, m_hwndForeground = %08x", hwnd, m_hwndForeground));
      //if (m_colors.getTrustedColor () != currentColor)
      if (false == m_colors.is_trusted_state (processState))
      {
        refreshBrush ();
        
        UINT flags       = SWP_NOACTIVATE | SWP_SHOWWINDOW;
        RECT marker_rect = wndRect;
        
        marker_rect.bottom = marker_rect.top + getWindowHeight (hwnd);
        
        if (IDC_BLINK_ALGO_DISABLE == m_currentBlinkAlgo)
        {
            marker_rect.bottom = marker_rect.top + 1;
            marker_rect.right  = marker_rect.left + 1;
        }
            
        result = 
            SetWindowPos (
                m_hwndToolWindow, 
                HWND_TOPMOST, 
                marker_rect.left, 
                marker_rect.top, 
                marker_rect.right - marker_rect.left, 
                marker_rect.bottom - marker_rect.top, 
                flags
            );
        
        if (true == m_enable_caption_button)
        {
            int   cx_size = GetSystemMetrics (SM_CXSIZE) - 2;
            int   cy_size = getWindowHeight (hwnd) - 1 * getFrameHeight (hwnd) - 4;
            POINT bitmap_size = { 0 };
            
            get_bitmap_info (cy_size, bitmap_size);
            if (bitmap_size.x < cx_size || bitmap_size.y < cy_size)
            {
                cx_size = bitmap_size.x;
                cy_size = bitmap_size.y;
            }
                
            
            ::SetWindowPos (
                m_hwndButtonWindow, 
                HWND_TOPMOST, 
                wndRect.right - (1 + get_caption_button_count (hwnd)) * GetSystemMetrics (SM_CXSIZE) - GetSystemMetrics (SM_CXSIZE) / 2, 
                wndRect.top + getFrameHeight (hwnd) + 1, 
                (cx_size > cy_size) ? cy_size : cx_size, 
                cy_size, 
                flags
            );
            MoveWindow (m_hwndButton, 0, 0, (cx_size > cy_size) ? cy_size : cx_size, cy_size, TRUE);
            //SetWindowPos (m_hwndButton, HWND_NOTOPMOST, 0, 0, 50, getWindowHeight (hwnd) - 2 * getFrameHeight (hwnd), flags);
        }
        
        m_currentDir   = -1;
        m_currentAlpha = 255;
        SetLayeredWindowAttributes (m_hwndToolWindow, RGB (0x80, 0x80, 0x80), m_currentAlpha, LWA_ALPHA);
        
        if (FALSE == result)
        {
          resetCurrentMarkedObjects ();
          return 0;
        }
      }
      else
      {
        resetCurrentMarkedObjects ();
        return 0;
      }
    } // if (m_hwndForeground != hwnd || currentColor != m_currentColor)
  } // if (NULL != hwnd)
  else
  {
    resetCurrentMarkedObjects ();
    return 0;
  }
  
  m_hwndForeground = hwnd;
  return 0;
} // checkForegroundWindow

LRESULT sendMessage (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  LRESULT result;
  
  if (TRUE == IsWindowUnicode (hwnd))
    result = SendMessageW (hwnd, message, wParam, lParam);
  else
    result = SendMessageA (hwnd, message, wParam, lParam);
    
  return result;  
} // sendMessage

BOOL postMessage (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  BOOL result;
  
  if (TRUE == IsWindowUnicode (hwnd))
    result = PostMessageW (hwnd, message, wParam, lParam);
  else
    result = PostMessageA (hwnd, message, wParam, lParam);
    
  return result;  
} // postMessage

//LRESULT passThoughtMessage (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
//{
//  LRESULT result = 0;
//  
//  if (NULL != m_hwndForeground && TRUE == IsWindowVisible (m_hwndForeground))
//  {
//    POINT coords;
//    
//    coords.x = GET_X_LPARAM (lParam);
//    coords.y = GET_Y_LPARAM (lParam);
//    ClientToScreen (hwnd, &coords);
//    
//    switch (message)
//    {
//      case WM_NCHITTEST:
//           result = sendMessage (m_hwndForeground, WM_NCHITTEST, 0, lParam);
//           if (HTCAPTION == result)
//             result = DefWindowProc (hwnd, message, wParam, lParam);
//      case WM_LBUTTONDBLCLK:
//           postMessage (m_hwndForeground, WM_NCLBUTTONDBLCLK, sendMessage (m_hwndForeground, WM_NCHITTEST, 0, MAKELPARAM (coords.x, coords.y)), MAKELPARAM (coords.x, coords.y));
//           break;
//      case WM_LBUTTONDOWN:
//debugString ((L"\nGsWui::passThoughtMessage (): WM_LBUTTONDOWN"));          
//           //SetCapture (hwnd);
//           postMessage (m_hwndForeground, WM_NCLBUTTONDOWN, sendMessage (m_hwndForeground, WM_NCHITTEST, 0, MAKELPARAM (coords.x, coords.y)), MAKELPARAM (coords.x, coords.y));
//           //SetForegroundWindow (m_hwndForeground);
//           //SetCapture (hwnd);
//           break;
//      case WM_LBUTTONUP:
//debugString ((L"\nGsWui::passThoughtMessage (): WM_LBUTTONUP"));
//           //postMessage (m_hwndForeground, WM_NCLBUTTONDOWN, sendMessage (m_hwndForeground, WM_NCHITTEST, 0, MAKELPARAM (coords.x, coords.y)), MAKELPARAM (coords.x, coords.y));
//           postMessage (m_hwndForeground, WM_NCLBUTTONUP, sendMessage (m_hwndForeground, WM_NCHITTEST, 0, MAKELPARAM (coords.x, coords.y)), MAKELPARAM (coords.x, coords.y));
//           //ReleaseCapture ();
//           break;     
//      case WM_NCLBUTTONDBLCLK:     
//           postMessage (m_hwndForeground, WM_NCLBUTTONDBLCLK, sendMessage (m_hwndForeground, WM_NCHITTEST, 0, lParam), lParam);
//           break;     
//      case WM_NCLBUTTONDOWN:
//           postMessage (m_hwndForeground, WM_NCLBUTTONDOWN, sendMessage (m_hwndForeground, WM_NCHITTEST, 0, lParam), lParam);
//           break;
//      case WM_NCLBUTTONUP:
//debugString ((L"\nGsWui::passThoughtMessage (): WM_NCLBUTTONUP"));
//           ReleaseCapture ();
//           postMessage (m_hwndForeground, WM_NCLBUTTONUP, sendMessage (m_hwndForeground, WM_NCHITTEST, 0, lParam), lParam);
//           break;
//      
//    } // switch (message)
//  
//    //if (FALSE == PostMessage (m_hwndForeground, message, wParam, lParam))
//    //  debugString ((L"\nGsWui::passThoughtMessage (): ERROR"));    
//  }
//  
//  return result;
//} // passThoughtMessage

void refreshBrush ()
{
  if (m_colors.getCurrentColor () != m_currentColor || NULL == m_bkgBrush)
  {
    if (NULL != m_bkgBrush)
      DeleteObject (m_bkgBrush);
    m_currentColor = m_colors.getCurrentColor ();
    m_bkgBrush     = CreateSolidBrush (m_currentColor);
  }
} // refreshBrush

wchar_t* getCaptionText ()
{
  if (m_colors.getUntrustedColor () == m_colors.getCurrentColor ())
    return untrustedCaption;
    
  if (m_colors.getIsolatedColor () == m_colors.getCurrentColor ())
    return isolatedCaption;  
    
  return trustedCaption;  
} // getCaptionText

int getWindowHeight (HWND hwnd)
{
   LONG style  = GetWindowLongW (hwnd, GWL_STYLE);
   int  height = GetSystemMetrics (SM_CYCAPTION);
   
   if (
          WS_THICKFRAME == (style & WS_THICKFRAME)
       || DS_MODALFRAME == (style & DS_MODALFRAME)
      )
     height += GetSystemMetrics (SM_CYSIZEFRAME);
   
   if (WS_BORDER == (style & WS_BORDER))
     height += GetSystemMetrics (SM_CYBORDER);

   return height;
} // getWindowHeight

int getFrameHeight (HWND hwnd)
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

   return height;
} // getFrameHeight

HFONT createAnyFont (int orientation, BYTE charSet, BYTE italic, wchar_t* faceName, int height, int width)
{
  LOGFONTW lf;
  memset (&lf,0,sizeof(LOGFONT));

  lstrcpy (lf.lfFaceName, faceName);
  
  lf.lfOrientation = lf.lfEscapement = orientation;
  lf.lfCharSet     = charSet;
  lf.lfItalic      = italic;
  lf.lfHeight      = height;
  lf.lfWidth       = width;
  
  return CreateFontIndirect (&lf);
} // createAnyFont

void onShowIsolatedDirectory (HWND hwnd)
{
  disable_menu disableMenu (m_disableMenu);
  if (0 != disableMenu.m_prevValue)
    return;
    
  DialogBox (m_globalInstance, MAKEINTRESOURCE (IDD_DIALOG_SELECT_ISOLATED_DIR), hwnd, showDirDialogProc);
} // onShowIsolatedDirectory

BOOL CALLBACK showDirDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  switch(uMsg)
  {
    case WM_INITDIALOG:
         return showDirInitDialog (hwndDlg);
    case WM_COMMAND:
         switch(wParam)
         {
           case IDOK:
                showDirCloseDialog (hwndDlg);
                EndDialog(hwndDlg, TRUE);
                return TRUE;
           case IDCANCEL:
                //CloseDialog (hwndDlg);
                EndDialog(hwndDlg, TRUE);
                return TRUE;     
           case IDC_BUTTON_DIR_BROWSE:     
                onSelectIsolatedDirectory (hwndDlg);
                return TRUE;
         }
         break;
    case WM_CLOSE:
         PostMessage (hwndDlg, WM_COMMAND, IDOK, 0);
         break;
  }
  return FALSE;
} // showDirDialogProc

BOOL showDirInitDialog (HWND hwnd)
{
#pragma message (__WARNING__"TODO init show dir dialog")
  return TRUE;
} // showDirInitDialog

void showDirCloseDialog (HWND hwnd)
{

#pragma message (__WARNING__"TODO get result show dir dialog")
} // showDirCloseDialog

void onSelectIsolatedDirectory (HWND hwnd)
{
  if (false == m_comInitialized)
    m_comInitialized = (S_OK  == CoInitializeEx (NULL, COINIT_APARTMENTTHREADED));
    
  LPMALLOC iMalloc = NULL;  
  if (true == m_comInitialized && NOERROR == SHGetMalloc (&iMalloc))
  {
    wchar_t     displayName [MAX_PATH];
    BROWSEINFOW bi;
    
    bi.hwndOwner      = hwnd;
    bi.pidlRoot       = NULL;
    bi.pszDisplayName = displayName;
    bi.lpszTitle      = L"Select isolated directory";
    bi.ulFlags        = BIF_RETURNONLYFSDIRS | BIF_DONTGOBELOWDOMAIN | BIF_NONEWFOLDERBUTTON;
    bi.lpfn           = NULL;
    bi.lParam         = 0;
    bi.iImage         = 0;
    
    LPITEMIDLIST itemList = SHBrowseForFolderW (&bi);
    if (NULL != itemList)
    {
      SHGetPathFromIDListW (itemList, displayName); // convert pidl to path
      iMalloc->Free (itemList);
      
      SetWindowTextW (GetDlgItem (hwnd, IDC_EDIT_DIRECTORY), displayName);  
    } // if (NULL != itemList)
    
    iMalloc->Release ();
  }
} // onSelectIsolatedDirectory

void resetCurrentMarkedObjects ()
{
  m_currentMarkedProcessId = -1;
  m_hwndForeground         = NULL;
  ShowWindow (m_hwndToolWindow, SW_HIDE);
  
  ShowWindow (m_hwndButtonWindow, SW_HIDE);
} // resetCurrentMarkedObjects

void refreshBlink (int command)
{
  m_currentDir       = -1;
  m_currentAlpha     = 255;
  m_currentBlinkAlgo = command;
} // refreshBlink

bool RestartAsNonIsolated(DWORD ProcessId)
{
  if (-1 == ProcessId)
    return false;
	//
	// get application's full path and params
	// we can not retrieve this information from the process itself as it is untrusted
	// so we use trusted info from driver
	//
	wchar_t NativeExecName[MAX_PATH];
	if ( !m_gswDrv->GetNativeExecName(ProcessId, NativeExecName, sizeof NativeExecName) ) return false;
	std::wstring ExecName = commonlib::Tools::FullNameToDOSName(NativeExecName);

	DWORD ParentPid = nttools::GetParentProcessId(ProcessId);
	EntityAttributes Attributes, ParentAttributes;
	memset(&Attributes, 0, sizeof Attributes);
	memset(&ParentAttributes, 0, sizeof ParentAttributes);
	ULONG RuleId, ParentRuleId;
	m_gswDrv->GetSubjAttributes(ProcessId, &Attributes, &RuleId);
	m_gswDrv->GetSubjAttributes(ParentPid, &ParentAttributes, &ParentRuleId);

	//
	// terminate children
	//
	HANDLE FSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 FProcessEntry32;
	FProcessEntry32.dwSize = sizeof(FProcessEntry32);

	bool ContinueLoop = Process32First(FSnapshotHandle, &FProcessEntry32) == TRUE;
	while ( ContinueLoop ) {
		if ( FProcessEntry32.th32ParentProcessID == ProcessId && m_gswDrv->GetSubjIntegrity(FProcessEntry32.th32ProcessID) != GesRule::modTCB ) {
			commonlib::SlayProcess(FProcessEntry32.th32ProcessID);
			break;
		}
		ContinueLoop = Process32Next(FSnapshotHandle, &FProcessEntry32) == TRUE;
	}
	CloseHandle(FSnapshotHandle);

	//
	// Terminate the process
	//
	commonlib::SlayProcess(ProcessId);

	//
	// Terminate parent
	//
	if ( Attributes.Param[GesRule::attSubjectId] == ParentAttributes.Param[GesRule::attSubjectId] && ParentAttributes.Param[GesRule::attIntegrity] < GesRule::modTCB ) {
		//
		// Also terminate parent if it has the same AppId and isolated.
		// This is required to properly terminate IE
		//
		commonlib::SlayProcess(ParentPid);
	}


	//
	// add modifier
	//
	gswui::gswclient_helper::get_client ().SetParamsModifier(modAlwaysTrusted, GetCurrentProcessId(), GetCurrentThreadId());
	//
	// CreateProcess
	//
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	if ( CreateProcess(ExecName.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) ) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	//
	// release modifier
	//
	gswui::gswclient_helper::get_client ().SetParamsModifier(modRemove, GetCurrentProcessId(), GetCurrentThreadId());
	return true;
} // RestartAsNonIsolated

LONG get_window_long (HWND hwnd, int index)
{
  LONG result;
  
  if (TRUE == IsWindowUnicode (hwnd))
    result = GetWindowLongW (hwnd, index);
  else
    result = GetWindowLongA (hwnd, index);
    
  return result;  
} // get_window_long

int get_caption_button_count (HWND hwnd)
{
  LONG styles = get_window_long (hwnd, GWL_STYLE);
  int  count  = 3;
  //int  count  = 1;
  //
  //if (WS_MAXIMIZEBOX == (WS_MAXIMIZEBOX & styles))
  //  ++count;
  //  
  //if (WS_MINIMIZEBOX == (WS_MINIMIZEBOX & styles))
  //  ++count;  
    
  styles = get_window_long (hwnd, GWL_EXSTYLE);
  
  if (WS_EX_CONTEXTHELP == (WS_EX_CONTEXTHELP & styles))
    ++count;  
    
  if (WS_EX_TOOLWINDOW == (WS_EX_TOOLWINDOW & styles))
    count -= 2;  
    
  return count;
} // get_caption_button_count

void create_reexec_button (HWND parent_hwnd)
{
  wchar_t*    className  = L"GsWUIToolWindow_ReexecButton";
  
  WNDCLASS    wndclass;

  ZeroMemory (&wndclass, sizeof(wndclass));
  wndclass.style         = CS_SAVEBITS | CS_DBLCLKS;
  wndclass.lpfnWndProc   = reexec_button_wndproc;
  wndclass.cbClsExtra    = 0;
  wndclass.cbWndExtra    = 0;
  wndclass.hInstance     = m_globalInstance;
  wndclass.hIcon         = NULL;
  wndclass.hCursor       = LoadCursor (NULL, IDC_ARROW);
  wndclass.hbrBackground = (HBRUSH) COLOR_BACKGROUND;
  wndclass.lpszMenuName  = NULL;
  wndclass.lpszClassName = className;

  if (0 != ::RegisterClassW (&wndclass))
  {
    RECT rect = { 0 };
    GetClientRect (parent_hwnd, &rect);
      
    m_hwndButtonWindow = CreateWindowExW (
      WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE, 
      className, 
      L"", 
      /*WS_VISIBLE | WS_BORDER | */WS_POPUP, 
      0, 
      0, 
      GetSystemMetrics (SM_CXSIZE), 
      GetSystemMetrics (SM_CYSIZE), 
      parent_hwnd, 
      NULL, 
      reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLong (parent_hwnd, GWL_HINSTANCE))), 
      NULL
    );
    
    if (NULL != m_hwndButtonWindow)
    {
      m_hwndButton = CreateWindowW (
        L"BUTTON",   // predefined class 
          L"G",       // button text 
          WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_OWNERDRAW,// | BS_ICON,  // styles 
        // Size and position values are given explicitly, because 
        // the CW_USEDEFAULT constant gives zero values for buttons. 
        0,           // starting x position 
        0,           // starting y position 
        GetSystemMetrics (SM_CXSIZE), // button width 
        GetSystemMetrics (SM_CYSIZE), // button height 
        m_hwndButtonWindow, // parent window 
        reinterpret_cast <HMENU> (IDC_SHOW_MENU),     // No menu 
        reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLong (parent_hwnd, GWL_HINSTANCE))), 
        NULL         // pointer not needed 
      );       
      
      //m_menu_button_picture = LoadBitmapW (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLong (parent_hwnd, GWL_HINSTANCE))), MAKEINTRESOURCE (IDB_BITMAP1/*_BUTTON*/)); 
      
      m_menu_button_picture = (HBITMAP) ::LoadImageW (
          reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLong (parent_hwnd, GWL_HINSTANCE))),
          MAKEINTRESOURCE (IDB_BITMAP_BUTTON),
          IMAGE_BITMAP, 
          0, 
          0, 
          LR_DEFAULTCOLOR
      );
      
      m_menu_button_picture_small = (HBITMAP) ::LoadImageW (
          reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLong (parent_hwnd, GWL_HINSTANCE))),
          MAKEINTRESOURCE (IDB_BITMAP_BUTTON_SMALL),
          IMAGE_BITMAP, 
          0, 
          0, 
          LR_DEFAULTCOLOR
      );
      
      HDC        hdc_wnd  = GetDC (m_hwndButton); 
      HDC        hdc_mem  = CreateCompatibleDC (hdc_wnd); 
      BITMAPINFO bmp_info = { 0 };
  
      bmp_info.bmiHeader.biSize = sizeof (BITMAPINFOHEADER);
      GetDIBits (hdc_mem, m_menu_button_picture, 0, 0, NULL, &bmp_info, DIB_RGB_COLORS);
      
      m_button_size.x = bmp_info.bmiHeader.biWidth;
      m_button_size.y = bmp_info.bmiHeader.biHeight;
      
      memset (&bmp_info, 0, sizeof (bmp_info));
      bmp_info.bmiHeader.biSize = sizeof (BITMAPINFOHEADER);
      GetDIBits (hdc_mem, m_menu_button_picture_small, 0, 0, NULL, &bmp_info, DIB_RGB_COLORS);
      
      m_button_small_size.x = bmp_info.bmiHeader.biWidth;
      m_button_small_size.y = bmp_info.bmiHeader.biHeight;
      
      DeleteDC (hdc_mem);
      ReleaseDC (m_hwndButton, hdc_wnd);
      
      //::SendMessageW (m_hwndButton, BM_SETIMAGE, IMAGE_ICON, (LPARAM) icon);
    }
  }
} // create_reexec_button

LRESULT paint_reexec_button_window (HWND hwnd)
{
  //PAINTSTRUCT ps; 
  //HDC         hdc = BeginPaint (hwnd, &ps); 
  //
  //RECT        wndRect;
  //
  //GetClientRect (hwnd, &wndRect);
  //FillRect (hdc, &wndRect, m_bkgBrush);
  //
  //HGDIOBJ     oldFont    = SelectObject (hdc, m_toolFont);
  //int         prevBkMode = SetBkMode (hdc, TRANSPARENT);
  //
  //wchar_t*    captionToolWindow = getCaptionText ();
  //
  //SIZE        textSize;
  //int         textLen = lstrlenW (captionToolWindow);
  //GetTextExtentPoint32W (hdc, captionToolWindow, textLen, &textSize);
  //TextOutW (hdc, wndRect.right / 2 - textSize.cx / 2, wndRect.bottom / 2 - textSize.cy / 2, captionToolWindow, textLen);
  //
  //SetBkMode (hdc, prevBkMode);
  //SelectObject (hdc, oldFont);
  //
  //EndPaint (hwnd, &ps); 
  
  return 0;
} // paint_reexec_button_window

HBITMAP get_bitmap_info (int wnd_height, POINT& bitmap_size)
{
  HBITMAP bitmap = m_menu_button_picture;
  
  bitmap_size = m_button_size;
  
  if (17 > wnd_height)
  {
      bitmap      = m_menu_button_picture_small;
      bitmap_size = m_button_small_size;
  }
  
  return bitmap;
} // get_bitmap_info

void  paint_reexec_button (LPDRAWITEMSTRUCT draw_info)
{
  if (ODA_DRAWENTIRE != draw_info->itemAction)
    return;
  
  POINT      bitmap_size = { 0 };
  HBITMAP    bitmap      = get_bitmap_info (draw_info->rcItem.bottom - draw_info->rcItem.top, bitmap_size);
  HDC        hdc_mem     = CreateCompatibleDC (draw_info->hDC); 
  
  HGDIOBJ old_obj = SelectObject (hdc_mem, bitmap);
  
  StretchBlt (
      draw_info->hDC, 
      draw_info->rcItem.left, 
      draw_info->rcItem.top, 
      draw_info->rcItem.right - draw_info->rcItem.left, 
      draw_info->rcItem.bottom - draw_info->rcItem.top, 
      hdc_mem, 
      0, 
      0, 
      bitmap_size.x,
      bitmap_size.y,
      SRCCOPY
  ); 

  SelectObject (hdc_mem, old_obj);
  DeleteDC (hdc_mem); 
} // paint_reexec_button

bool refresh_blink_algo (BlinkAlgo algo)
{
  switch (algo)
  {
    case BlinkAlgoCyclic:
         refreshBlink (IDC_BLINK_ALGO_CYCLIC);
         return true;
    case BlinkAlgoFallTo20:
         refreshBlink (IDC_BLINK_ALGO_FALLTO_020);
         return true;
    case BlinkAlgoFallTo40:
         refreshBlink (IDC_BLINK_ALGO_FALLTO_040);
         return true;
    case BlinkAlgoFallTo60:
         refreshBlink (IDC_BLINK_ALGO_FALLTO_060);
         return true;
    case BlinkAlgoFallTo80:
         refreshBlink (IDC_BLINK_ALGO_FALLTO_080);
         return true;
    case BlinkAlgoDisable:
         refreshBlink (IDC_BLINK_ALGO_DISABLE);
         return true;     
  }
  
  return false;
} // refresh_blink_algo


} // namespace toolwnd {
} // namespace gswui {
