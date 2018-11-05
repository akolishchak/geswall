//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "windowsx.h"
#include "reqdlg.h"
#include "licensedlg.h"
#include "logcount.h"
#include "resource1.h"

#include "gswclient_helper.h"
#include "gswuieventlog.h"

#include "processmarker/modulestub.h"
#include "processexecutor/processexecutor.h"

#include "commonlib/commondefs.h"
#include "commonlib/thread.h"
#include "commonlib/debug.h"
#include "config/configurator.h"
#include "toolwnd/toolwnd.h"
//#include "logwnd/logwnd.h"
#include "commonlib/exceptions.h"
#include "db/storage.h"

#include "update/update.h"
#include "notificator.h "
#include "license/licensemanager.h"
#include "trialmanager.h"

#include <string>

#include <io.h>

using namespace std;

#ifdef _CB_TEST_DEBUG_
 #pragma message (__WARNING__"this is cb.test.debug configurations")
 
 #include "attackfilter/process_manager.h"
#endif // _CB_TEST_DEBUG_ 

//#ifndef _CB_TEST_DEBUG_
//  #define _USE_HOOK_WINDOWS_
//#endif // _CB_TEST_DEBUG_  

#ifdef _USE_HOOK_WINDOWS_
 void hook ();
 void unhook ();
#endif //_USE_HOOK_WINDOWS_

typedef commonlib::thread WorkThread;

using commonlib::PtrToWcharArray;
using commonlib::Exception;
using commonlib::IOException;
using commonlib::OutOfMemoryException;
using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;
using commonlib::sguard::make_guard_chk;
using commonlib::sguard::is_null_equal;
using commonlib::sguard::is_null_non_equal;

using update::UpdateResult;

typedef BOOL (WINAPI *CREATEPROCESSINTERNALPTR_XP) (IN DWORD Unknown1, IN LPCWSTR lpApplicationName, IN LPWSTR lpCommandLine, IN LPSECURITY_ATTRIBUTES lpProcessAttributes, IN LPSECURITY_ATTRIBUTES lpThreadAttributes, IN BOOL bInheritHandles, IN DWORD dwCreationFlags, IN LPVOID lpEnvironment, IN LPCWSTR lpCurrentDirectory, IN LPSTARTUPINFOW lpStartupInfo, OUT LPPROCESS_INFORMATION lpProcessInformation, IN DWORD Unknown2);
typedef BOOL (WINAPI *CREATEPROCESSINTERNALPTR_2K) (IN DWORD Unknown1, IN LPCWSTR lpApplicationName, IN LPWSTR lpCommandLine, IN LPSECURITY_ATTRIBUTES lpProcessAttributes, IN LPSECURITY_ATTRIBUTES lpThreadAttributes, IN BOOL bInheritHandles, IN DWORD dwCreationFlags, IN LPVOID lpEnvironment, IN LPCWSTR lpCurrentDirectory, IN LPSTARTUPINFOW lpStartupInfo, OUT LPPROCESS_INFORMATION lpProcessInformation);


int      work_thread ();
bool     register_window_class (HINSTANCE instance, wchar_t* className);
void     window_dispatch (HINSTANCE hInstance);
void     tray_icon_init (HWND hwnd);
void     icon_hint_change (HWND hwnd);
void     tray_icon_destroy (HWND hwnd);
void     on_notify_icon (HWND hwnd, LPARAM lParam);
int      blink_algo2command (gswui::toolwnd::BlinkAlgo algo);
gswui::toolwnd::BlinkAlgo command2blink_algo (int command);
LRESULT  track_tray_menu (HWND hwnd);
LRESULT  on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify);
LRESULT  check_chk_update (HWND hwnd);
LRESULT  check_update (HWND hwnd);
LRESULT  check_update (HWND hwnd, UpdateResult update_db_result);
LRESULT  check_periodic_update (HWND hwnd);
LRESULT  check_chk_update (HWND hwnd, UpdateResult check_update_db_result);
bool check_license(HWND hwnd);

enum {
    PeriodicInit,
    UserInit
};

void     start_update_db (HWND hwnd, int init);
void     start_check_update_db (HWND hwnd, int init);
const wchar_t* decode_update_result (UpdateResult result);
bool RedirectToUrl(const wchar_t *Method);
void MessageBaloon(HWND hwnd, const wchar_t *Title, const wchar_t *Message);

static LRESULT CALLBACK wndProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

bool hintchange=true;
HICON      m_icon_logo                 = NULL;
HICON      m_icon_update               = NULL;
HICON	   m_icon_disabled_policy	   = NULL;
HICON	   m_icon_enabled_policy	   = NULL;
HICON	   m_icon_disabled_policy_w2k  = NULL;
HICON	   m_icon_enabled_policy_w2k   = NULL;

UINT_PTR   m_update_timer_id           = 1;
UpdateResult m_update_db_result        = update::UpdateNotRequired;

UINT_PTR   m_check_update_timer_id     = 2;
UpdateResult m_check_update_db_result  = update::UpdateNotRequired;

UINT       m_taskbar_restart_msg       = 0;

UINT_PTR   m_periodic_update_timer_id  = 3;
int        m_periodic_update_counter   = 0;
bool       m_force_update              = true;
UpdateResult m_periodic_update_db_result     = update::UpdateNotRequired;
UpdateResult m_periodic_chk_update_db_result = update::UpdateNotRequired;

CREATEPROCESSINTERNALPTR_XP m_create_process_internal_xp_ptr = NULL;
CREATEPROCESSINTERNALPTR_2K m_create_process_internal_2k_ptr = NULL;

#define NOTIFYICON_ID 1
#define WM_NOTIFYICON (WM_USER+99) 

#define  IDC_UPDATE_DB                1000
#define  IDC_CHECK_UPDATE_DB          1001
#define  IDC_EXIT                     1099
#define  IDC_HIDE_MENU                1100
#define  IDC_REQUEST_NEW_APP          1101
#define  IDC_RUN_CONSOLE			  1102
#define  IDC_LICENSE				  1104
//#define  IDC_AUTOMATIC_PROCESS_TERM   1105
#define	 IDC_TERMINATION								1105
#define  IDC_TERMINATION_DETECTED						1106
#define  IDC_TERMINATION_ALL							1107
#define  IDC_TERMINATION_DETECTED_NEVER					1108
#define  IDC_TERMINATION_DETECTED_AUTO					1109
#define  IDC_TERMINATION_DETECTED_INTERACTIVE_IGNORE	1110
#define  IDC_TERMINATION_DETECTED_INTERACTIVE_TERMINATE	1111

#define  IDC_ENABLE_CAPTION_BUTTON    1199
#define  IDC_SET_UNTRUSTED_COLOR      1200
#define  IDC_SET_ISOLATED_COLOR       1201
#define  IDC_SET_BLINK_ALGO           1202
#define  IDC_SET_ISOLATED_DIR         1203
#define  IDC_BLINK_ALGO_CYCLIC        1303
#define  IDC_BLINK_ALGO_FALLTO_020    1304
#define  IDC_BLINK_ALGO_FALLTO_040    1305
#define  IDC_BLINK_ALGO_FALLTO_060    1306
#define  IDC_BLINK_ALGO_FALLTO_080    1307
#define  IDC_BLINK_ALGO_DISABLE       1308

//#define  IDC_SET_LOG_WND_COLOR        1400
#define  IDC_LOG_NOTIFY               1400
#define  IDC_LOG_NOTIFY_ENABLE_ALL    1401
#define  IDC_LOG_NOTIFY_COLOR         1402
#define  IDC_LOG_NOTIFY_ENABLE_FILES  1403
#define  IDC_LOG_NOTIFY_DISABLE	      1404
#define  IDC_EXPOSURE_TIME			  1405
#define  IDC_EXPOSURE_TIME_1S		  1406
#define  IDC_EXPOSURE_TIME_2S		  1407
#define  IDC_EXPOSURE_TIME_3S		  1408
#define  IDC_EXPOSURE_TIME_4S		  1409
#define  IDC_EXPOSURE_TIME_5S		  1410
#define  IDC_LOG_NOTIFY_ENABLE_FILES_REGISTRY 1411

#define  IDC_LOG_ATTACK_NOTIFY        1500
#define  IDC_LOG_ATTACK_NOTIFY_ENABLE 1501
#define  IDC_LOG_ATTACK_NOTIFY_COLOR  1502
#define  IDC_LOG_ATTACK_NOTIFY_DISABLE 1503
#define  IDC_CONSOLE_STARTED		  1504
#define  IDC_DISABLE_POLICY			  1505
#define  IDC_ENABLE_POLICY			  1506

#define user_info L"Public"

HANDLE hTerminationEvent = NULL;
bool IsW2K = false;

int _stdcall WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
debugString ((L"\nStart GsWui"));
    hTerminationEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
	Storage::SetDBSetting(Node);
	license::LicenseManager::Refresh();

	OSVERSIONINFO VerInfo;
	VerInfo.dwOSVersionInfoSize = sizeof OSVERSIONINFO;
	if ( GetVersionEx(&VerInfo) && VerInfo.dwMajorVersion == 5 && VerInfo.dwMinorVersion == 0 ) IsW2K = true;

#ifdef _CB_TEST_DEBUG_
  gswui::attackfilter::process_manager pm;
  
  pm.add_process (L"test1", 1);
  pm.add_process (L"test2", 2);
  pm.add_process (L"test3", 3);
  pm.add_process (L"test3", 33);
  
  gswui::attackfilter::ptr_to_process_array proc_array1 = pm.get_processes ();
  gswui::attackfilter::ptr_to_process_array proc_array2 = pm.get_processes (L"test3");
  gswui::attackfilter::ptr_to_process_info  proc_info   = pm.get_process (2);
  
  for (int i = 0; NULL != proc_array1[i].get (); ++i)
  {
    debugString ((L"\nprocess_info: name = %s, process_id = %u", proc_array1[i]->name ().c_str (), proc_array1[i]->process_id ()));
  }

  for (int i = 0; NULL != proc_array2[i].get (); ++i)
  {
    debugString ((L"\nprocess_info: name = %s, process_id = %u", proc_array2[i]->name ().c_str (), proc_array2[i]->process_id ()));
  }
  
  pm.remove_process (L"test3");

//  client.RefreshApplications ();
//  return 0;
  try
  {
    window_dispatch (hInstance);
  
    //update::getDbUpdate (L"20050101", L"AA55AA55AA55AA55AA55", L"d:/tmp/dbupdate.bin");
    //update::getUpdate (L"file://D:/tmp/gsw/remote.test.bin", L"D:/tmp/gsw/local.test.bin");
    //update::updateDb (L"20050101", user_info, L"D:/tmp/gsw/db/public.bin");
    //update::applyDbUpdate (L"D:/tmp/gsw/db/data.sign", L"D:/tmp/gsw/db/db.chk", L"D:/tmp/gsw/db/public.bin");
  }
  catch (const Exception& e)
  {
debugString ((L"\nException: %s", e.getMessageAndCode ().c_str ()));
  }
  catch (...)
  {
  }

  Storage::close ();
  
  return 0;
#else
  
  //
  // Load settings
  //
  Node = config::Configurator::getUiNode();
  int WaitSecs = Node->getInt(L"UserWaitSecs");
  if ( WaitSecs > 0 && WaitSecs <= 5 ) WaitSecs = 6;
  if ( WaitSecs == 0 ) WaitSecs = UserWaitSecs;
  CReqDlg::WaitSecs = WaitSecs;

  GUIReply DefaultReply = (GUIReply) Node->getInt(L"DefaultGUIReply");
  if ( DefaultReply == gurUndefined ) DefaultReply = (GUIReply) DefaultGUIReply;
  CReqDlg::DefaultReply = DefaultReply;

  //
  WorkThread wrk_thread (&work_thread);

  window_dispatch (hInstance);
  
debugString ((L"\nEnd GsWui - wait end thread"));    
  wrk_thread.join ();
debugString ((L"\nEnd GsWui"));
  Storage::close ();
  return 0;
#endif // _CB_TEST_DEBUG_  
} // WinMain

void window_dispatch (HINSTANCE hInstance)
{
  wchar_t* className = L"GsWUINotificationWindow";
  register_window_class (hInstance, className);
  HWND hwnd = CreateWindowW (className, L"", WS_POPUP, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
  if (NULL != hwnd)
  {
    MSG  msg;
    UpdateWindow(hwnd);
    while (FALSE != GetMessage (&msg, 0, 0, 0))
    {
      TranslateMessage (&msg);
      DispatchMessage (&msg);
    } // while (TRUE == GetMessage (&msg, 0, 0, 0))
  } // if (NULL != hwnd)
} // window_dispatch

#ifdef _USE_HOOK_WINDOWS_
void hook ()
{
debugString ((L"\nGsWui::hook(): start"));  
  HMODULE procmarkerDll = LoadLibrary (L"procmarker.dll");
debugString ((L"\nGsWui::hook(): procmarkerDll = %08x", procmarkerDll));  
  if (NULL != procmarkerDll)
  {
    HOOK_PROC hook_proc = reinterpret_cast <HOOK_PROC> (GetProcAddress (procmarkerDll, "Hook"));
debugString ((L"\nGsWui::hook(): hook_proc = %08x", hook_proc));  
    if (NULL != hook_proc)
      hook_proc (0);
  }  
} // hook

void unhook ()
{
debugString ((L"\nGsWui::unhook(): start"));  
  HMODULE procmarkerDll = GetModuleHandle (L"procmarker.dll");
debugString ((L"\nGsWui::unhook(): procmarkerDll = %08x", procmarkerDll));  
  if (NULL != procmarkerDll)
  {
    UNHOOK_PROC unhook_proc = reinterpret_cast <UNHOOK_PROC> (GetProcAddress (procmarkerDll, "Unhook"));
debugString ((L"\nGsWui::unhook(): unhook_proc = %08x", unhook_proc));  
    if (NULL != unhook_proc)
      unhook_proc ();

//    FreeLibrary (procmarkerDll);
  }  
} // unhook
#endif //_USE_HOOK_WINDOWS_

struct thread_finalizer
{
  void operator () (WorkThread* thread)
  {
    if (NULL != thread)
    {
      gswui::gswclient_helper::get_client ().CancelCreateProcessWait (LongToHandle (GetCurrentProcessId ()));
      thread->join ();
      delete thread;
    }
  } // operator ()
}; // thread_finalizer

int work_thread ()
{
    HANDLE          globalObject  = NULL;
    wstring         objectName;
    HANDLE          hEvent        = NULL;
    int             maxRetryCount = 60;
    int             sleepTime     = 1000;
    ifstatus::Error resultCode    = ifstatus::errUnsuccess;
    
    HANDLE          eventLog      = ::RegisterEventSource (NULL, L"GsWui");
    scope_guard     event_log_guard = make_guard (eventLog, &::DeregisterEventSource);

    for (int i=0; i<maxRetryCount; ++i)
    {
      globalObject = OpenMutex (MUTEX_ALL_ACCESS, FALSE, ifstatus::GlobalObjectName);
      if (NULL != globalObject)
        break;
      Sleep (sleepTime);  
    }

    if (NULL == globalObject)
    {
      ReportEvent (eventLog, EVENTLOG_ERROR_TYPE, 0, WAIT_START_SERVICE_ERROR, NULL, 0, 0, NULL, NULL);
      //DeregisterEventSource (eventLog);
      return -1;
    }

    CloseHandle (globalObject);
    
    for (int i=0; i<maxRetryCount; ++i)
    {
      if (ifstatus::errSuccess == (resultCode = gswui::gswclient_helper::get_client ().QueryAuthorizationObject (LongToHandle (GetCurrentProcessId ()), objectName)))
        break;
      Sleep (sleepTime);  
    }  
    
    if (ifstatus::errSuccess != resultCode)
    {
      ReportEvent (eventLog, EVENTLOG_ERROR_TYPE, 0, QUERY_AUTHORIZATION_OBJECT_ERROR, NULL, 0, 0, NULL, NULL);
      //DeregisterEventSource (eventLog);
      return -1;
    }  
      
    for (int i=0; i<maxRetryCount; ++i)
    {
      if (NULL != (hEvent = CreateEvent (NULL, TRUE, FALSE, objectName.c_str ())))
        break;
      Sleep (sleepTime);    
    }
        
    if (NULL == hEvent)
    {
      ReportEvent (eventLog, EVENTLOG_ERROR_TYPE, 0, OPEN_AUTHORIZATION_OBJECT_ERROR, NULL, 0, 0, NULL, NULL);
      //DeregisterEventSource (eventLog);
      return -2;    
    }  
    
    for (int i=0; i<maxRetryCount; ++i)
    {
      if (ifstatus::errSuccess == (resultCode = gswui::gswclient_helper::get_client ().RegisterClient (LongToHandle (GetCurrentProcessId ()), hEvent, gswui::gswclient_helper::get_authority ())))
        break;
      Sleep (sleepTime);   
    }
    
    CloseHandle (hEvent);
    
    if (ifstatus::errSuccess != resultCode)
    {
      ReportEvent (eventLog, EVENTLOG_ERROR_TYPE, 0, REGISTER_CLIENT_ERROR, NULL, 0, 0, NULL, NULL);
      return -3;
    }  
    
    int            RequestId;
    GUIRequestInfo Request;
    
    while (ifstatus::errSuccess == gswui::gswclient_helper::get_client ().UiRequest (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority (), RequestId, Request))
    {
      GUIReply Reply = gurUndefined;
      CReqDlg Dlg;
      
      switch (Request.Type) 
      {
        case reqThreatPointSubject:
        case reqNotIsolateTracked:
             Reply = Dlg.Run((RequestType)Request.Type, Request.FileName1, Request.FileName2);
             break;

        case reqAccessSecretFile:
             Reply = Dlg.Run(Request.FileName1, Request.FileName2);
             break;
      }
      
      // get reply from dlg
      if (ifstatus::errSuccess != gswui::gswclient_helper::get_client ().PutReply (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority (), RequestId, Reply))
      {
        ReportEvent (eventLog, EVENTLOG_ERROR_TYPE, 0, PUT_REPLY_ERROR, NULL, 0, 0, NULL, NULL);
        break;
      }  
    }
    
    return 0;
} // work_thread

struct token_finalizer
{
  void operator () (HANDLE token)
  {
    if (NULL != token)
    {
      ::RevertToSelf ();
      ::CloseHandle (token);
    }  
  }
}; // token_finalizer

bool is_win2k (OSVERSIONINFOEXW& os_ver)
{
  return (5 == os_ver.dwMajorVersion && 0 == os_ver.dwMinorVersion);
} // is_win2k

bool is_winxp_and_above (OSVERSIONINFOEXW& os_ver)
{
  return (5 == os_ver.dwMajorVersion && 1 <= os_ver.dwMinorVersion);
} // is_winxp

bool register_window_class (HINSTANCE instance, wchar_t* className)
{
  WNDCLASS    wndclass;

  ZeroMemory (&wndclass, sizeof(wndclass));
  wndclass.style         = CS_SAVEBITS;
  wndclass.lpfnWndProc   = wndProc;
  wndclass.cbClsExtra    = 0;
  wndclass.cbWndExtra    = 0;
  wndclass.hInstance     = instance;
  wndclass.hIcon         = NULL;
  wndclass.hCursor       = LoadCursor (NULL, IDC_ARROW);
  wndclass.hbrBackground = (HBRUSH) COLOR_BACKGROUND;
  wndclass.lpszMenuName  = NULL;
  wndclass.lpszClassName = className;

  return (0 != ::RegisterClassW (&wndclass));
} // register_window_class

LRESULT CALLBACK wndProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
debugString ((L"\nGsWui::wndProc(): message = %08x", message));  
  switch (message)
  {
    case WM_CREATE:
		{
         m_icon_enabled_policy  = LoadIconW (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLongPtr (hwnd, GWLP_HINSTANCE))), MAKEINTRESOURCEW(IDI_ICON_LOGO));
         m_icon_update = LoadIconW (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLongPtr (hwnd, GWLP_HINSTANCE))), MAKEINTRESOURCEW(IDI_ICON_UPDATE_1));
         m_icon_disabled_policy = LoadIconW (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLongPtr (hwnd, GWLP_HINSTANCE))), MAKEINTRESOURCEW(IDI_ICON_DISABLED_POLICY));
         m_icon_enabled_policy_w2k  = LoadIconW (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLongPtr (hwnd, GWLP_HINSTANCE))), MAKEINTRESOURCEW(IDI_ICON_LOGO_W2K));
         m_icon_disabled_policy_w2k = LoadIconW (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLongPtr (hwnd, GWLP_HINSTANCE))), MAKEINTRESOURCEW(IDI_ICON_DISABLED_POLICY_W2K));
		 
		 config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
		 if ( Node.get() != NULL && Node->getInt(L"SecurityLevel") > GesRule::secLevel1 ) {
			 m_icon_logo = IsW2K ? m_icon_enabled_policy_w2k : m_icon_enabled_policy;
		 } else {
			 m_icon_logo = IsW2K ? m_icon_disabled_policy_w2k : m_icon_disabled_policy;
		 }

         m_periodic_update_timer_id = SetTimer (hwnd, m_periodic_update_timer_id, 60000, NULL);
         
         tray_icon_init (hwnd); 
#ifdef _USE_HOOK_WINDOWS_
         hook ();
#endif //_USE_HOOK_WINDOWS_
         //m_update_timer_id     = SetTimer (hwnd, m_update_timer_id, 500, NULL);
         m_taskbar_restart_msg = ::RegisterWindowMessageW (L"TaskbarCreated");
         
         gswui::toolwnd::create (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLongPtr (hwnd, GWLP_HINSTANCE))));
         gswui::notificator::create (reinterpret_cast <HINSTANCE> (LongToHandle (GetWindowLongPtr (hwnd, GWLP_HINSTANCE))), hTerminationEvent);
         break;
		}
    case WM_NOTIFYICON:
         switch (wParam)
         {
           case NOTIFYICON_ID:
                on_notify_icon (hwnd, lParam);
                break;
         }       
           
         break;     
    case WM_QUERYENDSESSION:
         gswui::gswclient_helper::get_client ().CancelUiRequest (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority ());
#ifdef _USE_HOOK_WINDOWS_
         unhook ();
#endif //_USE_HOOK_WINDOWS_
         break;
    case WM_ENDSESSION:
    case WM_CLOSE:
         gswui::gswclient_helper::get_client ().CancelUiRequest (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority ());
         SetEvent(hTerminationEvent);
#ifdef _USE_HOOK_WINDOWS_
         unhook ();
#endif //_USE_HOOK_WINDOWS_
         tray_icon_destroy (hwnd); 
         break;
    case WM_DESTROY:
         gswui::notificator::destroy ();
         gswui::toolwnd::destroy ();
    
         KillTimer (hwnd, m_update_timer_id);
#ifdef _USE_HOOK_WINDOWS_
         unhook ();
#endif //_USE_HOOK_WINDOWS_
         tray_icon_destroy (hwnd); 
         PostQuitMessage (0);
         break;
    case WM_TIMER:     
         if (static_cast <UINT_PTR> (wParam) == m_update_timer_id)
           return check_update (hwnd);
         if (static_cast <UINT_PTR> (wParam) == m_check_update_timer_id)
           return check_chk_update (hwnd);  
		 if (static_cast <UINT_PTR> (wParam) == m_periodic_update_timer_id) {
           return check_periodic_update (hwnd);
		 }
           
    case NIN_BALLOONUSERCLICK:
         if (update::UpdateAppAvailable == m_check_update_db_result)
           start_update_db (hwnd, UserInit);
         return 0;
           
    HANDLE_MSG (hwnd, WM_COMMAND, on_command);
    
    default:
         if (message == m_taskbar_restart_msg)
           tray_icon_init (hwnd); 
  }          

  return DefWindowProc (hwnd, message, wParam, lParam);
} // wndProc

void tray_icon_init (HWND hwnd)
{
  if (NULL != FindWindowW(L"Shell_TrayWnd", NULL))
  {
    NOTIFYICONDATAW   nd = { 0 }; 

    nd.cbSize           = sizeof (nd); 
    nd.hWnd             = hwnd;
    nd.uID              = NOTIFYICON_ID;
    nd.uCallbackMessage = WM_NOTIFYICON;
    nd.hIcon            = m_icon_logo;
    wcscpy (nd.szTip, L"GeSWall");
    nd.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;

    ::Shell_NotifyIconW (NIM_ADD, &nd);
    
    memset (&nd, 0, sizeof (nd));
    
    nd.cbSize           = sizeof (nd); 
    nd.hWnd             = hwnd;
    nd.uID              = NOTIFYICON_ID;
    nd.uVersion         = NOTIFYICON_VERSION;
    ::Shell_NotifyIconW (NIM_SETVERSION, &nd);
  }
} // tray_icon_init

void tray_icon_destroy (HWND hwnd)
{
  NOTIFYICONDATAW   nd; 

  nd.cbSize           = sizeof (nd); 
  nd.hWnd             = hwnd;
  nd.uID              = NOTIFYICON_ID;
  nd.uFlags           = 0;

  ::Shell_NotifyIconW (NIM_DELETE, &nd);
} // tray_icon_destroy

void on_notify_icon (HWND hwnd, LPARAM lParam)
{
    if (WM_RBUTTONDOWN == lParam || WM_LBUTTONDBLCLK == lParam )
    {
#ifndef _CB_TEST_DEBUG_
        license::LicenseManager::LicenseEssentials License;
        license::LicenseManager::LicenseCachedCopy(License);

        if ( License.Product != license::gswUnlicensed ) 
        {
            if ( TrialManager::Handle(TrialManager::eventTrayClick) ) 
                return;

            if ( WM_LBUTTONDBLCLK != lParam ) 
            {
                track_tray_menu(hwnd);
            } 
            else 
            {
                on_command(hwnd, IDC_RUN_CONSOLE, NULL, 0);
            }
        } 
        else 
        {
            MessageBaloon(hwnd, L"GeSWall License", L"Your GeSWall's license has been expired. \nPlease download new version from www.gentlesecurity.com");
        }
#else
        if ( WM_LBUTTONDBLCLK != lParam ) 
        {
            track_tray_menu(hwnd);
        } 
#endif // #ifdef _CB_TEST_DEBUG_	
    }
    else  
    {
        if ((hintchange)&(lParam==512))
        { 
            hintchange=false;
            icon_hint_change(hwnd);
        }
    }
} // on_notify_icon

gswui::toolwnd::BlinkAlgo command2blink_algo (int command)
{
  gswui::toolwnd::BlinkAlgo result = gswui::toolwnd::BlinkAlgoFallTo60;
  
  switch (command)
  {
    case IDC_BLINK_ALGO_CYCLIC:
         result = gswui::toolwnd::BlinkAlgoCyclic;
         break;
    case IDC_BLINK_ALGO_FALLTO_020:
         result = gswui::toolwnd::BlinkAlgoFallTo20;
         break;
    case IDC_BLINK_ALGO_FALLTO_040:
         result = gswui::toolwnd::BlinkAlgoFallTo40;
         break;
    case IDC_BLINK_ALGO_FALLTO_060:
         result = gswui::toolwnd::BlinkAlgoFallTo60;
         break;
    case IDC_BLINK_ALGO_FALLTO_080:
         result = gswui::toolwnd::BlinkAlgoFallTo80;
         break;
    case IDC_BLINK_ALGO_DISABLE:
         result = gswui::toolwnd::BlinkAlgoDisable;
         break;     
  }
  
  return result;
} // command2blink_algo

int blink_algo2command (gswui::toolwnd::BlinkAlgo algo)
{
  switch (algo)
  {
    case gswui::toolwnd::BlinkAlgoCyclic:
         return IDC_BLINK_ALGO_CYCLIC;
    case gswui::toolwnd::BlinkAlgoFallTo20:
         return IDC_BLINK_ALGO_FALLTO_020;
    case gswui::toolwnd::BlinkAlgoFallTo40:
         return IDC_BLINK_ALGO_FALLTO_040;
    case gswui::toolwnd::BlinkAlgoFallTo60:
         return IDC_BLINK_ALGO_FALLTO_060;
    case gswui::toolwnd::BlinkAlgoFallTo80:
         return IDC_BLINK_ALGO_FALLTO_080;
    case gswui::toolwnd::BlinkAlgoDisable:
         return IDC_BLINK_ALGO_DISABLE;     
  }
  
  return IDC_BLINK_ALGO_FALLTO_060;
} // blink_algo2command

LRESULT track_tray_menu (HWND hwnd)
{
  HMENU       menu       = CreatePopupMenu ();
  scope_guard menu_guard = make_guard_chk (menu, &::DestroyMenu, is_null_equal <HMENU, NULL> ());
  
  if (true == menu_guard.is_free ())
    return 0;
    
  POINT mousePos;
  if (FALSE == GetCursorPos (&mousePos))
    return 0;  
    
  UINT update_grayed     = (update::UpdatePending == m_check_update_db_result || update::UpdatePending == m_update_db_result) ? MF_GRAYED : 0;
  UINT chk_update_grayed = (update::UpdatePending == m_check_update_db_result || update::UpdatePending == m_update_db_result) ? MF_GRAYED : 0;

  license::LicenseManager::LicenseEssentials License;
  license::LicenseManager::LicenseCachedCopy(License);
#ifdef _CB_TEST_DEBUG_
  AppendMenuW (menu, MF_STRING,                IDC_EXIT,             L"Close gswui");
  AppendMenuW (menu, MF_SEPARATOR,             0,                    NULL);
#endif // _CB_TEST_DEBUG_
  
  AppendMenuW (menu, MF_STRING,                IDC_LICENSE,			 L"License...");
  AppendMenuW (menu, MF_SEPARATOR,             0,                    NULL);
  if ( License.Product != license::gswStandard ) {
	config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
	GesRule::SecurityLevel SecurityLevel = (GesRule::SecurityLevel) Node->getInt(L"SecurityLevel");
	//
	// Check for permissions to change this registry key
	//
	UINT level_grayed = MF_GRAYED;
	HKEY hKey;
	if ( ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\GeSWall\\Parameters\\GSWL", 0, KEY_SET_VALUE, &hKey) ) {
		RegCloseKey(hKey);
		level_grayed = 0;
	}
	// 
	if ( SecurityLevel > GesRule::secLevel1 ) 
		AppendMenuW (menu, MF_STRING | level_grayed,        IDC_DISABLE_POLICY,        L"Disable GeSWall Policy");
	else
		AppendMenuW (menu, MF_STRING | level_grayed,        IDC_ENABLE_POLICY,        L"Enable GeSWall Policy");
	AppendMenuW (menu, MF_SEPARATOR,             0,                       NULL);
  } 
  if ( License.Product != license::gswServer ) {
	AppendMenuW (menu, MF_STRING,                        IDC_RUN_CONSOLE,		 L"GeSWall Console...");
  }
  if ( License.Product != license::gswStandard ) {
	AppendMenuW (menu, MF_STRING | update_grayed,        IDC_UPDATE_DB,        L"Update GeSWall's Applications");
	AppendMenuW (menu, MF_STRING,                        IDC_REQUEST_NEW_APP,  L"Request New Application");
  }
  
  AppendMenuW (menu, MF_SEPARATOR,             0,                       NULL);
  
  AppendMenuW (menu, MF_STRING,                IDC_ENABLE_CAPTION_BUTTON, L"Enable Caption Button");
  AppendMenuW (menu, MF_STRING,                IDC_SET_ISOLATED_COLOR,  L"Isolated Window Color...");
  AppendMenuW (menu, MF_STRING,                IDC_SET_BLINK_ALGO,      L"Blink Effect");

  if ( License.Product != license::gswServer ) {
	AppendMenuW (menu, MF_SEPARATOR,             0,                       NULL);
	AppendMenuW (menu, MF_STRING,                IDC_LOG_NOTIFY,          L"");
	if ( License.Product != license::gswStandard ) {
		AppendMenuW (menu, MF_STRING,                IDC_LOG_ATTACK_NOTIFY,   L"");
	}
  }

  if (true == gswui::toolwnd::is_caption_button_enabled ())
    CheckMenuItem (menu, IDC_ENABLE_CAPTION_BUTTON, MF_BYCOMMAND | MF_CHECKED);
  
  HMENU blink_menu = ::CreatePopupMenu ();
  if (NULL == blink_menu)
    return 0;
  scope_guard blink_menu_guard = make_guard (blink_menu, &::DestroyMenu);
    
  AppendMenuW (blink_menu, MF_STRING, IDC_BLINK_ALGO_CYCLIC,     L"Cyclic");
  AppendMenuW (blink_menu, MF_STRING, IDC_BLINK_ALGO_FALLTO_020, L"Fall to 20%");
  AppendMenuW (blink_menu, MF_STRING, IDC_BLINK_ALGO_FALLTO_040, L"Fall to 40%");
  AppendMenuW (blink_menu, MF_STRING, IDC_BLINK_ALGO_FALLTO_060, L"Fall to 60%");
  AppendMenuW (blink_menu, MF_STRING, IDC_BLINK_ALGO_FALLTO_080, L"Fall to 80%");
  AppendMenuW (blink_menu, MF_STRING, IDC_BLINK_ALGO_DISABLE,    L"Disable");
  
  CheckMenuItem (blink_menu, blink_algo2command (gswui::toolwnd::get_blink_algo ()), MF_BYCOMMAND | MF_CHECKED);
  ModifyMenuW (menu, IDC_SET_BLINK_ALGO, MF_POPUP, HandleToLong (blink_menu), L"Blink Effect");
  
  
  //AppendMenuW (menu, MF_STRING,                IDC_SET_LOG_WND_COLOR,   L"Logs Window Color...");

  HMENU notify_menu = ::CreatePopupMenu ();
  if (NULL == notify_menu)
    return 0;
  scope_guard notify_menu_guard = make_guard (notify_menu, &::DestroyMenu);
  
  AppendMenuW (notify_menu, MF_STRING, IDC_LOG_NOTIFY_ENABLE_ALL,   L"Enable for All Resources");
  AppendMenuW (notify_menu, MF_STRING, IDC_LOG_NOTIFY_ENABLE_FILES_REGISTRY, L"Enable for Files && Regitry");
  AppendMenuW (notify_menu, MF_STRING, IDC_LOG_NOTIFY_ENABLE_FILES, L"Enable for Files Only");
  AppendMenuW (notify_menu, MF_STRING, IDC_LOG_NOTIFY_DISABLE,		L"Disable");

  AppendMenuW (notify_menu, MF_STRING,                IDC_EXPOSURE_TIME,   L"");
  HMENU exposure_menu = ::CreatePopupMenu ();
  if (NULL == exposure_menu)
    return 0;
  scope_guard exposure_menu_guard = make_guard (exposure_menu, &::DestroyMenu);
  AppendMenuW (exposure_menu, MF_STRING, IDC_EXPOSURE_TIME_1S,		L"1 Sec");
  AppendMenuW (exposure_menu, MF_STRING, IDC_EXPOSURE_TIME_2S,		L"2 Secs");
  AppendMenuW (exposure_menu, MF_STRING, IDC_EXPOSURE_TIME_3S,		L"3 Secs");
  AppendMenuW (exposure_menu, MF_STRING, IDC_EXPOSURE_TIME_4S,		L"4 Secs");
  AppendMenuW (exposure_menu, MF_STRING, IDC_EXPOSURE_TIME_5S,		L"5 Secs");
  int exposure_time = gswui::notificator::get_notification_exposure_time() - 1;
  for ( int i = 0; i < 5; i++ ) {
	  if ( i == exposure_time )
		  CheckMenuItem (exposure_menu, IDC_EXPOSURE_TIME_1S + i, MF_BYCOMMAND | MF_CHECKED);
	  else
		  CheckMenuItem (exposure_menu, IDC_EXPOSURE_TIME_1S + i, MF_BYCOMMAND);
  }

  ModifyMenuW (notify_menu, IDC_EXPOSURE_TIME, MF_POPUP, HandleToLong (exposure_menu), L"Exposure Time");

  if ( License.Product != license::gswStandard ) {
	AppendMenuW (notify_menu, MF_STRING, IDC_LOG_NOTIFY_COLOR,		L"Set Color");
  }
  
  if (true == gswui::notificator::is_notification_enabled_files ()) {
      CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES, MF_BYCOMMAND | MF_CHECKED);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES_REGISTRY, MF_BYCOMMAND);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_ALL, MF_BYCOMMAND);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_DISABLE, MF_BYCOMMAND);
  } else 
  if (true == gswui::notificator::is_notification_enabled_files_registry ()) {
      CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES_REGISTRY, MF_BYCOMMAND | MF_CHECKED);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES, MF_BYCOMMAND);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_ALL, MF_BYCOMMAND);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_DISABLE, MF_BYCOMMAND);
  } else 
  if (true == gswui::notificator::is_notification_enabled_all ()) {
      CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_ALL, MF_BYCOMMAND | MF_CHECKED);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES_REGISTRY, MF_BYCOMMAND);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES, MF_BYCOMMAND);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_DISABLE, MF_BYCOMMAND);
  } else {
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_DISABLE, MF_BYCOMMAND | MF_CHECKED);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES_REGISTRY, MF_BYCOMMAND);
      CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_ALL, MF_BYCOMMAND);
	  CheckMenuItem (notify_menu, IDC_LOG_NOTIFY_ENABLE_FILES, MF_BYCOMMAND);
  }

  if ( License.Product != license::gswServer ) {
	ModifyMenuW (menu, IDC_LOG_NOTIFY, MF_POPUP, HandleToLong (notify_menu), L"Policy Notifications");
  }
  
  HMENU attack_menu = ::CreatePopupMenu ();
  if (NULL == attack_menu)
    return 0;
  scope_guard attack_menu_guard = make_guard (attack_menu, &::DestroyMenu);
  
  AppendMenuW (attack_menu, MF_STRING, IDC_LOG_ATTACK_NOTIFY_ENABLE,     L"Enable");
  AppendMenuW (attack_menu, MF_STRING, IDC_LOG_ATTACK_NOTIFY_DISABLE,    L"Disable");
  AppendMenuW (attack_menu, MF_STRING, IDC_LOG_ATTACK_NOTIFY_COLOR,      L"Set Color");
  
  if (true == gswui::notificator::is_attack_notification_enabled ()) {
      CheckMenuItem (attack_menu, IDC_LOG_ATTACK_NOTIFY_ENABLE, MF_BYCOMMAND | MF_CHECKED);
      CheckMenuItem (attack_menu, IDC_LOG_ATTACK_NOTIFY_DISABLE, MF_BYCOMMAND);
  } else {
      CheckMenuItem (attack_menu, IDC_LOG_ATTACK_NOTIFY_DISABLE, MF_BYCOMMAND | MF_CHECKED);
      CheckMenuItem (attack_menu, IDC_LOG_ATTACK_NOTIFY_ENABLE, MF_BYCOMMAND);
  }

  if ( License.Product != license::gswServer && License.Product != license::gswStandard ) {
	ModifyMenuW (menu, IDC_LOG_ATTACK_NOTIFY, MF_POPUP, HandleToLong (attack_menu), L"Attacks Notifications");
  }

  if ( License.Product != license::gswServer && License.Product != license::gswStandard ) {
	AppendMenuW (menu, MF_STRING, IDC_TERMINATION_DETECTED,          L"");
  }
  /*
  HMENU termination_menu = ::CreatePopupMenu ();
  if (NULL == termination_menu)
	return 0;
  scope_guard termination_menu_guard = make_guard (termination_menu, &::DestroyMenu);

  AppendMenuW (termination_menu, MF_STRING, IDC_TERMINATION_DETECTED,          L"");
  AppendMenuW (termination_menu, MF_STRING, IDC_TERMINATION_ALL,			 L"Terminate All Isolated");
  */
  HMENU termination_detected_menu = ::CreatePopupMenu ();
  if (NULL == termination_detected_menu)
	return 0;
  scope_guard termination_detected_menu_guard = make_guard (termination_detected_menu, &::DestroyMenu);

  AppendMenuW (termination_detected_menu, MF_STRING, IDC_TERMINATION_DETECTED_NEVER,				  L"Never Terminate");
  AppendMenuW (termination_detected_menu, MF_STRING, IDC_TERMINATION_DETECTED_AUTO,					  L"Auto-Termination");
  AppendMenuW (termination_detected_menu, MF_STRING, IDC_TERMINATION_DETECTED_INTERACTIVE_IGNORE,	  L"Interactive Ignore");
  AppendMenuW (termination_detected_menu, MF_STRING, IDC_TERMINATION_DETECTED_INTERACTIVE_TERMINATE,  L"Interactive Terminate");

  if ( License.Product != license::gswServer && License.Product != license::gswStandard ) {
	ModifyMenuW (menu, IDC_TERMINATION_DETECTED, MF_POPUP, HandleToLong (termination_detected_menu), L"Malicious Process Termination");
  }
  //ModifyMenuW (menu, IDC_TERMINATION, MF_POPUP, HandleToLong (termination_menu), L"Isolated Process Termination");
	  
  //if (true == gswui::notificator::is_auto_process_terminate ())
  //  CheckMenuItem (menu, IDC_AUTOMATIC_PROCESS_TERM, MF_BYCOMMAND | MF_CHECKED);
  switch (gswui::notificator::get_process_termination_type ())
  {
      case gswui::logwnd::attack_wnd::termination_type_none:
          CheckMenuItem (menu, IDC_TERMINATION_DETECTED_NEVER, MF_BYCOMMAND | MF_CHECKED);
          break;
      case gswui::logwnd::attack_wnd::termination_type_auto:
          CheckMenuItem (menu, IDC_TERMINATION_DETECTED_AUTO, MF_BYCOMMAND | MF_CHECKED);
          break;
      case gswui::logwnd::attack_wnd::termination_type_interactive_ignore:
          CheckMenuItem (menu, IDC_TERMINATION_DETECTED_INTERACTIVE_IGNORE, MF_BYCOMMAND | MF_CHECKED);
          break;
      case gswui::logwnd::attack_wnd::termination_type_interactive_terminate:
          CheckMenuItem (menu, IDC_TERMINATION_DETECTED_INTERACTIVE_TERMINATE, MF_BYCOMMAND | MF_CHECKED);
          break;
      default:
          CheckMenuItem (menu, IDC_TERMINATION_DETECTED_NEVER, MF_BYCOMMAND | MF_CHECKED);
          break;
  }

  SetForegroundWindow (hwnd);
  TrackPopupMenu (menu, 0, mousePos.x, mousePos.y, 0, hwnd, NULL);
  
  termination_detected_menu_guard.release ();
  //termination_menu_guard.release ();
  exposure_menu_guard.release ();
  attack_menu_guard.release ();
  notify_menu_guard.release ();
  blink_menu_guard.release ();
  
  return 0;
} // track_tray_menu

LRESULT on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify)
{
  switch (idCommand)
  {
    case IDC_CHECK_UPDATE_DB:
         start_check_update_db (hwnd, UserInit);
         break;
    case IDC_UPDATE_DB:
         start_update_db (hwnd, UserInit);
         break;
    case IDC_EXIT:
         PostMessage (hwnd, WM_CLOSE, 0, 0);
         break;
    case IDC_REQUEST_NEW_APP:
         RedirectToUrl(L"apprequest");
         break;

	case IDC_RUN_CONSOLE:
	{
		config::Configurator::PtrToINode Node = config::Configurator::getDriverNode();
		std::wstring ConsoleFile = Node->getString(L"InstallDir");
		if ( IsW2K )
			ConsoleFile += L"\\gswmmcsa_w2k.msc";
		else
			ConsoleFile += L"\\gswmmcsa.msc";
		ShellExecute(NULL, NULL, ConsoleFile.c_str(), NULL, NULL, SW_SHOWNORMAL);
		break;
	}

	case IDC_LICENSE:
	{
		CLicenseDlg LicenseDlg;
		if ( LicenseDlg.Run() ) {
			//
			// License updated
			//
		}
		break;
	}
	
	//case IDC_AUTOMATIC_PROCESS_TERM:
    //     gswui::notificator::set_auto_process_terminate (!gswui::notificator::is_auto_process_terminate ());
    //     break;
	case IDC_TERMINATION_ALL:
	{
		break;
	}
    
	case IDC_TERMINATION_DETECTED_NEVER:
	{
	    gswui::notificator::set_process_termination_type (gswui::logwnd::attack_wnd::termination_type_none);
		break;
	}

	case IDC_TERMINATION_DETECTED_AUTO:
	{
	    gswui::notificator::set_process_termination_type (gswui::logwnd::attack_wnd::termination_type_auto);
		break;
	}

	case IDC_TERMINATION_DETECTED_INTERACTIVE_IGNORE:
	{
	    gswui::notificator::set_process_termination_type (gswui::logwnd::attack_wnd::termination_type_interactive_ignore);
		break;
	}

	case IDC_TERMINATION_DETECTED_INTERACTIVE_TERMINATE:
	{
	    gswui::notificator::set_process_termination_type (gswui::logwnd::attack_wnd::termination_type_interactive_terminate);
		break;
	}

	case IDC_ENABLE_CAPTION_BUTTON:
    {
         bool caption_button_enabled = !gswui::toolwnd::is_caption_button_enabled ();
         gswui::toolwnd::set_enable_caption_button (caption_button_enabled);
         break;
    }
    case IDC_SET_UNTRUSTED_COLOR:
    {
         gswui::toolwnd::set_untrasted_color (hwnd);
         break;
    }     
    case IDC_SET_ISOLATED_COLOR:
    {
         gswui::toolwnd::set_isolated_color (hwnd);
         break;
    }    
    case IDC_SET_ISOLATED_DIR:
    {
         gswui::toolwnd::show_isolated_dir (hwnd);
         break;
    }    
    case IDC_BLINK_ALGO_CYCLIC:
    case IDC_BLINK_ALGO_FALLTO_020:
    case IDC_BLINK_ALGO_FALLTO_040:
    case IDC_BLINK_ALGO_FALLTO_060:
    case IDC_BLINK_ALGO_FALLTO_080:
    case IDC_BLINK_ALGO_DISABLE:
         gswui::toolwnd::set_blink_algo (command2blink_algo (idCommand));
         break;
         
    //case IDC_SET_LOG_WND_COLOR:     
    //{
    //     gswui::logwnd::select_bkg_color (hwnd);
    //     break;
    //}
    case IDC_LOG_NOTIFY_ENABLE_FILES:
		 gswui::notificator::set_notification_filter (gswui::notificator::notification_for_files);
         break;
    case IDC_LOG_NOTIFY_ENABLE_FILES_REGISTRY:
		 gswui::notificator::set_notification_filter (gswui::notificator::notification_for_files_registry);
         break;
    case IDC_LOG_NOTIFY_ENABLE_ALL:
         gswui::notificator::set_notification_filter (gswui::notificator::notification_for_all);
         break;
    case IDC_LOG_NOTIFY_DISABLE:
         gswui::notificator::set_notification_filter (0);
         break;

    case IDC_EXPOSURE_TIME_1S:
    case IDC_EXPOSURE_TIME_2S:
    case IDC_EXPOSURE_TIME_3S:
    case IDC_EXPOSURE_TIME_4S:
    case IDC_EXPOSURE_TIME_5S:
         gswui::notificator::set_notification_exposure_time (idCommand - IDC_EXPOSURE_TIME_1S + 1);
         break;

	case IDC_LOG_NOTIFY_COLOR:
         //gswui::logwnd::select_bkg_color (gswui::logwnd::MessageTypeNotification, hwnd);
         gswui::notificator::select_bkg_color (gswui::notificator::notification_type_notification, hwnd);
         break;
    case IDC_LOG_ATTACK_NOTIFY_ENABLE:
         gswui::notificator::set_attack_notification_enabled (true);
         break;
    case IDC_LOG_ATTACK_NOTIFY_DISABLE:
         gswui::notificator::set_attack_notification_enabled (false);
         break;
    case IDC_LOG_ATTACK_NOTIFY_COLOR:
         //gswui::logwnd::select_bkg_color (gswui::logwnd::MessageTypeAttackNotification, hwnd);
         gswui::notificator::select_bkg_color (gswui::notificator::notification_type_attack, hwnd);
         break;

	case IDC_CONSOLE_STARTED:
		TrialManager::Handle(TrialManager::eventConsoleStart);
		break;

	case IDC_DISABLE_POLICY:
		{
			config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
			int CurrentLevel = Node->getInt(L"SecurityLevel");
			Node->setInt(L"PrevSecurityLevel", CurrentLevel);
			Node->setInt(L"SecurityLevel", GesRule::secLevel1);
			m_icon_logo = IsW2K ? m_icon_disabled_policy_w2k : m_icon_disabled_policy;
			GswClient Client;
			Client.RefreshSettings();
			NOTIFYICONDATAW nd;
			nd.cbSize           = sizeof (nd); 
			nd.hWnd             = hwnd;
			nd.uID              = NOTIFYICON_ID;
			nd.hIcon            = m_icon_logo;
			nd.uFlags           = NIF_ICON;
			::Shell_NotifyIconW (NIM_MODIFY, &nd);
		}
		break;

	case IDC_ENABLE_POLICY:
		{
			config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
			int PrevLevel = Node->getInt(L"PrevSecurityLevel");
			Node->setInt(L"SecurityLevel", PrevLevel);
			m_icon_logo = IsW2K ? m_icon_enabled_policy_w2k : m_icon_enabled_policy;
			GswClient Client;
			Client.RefreshSettings();
			NOTIFYICONDATAW nd;
			nd.cbSize           = sizeof (nd); 
			nd.hWnd             = hwnd;
			nd.uID              = NOTIFYICON_ID;
			nd.hIcon            = m_icon_logo;
			nd.uFlags           = NIF_ICON;
			::Shell_NotifyIconW (NIM_MODIFY, &nd);
		}
		break;
  }
  return 0;
} // on_command

void start_check_update_db (HWND hwnd, int init)
{
  if (update::UpdatePending != m_check_update_db_result)
  {
    int update_result = static_cast <int> (m_check_update_db_result);
	if ( gswui::gswclient_helper::get_client ().CheckUpdateDb (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority (), update_result) == ifstatus::errUnsuccess ) {
		update_result = update::UpdateLicenseExpired;
	}
    m_check_update_db_result = static_cast <UpdateResult> (update_result);
#ifndef _CB_TEST_DEBUG_
    if (update::UpdatePending == m_check_update_db_result)
#endif // _CB_TEST_DEBUG_
    {
      m_periodic_update_counter = 0;
      m_check_update_timer_id   = SetTimer (hwnd, m_check_update_timer_id, 1000, NULL);
    }  
#ifndef _CB_TEST_DEBUG_    
    else
    {
      if (update::UpdateStopped != m_check_update_db_result)
      {
        m_periodic_update_counter = 0;
        if ( init == PeriodicInit ) 
          m_periodic_chk_update_db_result = m_check_update_db_result;
        check_chk_update (hwnd, m_check_update_db_result);
      }
    }
#endif // _CB_TEST_DEBUG_    
  }
} // start_check_update_db

void start_update_db (HWND hwnd, int init)
{
  if ( check_license(hwnd) == false ) return;

  if (update::UpdatePending != m_update_db_result)
  {
    int update_result = static_cast <int> (m_update_db_result);
	if ( gswui::gswclient_helper::get_client ().UpdateDb (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority (), update_result) == ifstatus::errUnsuccess ) {
		update_result = update::UpdateLicenseExpired;
	}
    m_update_db_result = static_cast <UpdateResult> (update_result);
    
#ifndef _CB_TEST_DEBUG_
    if ( update::UpdatePending == m_update_db_result )
#endif // _CB_TEST_DEBUG_
    {
      m_periodic_update_counter = 0;
      m_update_timer_id  = SetTimer (hwnd, m_update_timer_id, 1000, NULL);
    
      if ( init == UserInit ) 
      {
        NOTIFYICONDATAW nd = {0};

        nd.cbSize      = sizeof (nd);
        nd.hWnd        = hwnd;
        nd.uID         = NOTIFYICON_ID;
        nd.uFlags      = NIF_INFO;
        wcscpy (nd.szInfo, L"...GeSWall Update pending...");
        nd.uTimeout    = 15000; // in milliseconds
        nd.dwInfoFlags = NIIF_INFO;
        wcscpy (nd.szInfoTitle, L"GeSWall Update");

        Shell_NotifyIconW (NIM_MODIFY, &nd);
      }
    }
#ifndef _CB_TEST_DEBUG_    
    else
    {
      if (update::UpdateStopped != m_update_db_result)
      {
        m_periodic_update_counter = 0;
        if ( init == PeriodicInit ) 
          m_periodic_update_db_result = m_update_db_result;
        check_update (hwnd, m_update_db_result);
      }
    }
#endif // _CB_TEST_DEBUG_    
  }
} // start_update_db

#include "license/msxmllicense.h"


LRESULT check_periodic_update (HWND hwnd)
{
  config::Configurator::PtrToINode node          = config::Configurator::getUpdateNode();
  int                              update_period = node->getInt(L"PeriodUpdateDb");       // into hours
  license::LicenseManager::LicenseEssentials License;
  license::LicenseManager::LicenseCachedCopy(License);
  if ( License.StateFlags & license::stateTrial ) update_period = 24;

  int                              update_action = node->getInt(L"PeriodUpdateDbAction"); // 0 - disable, 1 - update, 2 - check update
  update_action = update::PeriodicUpdate;
  
  //if (update::PeriodicUndefined == update_action)
  //{
  //  m_force_update = true;
  //  return 0;
  //}  
  
  if (true == m_force_update)
  {
    m_force_update            = false;
    m_periodic_update_counter = 0;
    
    if (update::PeriodicUpdate == update_action) {
      start_update_db (hwnd, PeriodicInit);
      m_periodic_update_db_result = m_update_db_result;
    } 
    else 
    {
      start_check_update_db (hwnd, PeriodicInit);
      m_periodic_chk_update_db_result = m_check_update_db_result;
    }
    return 0;
  }
  
  if (0 == update_period)
    update_period = 24; 
    
  update_period = update_period * 60;  
    
  if (update_period <= (++m_periodic_update_counter))
  {
    if (false == (update::UpdatePending == m_check_update_db_result || update::UpdatePending == m_update_db_result))
    {
      m_periodic_update_counter = 0;
      if (update::PeriodicUpdate == update_action)
      {
        start_update_db (hwnd, PeriodicInit);
        m_periodic_update_db_result = m_update_db_result;
      }  
      else
      {
        start_check_update_db (hwnd, PeriodicInit);
        m_periodic_chk_update_db_result = m_check_update_db_result;
      }  
    }
    else
    {
      --m_periodic_update_counter;
    }
  }
  return 0;
} // check_periodic_update

LRESULT check_chk_update (HWND hwnd)
{
  int update_result = static_cast <int> (m_check_update_db_result);
  gswui::gswclient_helper::get_client ().CheckUpdateDb (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority (), update_result);
  m_check_update_db_result = static_cast <UpdateResult> (update_result);
  
  return check_chk_update (hwnd, m_check_update_db_result);
} // check_chk_update

LRESULT check_chk_update (HWND hwnd, UpdateResult check_update_db_result)
{
  if (update::UpdatePending != check_update_db_result)
  {
    KillTimer (hwnd, m_check_update_timer_id);
    
    if (update::UpdatePending != m_periodic_chk_update_db_result || 
        update::UpdateAppAvailable == check_update_db_result ||
        update::UpdateUpgradeAvailable == check_update_db_result ||
        update::UpdateLicenseExpired == check_update_db_result)
    {
      NOTIFYICONDATAW   nd = {0};

      nd.cbSize      = sizeof (nd);
      nd.hWnd        = hwnd;
      nd.uID         = NOTIFYICON_ID;
      nd.uFlags      = NIF_INFO;
      nd.uTimeout    = 15000; // in milliseconds
      nd.dwInfoFlags = NIIF_INFO;
      
      wcscpy (nd.szInfoTitle, L"GeSWall Update");
      swprintf (nd.szInfo, L"%s", decode_update_result (check_update_db_result));

      Shell_NotifyIconW (NIM_MODIFY, &nd);
    }
    
    m_periodic_chk_update_db_result = check_update_db_result;
  }
    
  return 0;
} // check_chk_update

LRESULT check_update (HWND hwnd)
{
  int update_result = static_cast <int> (m_update_db_result);
  gswui::gswclient_helper::get_client ().UpdateDb (LongToHandle (GetCurrentProcessId ()), gswui::gswclient_helper::get_authority (), update_result);
  m_update_db_result = static_cast <UpdateResult> (update_result);
  
  return check_update (hwnd, m_update_db_result);
} // check_update

LRESULT check_update (HWND hwnd, UpdateResult update_db_result)
{
  if (update::UpdatePending != update_db_result)
  {
    KillTimer (hwnd, m_update_timer_id);
    
    NOTIFYICONDATAW   nd = {0};

    nd.cbSize           = sizeof (nd); 
    nd.hWnd             = hwnd;
    nd.uID              = NOTIFYICON_ID;
    nd.hIcon            = m_icon_logo;
    wcscpy (nd.szTip, L"GeSWall");
    nd.uFlags           = NIF_ICON | NIF_TIP;

    ::Shell_NotifyIconW (NIM_MODIFY, &nd);
    
    if (update::UpdatePending != m_periodic_update_db_result || update::UpdateSuccess == update_db_result)
    {
      memset (&nd, 0, sizeof (nd));

      nd.cbSize      = sizeof (nd);
      nd.hWnd        = hwnd;
      nd.uID         = NOTIFYICON_ID;
      nd.uFlags      = NIF_INFO;
      nd.uTimeout    = 15000; // in milliseconds
      nd.dwInfoFlags = NIIF_INFO;
      
      wcscpy (nd.szInfoTitle, L"GeSWall Update");
      swprintf (nd.szInfo, L"%s", decode_update_result (update_db_result), update_db_result);

      Shell_NotifyIconW (NIM_MODIFY, &nd);
      
      if ( update::UpdateLicenseExpired == update_db_result ) 
        RedirectToUrl(L"expired");
      else
      if ( update::UpdateUpgradeAvailable == update_db_result ) 
        RedirectToUrl(L"upgrade");
	  else
	  if ( update::UpdateSuccess == update_db_result )
		TrialManager::Handle(TrialManager::eventUpdated);
    }

    m_periodic_update_db_result = update_db_result;
  } 
  else
  {
    if ( update::UpdatePending != m_periodic_update_db_result ) 
    {
      NOTIFYICONDATAW   nd; 

      nd.cbSize           = sizeof (nd); 
      nd.hWnd             = hwnd;
      nd.uID              = NOTIFYICON_ID;
      nd.hIcon            = m_icon_update;
      wcscpy (nd.szTip, L"...GeSWall Update pending...");
      nd.uFlags           = NIF_ICON | NIF_TIP;

      ::Shell_NotifyIconW (NIM_MODIFY, &nd);
    }
  }
    
  return 0;
} // check_update

bool check_license(HWND hwnd)
{
	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCopy(License);
	if ( License.Product == license::gswUnlicensed ) {
		MessageBaloon(hwnd, L"GeSWall License", L"Your GeSWall's license has been expired.\nPlease download new version from www.gentlesecurity.com");
		return false;
	}

	if ( License.StateFlags & license::stateTrial ) {
		if ( License.StateFlags & license::stateTrialExpired ) {
			//
			TrialManager::HandleExpired();
			return true;
		}

		if ( License.TrialDaysLeft <= 5 ) {
			std::wstring Message;
			if ( License.TrialDaysLeft != 1 ) {
				wchar_t Buf[10];
				_itow(License.TrialDaysLeft, Buf, 10);
				Message = Buf;
				Message += L" days left for GeSWall Professional Edition Trial.";
			} else {
				Message += L"Only one day left for GeSWall Professional Edition Trial.";
			}
			Message += L"\nThen product reverts to functionality of Freeware version.";
			MessageBaloon(hwnd, L"GeSWall's License", Message.c_str());
		}
	}

	return true;
}

const wchar_t* decode_update_result (UpdateResult result)
{
  static const wchar_t* results [] = 
  {
    L"GeSWall is up to date",
    L"New Safe Applications available",
    L"Update is not available, server error, please try later",
    L"Update is not available due to invalid license",
    L"Your license has been expired\nPlease download new version from www.gentlesecurity.com",
    L"New version of GeSWall is now available\nDownload it free from www.gentlesecurity.com"
  };
  
  static const wchar_t* update_success = L"GeSWall Update successfully completed";
  static const wchar_t* update_error   = L"GeSWall Update server is not available";
  const wchar_t*        res            = update_error;
  
  switch (result)
  {
    case update::UpdateNotRequired:
    case update::UpdateAppAvailable:
    case update::UpdateServerError:
    case update::UpdateInvalidLicense:
    case update::UpdateLicenseExpired:
    case update::UpdateUpgradeAvailable:
         res = results [static_cast <int> (result)];
         break;
    case update::UpdateSuccess:
         res = update_success;
         break;     
    default:
         res = update_error;
         break;
  }
  
  return res;
} // decode_update_result

bool RedirectToUrl(const wchar_t *Method)
{
    std::wstring RedirectUrl = L"http://www.gentlesecurity.com/";
    RedirectUrl += Method;
    RedirectUrl += L".php?userinfo=";
    RedirectUrl += user_info;
    ShellExecute(NULL, NULL, RedirectUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
    return true;
}

void MessageBaloon(HWND hwnd, const wchar_t *Title, const wchar_t *Message)
{
    NOTIFYICONDATAW   nd = {0};
    nd.cbSize      = sizeof (nd);
    nd.hWnd        = hwnd;
    nd.uID         = NOTIFYICON_ID;
    nd.uFlags      = NIF_INFO;
    nd.uTimeout    = 15000; // in milliseconds
    nd.dwInfoFlags = NIIF_INFO;
    StringCchCopy(nd.szInfoTitle, sizeof nd.szInfoTitle / sizeof nd.szInfoTitle[0], Title);
    StringCchCopy(nd.szInfo, sizeof nd.szInfo / sizeof nd.szInfo[0], Message);
    Shell_NotifyIconW (NIM_MODIFY, &nd);
}

void     icon_hint_change (HWND hwnd)
{
  if (NULL != FindWindowW(L"Shell_TrayWnd", NULL))
  {
    NOTIFYICONDATAW   nd = { 0 }; 

    nd.cbSize           = sizeof (nd); 
    nd.hWnd             = hwnd;
    nd.uID              = NOTIFYICON_ID;
    nd.uCallbackMessage = WM_NOTIFYICON;
    nd.hIcon            = m_icon_logo;
    gswui::logcount::IntLog lastweek;
    wchar_t val[255];

    lastweek=gswui::logcount::CalculateLogs(7);
	wsprintf((LPTSTR) val,L"Attacks Prevented:         %ld\n"
						  L"Operations Restricted:    %ld\n"
						  L"Applications Isolated:      %ld",
						   lastweek.attacks,lastweek.notify,lastweek.isolated);
    wcscpy (nd.szTip,(LPTSTR) val);

    nd.uFlags           = NIF_TIP;

    ::Shell_NotifyIconW (NIM_MODIFY, &nd);
	Sleep(1000);
	hintchange=true;

  }
} // tray_icon_init