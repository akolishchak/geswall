//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __shellext_contextmenu_h__
 #define __shellext_contextmenu_h__

#define INC_OLE2        // WIN32, get ole2 from windows.h

#include <windows.h>
#include <windowsx.h>

#pragma data_seg(".text")
 #define INITGUID
 #include <initguid.h>
 #include <shlguid.h>
 #include <shlobj.h>
#pragma data_seg()

#include "commonlib/commondefs.h"

namespace shellext {

class GswShellExt
    : public 
        IContextMenu, IShellExtInit, IShellIconOverlayIdentifier, IShellExecuteHook
//,
//        IExtractIcon//,
//        IPersistFile,
//        IShellPropSheetExt,
//        ICopyHook
{
  private:
    typedef commonlib::IntrusiveAtomicCounter  AtomicCounter;

  public:
    GswShellExt ();
    virtual ~GswShellExt ();

	static bool GlobalInit(void);
	static void GlobalRelease(void);

    //IUnknown members
    STDMETHODIMP            QueryInterface (REFIID, LPVOID FAR *);
    STDMETHODIMP_(ULONG)    AddRef ();
    STDMETHODIMP_(ULONG)    Release ();

    //IShellExtInit methods
    STDMETHODIMP            Initialize (LPCITEMIDLIST pIDFolder, LPDATAOBJECT pDataObj, HKEY hKeyID);
    
    //IShell members
    STDMETHODIMP            QueryContextMenu (HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
    STDMETHODIMP            InvokeCommand (LPCMINVOKECOMMANDINFO lpcmi);
    STDMETHODIMP            GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT FAR *reserved, LPSTR pszName, UINT cchMax);

   //IShellIconOverlayIdentifier methods
   STDMETHODIMP 			IsMemberOf (LPCWSTR pwszPath, DWORD dwAttr);
   STDMETHODIMP 			GetOverlayInfo (LPWSTR pwszIconFile, int cchMax, LPINT pIndex, LPDWORD pdwFlags);
   STDMETHODIMP 			GetPriority (LPINT pPriority);
   
   // static as IShellExecuteHook is not used anymore, just real hook
   STDMETHODIMP      Execute(LPSHELLEXECUTEINFOW pei);

  private:
    //AtomicCounter m_ref_counter;
    long          m_ref_counter;
    LPDATAOBJECT  m_data_obj;
    wchar_t m_szFile[MAX_PATH];
	static bool ProcessExtension(LPSHELLEXECUTEINFOW pei,std::wstring &exepath,std::wstring &params);
	static bool ReplaceFunc(wstring &str1,wstring str2,wstring str3);

}; // class GswShellExt

BOOL CALLBACK WizardDlgProc(HWND hDlg, UINT message, WPARAM wParam,LPARAM lParam);

} // namespace shellext

#endif // __shellext_contextmenu_h__