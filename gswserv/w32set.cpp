//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "w32set.h"
#include "gswdrv.h"
#include "configurator.h"

namespace w32set {

typedef BOOL (WINAPI *_IsHungAppWindow)(IN HWND hwnd);
typedef BOOL (WINAPI *_RegisterRawInputDevices)(PCRAWINPUTDEVICE pRawInputDevices, UINT uiNumDevices, UINT cbSize);

LRESULT CALLBACK CallbackWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

bool Init(void)
{
    //return false;

    bool bRes = false;

    //
    // Set defaults
    //
    W32HooksetSyncParams Params;
    const ULONG DefaultValue = 0xccccccc7;
    const HWND DefaultHwnd = GetDesktopWindow();
    const UINT DefaultMsg = WM_USER;

    CGswDrv Drv;
    if ( !Drv.W32hooksetInit() ) {
        trace("W32hooksetInit error: %d\n", GetLastError());
        goto cleanup;
    }

    // BOOL IsHungAppWindow(IN HWND hwnd)
    // NtUserQueryWindow
    Params.Func = ntuQueryWindow;
    Params.ParamSize = sizeof HWND + sizeof W32Func;
    Params.TestParamsNum = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HWND;
    Params.Param[0].Param = (ULONG_PTR)DefaultHwnd;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    HMODULE hModule = GetModuleHandle(L"user32.dll");
    _IsHungAppWindow IsHungAppWindow = (_IsHungAppWindow) GetProcAddress(hModule, "IsHungAppWindow");
    IsHungAppWindow((HWND)DefaultHwnd);

    // BOOL PostThreadMessageW(IN DWORD idThread, IN UINT Msg, IN WPARAM wParam, IN LPARAM lParam);
    // NtUserPostThreadMesage
    Params.Func = ntuPostThreadMesage;
    Params.ParamSize = sizeof DWORD + sizeof UINT + sizeof WPARAM + sizeof LPARAM;
    Params.TestParamsNum = 4;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof DWORD;
    Params.Param[0].Param = GetCurrentThreadId();
    Params.Param[1].Offset = sizeof DWORD;
    Params.Param[1].Size = sizeof UINT;
    Params.Param[1].Param = DefaultMsg;
    Params.Param[2].Offset = sizeof DWORD + sizeof UINT;
    Params.Param[2].Size = sizeof WPARAM;
    Params.Param[2].Param = DefaultValue;
    Params.Param[3].Offset = sizeof DWORD + sizeof UINT + sizeof WPARAM;
    Params.Param[3].Size = sizeof LPARAM;
    Params.Param[3].Param = DefaultValue;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    PostThreadMessageW(GetCurrentThreadId(), DefaultMsg, DefaultValue, DefaultValue);

    // BOOL AttachThreadInput(IN DWORD idAttach, IN DWORD idAttachTo, IN BOOL fAttach);
    // NtUserAttachThreadInput
    Params.Func = ntuAttachThreadInput;
    Params.ParamSize = sizeof DWORD + sizeof DWORD + sizeof BOOL;
    Params.TestParamsNum = 2;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof DWORD;
    Params.Param[0].Param = DefaultValue;
    Params.Param[1].Offset = sizeof DWORD;
    Params.Param[1].Size = sizeof DWORD;
    Params.Param[1].Param = DefaultValue;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    AttachThreadInput(DefaultValue, DefaultValue, FALSE);

    // LRESULT SendMessageW(IN HWND hWnd, IN UINT Msg, IN WPARAM wParam, IN LPARAM lParam);
    // NtUserMessageCall
    Params.Func = ntuMessageCall;
    Params.ParamSize = sizeof HWND + sizeof UINT + sizeof WPARAM + sizeof LPARAM + sizeof PVOID + sizeof ULONG + sizeof ULONG;
    Params.TestParamsNum = 4;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HWND;
    Params.Param[0].Param = (ULONG_PTR) DefaultHwnd;
    Params.Param[1].Offset = sizeof HWND;
    Params.Param[1].Size = sizeof UINT;
    Params.Param[1].Param = DefaultMsg;
    Params.Param[2].Offset = sizeof HWND + sizeof UINT;
    Params.Param[2].Size = sizeof WPARAM;
    Params.Param[2].Param = DefaultValue;
    Params.Param[3].Offset = sizeof HWND + sizeof UINT + sizeof WPARAM;
    Params.Param[3].Size = sizeof LPARAM;
    Params.Param[3].Param = DefaultValue;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    SendMessageW(DefaultHwnd, DefaultMsg, DefaultValue, DefaultValue);

    // BOOL PostMessageW(IN HWND hWnd, IN UINT Msg, IN WPARAM wParam, IN LPARAM lParam);
    // NtUserPostMessage
    Params.Func = ntuPostMessage;
    Params.ParamSize = sizeof HWND + sizeof UINT + sizeof WPARAM + sizeof LPARAM;
    Params.TestParamsNum = 4;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HWND;
    Params.Param[0].Param = (ULONG_PTR) DefaultHwnd;
    Params.Param[1].Offset = sizeof HWND;
    Params.Param[1].Size = sizeof UINT;
    Params.Param[1].Param = DefaultMsg;
    Params.Param[2].Offset = sizeof HWND + sizeof UINT;
    Params.Param[2].Size = sizeof WPARAM;
    Params.Param[2].Param = DefaultValue;
    Params.Param[3].Offset = sizeof HWND + sizeof UINT + sizeof WPARAM;
    Params.Param[3].Size = sizeof LPARAM;
    Params.Param[3].Param = DefaultValue;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    PostMessageW(DefaultHwnd, DefaultMsg, DefaultValue, DefaultValue);

    // GetClassNameW
    //int NtUserGetClassName (IN HWND hwnd, IN BOOL bReal, IN OUT PUNICODE_STRING pstrClassName);
    Params.Func            = ntuGetClassName;
    Params.ParamSize       = sizeof (HWND) + sizeof (BOOL) + sizeof (void*);
    Params.TestParamsNum   = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size   = sizeof (HWND);
    Params.Param[0].Param  = (ULONG_PTR) DefaultHwnd;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    wchar_t className [1];
    GetClassNameW (DefaultHwnd, className, sizeof (className) / sizeof (className [0]));


    // SendInput
    //UINT NtUserSendInput(IN UINT cInputs, IN INPUT *pInputs, IN int cbSize);
	INPUT Input[1] = { 0 };

	Params.Func            = ntuSendInput;
    Params.ParamSize       = sizeof (UINT) + sizeof (INPUT *) + sizeof (int);
    Params.TestParamsNum   = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size   = sizeof (UINT);
    Params.Param[0].Param  = sizeof Input / sizeof Input[0];
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    SendInput(sizeof Input / sizeof Input[0], Input, sizeof INPUT );

    // GetKeyState
    //UINT NtUserGetKeyState(IN int vKey);
	Params.Func            = ntuGetKeyState;
    Params.ParamSize       = sizeof (int);
    Params.TestParamsNum   = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size   = sizeof (int);
    Params.Param[0].Param  = 0xff;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
	GetKeyState(0xff);

    // GetAsyncKeyState
    //UINT NtUserGetAsyncKeyState(IN int vKey);
	Params.Func            = ntuGetAsyncKeyState;
    Params.ParamSize       = sizeof (int);
    Params.TestParamsNum   = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size   = sizeof (int);
    Params.Param[0].Param  = 0xff;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
	GetAsyncKeyState(0xff);

	// SetWindowsHookEx
	// HHOOK SetWindowsHookEx(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
	HINSTANCE hMod = GetModuleHandle(NULL);
	Params.Func            = ntuSetWindowsHookEx;
    Params.ParamSize       = sizeof (HANDLE) + sizeof (PVOID) + sizeof (DWORD) + sizeof (int) + sizeof (PROC) + sizeof (BOOL);
    Params.TestParamsNum   = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size   = sizeof (HINSTANCE);
    Params.Param[0].Param  = (ULONG_PTR) hMod;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
	HHOOK Hook = SetWindowsHookEx(0, CallbackWndProc, hMod, GetCurrentThreadId());
	if ( Hook != NULL ) UnhookWindowsHookEx(Hook);

	// RegisterRawInputDevices
	// BOOL RegisterRawInputDevices(PCRAWINPUTDEVICE pRawInputDevices, UINT uiNumDevices, UINT cbSize);
	Params.Func            = ntuRegisterRawInputDevices;
    Params.ParamSize       = sizeof (PVOID) + sizeof (UINT) + sizeof (UINT);
    Params.TestParamsNum   = 3;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size   = sizeof (PVOID);
    Params.Param[0].Param  = NULL;
    Params.Param[1].Offset = sizeof (PVOID);
    Params.Param[1].Size   = sizeof (UINT);
    Params.Param[1].Param  = 0;
    Params.Param[2].Offset = sizeof (PVOID) + sizeof (UINT);
    Params.Param[2].Size   = sizeof (UINT);
    Params.Param[2].Param  = 0;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }

	_RegisterRawInputDevices RegisterRawInputDevices = (_RegisterRawInputDevices) GetProcAddress(hModule, "RegisterRawInputDevices");
	if ( RegisterRawInputDevices != NULL ) RegisterRawInputDevices(NULL, 0, 0);


    // BOOL BitBlt(IN HDC hdcDest, IN int nXDest, IN int nYDest, IN int nWidth, IN int nHeight, IN HDC hdcSrc, IN int nXSrc, IN int nYSrc, IN DWORD dwRop, IN DWORD crBackColor, IN FLONG fl)
    // NtGdiBitBlt
    Params.Func = ntuBitBlt;
    Params.ParamSize = 2*sizeof(HDC) + 6*sizeof(int) + 2*sizeof(DWORD) + sizeof(FLONG);
    Params.TestParamsNum = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HDC;
    Params.Param[0].Param = (ULONG_PTR)GetDC(NULL);
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
	BitBlt((HDC)Params.Param[0].Param, 0, 0, 0, 0, (HDC)Params.Param[0].Param, 0, 0, SRCCOPY);

    // BOOL WindowFromDC(IN HDC hdc)
    // NtUserCallOneParam
    Params.Func = ntuCallOneParam;
    Params.ParamSize = sizeof ULONG_PTR + sizeof DWORD;
    Params.TestParamsNum = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HDC;
    Params.Param[0].Param = (ULONG_PTR)DefaultHwnd;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
	WindowFromDC((HDC)DefaultHwnd);

    // BOOL SetClipboardViewer(IN HWND hwnd)
    // NtUserSetClipboardViewer
    Params.Func = ntuSetClipboardViewer;
    Params.ParamSize = sizeof HWND;
    Params.TestParamsNum = 1;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HWND;
    Params.Param[0].Param = (ULONG_PTR)DefaultHwnd;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
	SetClipboardViewer((HWND)DefaultHwnd);

	{
		config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
		if ( Node->getInt(L"ClipboardSecure") >= 2 ) {
			// BOOL GetClipboardData(IN UINT uFormat, OUT PVOID pData)
			// NtUserGetClipboardData
			Params.Func = ntuGetClipboardData;
			Params.ParamSize = sizeof UINT + sizeof PVOID;
			Params.TestParamsNum = 1;
			Params.Param[0].Offset = 0;
			Params.Param[0].Size = sizeof UINT;
			Params.Param[0].Param = 0xffff;
			if ( !Drv.W32hooksetSync(&Params) ) {
				trace("W32hooksetSync error: %d\n", GetLastError());
				goto cleanup;
			}
			GetClipboardData(0xffff);
		}
	}

    // BOOL GetClipboardOwner(VOID)
    // NtUserGetClipboardOwner
    Params.Func = ntuGetClipboardOwner;
    Params.ParamSize = 0;
    Params.TestParamsNum = 0;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
	GetClipboardOwner();


	//
    // w2k only
    //
    if ( NtVersion >= 0x0501 ) {
        bRes = true;
        goto cleanup;
    }

    // BOOL SendMessageCallbackW(IN HWND hWnd, IN UINT Msg, IN WPARAM wParam, IN LPARAM lParam, IN SENDASYNCPROC lpResultCallBack, IN ULONG_PTR dwData);
    // NtUserSendMessageCallback
    Params.Func = ntuSendMessageCallback;
    Params.ParamSize = sizeof HWND + sizeof UINT + sizeof WPARAM + sizeof LPARAM + sizeof SENDASYNCPROC + sizeof ULONG_PTR;
    Params.TestParamsNum = 4;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HWND;
    Params.Param[0].Param = (ULONG_PTR) DefaultHwnd;
    Params.Param[1].Offset = sizeof HWND;
    Params.Param[1].Size = sizeof UINT;
    Params.Param[1].Param = DefaultMsg;
    Params.Param[2].Offset = sizeof HWND + sizeof UINT;
    Params.Param[2].Size = sizeof WPARAM;
    Params.Param[2].Param = DefaultValue;
    Params.Param[3].Offset = sizeof HWND + sizeof UINT + sizeof WPARAM;
    Params.Param[3].Size = sizeof LPARAM;
    Params.Param[3].Param = DefaultValue;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    SendMessageCallbackW(DefaultHwnd, DefaultMsg, DefaultValue, DefaultValue, NULL, NULL);

    // BOOL SendNotifyMessageW(IN HWND hWnd, IN UINT Msg, IN WPARAM wParam, IN LPARAM lParam);
    // NtUserSendNotifyMessage
    Params.Func = ntuSendNotifyMessage;
    Params.ParamSize = sizeof HWND + sizeof UINT + sizeof WPARAM + sizeof LPARAM;
    Params.TestParamsNum = 4;
    Params.Param[0].Offset = 0;
    Params.Param[0].Size = sizeof HWND;
    Params.Param[0].Param = (ULONG_PTR) DefaultHwnd;
    Params.Param[1].Offset = sizeof HWND;
    Params.Param[1].Size = sizeof UINT;
    Params.Param[1].Param = DefaultMsg;
    Params.Param[2].Offset = sizeof HWND + sizeof UINT;
    Params.Param[2].Size = sizeof WPARAM;
    Params.Param[2].Param = DefaultValue;
    Params.Param[3].Offset = sizeof HWND + sizeof UINT + sizeof WPARAM;
    Params.Param[3].Size = sizeof LPARAM;
    Params.Param[3].Param = DefaultValue;
    if ( !Drv.W32hooksetSync(&Params) ) {
        trace("W32hooksetSync error: %d\n", GetLastError());
        goto cleanup;
    }
    SendNotifyMessageW(DefaultHwnd, DefaultMsg, DefaultValue, DefaultValue);

    bRes = true;

cleanup:
    Drv.W32hooksetRelease();
    return bRes;
}

} // namespace w32set {