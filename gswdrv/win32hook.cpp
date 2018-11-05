//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "win32hook.h"
#include "tools.h"
#include "hin.h"
#include "ntrulemap.h"

using namespace Rule;

typedef HANDLE HWND;
typedef int BOOL;
typedef int INT;
typedef unsigned int UINT;
typedef unsigned int *PUINT;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef LONG_PTR LRESULT;
typedef VOID (*SENDASYNCPROC)(HWND, UINT, ULONG_PTR, LRESULT);


namespace Win32Hook {

    typedef BOOL (*_NtUserPostThreadMessage)(
        IN DWORD idThread,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam
        );
    BOOL NewNtUserPostThreadMessage(
        IN DWORD idThread,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam
        );
    _NtUserPostThreadMessage OldNtUserPostThreadMessage = NULL;
    ULONG PostThreadMessageId = 0;

    typedef BOOL (*_NtUserAttachThreadInput)(
        IN DWORD idAttach,
        IN DWORD idAttachTo,
        IN BOOL fAttach
        );
    BOOL NewNtUserAttachThreadInput(
        IN DWORD idAttach,
        IN DWORD idAttachTo,
        IN BOOL fAttach
    );
    _NtUserAttachThreadInput OldNtUserAttachThreadInput = NULL;
    ULONG AttachThreadInputId = 0;

    typedef LRESULT (*_NtUserMessageCall)(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam,
        IN PVOID Unknown1,
        IN ULONG Unknown2,
        IN ULONG Unknown3
        );
    LRESULT NewNtUserMessageCall(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam,
        IN PVOID Unknown1,
        IN ULONG Unknown2,
        IN ULONG Unknown3
        );
    _NtUserMessageCall OldNtUserMessageCall = NULL;
    ULONG MessageCallId = 0;

    typedef BOOL (*_NtUserPostMessage)(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam
        );
    BOOL NewNtUserPostMessage(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam
        );
    _NtUserPostMessage OldNtUserPostMessage = NULL;
    ULONG PostMessageId = 0;

    typedef BOOL (*_NtUserSendMessageCallback)(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam,
        IN SENDASYNCPROC lpCallBack,
        IN ULONG_PTR dwData
    );
    BOOL NewNtUserSendMessageCallback(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam,
        IN SENDASYNCPROC lpCallBack,
        IN ULONG_PTR dwData
    );
    _NtUserSendMessageCallback OldNtUserSendMessageCallback = NULL;
    ULONG SendMessageCallbackId = 0;

    typedef BOOL (*_NtUserSendNotifyMessage)(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam
    );
    BOOL NewNtUserSendNotifyMessage(
        IN HWND hWnd,
        IN UINT Msg,
        IN WPARAM wParam,
        IN LPARAM lParam
    );
    _NtUserSendNotifyMessage OldNtUserSendNotifyMessage = NULL;
    ULONG SendNotifyMessageId = 0;

	typedef PVOID PINPUT;
	typedef UINT (*_NtUserSendInput)(IN UINT cInputs, IN PINPUT pInputs, IN int cbSize);
	UINT NewNtUserSendInput(IN UINT cInputs, IN PINPUT pInputs, IN int cbSize);
	_NtUserSendInput OldNtUserSendInput = NULL;
	ULONG SendInputId = 0;

	typedef SHORT (*_NtUserGetKeyState)(IN int vKey);
	SHORT NewNtUserGetKeyState(IN int vKey);
	_NtUserGetKeyState OldNtUserGetKeyState = NULL;
	ULONG GetKeyStateId = 0;

	typedef SHORT (*_NtUserGetAsyncKeyState)(IN int vKey);
	SHORT NewNtUserGetAsyncKeyState(IN int vKey);
	_NtUserGetAsyncKeyState OldNtUserGetAsyncKeyState = NULL;
	ULONG GetAsyncKeyStateId = 0;

	typedef PVOID HHOOK;
	typedef PVOID PROC;
	typedef HHOOK (*_NtUserSetWindowsHookEx)(
		IN HANDLE hmod,
		IN PUNICODE_STRING pstrLib OPTIONAL,
		IN DWORD idThread,
		IN int nFilterType,
		IN PROC pfnFilterProc,
		IN BOOL bAnsi);
	HHOOK NewNtUserSetWindowsHookEx(
		IN HANDLE hmod,
		IN PUNICODE_STRING pstrLib OPTIONAL,
		IN DWORD idThread,
		IN int nFilterType,
		IN PROC pfnFilterProc,
		IN BOOL bAnsi);
	_NtUserSetWindowsHookEx OldNtUserSetWindowsHookEx = NULL;
	ULONG SetWindowsHookExId = 0;
	
	typedef PVOID PCRAWINPUTDEVICE;
	typedef BOOL (*_NtUserRegisterRawInputDevices)(
		IN PCRAWINPUTDEVICE pRawInputDevices,
		IN UINT uiNumDevices,
		IN UINT cbSize);
	BOOL NewNtUserRegisterRawInputDevices(
		IN PCRAWINPUTDEVICE pRawInputDevices,
		IN UINT uiNumDevices,
		IN UINT cbSize);
	_NtUserRegisterRawInputDevices OldNtUserRegisterRawInputDevices = NULL;
	ULONG RegisterRawInputDevicesId = 0;

	typedef HANDLE HDC;
	typedef BOOL (*_NtGdiBitBlt)(
		IN HDC hdcDest,
		IN int nXDest,
		IN int nYDest,
		IN int nWidth,
		IN int nHeight,
		IN HDC hdcSrc,
		IN int nXSrc,
		IN int nYSrc,
		IN DWORD dwRop,
		IN DWORD crBackColor,
		IN FLONG fl);
	BOOL NewNtGdiBitBlt(
		IN HDC hdcDest,
		IN int nXDest,
		IN int nYDest,
		IN int nWidth,
		IN int nHeight,
		IN HDC hdcSrc,
		IN int nXSrc,
		IN int nYSrc,
		IN DWORD dwRop,
		IN DWORD crBackColor,
		IN FLONG fl);
	_NtGdiBitBlt OldNtGdiBitBlt = NULL;
	ULONG BitBltId = 0;

	typedef HWND (*_NtUserSetClipboardViewer)(
		IN HWND hwnd);
	HWND NewNtUserSetClipboardViewer(
		IN HWND hwnd);
	_NtUserSetClipboardViewer OldNtUserSetClipboardViewer = NULL;
	ULONG SetClipboardViewerId = 0;

	typedef HANDLE (*_NtUserGetClipboardData)(
		IN  UINT uFormat,
		OUT PVOID pData);
	HANDLE NewNtUserGetClipboardData(
		IN  UINT uFormat,
		OUT PVOID pData);
	_NtUserGetClipboardData OldNtUserGetClipboardData = NULL;
	ULONG GetClipboardDataId = 0;


    typedef enum _WINDOW_INFORMATION_CLASS {
        WindowProcessInformation
    } WINDOW_INFORMATION_CLASS;

    typedef HANDLE (*_NtUserQueryWindow)(
        IN HWND hWnd,
        IN WINDOW_INFORMATION_CLASS WindowInformationClass
        );
	HANDLE NewNtUserQueryWindow(IN HWND hWnd, IN WINDOW_INFORMATION_CLASS WindowInformationClass);
    _NtUserQueryWindow OldNtUserQueryWindow = NULL;
    ULONG QueryWindowId = 0;

    typedef int (*_NtUserGetClassName)(
        IN HWND hwnd, 
        IN BOOL bReal, 
        IN OUT PUNICODE_STRING pstrClassName
        );
    _NtUserGetClassName NtUserGetClassName = NULL;
    ULONG GetClassNameId = 0;

	typedef HWND (*_NtUserGetClipboardOwner)(VOID);
	_NtUserGetClipboardOwner NtUserGetClipboardOwner = NULL;
	ULONG GetClipboardOwnerId = 0;

	typedef ULONG_PTR (*_NtUserCallOneParam)(IN ULONG_PTR Param, IN DWORD Proc);
	_NtUserCallOneParam NtUserCallOneParam = NULL;
	DWORD CallOneParamId = 0;


    inline BOOLEAN CheckAccess(HWND hWnd, UINT Msg);

    ULONG W32ServiceIndex[ntuMax] = { 0 };
    LONG Inited = FALSE;
	PEPROCESS InitProcess = NULL;
//}; // namespace Win32Hook
	ULONG_PTR WindowsFromDCIndex = 0;

NTSTATUS Init(VOID)
{
    NTSTATUS rc;
	if ( InterlockedExchange(&Inited, TRUE) == TRUE ) return STATUS_SUCCESS;

    InitProcess = PsGetCurrentProcess();

    if ( GetClassNameId == 0 || GetClipboardOwnerId == 0 || CallOneParamId == 0 ) {
        rc = STATUS_UNSUCCESSFUL;
        ERR(rc);
        return rc;
    }
    NtUserGetClassName = (_NtUserGetClassName) KeServiceDescriptorTableShadow[1].SSDT[GetClassNameId-0x1000].SysCallPtr;
	NtUserGetClipboardOwner = (_NtUserGetClipboardOwner) KeServiceDescriptorTableShadow[1].SSDT[GetClipboardOwnerId-0x1000].SysCallPtr;
	NtUserCallOneParam = (_NtUserCallOneParam) KeServiceDescriptorTableShadow[1].SSDT[CallOneParamId-0x1000].SysCallPtr;

    //
    // Hook win32 functions
    //

	//
    // NtUserQueryWindow
    //
    if ( QueryWindowId == 0 ) {
        rc = STATUS_UNSUCCESSFUL;
        ERR(rc);
        return rc;
	} else {
		rc = hin::HookService(NULL, QueryWindowId, NewNtUserQueryWindow, (PVOID *) &OldNtUserQueryWindow, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserQueryWindow = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	}
    //
    // NtUserPostThreadMessage
    //
    if ( PostThreadMessageId != 0 ) {
		rc = hin::HookService(NULL, PostThreadMessageId, NewNtUserPostThreadMessage, 
				(PVOID *) &OldNtUserPostThreadMessage, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserPostThreadMessage = NULL;
            Release();
            ERR(rc);
            return rc;
        }
    } else
		ERR(0);
    //
    // NtUserAttachThreadInput
    //
    if ( AttachThreadInputId != 0 ) {
        rc = hin::HookService(NULL, AttachThreadInputId, NewNtUserAttachThreadInput, 
                        (PVOID *) &OldNtUserAttachThreadInput, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserAttachThreadInput = NULL;
            Release();
            ERR(rc);
            return rc;
        }
    } else
		ERR(0);
    //
    // NtUserMessageCall
    //
    if ( MessageCallId != 0 ) {
        rc = hin::HookService(NULL, MessageCallId, NewNtUserMessageCall, 
                        (PVOID *) &OldNtUserMessageCall, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserMessageCall = NULL;
            Release();
            ERR(rc);
            return rc;
        }
    } else
		ERR(0);
    //
    // NtUserPostMessage
    //
    if ( PostMessageId != 0 ) {
        rc = hin::HookService(NULL, PostMessageId, NewNtUserPostMessage, 
                        (PVOID *) &OldNtUserPostMessage, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserPostMessage = NULL;
            Release();
            ERR(rc);
            return rc;
        }
    } else
		ERR(0);
    //
    // NtUserSendMessageCallback
    //
    if ( SendMessageCallbackId != 0 ) {

        rc = hin::HookService(NULL, SendMessageCallbackId, NewNtUserSendMessageCallback, 
                         (PVOID *) &OldNtUserSendMessageCallback, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserSendMessageCallback = NULL;
            Release();
            ERR(rc);
            return rc;
        }
    } else
		ERR(0);
    //
    // NtUserSendNotifyMessage
    //
    if ( SendNotifyMessageId != 0 ) {

        rc = hin::HookService(NULL, SendNotifyMessageId, NewNtUserSendNotifyMessage, 
                         (PVOID *) &OldNtUserSendNotifyMessage, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserSendNotifyMessage = NULL;
            Release();
            ERR(rc);
            return rc;
        }
    } else
		ERR(0);
	//
	// NtUserSendInput
	//
	if ( SendInputId != 0 ) {

        rc = hin::HookService(NULL, SendInputId, NewNtUserSendInput, 
                         (PVOID *) &OldNtUserSendInput, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserSendInput = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);
	//
	// NtUserGetKeyState
	//
	if ( GetKeyStateId != 0 ) {

        rc = hin::HookService(NULL, GetKeyStateId, NewNtUserGetKeyState, 
                         (PVOID *) &OldNtUserGetKeyState, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserGetKeyState = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);
	//
	// NtUserGetAsyncKeyState
	//
	if ( GetAsyncKeyStateId != 0 ) {

        rc = hin::HookService(NULL, GetAsyncKeyStateId, NewNtUserGetAsyncKeyState, 
                         (PVOID *) &OldNtUserGetAsyncKeyState, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserGetAsyncKeyState = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);
	//
	// NtUserSetWindowsHookEx
	//
	if ( SetWindowsHookExId != 0 ) {

		rc = hin::HookService(NULL, SetWindowsHookExId, NewNtUserSetWindowsHookEx, (PVOID *) &OldNtUserSetWindowsHookEx, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserSetWindowsHookEx = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);
	//
	// NtUserRegisterRawInputDevices
	//
	if ( RegisterRawInputDevicesId != 0 ) {

		rc = hin::HookService(NULL, RegisterRawInputDevicesId, NewNtUserRegisterRawInputDevices, (PVOID *) &OldNtUserRegisterRawInputDevices, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserRegisterRawInputDevices = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);
	//
	// NtGdiBitBlt
	//
	if ( BitBltId != 0 ) {

		rc = hin::HookService(NULL, BitBltId, NewNtGdiBitBlt, (PVOID *) &OldNtGdiBitBlt, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtGdiBitBlt = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);
	//
	// NtUserSetClipboardViewer
	//
	if ( SetClipboardViewerId != 0 ) {

		rc = hin::HookService(NULL, SetClipboardViewerId, NewNtUserSetClipboardViewer, (PVOID *) &OldNtUserSetClipboardViewer, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserSetClipboardViewer = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);

	//
	// NtUserGetClipboardData
	//
	if ( GetClipboardDataId != 0 ) {

		rc = hin::HookService(NULL, GetClipboardDataId, NewNtUserGetClipboardData, (PVOID *) &OldNtUserGetClipboardData, hin::srvWin32);
        if (!NT_SUCCESS(rc)) {
            OldNtUserGetClipboardData = NULL;
            Release();
            ERR(rc);
            return rc;
        }
	} else
		ERR(0);

	return STATUS_SUCCESS;
}

VOID SetServiceIndex(W32Func Service, ULONG Index)
{
    switch( Service ) {
        case ntuQueryWindow:
            QueryWindowId = Index;
            break;
        case ntuPostThreadMesage:
            PostThreadMessageId = Index;
            break;
        case ntuAttachThreadInput:
            AttachThreadInputId = Index;
            break;
        case ntuMessageCall:
            MessageCallId = Index;
            break;
        case ntuPostMessage:
            PostMessageId = Index;
            break;
        case ntuSendMessageCallback:
            SendMessageCallbackId = Index;
            break;
        case ntuSendNotifyMessage:
            SendNotifyMessageId = Index;
            break;
        case ntuGetClassName:
            GetClassNameId = Index;
            break;
		case ntuSendInput:
			SendInputId = Index;
			break;
		case ntuGetKeyState:
			GetKeyStateId = Index;
			break;
		case ntuGetAsyncKeyState:
			GetAsyncKeyStateId = Index;
			break;
		case ntuSetWindowsHookEx:
			SetWindowsHookExId = Index;
			break;
		case ntuRegisterRawInputDevices:
			RegisterRawInputDevicesId = Index;
			break;
		case ntuBitBlt:
			BitBltId = Index;
			break;
		case ntuCallOneParam:
			CallOneParamId = Index;
			break;
		case ntuSetClipboardViewer:
			SetClipboardViewerId = Index;
			break;
		case ntuGetClipboardData:
			GetClipboardDataId = Index;
			break;
		case ntuGetClipboardOwner:
			GetClipboardOwnerId = Index;
			break;
    }
}

VOID Release(VOID)
{
/*
    if ( OldNtUserPostThreadMessage != NULL )  {
        UnHookService(NULL, PostThreadMessageId, OldNtUserPostThreadMessage, 
                      NewNtUserPostThreadMessage, srvWin32);
    }
*/
}

BOOLEAN CheckAccess(HWND hWnd, UINT Msg)
{
    HANDLE hProcess = OldNtUserQueryWindow(hWnd, WindowProcessInformation);
    if ( hProcess != NULL ) {
        PEPROCESS Object;
        NTSTATUS rc = PsLookupProcessByProcessId(hProcess, &Object);
        if ( NT_SUCCESS(rc) ) {
            ACCESS_MASK DesiredAccess = Msg;

            RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), 
                                                   Object, NULL, nttProcess, DesiredAccess);

            ObDereferenceObject(Object);
            if ( Result == rurBlockAction )
              return FALSE;
        }
    }

    return TRUE;
} // CheckAccess


BOOL NewNtUserPostThreadMessage(
    IN DWORD idThread,
    IN UINT Msg,
    IN WPARAM wParam,
    IN LPARAM lParam
    ) 
{
    PETHREAD Thread;
    NTSTATUS rc = PsLookupThreadByThreadId(UlongToPtr(idThread), &Thread);
    if ( NT_SUCCESS(rc) ) {
        PEPROCESS Object = IoThreadToProcess(Thread);

        ACCESS_MASK DesiredAccess = Msg;
        RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), 
                                               Object, NULL, nttProcess, DesiredAccess);

        //if ( Result == rurBlockAction )
        //  Result = filterMessages (Result, Msg, Object, PsGetCurrentProcess(), NULL);

        ObDereferenceObject(Thread);
        if ( Result == rurBlockAction )
          return FALSE;
    }

    return OldNtUserPostThreadMessage(
                    idThread,
                    Msg,
                    wParam,
                    lParam);
}

BOOL NewNtUserAttachThreadInput(
     IN DWORD idAttach,
     IN DWORD idAttachTo,
     IN BOOL fAttach
    )
{
    PETHREAD Thread;
    NTSTATUS rc = PsLookupThreadByThreadId(UlongToPtr(idAttachTo), &Thread);
    if ( NT_SUCCESS(rc) ) {
        PEPROCESS Object = IoThreadToProcess(Thread);

        ACCESS_MASK DesiredAccess = 1;
        RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), 
                                               Object, NULL, nttProcess, DesiredAccess);

        //if ( Result == rurBlockAction )
        //  Result = filterMessages (Result, 0xffff, Object, PsGetCurrentProcess (), NULL);

        ObDereferenceObject(Thread);
        if ( Result == rurBlockAction )
            return FALSE;
    }

    return OldNtUserAttachThreadInput(
                    idAttach,
                    idAttachTo,
                    fAttach);
}


LRESULT NewNtUserMessageCall(
    IN HWND hWnd,
    IN UINT Msg,
    IN WPARAM wParam,
    IN LPARAM lParam,
    IN PVOID Unknown1,
    IN ULONG Unknown2,
    IN ULONG Unknown3
    )
{
    if ( !CheckAccess(hWnd, Msg) ) return NULL;

    return OldNtUserMessageCall(
                    hWnd,
                    Msg,
                    wParam,
                    lParam,
                    Unknown1,
                    Unknown2,
                    Unknown3);
}

BOOL NewNtUserPostMessage(
    IN HWND hWnd,
    IN UINT Msg,
    IN WPARAM wParam,
    IN LPARAM lParam
    )
{
    if ( !CheckAccess(hWnd, Msg) ) return FALSE;

    return OldNtUserPostMessage(
                    hWnd,
                    Msg,
                    wParam,
                    lParam);
}

BOOL NewNtUserSendMessageCallback(
    IN HWND hWnd,
    IN UINT Msg,
    IN WPARAM wParam,
    IN LPARAM lParam,
    IN SENDASYNCPROC lpCallBack,
    IN ULONG_PTR dwData
    )
{
    if ( !CheckAccess(hWnd, Msg) ) return FALSE;

    return OldNtUserSendMessageCallback(
                    hWnd,
                    Msg,
                    wParam,
                    lParam,
                    lpCallBack,
                    dwData);
}

BOOL NewNtUserSendNotifyMessage(
    IN HWND hWnd,
    IN UINT Msg,
    IN WPARAM wParam,
    IN LPARAM lParam
    )
{
    if ( !CheckAccess(hWnd, Msg) ) return FALSE;

    return OldNtUserSendNotifyMessage(
                    hWnd,
                    Msg,
                    wParam,
                    lParam);
}

UINT NewNtUserSendInput(IN UINT cInputs, IN PINPUT pInputs, IN int cbSize)
{
	ACCESS_MASK DesiredAccess = 2;
	//
	// TODO: Check if there is any way to define receiver process
	//
    RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), 
                                           InitProcess, NULL, nttProcess, DesiredAccess);
	if ( Result != rurAllowAction ) return 0;

	return OldNtUserSendInput(cInputs, pInputs, cbSize);
}

bool AllowKeyState(int vKey)
{
	ACCESS_MASK DesiredAccess = 1;

	if ( ( 0x30 <= vKey && vKey <= 0x5a ) || ( 0x5f <= vKey && vKey <= 0x8f ) ||
		 vKey >= 0xba || vKey == 0x20 || vKey == 0x0d || vKey == 0x09 ) {
		RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), 
											InitProcess, NULL, nttProcess, DesiredAccess);
		if ( Result != rurAllowAction ) return false;
	}
	return true;
}

SHORT NewNtUserGetKeyState(IN int vKey)
{
	if ( !AllowKeyState(vKey) ) return 0;

	return OldNtUserGetKeyState(vKey);
}

SHORT NewNtUserGetAsyncKeyState(IN int vKey)
{
	if ( !AllowKeyState(vKey) ) return 0;

	return OldNtUserGetAsyncKeyState(vKey);
}

HHOOK NewNtUserSetWindowsHookEx(
		IN HANDLE hmod,
		IN PUNICODE_STRING pstrLib OPTIONAL,
		IN DWORD idThread,
		IN int nFilterType,
		IN PROC pfnFilterProc,
		IN BOOL bAnsi)
{
	PETHREAD Thread = NULL;
	PEPROCESS Object = InitProcess;
	if ( idThread != 0 ) {
		NTSTATUS rc = PsLookupThreadByThreadId(UlongToHandle(idThread), &Thread);
		if ( NT_SUCCESS(rc) ) Object = IoThreadToProcess(Thread);
	}
		
    ACCESS_MASK DesiredAccess = 3;
    RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), Object, NULL, nttProcess, DesiredAccess);
	if ( Thread != NULL ) ObDereferenceObject(Thread);
    if ( Result != rurAllowAction ) idThread = HandleToUlong(PsGetCurrentThreadId());

	return OldNtUserSetWindowsHookEx(hmod, pstrLib, idThread, nFilterType, pfnFilterProc, bAnsi);
}

BOOL NewNtUserRegisterRawInputDevices(
		IN PCRAWINPUTDEVICE pRawInputDevices,
		IN UINT uiNumDevices,
		IN UINT cbSize)
{
	ACCESS_MASK DesiredAccess = 4;

	RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), InitProcess, NULL, nttProcess, DesiredAccess);
	if ( Result != rurAllowAction ) return TRUE;

	return OldNtUserRegisterRawInputDevices(pRawInputDevices, uiNumDevices, cbSize);
}


HANDLE NewNtUserQueryWindow(IN HWND hWnd, IN WINDOW_INFORMATION_CLASS WindowInformationClass)
{
	HANDLE Handle = OldNtUserQueryWindow(hWnd, WindowInformationClass);

	if ( WindowInformationClass == WindowProcessInformation && Handle != NULL ) {
        PEPROCESS Object;
        NTSTATUS rc = PsLookupProcessByProcessId(Handle, &Object);
        if ( NT_SUCCESS(rc) ) {
            ACCESS_MASK DesiredAccess = 4;
            RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), Object, NULL, nttProcess, DesiredAccess);
            ObDereferenceObject(Object);
			if ( Result != rurAllowAction ) {
				Handle = NULL;
			}
        }
    }

	return Handle;
}

BOOL NewNtGdiBitBlt(
		IN HDC hdcDest,
		IN int nXDest,
		IN int nYDest,
		IN int nWidth,
		IN int nHeight,
		IN HDC hdcSrc,
		IN int nXSrc,
		IN int nYSrc,
		IN DWORD dwRop,
		IN DWORD crBackColor,
		IN FLONG fl)
{
	HWND hWnd = (HWND) NtUserCallOneParam((ULONG_PTR)hdcSrc, WindowsFromDCIndex);
	if ( hWnd != NULL ) {
		if ( !CheckAccess(hWnd, 5) ) return FALSE;
	}

	return OldNtGdiBitBlt(hdcDest, nXDest, nYDest, nWidth, nHeight, hdcSrc, nXSrc, nYSrc, dwRop, crBackColor, fl);
}

HWND NewNtUserSetClipboardViewer(
		IN HWND hwnd)
{
	ACCESS_MASK DesiredAccess = 6;

	RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), InitProcess, NULL, nttProcess, DesiredAccess);
	if ( Result != rurAllowAction ) return NULL;

	return OldNtUserSetClipboardViewer(hwnd);
}

HANDLE NewNtUserGetClipboardData(
		IN  UINT uFormat,
		OUT PVOID pData)
{
	HWND hWnd = NtUserGetClipboardOwner();
	if ( hWnd != NULL ) {
		if ( !CheckAccess(hWnd, 7) )
			return NULL;
	} else {
		ACCESS_MASK DesiredAccess = 7;
		RuleResult Result = Rule::AccessObject(acsMessage, PsGetCurrentProcess(), InitProcess, NULL, nttProcess, DesiredAccess);
		if ( Result == rurBlockAction )
			return NULL;
	}

	return OldNtUserGetClipboardData(uFormat, pData);
}


}; // namespace Win32Hook