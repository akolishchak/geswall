//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "DeleBase.h"
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

//const GUID CDelegationBase::thisGuid = { 0x2974380b, 0x4c4b, 0x11d2, { 0x89, 0xd8, 0x0, 0x0, 0x21, 0x47, 0x31, 0x28 } };

// {E591A0EC-41D0-43ff-A306-8E9522B7067B}
const GUID CDelegationBase::thisGuid = 
{ 0xe591a0ec, 0x41d0, 0x43ff, { 0xa3, 0x6, 0x8e, 0x95, 0x22, 0xb7, 0x6, 0x7b } };

HBITMAP CDelegationBase::m_pBMapSm = NULL;
HBITMAP CDelegationBase::m_pBMapLg = NULL;


//==============================================================
//
// CDelegationBase implementation
//
//
CDelegationBase::CDelegationBase() 
: bExpanded(FALSE), bEmpty(TRUE), m_ipConsoleNameSpace(NULL) 
{ 
    if (NULL == m_pBMapSm || NULL == m_pBMapLg)
        LoadBitmaps(); 
}

CDelegationBase::~CDelegationBase() 
{ 
}

// CDelegationBase::AddImages sets up the collection of images to be displayed
// by the IComponent in the result pane as a result of its MMCN_SHOW handler
HRESULT CDelegationBase::OnAddImages(IImageList *pImageList, HSCOPEITEM hsi) 
{
    return pImageList->ImageListSetStrip((long *)m_pBMapSm, // pointer to a handle
        (long *)m_pBMapLg, // pointer to a handle
        0, // index of the first image in the strip
        RGB(0, 128, 128)  // color of the icon mask
        );
}

bool CDelegationBase::InitCom(void)
{
	MainThreadId = GetCurrentThreadId();

	wchar_t className[100];
	StringCchPrintf(className, sizeof className / sizeof className[0], L"gswmmccom%d", MainThreadId);

	ComWnd = FindWindow(className, NULL);
	if ( ComWnd == NULL ) {
		//
		// Create hidden window for communications
		//
		WNDCLASS    wndclass;
		ZeroMemory (&wndclass, sizeof(wndclass));
		wndclass.style         = 0;
		wndclass.lpfnWndProc   = ComProc;
		wndclass.cbClsExtra    = 0;
		wndclass.cbWndExtra    = 0;
		wndclass.hInstance     = g_hinst;
		wndclass.hIcon         = NULL;
		wndclass.hCursor       = NULL;
		wndclass.hbrBackground = NULL;
		wndclass.lpszMenuName  = NULL;
		wndclass.lpszClassName = className;
		RegisterClass(&wndclass);
		ComWnd = CreateWindow(className, L"", 0, 0, 0, 0, 0, NULL, NULL, g_hinst, NULL);
	}

	return true;
}

LRESULT CALLBACK CDelegationBase::ComProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch ( message ) {
		case ComDialogProcMessage:
			{
				ComDialogProcParams *Params = (ComDialogProcParams *)lParam;
				Params->rc = Params->WndProc(Params->hwndDlg, Params->uMsg, Params->wParam, Params->lParam);
			}
			break;
	}

	return DefWindowProc (hwnd, message, wParam, lParam);
}

INT_PTR CDelegationBase::ComDialogProc(WNDPROC WndProc, HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	ComDialogProcParams Params;
	Params.WndProc = WndProc;
	Params.hwndDlg = hwndDlg;
	Params.uMsg = uMsg;
	Params.wParam = wParam;
	Params.lParam = lParam;

	SendMessage(ComWnd, ComDialogProcMessage, (WPARAM)this, (LPARAM)&Params);
	return Params.rc;
}