//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "resource1.h"
#include "reqdlg.h"
#include <strsafe.h>
#include "config/configurator.h"
#include "commonlib/setupdetect.h"


#define IDT_PROGRESS		1
#define IDT_COMPLETE		2

void InitializeFont(HWND hWnd, wchar_t *szFaceName, LONG lHeight, LONG lWidth, LPLOGFONT lpLf);

int CReqDlg::WaitSecs				= UserWaitSecs;
GUIReply CReqDlg::DefaultReply		= (GUIReply) DefaultGUIReply;


CReqDlg::CReqDlg()
{
	hExecIcon = NULL;
	hFileIcon = NULL;
	hInstance = GetModuleHandle(NULL);
	IsSetup = false;
}

CReqDlg::~CReqDlg()
{
	Release();
}

void CReqDlg::Release(void)
{
	if ( hExecIcon != NULL ) {
		DestroyIcon(hExecIcon);
		hExecIcon = NULL;
	}
	if ( hFileIcon != NULL ) {
		DestroyIcon(hFileIcon);
		hFileIcon = NULL;
	}
	IsSetup = false;
}

GUIReply CReqDlg::Run(RequestType _Type, const wchar_t *_ExecName, const wchar_t *_FileName)
{
	GUIReply Result = gurUndefined;
	HWND CurrentWnd = GetForegroundWindow();

	Release();
	Type = _Type;
	//
	if ( Type == reqNotIsolateTracked ) {
		//
		// Check if file is setup
		//
		IsSetup = commonlib::SetupDetect::IsSetup(_ExecName);
		//
		// Check for ploNoPopups
		//
		config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
		if ( GesRule::TranslateSecurityLevel((GesRule::SecurityLevel)Node->getInt(L"SecurityLevel")) & GesRule::ploNoPopups && !IsSetup ) {
			Result = gurYes; //gurNo;
			return Result;
		}
	}

	bool SimulateNotIsolateTracked = false;

	if ( Type == reqThreatPointSubject ) {

		static wchar_t MsiExePath[MAX_PATH] = { 0 };
		if ( MsiExePath[0] == 0 ) {
			if ( GetSystemDirectory(MsiExePath, sizeof MsiExePath / sizeof MsiExePath[0]) != 0 ) {
				StringCchCat(MsiExePath, sizeof MsiExePath / sizeof MsiExePath[0], L"\\msiexec.exe");
			}
		}

		if ( wcsicmp(MsiExePath, _ExecName) == 0 ) {
			//SimulateNotIsolateTracked = true;
			Type = reqNotIsolateTracked;
			_ExecName = _FileName;
			IsSetup = true;
		}
	}


	ExecName = _ExecName;
	hExecIcon = ExtractIcon(hInstance, FileName.c_str(), 0);
	if ( hExecIcon == NULL || hExecIcon == (HICON)1 ) {
		CoInitialize(NULL);
		SHFILEINFO Info;
		if ( SHGetFileInfo(_ExecName, 0, &Info, sizeof Info, SHGFI_ICON) ) {
			hExecIcon = Info.hIcon;
		}
		CoUninitialize();
	}
	Ver.Init(_ExecName);
	Ver.GetStr(L"FileDescription", &Description);
	Ver.GetStr(L"ProductName", &Product);
	Ver.GetStr(L"CompanyName", &Company);

	WORD DlgRes = 0;
	if ( Type == reqThreatPointSubject ) 
		DlgRes = IDD_DIALOG_REQ;
	else
	if ( Type == reqNotIsolateTracked ) {
		if ( IsSetup )
			DlgRes = IDD_DIALOG_SETUP;
		else
			DlgRes = IDD_DIALOG_TRACKED;
	}

	HWND hWnd = GetDesktopWindow();
	Result = (GUIReply) DialogBoxParam(hInstance, MAKEINTRESOURCE(DlgRes), hWnd, DialogProc, (LPARAM)this);
	
	if ( SimulateNotIsolateTracked ) {
		// convert result to reqThreatPointSubject
		switch ( Result ) {
			case gurYes:
				Result = gurNo;
				break;
			case gurNo:
				Result = gurYes;
				break;
			case gurYesAlways:
				Result = gurNoAlways;
				break;
			case gurNoAlways:
				Result = gurYesAlways;
				break;
		}
	}

	SetForegroundWindow(CurrentWnd);
	Release();
	return Result;
}

GUIReply CReqDlg::Run(const wchar_t *_ExecName, const wchar_t *_FileName)
{
	GUIReply Result = gurUndefined;

	Release();
	Type = reqAccessSecretFile;
	ExecName = _ExecName;
	CoInitialize(NULL);
	hExecIcon = ExtractIcon(hInstance, ExecName.c_str(), 0);
	if ( hExecIcon == NULL || hExecIcon == (HICON)1 ) {
		SHFILEINFO Info;
		if ( SHGetFileInfo(_ExecName, 0, &Info, sizeof Info, SHGFI_ICON) ) {
			hExecIcon = Info.hIcon;
		}
	}
	Ver.Init(_ExecName);
	Ver.GetStr(L"FileDescription", &Description);
	Ver.GetStr(L"ProductName", &Product);
	Ver.GetStr(L"CompanyName", &Company);

	FileName = _FileName;
	SHFILEINFO Info;
	if ( SHGetFileInfo(_FileName, 0, &Info, sizeof Info, SHGFI_ICON) ) {
		hFileIcon = Info.hIcon;
	}
	CoUninitialize();

	HWND hWnd = GetDesktopWindow();
	Result = (GUIReply) DialogBoxParam (hInstance, MAKEINTRESOURCE(IDD_DIALOG_REQCONF), hWnd, DialogProc, (LPARAM)this);
	Release();
	return Result;
}

INT_PTR CALLBACK CReqDlg::DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//static HWND RedControl = NULL;

    switch ( uMsg ) {

		case WM_INITDIALOG:
			{
				CReqDlg *ReqDlg = (CReqDlg *)lParam;
				switch ( ReqDlg->Type ) {
					case reqThreatPointSubject:
					case reqNotIsolateTracked:
						SetDlgItemText(hwndDlg, IDC_LABEL_FILENAME, ReqDlg->ExecName.c_str());
						SendDlgItemMessage(hwndDlg, IDI_REQ_APPLICATION, STM_SETIMAGE, IMAGE_ICON, (LPARAM)ReqDlg->hExecIcon);
						SetDlgItemText(hwndDlg, IDC_LABEL_DESCRIPTION, ReqDlg->Description);
						SetDlgItemText(hwndDlg, IDC_LABEL_PRODUCT, ReqDlg->Product);
						SetDlgItemText(hwndDlg, IDC_LABEL_COMPANY, ReqDlg->Company);
/*
						if ( ReqDlg->IsSetup ) {
							HWND RedControl = GetDlgItem(hwndDlg, IDC_LABEL_SETUP_NOTE);
							int rr = GetLastError();
							SetDlgItemText(hwndDlg, IDC_LABEL_SETUP_NOTE, L"Note: Isolated INSTALLER may not work properly to complete installation. If you trust the INSTALLER, run it non-isolated - press NO.");
							SetTextColor(GetDC(GetDlgItem(hwndDlg, IDC_LABEL_SETUP_NOTE)), RGB(255, 0, 0));
						}
*/
						SetWindowPos(hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
						SetFocus(GetDlgItem(hwndDlg, DefaultReply == gurYes ? IDYES : IDNO));

						break;

					case reqAccessSecretFile:
						SetDlgItemText(hwndDlg, IDC_LABEL_APP, ReqDlg->ExecName.c_str());
						SendDlgItemMessage(hwndDlg, IDI_REQCONF_APPLICATION, STM_SETIMAGE, IMAGE_ICON, (LPARAM)ReqDlg->hExecIcon);
						SetDlgItemText(hwndDlg, IDC_LABEL_DESCRIPTION_CONF, ReqDlg->Description);
						SetDlgItemText(hwndDlg, IDC_LABEL_PRODUCT_CONF, ReqDlg->Product);
						SetDlgItemText(hwndDlg, IDC_LABEL_COMPANY_CONF, ReqDlg->Company);
						SendDlgItemMessage(hwndDlg, IDI_REQCONF_CONFIDENT, STM_SETIMAGE, IMAGE_ICON, (LPARAM)ReqDlg->hFileIcon);
						SetDlgItemText(hwndDlg, IDC_LABEL_CONFIDENT, ReqDlg->FileName.c_str());
						SetWindowPos(hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
						SetFocus(GetDlgItem(hwndDlg, DefaultReply == gurYes ? IDYES : IDNO));
						break;
				}
				//
				// set timers, if requred
				//
				if ( WaitSecs > 0 ) {
					SetTimer(hwndDlg, IDT_PROGRESS, 1*1000, NULL);
					SetTimer(hwndDlg, IDT_COMPLETE, (WaitSecs-5)*1000, NULL);
				}
			}
			break;

		case WM_COMMAND:
			switch ( LOWORD(wParam) ) {
				case IDYES:
					if ( IsDlgButtonChecked(hwndDlg, IDC_CHECK_REQ) == BST_CHECKED )
						EndDialog(hwndDlg, gurYesAlways);
					else
						EndDialog(hwndDlg, gurYes);
					break;

				case IDNO:
					if ( IsDlgButtonChecked(hwndDlg, IDC_CHECK_REQ) == BST_CHECKED )
						EndDialog(hwndDlg, gurNoAlways);
					else
						EndDialog(hwndDlg, gurNo);
					break;

				default:
					return FALSE;
			}
			break;

		case WM_TIMER:
			SetForegroundWindow(hwndDlg);
			switch ( wParam ) {
				case IDT_PROGRESS:
					{
						//
						// get current counter
						//
						wchar_t Str[100];
						if ( DefaultReply == gurNo )
							GetDlgItemText(hwndDlg, IDNO, Str, sizeof Str / sizeof Str[0]);
						else
							GetDlgItemText(hwndDlg, IDYES, Str, sizeof Str / sizeof Str[0]);
						wchar_t *Pos = wcschr(Str, '(');
						int Counter = WaitSecs - 5;
						if ( Pos != NULL ) {
							Counter = _wtoi(Pos+1);
							*--Pos = 0; // not count space
						} else {
							Pos = Str + wcslen(Str);
						}
						if ( Counter > 1 )
							StringCchPrintf(Pos, ( sizeof Str - ((byte *)Pos - (byte *)Str) ) / sizeof Str[0], L" (%d)", --Counter);
						if ( DefaultReply == gurNo )
							SetDlgItemText(hwndDlg, IDNO, Str);
						else
							SetDlgItemText(hwndDlg, IDYES, Str);
					}
					break;

				case IDT_COMPLETE:
					if ( DefaultReply == gurNo )
						PostMessage(hwndDlg, WM_COMMAND, IDNO, 0);
					else
						PostMessage(hwndDlg, WM_COMMAND, IDYES, 0);
					break;
			}
			break;

		case WM_CTLCOLORSTATIC:
			if ( (HWND)lParam == GetDlgItem(hwndDlg, IDC_LABEL_SETUP_NOTE) )  {
				SetTextColor((HDC)wParam, RGB(255, 0, 0));
				SetBkMode((HDC)wParam, TRANSPARENT);
				return (LRESULT) GetStockObject(NULL_BRUSH);
			}
			//break;

		default:
			return FALSE;
    }

    return TRUE;
	//return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

void InitializeFont(HWND hWnd, wchar_t *szFaceName, LONG lHeight, LONG lWidth, LPLOGFONT lpLf)
{
    lpLf->lfHeight      = lHeight ; 
    lpLf->lfWidth       = lWidth ; 
    lpLf->lfEscapement  = 0 ; 
    lpLf->lfOrientation = 0 ; 
    lpLf->lfWeight      = FW_DONTCARE ; 
    lpLf->lfItalic      = FALSE ; 
    lpLf->lfUnderline   = FALSE ; 
    lpLf->lfStrikeOut   = FALSE ; 
    lpLf->lfCharSet     = DEFAULT_CHARSET ; 
    lpLf->lfOutPrecision= OUT_DEFAULT_PRECIS ; 
    lpLf->lfClipPrecision = CLIP_DEFAULT_PRECIS ; 
    lpLf->lfQuality     = DEFAULT_QUALITY ; 
    lpLf->lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE ; 
    wcsncpy(lpLf->lfFaceName, szFaceName,min(wcslen(lpLf->lfFaceName), wcslen(szFaceName)));
}

/*
				LOGFONT BoldFont;
				InitializeFont(hwndDlg, L"MS Shell Dlg", 0, FW_BOLD, &BoldFont);
				HFONT hBoldFont = CreateFontIndirect(&BoldFont);
				if ( hBoldFont == NULL ) return FALSE;
				SendDlgItemMessage(hwndDlg, IDC_LABEL_TEXT, WM_SETFONT, (WPARAM) hBoldFont,  MAKELPARAM(TRUE, 0)) ;
				DeleteObject(hBoldFont);
*/
