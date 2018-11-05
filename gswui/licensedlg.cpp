//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "resource1.h"
#include "licensedlg.h"
#include "interface/gswclient.h"
#include "commonlib/commonlib.h"

extern void start_update_db (HWND hwnd, int init);

CLicenseDlg::CLicenseDlg(void)
{
}

CLicenseDlg::~CLicenseDlg()
{
}

INT_PTR CLicenseDlg::Run(void)
{
	INT_PTR Result = actUndefined;

	WORD DlgRes = IDD_DIALOG_LICENSE;
	HWND hWnd = GetDesktopWindow();
	Result = DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(DlgRes), hWnd, DialogProc, (LPARAM)this);

	switch ( Result ) {
		case actUndefined:
			break;
		case actAuthorise:
			break;
		case actPurchase:
		    ShellExecute(NULL, NULL, L"http://www.gentlesecurity.com/order.php", NULL, NULL, SW_SHOWNORMAL);
			break;
		case actLater:
			break;
		case actTryProfessional:
			break;
	}

	return Result;
}

void CLicenseDlg::Init(HWND hwndDlg)
{
	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCopy(License);

	std::wstring LicenseInfo = License.ProductString;
	LicenseInfo += L"\r\nCopyright (C) GentleSecurity Sarl";
	if ( License.Product != license::gswStandard ) LicenseInfo += L"\r\n" + License.Features;
	LicenseInfo += L"\r\n\r\nLicensed to:\t" + License.LicensedTo;
	LicenseInfo += L"\r\nExpires: \t" + License.Expired;

	SetDlgItemText(hwndDlg, IDC_LICENSE_INFO, LicenseInfo.c_str());
	SetDlgItemText(hwndDlg, IDC_LICNUMBER, License.Number.c_str());
	//SetWindowPos(hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	SetFocus(GetDlgItem(hwndDlg, IDPURCHASE));
	if ( License.Product == license::gswStandard ) {
		if ( License.StateFlags & license::stateTrialAllowed ) {
			ShowWindow(GetDlgItem(hwndDlg, IDTRYPRO), SW_SHOW);
			ShowWindow(GetDlgItem(hwndDlg, IDC_PROEXPIRED), SW_HIDE);
		} else {
			ShowWindow(GetDlgItem(hwndDlg, IDTRYPRO), SW_HIDE);
			ShowWindow(GetDlgItem(hwndDlg, IDC_PROEXPIRED), SW_SHOW);
		}
	} else {
		ShowWindow(GetDlgItem(hwndDlg, IDTRYPRO), SW_HIDE);
		ShowWindow(GetDlgItem(hwndDlg, IDC_PROEXPIRED), SW_HIDE);
	}

	//
	// Buttons
	//

	if ( License.Product == license::gswStandard ) {
		ShowWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), SW_SHOW);
		if ( License.StateFlags & license::stateTrialAllowed )
			ShowWindow(GetDlgItem(hwndDlg, IDPURCHASE), SW_HIDE);
		else
			ShowWindow(GetDlgItem(hwndDlg, IDPURCHASE), SW_SHOW);
		ShowWindow(GetDlgItem(hwndDlg, IDLATER), SW_SHOW);
		ShowWindow(GetDlgItem(hwndDlg, IDC_LICNUMBER_LABEL), SW_HIDE);
		ShowWindow(GetDlgItem(hwndDlg, IDC_LICNUMBER), SW_HIDE);
		SetFocus(GetDlgItem(hwndDlg, IDLATER));
	} else {
		if ( License.StateFlags & license::stateTrial ) {
			ShowWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), SW_SHOW);
			ShowWindow(GetDlgItem(hwndDlg, IDPURCHASE), SW_SHOW);
			ShowWindow(GetDlgItem(hwndDlg, IDLATER), SW_SHOW);
			ShowWindow(GetDlgItem(hwndDlg, IDC_LICNUMBER_LABEL), SW_HIDE);
			ShowWindow(GetDlgItem(hwndDlg, IDC_LICNUMBER), SW_HIDE);
			SetFocus(GetDlgItem(hwndDlg, IDPURCHASE));
		} else {
			ShowWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), SW_SHOW);
			ShowWindow(GetDlgItem(hwndDlg, IDPURCHASE), SW_HIDE);
			ShowWindow(GetDlgItem(hwndDlg, IDLATER), SW_SHOW);
			ShowWindow(GetDlgItem(hwndDlg, IDC_LICNUMBER_LABEL), SW_SHOW);
			ShowWindow(GetDlgItem(hwndDlg, IDC_LICNUMBER), SW_SHOW);
			SetFocus(GetDlgItem(hwndDlg, IDC_LICENSE_BROWSE_BUTTON));
		}
	}
}

INT_PTR CALLBACK CLicenseDlg::DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch ( uMsg ) {

		case WM_INITDIALOG:
			{
				CLicenseDlg *LicenseDlg = (CLicenseDlg *)lParam;
				Init(hwndDlg);
			}
			break;

		case WM_CLOSE:
			EndDialog(hwndDlg, actUndefined);
			break;

		case WM_COMMAND:
			switch ( LOWORD(wParam) ) {
				case IDAUTHORIZE:
					{
						EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), FALSE);
						EnableWindow(GetDlgItem(hwndDlg, IDLATER), FALSE);
						/*
						//
						// Check for UAC
						//
						if ( commonlib::IsUACSupported() && !commonlib::IsElevatedContext() ) {
							MessageBox(hwndDlg, L"The operation requires elevated privileges to proceed.\n"
												L"Please disable UAC (User Account Control). As soon as GeSWall Professional Edition activated, you can enable UAC again.",
												L"GeSWall Professional Edtion", MB_OK);
							EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), TRUE);
							EnableWindow(GetDlgItem(hwndDlg, IDLATER), TRUE);
							break;
						}
						*/
						//
						// Check the license
						//
						int n = (int)SendDlgItemMessage(hwndDlg, IDC_LICENSE_EDIT, WM_GETTEXTLENGTH, 0, 0);
						if ( n <= 0 ) {
							MessageBox(hwndDlg, L"A valid license file name is required.", L"Error", MB_OK);
							EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), TRUE);
							EnableWindow(GetDlgItem(hwndDlg, IDLATER), TRUE);
							break;
						}
							
						wchar_t FileName[512];
						GetDlgItemText(hwndDlg, IDC_LICENSE_EDIT, FileName, sizeof FileName / sizeof FileName[0]);
						//
						// Sanity checks
						//
						if ( GetFileAttributes(FileName) == INVALID_FILE_ATTRIBUTES ) {
							MessageBox(hwndDlg, (std::wstring(FileName) + L" is invalid file path").c_str(), L"Error", MB_OK);
							EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), TRUE);
							EnableWindow(GetDlgItem(hwndDlg, IDLATER), TRUE);
							break;
						}
						//
						license::LicenseManager::LicenseEssentials NewLicense;
						if ( license::LicenseManager::getLicenseEssentials(NewLicense, FileName) == false ) {
							MessageBox(hwndDlg, (std::wstring(FileName) + L" is invalid license file").c_str(), L"Error", MB_OK);
							EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), TRUE);
							EnableWindow(GetDlgItem(hwndDlg, IDLATER), TRUE);
							break;
						}

						license::LicenseManager::LicenseEssentials CurrentLicense;
						license::LicenseManager::LicenseCopy(CurrentLicense);
						bool DbUpdateRequired = CurrentLicense.Product == license::gswStandard && 
												NewLicense.Product == license::gswProfessional;
						//SetDlgItemText(hwndDlg, IDC_LICENSE_EDIT, L"");
						GswClient Client;
						ifstatus::Error Error = Client.SwitchToLicense(FileName);
						if ( Error == ifstatus::errSuccess ) {
							if ( DbUpdateRequired ) {
								HWND hWnd = FindWindow(L"GsWUINotificationWindow", NULL);
								start_update_db(hWnd, 1);
							}
							std::wstring Message = L"New license has been successfully applied!";
							if ( DbUpdateRequired ) Message += L"\nPlease wait for the Application Database update completion.";
							MessageBox(hwndDlg, Message.c_str(), L"GeSWall's License", MB_OK);
							SetDlgItemText(hwndDlg, IDC_LICENSE_EDIT, L"");
						} else
						if ( Error == ifstatus::errAccessDenied ) {
							MessageBox(hwndDlg, L"You don't have enough privileges to complete this operation.\n"
												L"Please logon as an administrator.",
												L"Error", MB_OK);
						} else {
							std::wstring ErrorMsg = L"The license cannot be applied.\n";
							if ( Error == ifstatus::errServerInaccessible ) {
								ErrorMsg += L"www.gentlesecurity.com is not available, please check your connection status!";
							} else {
								ErrorMsg += FileName;
								ErrorMsg += L" is invalid or expired!";
							}
							MessageBox(hwndDlg, ErrorMsg.c_str(), L"Error", MB_OK);
						}
						EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), TRUE);
						EnableWindow(GetDlgItem(hwndDlg, IDLATER), TRUE);
						Init(hwndDlg);
					}
					break;

				case IDPURCHASE:
					EndDialog(hwndDlg, actPurchase);
					break;

				case IDLATER:
					EndDialog(hwndDlg, actLater);
					break;

				case IDC_LICENSE_BROWSE_BUTTON:
					{
						OPENFILENAME ofn;       // common dialog box structure
						wchar_t szFile[260];       // buffer for file name
						// Initialize OPENFILENAME
						ZeroMemory(&ofn, sizeof(ofn));
						ofn.lStructSize = sizeof(ofn);
						ofn.hwndOwner = hwndDlg;
						ofn.lpstrFile = szFile;
						//
						// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
						// use the contents of szFile to initialize itself.
						//
						ofn.lpstrFile[0] = '\0';
						ofn.nMaxFile = sizeof szFile / sizeof szFile[0];
						ofn.lpstrFilter = L"License\0license*.xml\0All\0*.*\0";
						ofn.nFilterIndex = 1;
						ofn.lpstrFileTitle = NULL;
						ofn.nMaxFileTitle = 0;
						ofn.lpstrInitialDir = NULL;
						ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
						if (GetOpenFileName(&ofn)) {
							SetDlgItemText(hwndDlg, IDC_LICENSE_EDIT, szFile);
						}
					}
					break;

				case IDTRYPRO:
					//
					// Display message box
					//
					if ( MessageBox(hwndDlg, L"GeSWall Professional Edition is enhanced version of GeSWall Freeware.\n"
											 L"You can enable it for 15 days trial period. After 15 days the product reverts to\n"
											 L"functionality available in Freeware version.\n\n"
											 L"Do you want to enable GeSWall Professional Edition trial?",
											 L"GeSWall Professional Edtion",
											 MB_YESNO) == IDYES )
					{
						EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), FALSE);
						EnableWindow(GetDlgItem(hwndDlg, IDLATER), FALSE);
						//
						// switch license
						//
						ifstatus::Error Error = license::LicenseManager::SwithTo(license::gswProfessional);
						if ( Error == ifstatus::errSuccess ) {
							HWND hWnd = FindWindow(L"GsWUINotificationWindow", NULL);
							start_update_db(hWnd, 1);
							MessageBox(hwndDlg, L"GeSWall Professional Edtion is successfully enabled.\n"
												L"Please wait for Application Database update completion.", 
												L"GeSWall Professional Edtion", MB_OK);
						} else 
						if ( Error == ifstatus::errAccessDenied ) {
							MessageBox(hwndDlg, L"You don't have enough privileges to complete this operation.\n"
												L"Please logon as an administrator.",
												L"Error", MB_OK);
						} else {
							std::wstring ErrorMsg = L"GeSWall Professional Edtion cannot be enabled.";
							if ( Error == ifstatus::errServerInaccessible )
								ErrorMsg += L"\nwww.gentlesecurity.com is not available, please check your connection status.";
							MessageBox(hwndDlg, ErrorMsg.c_str(), L"Error", MB_OK);
						}
						//
						// Refresh info
						//
						EnableWindow(GetDlgItem(hwndDlg, IDAUTHORIZE), TRUE);
						EnableWindow(GetDlgItem(hwndDlg, IDLATER), TRUE);
						Init(hwndDlg);
					}

					break;

				default:
					return FALSE;
			}
			break;

		default:
			return FALSE;
    }

    return TRUE;
}
