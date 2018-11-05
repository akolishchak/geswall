//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "resource1.h"
#include "trialmanager.h"
#include "license/licensemanager.h"
#include "config/configurator.h"
#include "commonlib/hyperlinks.h"
#include "commonlib/commonlib.h"
#include "appstat.h"

extern void start_update_db (HWND hwnd, int init);


namespace TrialManager {

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool IsDialogRun = false;

bool Handle(EventType Event)
{
	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCachedCopy(License);
	if ( !( License.StateFlags & license::stateTrialAllowed ) ) return false;
	//
	// Check for don't ask checkbox
	//
	config::Configurator::PtrToINode Node = config::Configurator::getTrialManagerNode();
	if ( Node->getBool(L"DontAskAgain") || IsDialogRun == true ) return false;
	switch ( Event ) {
		case eventConsoleStart:
			{
				int Counter = Node->getInt(L"ConsoleStart") + 1;
				Node->setInt(L"ConsoleStart", Counter);
				if ( Counter % 2 != 0 ) return false;
			}
			break;
		case eventUpdated:
			//
			// react on any event
			//
			break;
		case eventUpdateCheck:
			{
				return false;

				//int Counter = Node->getInt(L"UpdateCheck") + 1;
				//Node->setInt(L"UpdateCheck", Counter);
				//if ( Counter % 3 != 0 ) return false;
			}
			break;
		case eventTrayClick:
			{
				int Counter = Node->getInt(L"TrayClick") + 1;
				Node->setInt(L"TrayClick", Counter);
				if ( Counter % 3 != 0 ) return false;
			}
			break;
	}

	IsDialogRun = true;
	WORD DlgRes = IDD_DIALOG_TRIALREQ;
	HWND hWnd = GetDesktopWindow();
	DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(DlgRes), hWnd, DialogProc, NULL);
	IsDialogRun = false;

	return true;
}

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch ( uMsg ) {

		case WM_INITDIALOG:
			{
				ConvertStaticToHyperlink(hwndDlg, (UINT)IDC_STATIC_HT1, L"http://www.gentlesecurity.com/professional.php");
				//CLicenseDlg *LicenseDlg = (CLicenseDlg *)lParam;
				config::Configurator::PtrToINode Node = config::Configurator::getTrialManagerNode();
				int Counter = Node->getInt(L"DisplayDialog") + 1;
				Node->setInt(L"DisplayDialog", Counter);
				if ( Counter <= 1 ) {
					ShowWindow(GetDlgItem(hwndDlg, IDC_CHECK_TRIAL_QUERY), SW_HIDE);
				} else {
					ShowWindow(GetDlgItem(hwndDlg, IDC_CHECK_TRIAL_QUERY), SW_SHOW);
				}
			}
			break;

		case WM_CLOSE:
			EndDialog(hwndDlg, FALSE);
			break;

		case WM_COMMAND:
			switch ( LOWORD(wParam) ) {
				case IDSTART_TRIAL:
					{
						/*
						if ( commonlib::IsUACSupported() && !commonlib::IsElevatedContext() ) {
							MessageBox(hwndDlg, L"The operation requires elevated privileges to proceed.\n"
												L"Please disable UAC (User Account Control). As soon as GeSWall Professional Edition activated, you can enable UAC again.",
												L"GeSWall Professional Edtion", MB_OK);
							EndDialog(hwndDlg, TRUE);
							break;
						}
						*/
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
							EndDialog(hwndDlg, TRUE);
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
					}
					break;

				case IDTRIAL_LATER:
					{
						config::Configurator::PtrToINode Node = config::Configurator::getTrialManagerNode();
						Node->setBool(L"DontAskAgain", IsDlgButtonChecked(hwndDlg, IDC_CHECK_TRIAL_QUERY) == BST_CHECKED);
						EndDialog(hwndDlg, FALSE);
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

INT_PTR CALLBACK ExpireMessageDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch ( uMsg ) {

		case WM_INITDIALOG:
			{
				ConvertStaticToHyperlink(hwndDlg, (UINT)IDC_STATIC_HT2, L"http://www.gentlesecurity.com/prevention.php");

				std::wstring AppsString;
				std::vector<std::wstring> Apps;
				AppStat::GetTrialApps(Apps);
				for ( size_t i = 0; i < 4; i++ ) {
					if ( i < Apps.size() ) {
						AppsString += L" -  " + Apps[i];
						AppsString += L"\n";
					} else {
						const wchar_t *DefGroups[] = {
								   L"E-Mail clients",
								   L"Messengers",
								   L"File sharing clients",
								   L"Office applications"
						};
						AppsString += L" -  ";
						AppsString += DefGroups[i];
						AppsString += L"\n";
					}
				}
				AppsString += L" -  etc.";
				SetDlgItemText(hwndDlg, IDC_STATIC_APPS_LIST, AppsString.c_str());
			}
			break;

		case WM_CLOSE:
			EndDialog(hwndDlg, FALSE);
			break;

		case WM_COMMAND:
			switch ( LOWORD(wParam) ) {
				case IDPURCHASENOW:
					ShellExecute(NULL, NULL, L"http://www.gentlesecurity.com/order.php", NULL, NULL, SW_SHOWNORMAL);
					EndDialog(hwndDlg, FALSE);
					break;

				case IDCLOSE:
					EndDialog(hwndDlg, FALSE);
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

bool HandleExpired(void)
{
	license::LicenseManager::SwithTo(license::gswStandard);
	//
	// Get list of missed apps
	// These applications will not be safe next time you start them.
	// Malware and other attacks coming through these applications would cause a damage of your system.
	//

	WORD DlgRes = IDD_DIALOG_TRIALEXP;
	HWND hWnd = GetDesktopWindow();
	DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(DlgRes), hWnd, ExpireMessageDialogProc, NULL);

	return true;
}


}; // namespace TrialManager {
