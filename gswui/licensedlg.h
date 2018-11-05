//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __licensedlg_h__
#define __licensedlg_h__

#include "license/licensemanager.h"


class CLicenseDlg {

	enum {
		actUndefined,
		actAuthorise,
		actPurchase,
		actLater,
		actTryProfessional
	};

public:
	CLicenseDlg(void);
	~CLicenseDlg();

	INT_PTR Run(void);

private:
	static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static void Init(HWND hwndDlg);

}; // class CLicenseDlg

#endif // __licensedlg_h__