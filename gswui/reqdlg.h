//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __reqdlg_h__
#define __reqdlg_h__

class CReqDlg {

public:
	CReqDlg();
	~CReqDlg();

	GUIReply Run(RequestType _Type, const wchar_t *_ExecName, const wchar_t *_FileName);
	GUIReply Run(const wchar_t *_ExecName, const wchar_t *_FileName);

	static int WaitSecs;
	static GUIReply DefaultReply;

private:
	void Release(void);
	static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

	RequestType Type;
	std::wstring FileName;
	std::wstring ExecName;
	HINSTANCE hInstance;
	HICON hExecIcon;
	HICON hFileIcon;
	commonlib::VerInfo Ver;
	wchar_t *Description;
	wchar_t *Product;
	wchar_t *Company;
	bool IsSetup;
 };

#endif // __reqdlg_h__