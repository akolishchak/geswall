//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "service.h"

namespace Service {

wchar_t *ServiceName = NULL;
SERVICE_STATUS_HANDLE hStatusHandle;
SERVICE_STATUS Status = { SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, NO_ERROR, 0, 0, 2000 };

_ServiceStart ServiceStart = NULL;
_ServiceStop ServiceStop = NULL;

void WINAPI ServiceMain(DWORD dwArgc, wchar_t **Argv);
DWORD WINAPI HandlerProc(DWORD dwCtrlCode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);

bool Setup(wchar_t *_ServiceName, _ServiceStart Start, _ServiceStop Stop)
{
	ServiceName = _ServiceName;
	ServiceStart = Start;
	ServiceStop = Stop;

	static SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ ServiceName, ServiceMain },
		{ NULL, NULL }
	};

	if ( !StartServiceCtrlDispatcher(DispatchTable) ) {
		trace("StartServiceCtrlDispatcher error: %%d\n", GetLastError()); 
		return false;
	} 

	return true;
}

void WINAPI ServiceMain(DWORD Argc, wchar_t **Argv)
{
	// register our service control handler:
	//
	hStatusHandle = RegisterServiceCtrlHandlerEx(ServiceName, HandlerProc, NULL);

	if ( hStatusHandle == 0 ) {
		ReportStatus(SERVICE_STOPPED);
		return;
	}

	ServiceStart(Argc, Argv);

	ReportStatus(SERVICE_STOPPED);
	return;
}

DWORD WINAPI HandlerProc(DWORD dwCtrlCode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch (dwCtrlCode) {
		case SERVICE_CONTROL_STOP:
		case SERVICE_CONTROL_SHUTDOWN:
			trace("stop control\n");
			ServiceStop();
			return NO_ERROR;

		default:
			break;
	}

	ReportStatus(Status.dwCurrentState, NO_ERROR, 0);
	return ERROR_CALL_NOT_IMPLEMENTED;
}

BOOL ReportStatus(DWORD CurrentState, DWORD Win32ExitCode, DWORD WaitHint)
{
	static DWORD CheckPoint = 1;

	if ( CurrentState == SERVICE_START_PENDING )
		Status.dwControlsAccepted = 0;
	else
		Status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    Status.dwCurrentState = CurrentState;
    Status.dwWin32ExitCode = Win32ExitCode;
    Status.dwWaitHint = WaitHint;

	if ( CurrentState == SERVICE_RUNNING || CurrentState == SERVICE_STOPPED ) {
		Status.dwCheckPoint = 0;
		Status.dwWaitHint = 0;
	} else
        Status.dwCheckPoint = CheckPoint++;

	//
	// Report the status of the service to the service control manager.
    //
	BOOL rc;
    rc = SetServiceStatus(hStatusHandle, &Status);
	if ( !rc ) trace("SetServiceStatus error %d\n", GetLastError());

	return rc;
}

bool IsProcessService(HANDLE hProcess)
{
	HANDLE hToken;
	if ( !OpenProcessToken(hProcess, TOKEN_ALL_ACCESS_P, &hToken) ) {
		trace("OpenProcessToken error %d\n", GetLastError());
		return false;
	}

	DWORD BufSize = 0;
	PBYTE Buf = NULL;
	GetTokenInformation(hToken, TokenGroups, Buf, BufSize, &BufSize);
	Buf = new BYTE[BufSize];
	if ( !GetTokenInformation(hToken, TokenGroups, Buf, BufSize, &BufSize) ) {
		trace("GetTokenInformation error %d\n", GetLastError());
		return false;
	}

	PTOKEN_GROUPS Groups = (PTOKEN_GROUPS) Buf;
	bool bRes = false;
	bool bInteractive = false;

	// try to match sids
	for ( DWORD i = 0; i < Groups->GroupCount; i++ ) {

        static const unsigned char ServiceSid[] = {
           1,                   // rev
           1,                   // subauthcount
           0, 0, 0, 0, 0, 5,    // sia
           6, 0, 0, 0};

		if ( EqualSid( Groups->Groups[i].Sid, (PSID)ServiceSid ) ) {
			bRes = true;
			break;
		}

        static const unsigned char InteractiveSid[] = {
           1,                   // rev
           1,                   // subauthcount
           0, 0, 0, 0, 0, 5,    // sia
           4, 0, 0, 0};

		if ( EqualSid( Groups->Groups[i].Sid, (PSID)InteractiveSid ) ) bInteractive = true;
	}

	if ( !bInteractive ) bRes = true;

	delete[] Buf;
	CloseHandle(hToken);

	return bRes;
}

} // namespace Service {