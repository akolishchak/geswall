//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __service_h__
#define __service_h__

namespace Service {

	typedef void (*_ServiceStart)(DWORD Argc, wchar_t **Argv);
	typedef void ( *_ServiceStop)(void);

	bool Setup(wchar_t *_ServiceName, _ServiceStart Start, _ServiceStop Stop);
	BOOL ReportStatus(DWORD CurrentState, DWORD Win32ExitCode = NO_ERROR, DWORD WaitHint = 0);
	bool IsProcessService(HANDLE hProcess);
};

#endif // __service_h__