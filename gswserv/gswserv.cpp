//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include <conio.h>
#include <stdio.h>
#include "service.h"
#include "w32set.h"
#include "reqserv.h"
#include "rpcserv.h"
#include "test.h"
#include "configurator.h"
#include "guictrl/gswuisupport.h"
#include "guictrl/execsupport.h"
//#include "guictrl/procmarkersupport.h"
#include "ifstatus.h"
#include "logs/checker.h"
#include "gswproc.h"
#include "license/licensemanager.h"

DWORD NtVersion;

void Main(DWORD Argc, wchar_t **Argv);
void Stop(void);
void testRpc ();

HANDLE hStopEvent = NULL;
HANDLE hMainThread = NULL;
bool bService = false;

HANDLE CreateGlobalSyncObject ();

void Main(DWORD Argc, wchar_t **Argv)
{
    DWORD Version = GetVersion();
    NtVersion = LOBYTE(LOWORD(Version))<<8;
    NtVersion += HIBYTE(LOWORD(Version));

    if ( bService ) Service::ReportStatus(SERVICE_START_PENDING, NO_ERROR, 100);

    hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if ( hStopEvent == NULL ) {
		DWORD Err = GetLastError();
        trace("CreateEvent error: %d\n", Err);
		Service::ReportStatus(SERVICE_STOPPED, Err, 0);
        return;
    }

	BOOL Res = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), 
								&hMainThread, THREAD_ALL_ACCESS, FALSE, 0);
	if ( Res == FALSE ) {
		DWORD Err = GetLastError();
        trace("DuplicateHandle error: %d\n", Err);
		Service::ReportStatus(SERVICE_STOPPED, Err, 0);
        return;
	}
    
    //
    // init procedures
    //
	WSADATA WsaData;
	WSAStartup(MAKEWORD(2, 2), &WsaData);

    config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
    Storage::SetDBSetting(Node);

    if ( bService ) Service::ReportStatus(SERVICE_START_PENDING, NO_ERROR, 1000);
    
    w32set::Init();

    if ( bService ) Service::ReportStatus(SERVICE_START_PENDING, NO_ERROR, 100);
    
    ReqServ::Init();

    if ( bService ) Service::ReportStatus(SERVICE_START_PENDING, NO_ERROR, 100);
    
    RpcServ::Init();

    if ( bService ) Service::ReportStatus(SERVICE_START_PENDING, NO_ERROR, 500);
    
//    gswserv::guictrl::ProcMarkerSupport::init ();
    gswserv::guictrl::GsWuiSupport::init ();
    gswserv::guictrl::exec_support::init ();
	gswserv::logs::Checker::start ();

    //
    if ( bService ) Service::ReportStatus(SERVICE_RUNNING);

    HANDLE globalObject = CreateGlobalSyncObject ();

    if ( !bService ) 
	{
#ifdef _DEBUG
		commonlib::Debug::SetMode(commonlib::Debug::outConsole);
        Test::Run();
#else
        printf("press any key to complete");
        getch();
#endif
        SetEvent(hStopEvent);
    }
	//
	// re-mark app's files according to its db settings, might be required in case of
	// update erasing our SACL marks
	//
    GswProc::RefreshApplications();

	//
	// check license
	//
	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCopy(License);
	if ( License.Product == license::gswUnlicensed ) {
		//
		// Set log only level and exit
		//
		//config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
		//Node->setInt(L"SecurityLevel", GesRule::secLevel6);
		//GswProc::RefreshSettings();
//	} else
//	if ( License.StateFlags & license::stateExpired && License.Product == license::gswProfessional ) {
//		license::LicenseManager::SwithTo(license::gswStandard);
	} else {
		HANDLE hEvents[] = { hStopEvent };
		DWORD rc = WaitForMultipleObjects(sizeof hEvents / sizeof hEvents[0], hEvents, FALSE, INFINITE);
	}
    
    if ( bService ) Service::ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);

	//
	// re-mark app's files according to its db settings, might be required in case of
	// update erasing our SACL marks
	//
    GswProc::RefreshApplications();

    //
    // Cleanup stuff
    //
	gswserv::logs::Checker::stop ();
    gswserv::guictrl::exec_support::clear ();
    gswserv::guictrl::GsWuiSupport::clear ();
//    gswserv::guictrl::ProcMarkerSupport::clear ();
    RpcServ::Release();
    ReqServ::Release();
    Storage::close ();
	WSACleanup();
    CloseHandle (globalObject);
}

void Stop(void)
{
    if ( hStopEvent ) SetEvent(hStopEvent);
	WaitForSingleObject(hMainThread, INFINITE);
    CloseHandle(hStopEvent);
	CloseHandle(hMainThread);
}

PSECURITY_ATTRIBUTES initSecurityAttr (PSECURITY_DESCRIPTOR sd, SECURITY_ATTRIBUTES& sa)
{
  PSECURITY_ATTRIBUTES _sa = NULL;
  
  if (
         TRUE == InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)
      && TRUE == SetSecurityDescriptorDacl (sd, TRUE, (PACL) NULL, FALSE)
     )
  {
    sa.nLength              = sizeof (sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle       = TRUE;
    _sa = &sa;
  }
  
  return _sa;
} // initSecurityAttr

HANDLE CreateGlobalSyncObject ()
{
  unsigned char        sdBuffer [SECURITY_DESCRIPTOR_MIN_LENGTH];
  PSECURITY_DESCRIPTOR sd = reinterpret_cast <PSECURITY_DESCRIPTOR> (sdBuffer);;
  SECURITY_ATTRIBUTES  sa;

  PSECURITY_ATTRIBUTES gsa = initSecurityAttr (sd, sa);

  return CreateMutex (gsa, FALSE, ifstatus::GlobalObjectName);
} // CreateGlobalSyncObject

int wmain(int argc, wchar_t *argv[])
{
	bService = Service::IsProcessService(GetCurrentProcess());

    trace("bService == %d\n", bService);

    if ( bService ) 
        Service::Setup(L"gswserv", Main, Stop);
    else
        Main(argc, argv);

    return 0;
}

