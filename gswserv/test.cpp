//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "test.h"
#include "ifgswrpc_h.h"

#include <conio.h>
#include <time.h>

#include "db/storage.h"
#include "db/setting.h"
#include "replication.h"
#include "gswproc.h"
#include "gswdrv.h"
#include "nttools.h"
#include "macroresolver.h"
#include "reqserv.h"
#include "reqhandle.h"
#include "w32registrynode.h"
#include "commonlib/tools.h"
#include "commonlib/argumentexception.h"

#include "cdbc/iconnectionfactory.h"
#include "cdbc/iconnection.h"
#include "cdbc/istatement.h"
#include "cdbc/cdbcsupport.h"
#include "setting.h"

#include "guictrl/clientmanager.h"
#include "guictrl/gswuiclient.h"
#include "guictrl/sessionclientid.h"
#include "guictrl/gswuirequest.h"
#include "guictrl/gswuiresponse.h"
#include "guictrl/authoritychecker.h"
#include "guictrl/gswuisupport.h"
#include "guictrl/execsupport.h"
#include "processexecutor/processexecutor.h"

#include "logs/checker.h"
#include "license/msxmllicense.h"
#include "update/update.h"

using namespace sql;
using namespace Storage;
using namespace Storage::replication;
using namespace config;
using namespace gswserv::guictrl;
using namespace ReqServ;
using namespace commonlib::Tools;

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

namespace Test {

void Test1(void);
void Test2(void);
void Test3(void);
void Test4(void);
void Test5(void);
void TestConfigRegistry (void);
void TestReplication (void);
void TestDebugReplication (void);
void TestCompare (void);
void TestDebugCompare (void);
void TestGUICtrl (void);
void TestAuthorityChecker (void);
void TestDelApp (void);
void TestDrvReq(void);
void TestGsWuiSupport(void);
void TestMacroResolver(void);
void TestObjectNameConversion(void);
void TestLogChecker(void);
void TestLicense (void);
void TestUpdate (void);
void TestRedirectExec (void);
void TestRedirectExecAcrobat (void);
void TestConvertFileName (void);

typedef void (*TestFunc)(void);

struct TestItem {
    TestFunc Func;
    wchar_t *MenuText;
};

TestItem MenuItem[] = {
    { Test1,                L"Insert application records in db" },
    { Test2,                L"Refresh common resources" },
    { Test3,                L"Refresh application" },
    { Test4,                L"Refresh all applications" },
    { Test5,                L"Dynamic rules load" },
    { TestConfigRegistry,   L"Registry parameters storage" },
    { TestReplication,      L"Replication" },
    { TestCompare,          L"Compare" },
    { TestDebugReplication, L"Debug Replication" },
    { TestDebugCompare,     L"Debug Compare" },
    { TestGUICtrl,          L"Test message queue for gui control" },
    { TestAuthorityChecker, L"Test Authority Checker for gui control" },
    { TestDrvReq,           L"Test gswui dialog" },
    { TestDelApp,           L"Test delete application" },
    { TestGsWuiSupport,     L"Test GsWuiSupport" },
    { TestMacroResolver,    L"Test MacroResolver" },
    { TestObjectNameConversion, L"Test Object Name Conversion" },
    { TestLogChecker,       L"Test logs checker" },
    { TestLicense,          L"Test license" },
    { TestUpdate,           L"Test db update" },
    { TestRedirectExec,     L"Test redirect execution" },
    { TestRedirectExecAcrobat, L"Test redirect execution acrobat" },
    { TestConvertFileName,  L"Test convert file name" }
};


void Test1(void)
{
    {
      IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
      IConnection::PtrToIConnection        conn = connHolder.connection ();
    }
    
    Setting::setConnectString (wstring (L"./" + Setting::getConnectString ()));
    
    {
      IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
      IConnection::PtrToIConnection        conn = connHolder.connection ();
    }
    
    {
      IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
      IConnection::PtrToIConnection        conn = connHolder.connection ();
    }
    
    int Num;
    trace("Number of records (e.g. - 300): ");
    scanf("%d", &Num);
    int SubjectId;
    trace("Start subject id (start of unique range, e.g. - 5000): ");
    scanf("%d", &SubjectId);

    for ( int i = 0; i < Num; i++ ) {

        trace("record %d\r", i+1);
        //
        // insert application
        //
        int Id;
        ParamsInfo Info;
        memset(Info.Attributes.Param, 0, sizeof Info.Attributes.Param);
        Info.Attributes.Param[GesRule::attSubjectId] = SubjectId+i;
        Info.Id = 0;
        Info.GroupId = 6;
        Info.Description[0] = 0;
        Info.Type = parAppContent;
        Id = InsertParams(Info);
        if ( Id == 0 ) {
            trace("\nInsertParams error\n");
            break;
        }

        memset(Info.Attributes.Param, 0, sizeof Info.Attributes.Param);
        Info.Attributes.Param[GesRule::attObjectId] = SubjectId+i;
        Info.Id = 0;
        Info.GroupId = 6;
        Info.Description[0] = 0;
        Info.Type = parResourceApp;
        Id = InsertParams(Info);
        if ( Id == 0 ) {
            trace("\nInsertParams error\n");
            break;
        }

        ContentInfo Content;
        Content.Id = 0;
        Content.ParentId = Id;
        wcscpy(Content.FileName, L"test.test");
        Content.Type = cntInternalName;
        wstring cont = L"test;test Corporation_";
        wchar_t num[30];
        _itow(i, num, 10);
        cont += num;
        wcscpy(Content.Content, cont.c_str());
        if ( InsertContent(Content) == 0 ) {
            trace("\nInsertContent error\n");
            break;
        }

        //
        // insert its resources
        //
        PathInfo Path;
        Path.Id = 0;
        Path.ParentId = Id;
        Path.Type = nttFile;
        wcscpy(Path.Path, L"%USERPROFILE%\\Local Settings\\Temporary Internet Files\\");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
        Path.Type = nttFile;
        wcscpy(Path.Path, L"%USERPROFILE%\\Local Settings\\Application Data\\Microsoft\\Internet Explorer\\");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
        Path.Type = nttKey;
        wcscpy(Path.Path, L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
        Path.Type = nttKey;
        wcscpy(Path.Path, L"%HKEY_CURRENT_USER%\\SOFTWARE\\Microsoft\\Internet Explorer");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
        Path.Type = nttKey;
        wcscpy(Path.Path, L"%HKEY_CURRENT_USER%\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
        Path.Type = nttFile;
        wcscpy(Path.Path, L"%HKEY_LOCAL_MACHINE\\SOFTWARE\\Mirabilis\\ICQ\\ICQPro\\DefaultPrefs\\ICQPath%");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
        Path.Type = nttKey;
        wcscpy(Path.Path, L"%HKEY_LOCAL_MACHINE\\SOFTWARE\\Mirabilis\\ICQ%");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
        Path.Type = nttKey;
        wcscpy(Path.Path, L"%HKEY_CURRENT_USER%\\Software\\Mirabilis\\ICQ");
        if ( InsertPath(Path) == 0 ) {
            trace("\nInsertPath error\n");
            break;
        }
    }
}

void Test2(void)
{
    if ( GswProc::RefreshResources() != 0 ) {
        trace("\nResources refresh is failed\n");
    } else {
        trace("\nResources refresh is successful\n");
    }
}

void Test3(void)
{
    int AppId;
    trace("Application ID: ");
    scanf("%d", &AppId);
    
    if ( GswProc::RefreshApp(AppId) != 0 ) {
        trace("\nApplication refresh is failed\n");
    } else {
        trace("\nApplication refresh is successful\n");
    }
}

void Test4(void)
{
    if ( GswProc::RefreshApplications() != 0 ) {
        trace("\nAll applications refresh is failed\n");
    } else {
        trace("\nAll applications refresh is successful\n");
    }
}

void Test5(void)
{
    static std::wstring ExecName = L"%ProgramFiles%\\Internet Explorer\\IEXPLORE.EXE";
    wchar_t Str[256] = { 0 };
    printf("File to start (empty for default %S)\n", ExecName.c_str());
    fflush(stdin);
    fgetws(Str, sizeof Str / sizeof Str[0] - 1, stdin);
    if ( Str[0] != 10 ) {
        Str[wcslen(Str)-1] = 0;
        ExecName = Str;
    }

    int Num;
    printf("Number of starts: ");
    scanf("%d", &Num);

    CGswDrv Drv;

    for ( int i = 0; i < Num; i++ ) {
        if ( Drv.IsValid() ) {
            STARTUPINFO si = { 0 };
            PROCESS_INFORMATION  pi;
            si.cb = sizeof si;
            if ( !CreateProcess(ExecName.c_str(), NULL, NULL, NULL, TRUE, 0, 0, NULL, &si, &pi) ) {
                trace("CreateProcess error: %d\n", GetLastError());
                return;
            }
            CloseHandle(pi.hThread);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
        } else {
            wstring Resolved;
            size_t Length = macro::process(Resolved, ExecName, LongToHandle(GetCurrentProcessId()), L"");
            if ( Length == 0 ) {
                trace("Wrong name\n");
                return;
            }
            wstring Native;
            if (0 == (Length = DOSNameToFullName(Native, Resolved)))
                Length = UNCNameToFullName(Native, Resolved);
            if ( Length == 0 ) {
                trace("Wrong name\n");
                return;
            }

            ProcExecReq Req;
            memset(&Req, 0, sizeof Req);
            PVOID Response;
            SIZE_T ResponseSize;
            if ( Native.size() > sizeof Req.FileName / sizeof Req.FileName[0] - 1 ) {
                trace("Wrong name\n");
                return;
            }
            Req.ProcessId = LongToHandle(GetCurrentProcessId());
            wcscpy(Req.FileName, Native.c_str());
            if ( !ReqServ::HandleProcExec(&Req, &Response, &ResponseSize) ) {
                trace("HandleProcExec error\n");
            } else
                CReqHandle::FreeResponse(Response);
        }
    }
}

void TestConfigRegistry (void)
{
  wchar_t rootKey [1024];
  wchar_t valueName [1024];
  int     testType = 0;
  
  trace ("Input test type:\n"
         "  0 - get string\n"
         "  1 - set string\n"
         "  2 - get int\n"
         "  3 - set int\n"
         "  4 - set binary\n"
         "  5 - get binary\n"
         ": "
        );
  scanf("%d", &testType);
  
  trace ("Input key name: ");
  wscanf (L"%s", rootKey);
  
  trace ("Input value name: ");
  wscanf (L"%s", valueName);
  
  try
  {
    switch (testType)
    {
      case 0: 
      {
           W32RegistryNode node (wstring (rootKey), true);
           wstring value = node.getString (wstring (valueName));
           wprintf (L"\nvalue => %s", value.c_str ());
           break;
      }     
      case 1:
      {
           wchar_t value [1024];
           trace ("Input value: ");
           wscanf (L"%s", value);
  
           W32RegistryNode node (wstring (rootKey), true);
           node.setString (wstring (valueName), wstring (value));
           trace ("setString - ok");
           break;
      }
      case 2: 
      {
           W32RegistryNode node (wstring (rootKey), true);
           int value = node.getInt (wstring (valueName));
           wprintf (L"\nvalue => %d", value);
           break;
      }
      case 3:
      {
           int value;
           trace ("Input value: ");
           wscanf (L"%d", &value);
  
           W32RegistryNode node (wstring (rootKey), true);
           node.setInt (wstring (valueName), value);
           trace ("setInt - ok");
           break;
      }
      case 4: 
      {
           wchar_t value [1024];
           trace ("Input value: ");
           wscanf (L"%s", value);
  
           W32RegistryNode node (wstring (rootKey), true);
           node.setBinary (wstring (valueName), reinterpret_cast <unsigned char*> (value), wcslen (value) * sizeof (wchar_t));
           trace ("setString - ok");
           break;
      }     
      case 5:
      {
           unsigned char value [1024];
           W32RegistryNode node (wstring (rootKey), true);
           size_t result = node.getBinary (wstring (valueName), value, sizeof (value));
           
           wstring valueStr (reinterpret_cast <wchar_t*> (value), result / sizeof (wchar_t));
           wprintf (L"\nvalue => %s", valueStr.c_str ());
           break;
      }     
      default:
           trace ("Unknown test");
           break;
    }
  }
  catch (ConfigException& e)
  {
    wprintf (L"\nException => %s", e.getMessageTextAndCode ());
  }
  
} // TestConfigRegistry

void TestReplication (void)
{
  wchar_t source [1024];
  wchar_t destination [1024];
  int     rplOptions = 0;
  int     type       = 0;
  int     scanf_result;
  
  trace ("Input replication type"
         "\n  0 - new replication"
         "\n  1 - old replication"
         "\n  0 - default"
         "\n> ");
  scanf_result = wscanf (L"%u", &type);
  if (0 == scanf_result)
    type = 0;
  
  if (0 > type || 1 < type)
  {
    trace ("Bad replication type - %u", type);
    return;
  }  
  
  trace ("type - %u\n", type);
  
  trace ("Input source db connect string: ");
  scanf_result = wscanf (L"%s", source);
//  wcscpy (source, L"repltest\\2\\geswall.dat");
  
  trace ("Input destination db connect string: ");
  scanf_result = wscanf (L"%s", destination);
//  wcscpy (destination, L"repltest\\1\\geswall.dat");
  
  try
  {
    if (0 == type)
    {
      trace ("Input replicate options: ");
      wscanf (L"%u", &rplOptions);
      
	  START_COUNTER;
	  bool Result = Storage::replication::Replicate (source, destination, rplOptions);
	  END_COUNTER(Storage::replication::Replicate);
      if (true == Result)
        trace ("\nReplicate - ok");
      else
        trace ("\nReplicate - error");  
    }
    
    
    if (1 == type)
    {
      if (true == Replicate (wstring (source), wstring (destination)))
      {
        trace ("\nReplicate - ok");
        //if (true == Compare (wstring (source), wstring (destination)))
        //  trace ("\nCompare - ok");
        //else  
        //  trace ("\nCompare - error");
      }  
      else  
      {
        trace ("\nReplicate - error");
      }  
    } // if (1 == type)
  }
  catch (StorageException& e)
  { 
    wprintf (L"\n\nReplicate - error => %s", e.getMessageTextAndCode ());
  }
} // TestReplication

void TestDebugReplication (void)
{
  if (true == Replicate (wstring (L"replication/src/geswall.dat"), wstring (L"replication/dst/geswall.dat")))
    trace ("\nReplicate - ok");
  else  
    trace ("\nReplicate - error");
} // TestDebugReplication

void TestCompare (void)
{
  wchar_t source [1024];
  wchar_t destination [1024];
  
  trace ("Input source db connect string: ");
  wscanf (L"%s", source);
  
  trace ("Input destination db connect string: ");
  wscanf (L"%s", destination);
  
  //if (true == Compare (wstring (source), wstring (destination)))
  //  trace ("\nCompare - ok");
  //else  
  //  trace ("\nCompare - error");
} // TestCompare

void TestDebugCompare (void)
{
//  if (true == Compare (wstring (L"replication/src/geswall.dat"), wstring (L"replication/dst/geswall.dat")))
//    trace ("\nCompare - ok");
//  else  
//    trace ("\nCompare - error");
} // TestDebugCompare

//#include <ntsecpkg.h>

void TestGUICtrl (void)
{
  typedef ClientManager<GsWuiClient, SessionClientId> GuiClientManager;
  GuiClientManager manager;
  
  ImpersonateSelf (SecurityImpersonation);
  
  GuiClientManager::PtrToClient client (new GsWuiClient (LongToHandle (GetCurrentProcessId ()), wstring (L"")));
  
  try
  {
    manager.registerClient (GuiClientManager::ClientId (), client);
    trace ("\nregisterClient ok");
  }
  catch (GUICtrlException&)
  {
    trace ("\nregisterClient error");
  }
  
  try
  {
    manager.registerClient (GuiClientManager::ClientId (), GuiClientManager::PtrToClient (new GsWuiClient (LongToHandle (GetCurrentProcessId ()), wstring (L""))));
    trace ("\nalready exist test error");
  }
  catch (GUICtrlException&)
  {
    trace ("\nalready exist test ok");
  }
  
  GuiClientManager::PtrToClient clientGet = manager.getClient (GuiClientManager::ClientId ());
  if (clientGet != client)
    trace ("\ngetClient error");
  else
    trace ("\ngetClient ok");  
    
  if (NULL != clientGet.get ())
  {
    GsWuiRequest::PtrToGsWuiRequest request (new GsWuiRequest (LongToHandle (GetCurrentProcessId ()), reqThreatPointSubject, L"", L""));
    
    trace ("\nplease wait 5 secs");
    GsWuiRequest::PtrToRpcReply requestWait = clientGet->call (request, 5*1000);
    if (NULL != requestWait.get ())
      trace ("\nwaitRequest error");
    else
      trace ("\nwaitRequest ok");  
    
    //if (requestWait != request)
    //  trace ("\nwaitRequest error");
    //else
    //  trace ("\nwaitRequest ok");  
      
    //GsWuiResponse::PtrToGsWuiResponse response (new GsWuiResponse (requestWait->getId (), gurUndefined));
    //clientGet->addRequest (response);
    //
    //Request::PtrToRequest responseWait = clientGet->waitResponse (response->getParentRequestId (), GsWuiClient::Const::infiniteTimeout);
    //if (responseWait != response)
    //  trace ("\nwaitResponse error");
    //else
    //  trace ("\nwaitResponse ok");  
  }
  
  GuiClientManager::PtrToClient clientUnreg = manager.unregisterClient (GuiClientManager::ClientId ());
  
  if (clientUnreg != client)
    trace ("\nunregisterClient error");
  else
    trace ("\nunregisterClient ok");  
   
  try
  {
    manager.registerClient (GuiClientManager::ClientId (), client);
    trace ("\nregisterClient ok");
  }
  catch (GUICtrlException&)
  {
    trace ("\nregisterClient error");
  }
   
  manager.unregisterAllClients ();
  
  RevertToSelf ();
} // TestGUICtrl

void TestAuthorityChecker (void)
{
  AuthorityChecker checker;
  
  wstring objectName;
  checker.queryAuthorityObject (LongToHandle (GetCurrentProcessId ()), objectName);
  if (0 >= objectName.size ())
  {
    trace ("\nqueryAuthorityObject error");  
    return;
  } 
  
  wstring authorityHash;
  HANDLE  hEvent = CreateEvent (NULL, TRUE, FALSE, objectName.c_str ());  
  if (true == checker.queryAuthorityHash (LongToHandle (GetCurrentProcessId ()), hEvent, authorityHash))
  {
    trace ("\nqueryAuthorityHash ok");
    checker.releaseAuthorityHash (authorityHash, LongToHandle (GetCurrentProcessId ()));
  }
  else
  {
    trace ("\nqueryAuthorityHash error");  
  }
  
  CloseHandle (hEvent);
} // TestAuthorityChecker

void TestDelApp (void)
{
  //DeleteApplication (2045);
  
  //try
  //{
  //  IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
  //  IConnection::PtrToIConnection        conn = connHolder.connection ();
  //  
  //  CDBCSupport::PtrToIResultSet checkException = CDBCSupport ().executeQuery <tuple <const wstring& , int, int, int> > (conn, wstring (L"select id from pathes where path = ? and res_type = ? and params_id in (select id from params where param2 = ?) and options = ?"), tuple <const wstring& , int, int, int> (wstring (L"test"), 1, 1, dboNone));
  //}
  //catch (SQLException&)
  //{
  //}
  
  try
  {
    DeleteApplication (2001);
    DeleteApplication (2001);
    ApplicationItem appItem;
    bool result = GetApplicationItem (2000, appItem);
    if (true == result)
    {
      wcscat (appItem.Identity.Info.Content, L"_test");
      int appId;
	  InsertApplication (appItem, appId);
    }
  }
  catch (StorageException&)
  {
  }
  
} // TestDelApp

void TestDrvReq(void)
{
    ThreatPointSubjectReq Req;
    Req.ProcessId = LongToHandle(GetCurrentProcessId());
    memset(&Req.Attr, 0, sizeof Req.Attr);
    Req.Attr.Param[GesRule::attIntegrity] = GesRule::modTCB;
    Req.Attr.Param[GesRule::attSubjectId] = 1000;
    wcscpy(Req.FileName, L"\\Device\\HarddiskVolume1\\Program Files\\Internet Explorer\\IEXPLORE.EXE");
//  wcscpy(Req.FileName, L"\\Device\\HarddiskVolume1\\Program Files\\Messenger\\msmsgs.exe");
    PVOID Response = NULL;
    SIZE_T ResponseSize = 0;
    ReqServ::Handle(&Req, &Response, &ResponseSize);
}

void TestGsWuiSupport0 (void)
{
  GUIReply Reply0 = GsWuiSupport::queryReply(
                                            LongToHandle(GetCurrentProcessId()), 
                                            reqThreatPointSubject, 
                                            std::wstring(L"C:\\Program Files\\Internet Explorer\\iexplore.exe"), 
                                            std::wstring(L"")
                                           );
}

void TestGsWuiSupport (void)
{
  int     clientId = 0;
  
  trace ("Input client process id:");
  scanf("%d", &clientId);
  
  GUIReply Reply0 = GsWuiSupport::queryReply(
                                            LongToHandle(clientId), 
                                            reqThreatPointSubject, 
                                            std::wstring(L"C:\\Program Files\\Internet Explorer\\iexplore.exe"), 
                                            std::wstring(L"")
                                           );
                                           
  GUIReply Reply1 = GsWuiSupport::queryReply(
                                            LongToHandle(clientId), 
                                            reqThreatPointSubject, 
                                            std::wstring(L"C:\\Program Files\\Internet Explorer\\iexplore.exe"), 
                                            std::wstring(L"")
                                           );
                                           
  GUIReply Reply2 = GsWuiSupport::queryReply(
                                            LongToHandle(clientId), 
                                            reqThreatPointSubject, 
                                            std::wstring(L"C:\\Program Files\\Internet Explorer\\iexplore.exe"), 
                                            std::wstring(L"")
                                           );                                      
} // TestGsWuiSupport

void TestMacroResolver (void)
{
  wstring resolve_boot;
  size_t  resolve_boot_size = macro::process (resolve_boot, L"%boot_volume%\\ntldr", LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName_X;
  size_t  resolveSize_X = macro::process (resolveName_X, L"%regexp_parse% (\\s*\\\"Class\\\"\\s*=\\s*\\\"([^\\\"]*), \"%readfile% (L:/tmp/test.reg, wchar)\")", LongToHandle(GetCurrentProcessId ()), L"");
  
  macro::ResultList resolveName_XX;
  size_t  resolveSize_XX = macro::process (resolveName_XX, L"%regexp_parse_x% (\\s*\\\"DriverDesc\\\"\\s*=\\s*\\\"([^\\\"]*), \"%readfile% (L:/tmp/test.reg, wchar)\")", LongToHandle(GetCurrentProcessId ()), L"");
  
  if (0 < resolveSize_XX)
  {
    printf("\n%regexp_parse_x%\\Test =>");
    for (macro::ResultList::iterator i = resolveName_XX.begin (); i != resolveName_XX.end (); ++i)
    {
      printf("\n      %S", (*i).c_str ());
    }
    
    printf("\n");
  }
  
  wstring resolveName_2;
  size_t  resolveSize_2 = macro::process (resolveName_2, L"%HKEY_CURRENT_USER\\Software\\Winamp\\%", LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName_1;
  size_t  resolveSize_1 = RegLinkToRegName (resolveName_1, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\aec", LongToHandle(GetCurrentProcessId ()));

  wstring resolveName0; //%HKCU\\test%
  size_t  resolveSize0 = macro::process (resolveName0, wstring (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\BuildLab"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName1; //%HKCU\\test%
  size_t  resolveSize1 = macro::process (resolveName1, wstring (L"%HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\BuildLab%\\%test%"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName2; //%HKCU\\test%
  size_t  resolveSize2 = macro::process (resolveName2, wstring (L"%HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\BuildLab%\\%winddk%\\%HKCU%\\%USERPROFILE%\\%SystemRoot%\\system32\\msdtc.exe"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName3; //%HKCU\\...\\shellex%
  size_t  resolveSize3 = macro::process (resolveName3, wstring (L"%HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\shellex%"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName4; 
  size_t  resolveSize4 = macro::process (resolveName4, wstring (L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\shellex"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName5; 
  size_t  resolveSize5 = macro::process (resolveName5, wstring (L"%USERPROFILE%\\system32\\msdtc.exe"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName6; 
  size_t  resolveSize6 = macro::process (resolveName6, wstring (L"%SystemRoot%\\system32\\msdtc.exe"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName7; 
  size_t  resolveSize7 = macro::process (resolveName7, wstring (L"%getdir% (%SystemRoot%\\system32\\msdtc.exe)"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName8; //%HKCU\\...\\shellex%
  size_t  resolveSize8 = macro::process (resolveName8, wstring (L"%getdir% (%HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\shellex%)"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName9;
  size_t  resolveSize9 = macro::process (resolveName9, wstring (L"%HKEY_CURRENT_USER%\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"), LongToHandle(GetCurrentProcessId ()), L"");
  
  wstring resolveName10;
  size_t  resolveSize10 = RegLinkToRegName (resolveName10, resolveName9, LongToHandle(GetCurrentProcessId ()));
  
  macro::ResultList resolveName11;
  size_t  resolveSize11 = macro::process (resolveName11, L"%ANYHKU%\\Test", LongToHandle(GetCurrentProcessId ()), L"");
  
  if (0 < resolveSize11)
  {
    printf("\n%%ANYHKU%%\\Test =>");
    for (macro::ResultList::iterator i = resolveName11.begin (); i != resolveName11.end (); ++i)
    {
      printf("\n      %S", (*i).c_str ());
    }
    
    printf("\n");
  }
  
  macro::ResultList resolveName12;
  size_t  resolveSize12 = macro::process (resolveName12, L"%ANYUSERPROFILE%\\Test", LongToHandle(GetCurrentProcessId ()), L"");
  
  if (0 < resolveSize12)
  {
    printf("\n%%ANYUSERPROFILE%%\\Test =>");
    for (macro::ResultList::iterator i = resolveName12.begin (); i != resolveName12.end (); ++i)
    {
      printf("\n      %S", (*i).c_str ());
      wstring fullName;
      if (0 < DOSNameToFullName (fullName, (*i)))
        printf("\nfull: %S", fullName.c_str ());
    }
    
    printf("\n");
  }
  
  macro::ResultList resolveName13;
  size_t  resolveSize13 = macro::process (resolveName13, L"%ANYHKU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Cache%", LongToHandle(GetCurrentProcessId ()), L"");
                                                             
  if (0 < resolveSize13)
  {
    printf("\n%%ANYHKU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Cache%% =>");
    for (macro::ResultList::iterator i = resolveName13.begin (); i != resolveName13.end (); ++i)
    {
      printf("\n      %S", (*i).c_str ());
    }
    
    printf("\n");
  }
  
  macro::ResultList resolveName14;
  size_t  resolveSize14 = macro::process (resolveName14, L"%HKEY_CURRENT_USER%\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", LongToHandle(GetCurrentProcessId ()), L"");
                                                             
  if (0 < resolveSize14)
  {
    printf("\n%%HKEY_CURRENT_USER%%\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings =>");
    for (macro::ResultList::iterator i = resolveName14.begin (); i != resolveName14.end (); ++i)
    {
      printf("\n      %S", (*i).c_str ());
    }
    
    printf("\n");
  }
  
  
  ProcExecReq request;  
  void*       response;
  SIZE_T      responseSize = sizeof (response);
    
  request.ProcessId = LongToHandle (GetCurrentProcessId ());
  wcscpy (request.FileName, L"\\Device\\HarddiskVolume8\\Program Files\\Internet Explorer\\IEXPLORE.EXE");
  HandleProcExec (&request, &response, &responseSize);

  wchar_t Str[256] = { 0 };
  printf("Enter a path to resolve: ");
  fflush(stdin);
  fgetws(Str, sizeof Str / sizeof Str[0] - 1, stdin);
  
  wstring resolveName;
  size_t  resolveSize = macro::process (resolveName, wstring (Str), LongToHandle(GetCurrentProcessId ()), L"");
  printf("Resolved path: %S\n", resolveName.c_str());

} // TestMacroResolver


#include <process.h>

DWORD WINAPI ThreadProc (void*)
{
  ::Sleep (30000);
  //Test::TestGsWuiSupport0 (); 
  Test::TestDrvReq ();
  return 0;
} // ThreadProc

void testDeferredRpc (void)
{
   DWORD  threadId;
   HANDLE lock = (HANDLE) _beginthreadex (NULL, 0, (unsigned int (__stdcall *)(void *))ThreadProc, NULL, 0, (unsigned int *)&threadId); 
   
   if (lock != (HANDLE)-1 && lock != (HANDLE)0)
   {
     ::WaitForSingleObject (lock, INFINITE);
   }
} // testRpc

void TestObjectNameConversion (void)
{
  wstring shortName;
  if (0 == macro::process (shortName, L"%shortname%(%ProgramFiles%\\Internet Explorer\\IEXPLORE.EXE)", LongToHandle(GetCurrentProcessId ()), L""))
    wprintf (L"\nmacro::process error: %s", wstring (L"%shortname%(%ProgramFiles%\\Internet Explorer\\IEXPLORE.EXE)").c_str ());  
  else
    wprintf (L"\nmacro::process success: %s => %s", wstring (L"%shortname%(%ProgramFiles%\\Internet Explorer\\IEXPLORE.EXE)").c_str (), shortName.c_str ());  
  
  wstring longName;
  if (0 == macro::process (longName, wstring (L"%longname%(") + shortName + wstring (L")"), LongToHandle(GetCurrentProcessId ()), L""))
    wprintf (L"\nmacro::process error: %s", shortName.c_str ());  
  else
    wprintf (L"\nmacro::process success: %s => %s", shortName.c_str (), longName.c_str ());    
} // TestObjectNameConversion

void TestLogChecker (void)
{
  gswserv::logs::Checker::start ();
  
  wprintf (L"\npress any key for refresh setting");    
  getch ();
  
  try
  {
    gswserv::logs::Checker::refreshSetting ();
    wprintf (L"\nrefresh setting - ok");    
  }
  catch (commonlib::ArgumentException& e)
  {
    wprintf (L"\nException => %s", e.getMessageTextAndCode ());
  }
  
  wprintf (L"\npress any key for exit");    
  getch ();
  
  gswserv::logs::Checker::stop ();
} // TestLogChecker

void TestLicense (void)
{
  try
  {
    license::msxml_license                lic (L"license.xml", L"public.key", L"private.key");
    license::msxml_object::PtrToXmlObject root = lic.getRoot ();
    
    wstring subject = root->queryValue (L"Subject");
    
    license::msxml_object::PtrToXmlObject product_record = root->queryObject (L"ProductRecord");
    wstring product = product_record->queryValue (L"Product");
    
    wstring sign = lic.sign ();
    printf ("\nsign: %S\n", sign.c_str ());
    
    lic.validate ();
    
    printf ("\nvalidate - OK\n");
  }
  catch (commonlib::Exception& e)
  {
    wprintf (L"\nTestLicense (): Exception => %s", e.getMessageTextAndCode ());
  }
} // TestLicense 

void TestUpdate (void)
{
  try
  {
    wstring result_name;
    size_t size = update::getDbUpdate (L"1", L"10", L"3572389598236739679236729367236792836702368092368093246092346823602346", result_name);
  }
  catch (commonlib::Exception& e)
  {
    wprintf (L"\nException => %s", e.getMessageTextAndCode ());
  }
  
} // TestUpdate

void TestRedirectExec (void)
{
  printf ("\nStart GsWui and press any key\n");
  getch ();
  
  wchar_t* current_dir = ::_wgetcwd (NULL, _MAX_PATH);
  if (NULL == current_dir)
  {
    trace ("getcwd error\n");
    printf ("getcwd error\n");
    return;
  }
  
  scope_guard current_dir_guard = make_guard (current_dir, &::free);
  
  //HMODULE hmod = LoadLibraryW (L"procexec.dll");
  commonlib::InjectLibW (GetCurrentProcessId (), wstring (current_dir).append (L"/procexec.dll").c_str ());
  
  STARTUPINFO          si = { 0 };
  PROCESS_INFORMATION  pi = { 0 };
  
  wstring process_name;
  size_t  process_name_size = macro::process (process_name, L"%SystemRoot%\\system32\\notepad.exe", LongToHandle(GetCurrentProcessId ()), L"");
  
  si.cb = sizeof si;
  if (FALSE == CreateProcessW (process_name.c_str (), NULL, NULL, NULL, TRUE, 0, 0, NULL, &si, &pi) ) 
  {
    trace ("CreateProcess error: %d\n", GetLastError());
    printf ("CreateProcess error: %d\n", GetLastError());
  }
  else
  {
    trace ("CreateProcess success\n");
    printf ("CreateProcess success\n");
    ::CloseHandle (pi.hThread);
    ::CloseHandle (pi.hProcess);
  }  
  
  //FreeLibrary (hmod);
} // TestRedirectExec

void TestRedirectExecAcrobat (void)
{
  printf ("\nStart GsWui and press any key\n");
  getch ();
  
  STARTUPINFO          si = { 0 };
  PROCESS_INFORMATION  pi = { 0 };
  
  wstring process_name;
  size_t  process_name_size = macro::process (process_name, L"%ProgramFiles%\\Internet Explorer\\IEXPLORE.EXE", LongToHandle(GetCurrentProcessId ()), L"");
  //size_t  process_name_size = macro::process (process_name, L"%SystemRoot%\\system32\\notepad.exe", LongToHandle(GetCurrentProcessId ()), L"");
  //size_t  process_name_size = macro::process (process_name, L"%SystemRoot%\\explorer.exe", LongToHandle(GetCurrentProcessId ()), L"");
  
  si.cb = sizeof si;
  if (FALSE == CreateProcessW (process_name.c_str (), NULL, NULL, NULL, TRUE, 0, 0, NULL, &si, &pi) ) 
  {
    trace ("CreateProcess error: %d\n", GetLastError());
    printf ("CreateProcess error: %d\n", GetLastError());
  }
  else
  {
    trace ("CreateProcess success\n");
    printf ("CreateProcess success, wait start process and press any key\n");
    getch ();
    
    wchar_t*    current_dir       = ::_wgetcwd (NULL, _MAX_PATH);
    scope_guard current_dir_guard = make_guard (current_dir, &::free);
  
    if (TRUE == commonlib::InjectLibW (pi.dwProcessId, wstring (current_dir).append (L"/procexec.dll").c_str ()))
    {
      trace ("inject hooker dll success\n");
      printf ("inject hooker dll success\n");
      printf ("\nopen pdf file into iexplorer and press any key\n");
      getch ();
    }
    else
    {
      trace ("inject hooker dll error\n");
      printf ("inject hooker dll error\n");
    }
    
    ::CloseHandle (pi.hThread);
    ::CloseHandle (pi.hProcess);
  }  
} // TestRedirectExecAcrobat
    
void TestConvertFileName (void)
{
  wchar_t source [4096];
  int     scanf_result;
  
  printf ("\n[0] input DOS file name: ");
  scanf_result = wscanf (L"%s", source);
  if (0 < scanf_result)
  {
    wstring result_name;
    DOSNameToFullName (result_name, source);
    printf ("[0] native file name: %S\n", result_name.c_str ());
  }
  
  printf ("\n[1] input native file name: ");
  scanf_result = wscanf (L"%s", source);
  if (0 < scanf_result)
  {
    wstring result_name;
    FullNameToDOSName (result_name, source);
    printf ("[1] DOS file name: %S\n", result_name.c_str ());
  }
} // TestConvertFileName
    
void Run(void)
{
    wchar_t BaseSymbol = 'A';

    while ( true ) {
        printf("\n=========================== GswServ Test Menu ===========================\n");
        for (int i=0; i < sizeof MenuItem / sizeof MenuItem[0]; i++) {
            printf("%c - %-33.33S", BaseSymbol+i, MenuItem[i].MenuText);
            if ( (i+1)%2 && i+1 < sizeof MenuItem / sizeof MenuItem[0] ) 
                printf("\t");
            else
                printf("\n");
        }
        printf("\n press ^C to exit, your choice: ");

        while ( true ) {
            int in = getch();
            if ( in == 27 || in == 3 ) {
                printf("^C\n");
                return;
            }

            in = towupper(in);
            if ( (wchar_t)in < BaseSymbol || (wchar_t)in > ( BaseSymbol + sizeof MenuItem / sizeof MenuItem[0] ) )
                continue;

            printf("%c\n", in);
            MenuItem[in - BaseSymbol].Func();
            break;
        }
    }
}


};
