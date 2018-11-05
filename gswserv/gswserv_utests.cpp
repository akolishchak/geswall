//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdafx.h>

#include <stdio.h>
#include <conio.h>
#include <new.h>

#include <string>

#include "commonlib/tools.h"
#include "macroresolver.h"
#include "reqserv.h"
#include "commonlib.h" 

#include <boost/thread/thread.hpp>

using namespace std;
using namespace commonlib::Tools;
using namespace macro;
using namespace ReqServ;

struct PerformanceTestThread
{
  void operator() ()
  {
    SetThreadAffinityMask (GetCurrentThread (), 1);
    
    ProcExecReq request;  
    char        response [2048];
    SIZE_T      responseSize = sizeof (response);
    
    request.ProcessId = LongToHandle (GetCurrentProcessId ());
    wcscpy (request.FileName, L"\\Device\\HarddiskVolume3\\Program Files\\Internet Explorer\\IEXPLORE.EXE");
    
    int   i;
    LARGE_INTEGER freq;
    LARGE_INTEGER startTime;
    LARGE_INTEGER endTime;
    LARGE_INTEGER time;
    
    QueryPerformanceFrequency (&freq);
    QueryPerformanceCounter (&startTime);
    //DWORD startTime = GetTickCount ();
    
    for (i=0; i<500; ++i)
    {
      bool result = HandleProcExec (&request, response, &responseSize);
    }
    
    QueryPerformanceCounter (&endTime);
    time.QuadPart = endTime.QuadPart - startTime.QuadPart;
    double _time = ((double) (time.QuadPart) * 1000.0 / (double) (freq.QuadPart)) / (double) i;
    
    //DWORD endTime = GetTickCount ();
    //DWORD time    = endTime - startTime;
    //float _time   = time / i;
    
    printf ("\ntime = %lf msec", _time);
  }
}; // PerformanceTestThread


int main (int nCountArg, char *lpszArg[], char *lpszEnv[])
{
  commonlib::PtrToUCharArray hash;
  size_t hashSize = commonlib::QueryRSAHash (wstring (L"E:\\WINXP\\explorer.exe"), hash);

  wstring fullName;
  size_t  fullSize = DOSNameToFullName (fullName, wstring (L"t:\\winnt"));
  
  wstring _fullName;
  size_t  _fullSize = UNCNameToFullName (_fullName, wstring (L"\\\\scout\\TempDisk$\\winnt"));
  
  wstring dosName;
  size_t  dosSize = FullNameToDOSName (dosName, wstring (L"\\Device\\HarddiskVolume3\\WINXP\\system32\\msdtc.exe"));
  
  wstring uncName;
  size_t  uncSize = FullNameToUNCName (uncName, wstring (L"\\Device\\LanmanRedirector\\WINDOWS\\system32\\msdtc.exe"));
  
  wstring regName0;
  size_t  regSize0 = RegLinkToRegName (regName0, wstring (L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\shellex"), LongToHandle(GetCurrentProcessId ()));
  
  wstring regName1;
  size_t  regSize1 = RegLinkToRegName (regName1, wstring (L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\shellex"), LongToHandle(GetCurrentProcessId ()));
  
  wstring content;
  size_t  contentSize = QueryObjectContent (content, wstring (L"\\Device\\HarddiskVolume3\\WINXP\\system32\\msdtc.exe"));
  
  wstring resolveName0; //%HKCU\\test%
  size_t  resolveSize0 = process (resolveName0, wstring (L"%HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\BuildLab%\\%winddk%\\%HKCU%\\%USERPROFILE%\\%SystemRoot%\\system32\\msdtc.exe"), LongToHandle(GetCurrentProcessId ()));
  
  wstring resolveName1; //%HKCU\\...\\shellex%
  size_t  resolveSize1 = process (resolveName1, wstring (L"%HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\shellex%"), LongToHandle(GetCurrentProcessId ()));
  
  wstring resolveName2; 
  size_t  resolveSize2 = process (resolveName2, wstring (L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\shellex"), LongToHandle(GetCurrentProcessId ()));
  
  wstring resolveKName0; 
  size_t  resolveKSize0 = process (resolveKName0, wstring (L"%USERPROFILE%\\system32\\msdtc.exe"), LongToHandle(GetCurrentProcessId ()));
  
  wstring resolveKName1; 
  size_t  resolveKSize1 = process (resolveKName1, wstring (L"%SystemRoot%\\system32\\msdtc.exe"), LongToHandle(GetCurrentProcessId ()));
  
  PerformanceTestThread testThread;
  boost::thread thrd (testThread);
  thrd.join();

  getch ();
  return 0;
} // main

