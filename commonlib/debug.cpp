//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifdef __GSW_NO_STD_AFX__
 #include <windows.h>
#else
 #include "stdafx.h"
#endif __GSW_NO_STD_AFX__ 

#include "debug.h"
#include <stdio.h>
#include <string>

namespace commonlib {

namespace Debug {

#if _DEBUG  
int Mode = outDebugger;
#else
int Mode = 0;
#endif // #if _DEBUG

FILE *File = NULL;
//const wchar_t DefaultLogName[] = L"%SystemRoot%\\geswall\\gswlog.txt";
const wchar_t DefaultLogName[] = L"%temp%\\gswlog.txt";
std::wstring LogName = DefaultLogName;

void Write (int _Mode, const char *fmt, ...)
{
  if ( _Mode == 0 ) return;
  static const BufSize = 2048;
  char Buf[BufSize];
  va_list ap;
  va_start(ap, fmt);
  DWORD len = _vsnprintf(Buf, sizeof Buf, fmt, ap);
  if ( len == 0 ) return;
  Buf[BufSize - 1] = 0;

  if ( _Mode & outDebugger ) OutputDebugStringA(Buf);
  if ( _Mode & outFile ) WriteFile(Buf);
  if ( _Mode & outConsole ) fputs(Buf, stderr);

} // Write

void Write (wchar_t* format, ...)
{
  if ( Mode == 0 ) return;
  static const buf_size = 4096;

  wchar_t LogBuf [buf_size];
  *LogBuf = 0;

  va_list    va;
  va_start(va, format);
  int count = vswprintf (LogBuf, format, va);
  va_end(va);
  if (count > 0)
  {
    LogBuf[buf_size - 1] = 0;
    OutputDebugStringW (LogBuf);
  }
} // Write

void SetMode(int _Mode)
{
	Mode = _Mode;
}

void SetLogName(const wchar_t *Name)
{
	LogName = Name;
	if ( File != NULL ) {
		fclose(File);
		File = NULL;
	}
}

void Write (const char *fmt, ...)
{
  if ( Mode == 0 ) return;
  static const BufSize = 2048;
  char Buf[BufSize];
  va_list ap;
  va_start(ap, fmt);
  DWORD len = _vsnprintf(Buf, sizeof Buf, fmt, ap);
  if ( len == 0 ) return;
  Buf[BufSize - 1] = 0;

  if ( Mode & outDebugger ) OutputDebugStringA(Buf);
  if ( Mode & outFile ) WriteFile(Buf);
  if ( Mode & outConsole ) fputs(Buf, stderr);
}

void WriteFile(char *Buf)
{
	static HANDLE hFile = NULL;
	if ( hFile == NULL ) {
		wchar_t Name [MAX_PATH];
		ExpandEnvironmentStrings(LogName.c_str(), Name, sizeof Name / sizeof Name[0]);
		hFile = CreateFile(Name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if ( hFile == INVALID_HANDLE_VALUE ) {
			hFile = NULL;
			return;
		}
		SetFilePointer(hFile, 0, NULL, FILE_END);
	}
	DWORD Written;
	::WriteFile(hFile, Buf, (DWORD)strlen(Buf), &Written, NULL);
	//FlushFileBuffers(hFile);
}

void WriteFile(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	Write(outFile, fmt, ap);
}

#if _DEBUG  
void _debugString (const wchar_t* format, ...)
{
  wchar_t LogBuf [4096];
  *LogBuf = 0;

  va_list    va;
  va_start(va, format);
  int count = vswprintf (LogBuf, format, va);
  va_end(va);
  if (count > 0)
    OutputDebugStringW (LogBuf);
} // debugString
#endif // _DEBUG  

} // namespace Debug {

} // namespace commonlib {