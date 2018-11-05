//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GSW_COMMON_LIB_H_
#define _GSW_COMMON_LIB_H_
 
#ifndef __GSW_NO_STD_AFX__
 #include "stdafx.h"
#else
 #include <windows.h>
 #include <sddl.h>
#endif // __GSW_NO_STD_AFX__ 

#include <wincrypt.h>
#include <string> 

#include "commondefs.h"

using namespace std;

namespace commonlib {

class ObjectHolder
{
  public:
   ObjectHolder ()
    : m_handle (NULL)
   {
   } // ObjectHolder
   
   explicit ObjectHolder (HANDLE handle)
    : m_handle (handle)
   {
   } // ObjectHolder
   
   ObjectHolder (ObjectHolder& right)
    : m_handle (right.release ())
   {
   } // ObjectHolder
    
   ObjectHolder& operator= (ObjectHolder& right)
   {
     if (this != &right)
       ObjectHolder (right).swap (*this);
      
     return *this;
   } // operator=
   
   ~ObjectHolder ()
   {
     if (NULL != m_handle)
       CloseHandle (m_handle);
     m_handle = NULL;  
   } // ~ObjectHolder
   
   const HANDLE get () const
   {
     return m_handle;
   } // getHandle
   
   HANDLE release ()
   {
     HANDLE handle = m_handle;
     m_handle = NULL;
     return handle;
   } // release
   
   HANDLE& reference ()
   {
     return m_handle;
   } // reference
 
  private:
   void swap (ObjectHolder& right)
   {
     HANDLE handle  = m_handle;
     m_handle       = right.m_handle;
     right.m_handle = handle;
   } // swap
   
  public: 
   HANDLE m_handle;
}; // ObjectHolder

size_t  QueryHash (ALG_ID hashAlg, const wstring& fileName, PtrToUCharArray& hashArray);

wstring querySid (HANDLE processId);
size_t  querySid (wstring& sid,  HANDLE processId);

size_t bin2hex (const unsigned char* bin, size_t binLength, wchar_t* str, size_t strLength);
size_t hex2bin (const std::wstring& hex, unsigned char* bin, size_t bin_length); 
size_t bin2hex (const unsigned char* bin, size_t bin_length, std::wstring& hex);

bool LoadBinaryFile(const wchar_t *FileName, byte *&Buf, size_t &Size);
bool SaveBinaryFile(const wchar_t *FileName, const byte *Buf, const size_t Size);

std::wstring& trim_self (std::wstring& str);
std::wstring& string2wstring (std::wstring& result, const std::string& source, std::locale const & loc = std::locale());

BOOL WINAPI InjectLibW (DWORD dwProcessId, const wchar_t* pszLibFile);

bool IsElevatedContext(void);
bool IsUACSupported(void);
BOOL SlayProcess( IN DWORD PID);
HANDLE GetProcessHandleWithEnoughRights( IN DWORD PID, IN DWORD AccessRights);
BOOL EnableTokenPrivilege( IN HANDLE htok, IN LPCTSTR szPrivilege, IN OUT TOKEN_PRIVILEGES &tpOld);
BOOL RestoreTokenPrivilege( IN HANDLE htok, IN const TOKEN_PRIVILEGES &tpOld);
BOOL AdjustDacl( IN HANDLE h, IN DWORD DesiredAccess);

} // namespace commonlib {

#endif // _GSW_COMMON_LIB_H_