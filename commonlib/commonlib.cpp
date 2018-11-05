//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "commonlib.h" 
#include "debug.h" 
#include <sddl.h>

#include "filemmapw32.h"
#include <aclapi.h>


using namespace commonlib::mmap;
using namespace std;

namespace commonlib {

size_t QueryHash (ALG_ID hashAlg, const wstring& fileName, PtrToUCharArray& hashArray)
{
  size_t      sizeHash   = 0;
  HCRYPTPROV  hCryptProv = NULL;
  HCRYPTHASH  hHash      = NULL;
   
  if (
         TRUE == CryptAcquireContext (&hCryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)
      || TRUE == CryptAcquireContext (&hCryptProv,  NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET)
     )
  {
    if (TRUE == CryptCreateHash (hCryptProv, hashAlg, 0, 0, &hHash))
    {
      FileMMapW32 mmap (fileName, GENERIC_READ, FILE_SHARE_READ);
      size_t      offset = 0;
      size_t      size   = 1024*1024;
      void*       view;
      BOOL        result = FALSE;
      
      while (NULL != (view = mmap.map (0, size, offset)))
      {
        result = CryptHashData (hHash, reinterpret_cast <BYTE*> (view), static_cast <DWORD> (mmap.viewSize ()), 0);
        if (FALSE == result)
          break;
          
        offset += mmap.viewSize ();
      }
      
      if (TRUE == result)
      {
        DWORD sz  = 0;
        DWORD len = sizeof (sz);
        if (TRUE == CryptGetHashParam (hHash, HP_HASHSIZE, reinterpret_cast <BYTE*> (&sz), &len, 0))
        {
          PtrToUCharArray array (new unsigned char [sz]);
          if (NULL != array.get () && TRUE == CryptGetHashParam (hHash, HP_HASHVAL, array.get (), &sz, 0))
          {
            hashArray = array;
            sizeHash  = sz;
          }
        }
      } 
      
      CryptDestroyHash (hHash);
    } // if (TRUE == CryptCreateHash (hCryptProv, hashAlg, 0, 0, &hHash))
    
    CryptReleaseContext (hCryptProv, 0);
  } // if (TRUE == CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))

  return sizeHash;
} // QueryRSAHash

wstring querySid (HANDLE processId)
{
  wstring sid;
  querySid (sid,  processId);
  return sid;
} // querySid

size_t querySid (wstring& sid,  HANDLE processId)
{
  size_t  sidSize  = sid.size ();
  HANDLE  hProcess = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong(processId));

  if (NULL != hProcess)
  {
    HANDLE hToken = NULL;
    if (TRUE == OpenProcessToken (hProcess, TOKEN_QUERY, &hToken))
    {
      DWORD      size = 0;
      GetTokenInformation (hToken, TokenUser, NULL, 0, &size);
      if (0 != size)
      {
        PtrToByte buffer (new BYTE [size]);
        if (NULL != buffer.get () && TRUE == GetTokenInformation (hToken, TokenUser, buffer.get (), size, &size))
        {
          PTOKEN_USER user = reinterpret_cast <PTOKEN_USER> (buffer.get ());
          LPTSTR stringSID = NULL;
          if (TRUE == ConvertSidToStringSid (user->User.Sid, &stringSID))
          {
            sid.append (stringSID);
            LocalFree (stringSID);
          }
        }
      } // if (0 != size)
      CloseHandle (hToken);
    } // if (TRUE == OpenProcessToken (hProcess, TOKEN_QUERY, &hToken))
    CloseHandle (hProcess);
  } // if (NULL != hProcess)
  
  return (sid.size () - sidSize);
} // querySid

size_t bin2hex (const unsigned char* bin, size_t binLength, wchar_t* str, size_t strLength) 
{ 
  if (strLength < (binLength*2+1)) 
    return -1; 

  static wchar_t hexMap[] = {
                              L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', 
                              L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F'
                            }; 
  wchar_t* p = str; 
  
  for (size_t i=0; i < binLength; ++i)  
  { 
    *p++ = hexMap[*bin >> 4];  
    *p++ = hexMap[*bin & 0xf]; 
    ++bin;
  } 
  *p = 0; 

  return p - str; 
} // bin2hex

size_t hex2bin (const std::wstring& hex, unsigned char* bin, size_t bin_length) 
{ 
  static unsigned char hexMap[] = {
    0, 1,  2,  3,  4,  5,  6,  7, 
    8, 9, 10, 11, 12, 13, 14, 15
  }; 
  
  const wchar_t* str        = hex.c_str ();
  size_t         str_length = hex.length ();
  
  if (bin_length < (str_length/2)) 
    return -1; 
  
  unsigned char* p = bin; 
  wchar_t        sym;
  
  for (size_t i=0; i < str_length; ++i)  
  { 
    sym = 0;
    if (L'0' <= *str && L'9' >= *str)
    {
      sym = hexMap [*str - L'0'];
    }
    else
    {
      if (L'a' <= *str && L'f' >= *str)
      {
        sym = hexMap [*str - 'a' + 10];
      }
      else
      {
        if (L'A' <= *str && L'F' >= *str)
          sym = hexMap [*str - 'A' + 10];
      }
    }
    
    if (!(i & 1))
    {
      *p = sym << 4;
    }  
    else
    {  
      *p += sym;
      ++p;
    }  
    
    ++str;
  } 

  return p - bin; 
} // hex2bin

size_t bin2hex (const unsigned char* bin, size_t bin_length, std::wstring& hex) 
{ 
  static wchar_t hexMap[] = {
    L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', 
    L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F'
  }; 
  
  size_t size0 = hex.length ();
  
  for (size_t i=0; i < bin_length; ++i)  
  { 
    hex.append (1, hexMap[*bin >> 4]);
    hex.append (1, hexMap[*bin & 0xf]);
    ++bin;
  } 

  return hex.length () - size0; 
} // bin2hex


bool LoadBinaryFile(const wchar_t *FileName, byte *&Buf, size_t &Size)
{
    Buf = NULL;
    Size = 0;

    HANDLE hFile = CreateFile(FileName, FILE_READ_ACCESS, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if ( hFile == INVALID_HANDLE_VALUE ) return false;

    Size = GetFileSize(hFile, NULL);
    if ( Size == INVALID_FILE_SIZE || Size == 0 ) {
        CloseHandle(hFile);
        return false;
    }

    Buf = new byte[Size];
    if ( Buf == NULL ) {
        CloseHandle(hFile);
        return false;
    }

    DWORD Read;
    BOOL rc = ReadFile(hFile, Buf, (DWORD)Size, &Read, NULL);
    CloseHandle(hFile);
    if ( rc != TRUE || Read != Size ) {
        delete[] Buf;
        Buf = NULL;
        Size = 0;
        return false;
    }

    return true;
}

bool SaveBinaryFile(const wchar_t *FileName, const byte *Buf, const size_t Size) 
{
    HANDLE hFile = CreateFile(FileName, FILE_WRITE_ACCESS, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if ( hFile == INVALID_HANDLE_VALUE ) return false;

    DWORD Written;
    BOOL rc = WriteFile(hFile, Buf, (DWORD)Size, &Written, NULL);

    CloseHandle(hFile);
    return rc == TRUE && Size == Written;
}

std::wstring& trim_self (std::wstring& str)
{
  const  wchar_t* spaces = L" \t\r\n";
  
  if (0 != str.size ())
  {
    size_t p;
    
    p = str.find_last_not_of (spaces) + 1;
    str.erase (p, str.size () - p);
    p = str.find_first_not_of (spaces);
    str.erase (0, p);
  }
  
  return str;
} // trim_self

std::wstring& string2wstring (std::wstring& result, const std::string& source, std::locale const & loc)
{
  const std::ctype<wchar_t>& ct = std::use_facet<std::ctype<wchar_t> > (loc);

  std::string::const_iterator it (source.begin ());
  std::string::const_iterator end (source.end ());

  for (; it != end; ++it)
  {
    result.append (1, static_cast<wchar_t> (ct.widen (*it)));
  }    

  return result;
} // string2wstring


//
// Notices: Copyright (c) 2000 Jeffrey Richter
// 
void __stdcall test_thread (wchar_t* lib_name)
{
  debugString ((L"lib_name: %s", lib_name));
} // test_thread


BOOL WINAPI InjectLibW (DWORD dwProcessId, const wchar_t* pszLibFile) 
{
   BOOL   fOk              = FALSE; // Assume that the function fails
   HANDLE hProcess         = NULL;
   HANDLE hThread          = NULL;
   PWSTR  pszLibFileRemote = NULL;

   __try 
   {
      // Get a handle for the target process.
      hProcess = OpenProcess(
         PROCESS_QUERY_INFORMATION |   // Required by Alpha
         PROCESS_CREATE_THREAD     |   // For CreateRemoteThread
         PROCESS_VM_OPERATION      |   // For VirtualAllocEx/VirtualFreeEx
         PROCESS_VM_WRITE,             // For WriteProcessMemory
         FALSE, 
         dwProcessId
      );
      
      if (hProcess == NULL) 
        return fOk; //__leave;

      // Calculate the number of bytes needed for the DLL's pathname
      int cch = 1 + lstrlenW (pszLibFile);
      int cb  = cch * sizeof (WCHAR);

      // Allocate space in the remote process for the pathname
      pszLibFileRemote = (PWSTR) VirtualAllocEx (hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
      if (pszLibFileRemote == NULL) 
        return fOk; //__leave;

      // Copy the DLL's pathname to the remote process's address space
      if (FALSE == WriteProcessMemory (hProcess, pszLibFileRemote, (PVOID) pszLibFile, cb, NULL)) 
        return fOk; //__leave;

      // Get the real address of LoadLibraryW in Kernel32.dll
      PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE) GetProcAddress (GetModuleHandleW (L"Kernel32"), "LoadLibraryW");
      //PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE) test_thread;
      if (pfnThreadRtn == NULL) 
        return fOk; //__leave;

      // Create a remote thread that calls LoadLibraryW(DLLPathname)
      hThread = CreateRemoteThread (hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
      if (hThread == NULL) 
        return fOk; //__leave;

      // Wait for the remote thread to terminate
      WaitForSingleObject (hThread, INFINITE);

      fOk = TRUE; // Everything executed successfully
   }
   __finally 
   { // Now, we can clean everthing up

      // Free the remote memory that contained the DLL's pathname
      if (pszLibFileRemote != NULL) 
         VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

      if (hThread  != NULL) 
         CloseHandle(hThread);

      if (hProcess != NULL) 
         CloseHandle(hProcess);
   }

   return(fOk);
} // InjectLibW

typedef struct _TOKEN_ELEVATION {
    DWORD TokenIsElevated;
} TOKEN_ELEVATION, *PTOKEN_ELEVATION;

bool IsElevatedContext(void)
{
	bool Result = false;

	HANDLE hToken;
	DWORD rc = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken);
	if ( !rc ) {
		rc = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
		if ( !rc ) return false;
	}

	TOKEN_ELEVATION Elevation;
	DWORD ReturnLength;
	rc = GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)20, &Elevation, sizeof Elevation, &ReturnLength);
	if ( rc ) Result = Elevation.TokenIsElevated != 0;

	CloseHandle(hToken);
	return Result;
}

bool IsUACSupported(void)
{
	OSVERSIONINFO VerInfo;
	VerInfo.dwOSVersionInfoSize = sizeof OSVERSIONINFO;
	if ( GetVersionEx(&VerInfo) && VerInfo.dwMajorVersion >= 6 ) return true;

	return false;
}

HANDLE GetProcessHandleWithEnoughRights( IN DWORD PID, IN DWORD AccessRights)
{
    HANDLE hProcess = ::OpenProcess( AccessRights, FALSE, PID);
    if( !hProcess)
    {
        HANDLE hpWriteDAC = OpenProcess( WRITE_DAC, FALSE, PID);
        if( !hpWriteDAC)
        {
            // hmm, we don't have permissions to modify the DACL...
            // time to take ownership...
            HANDLE htok;
            if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &htok))
                return FALSE;

            TOKEN_PRIVILEGES tpOld;
            if( EnableTokenPrivilege( htok, SE_TAKE_OWNERSHIP_NAME, tpOld))
            {
                // SeTakeOwnershipPrivilege allows us to open objects with
                // WRITE_OWNER, but that's about it, so we'll update the owner,
                // and dup the handle so we can get WRITE_DAC permissions.
                HANDLE hpWriteOwner = OpenProcess( WRITE_OWNER, FALSE, PID);
                if( hpWriteOwner)
                {
                    BYTE buf[512]; // this should always be big enough
                    DWORD cb = sizeof( buf);
                    if( GetTokenInformation( htok, TokenUser, buf, cb, &cb))
                    {
                        DWORD err = SetSecurityInfo( 
                                hpWriteOwner, 
                                SE_KERNEL_OBJECT,
                                OWNER_SECURITY_INFORMATION,
                                reinterpret_cast<TOKEN_USER*>(buf)->User.Sid,
                                0, 0, 0);
                        if( err == ERROR_SUCCESS)
                        {
                            // now that we're the owner, we've implicitly got WRITE_DAC
                            // permissions, so ask the system to reevaluate our request,
                            // giving us a handle with WRITE_DAC permissions
                            if ( !DuplicateHandle( 
                                    GetCurrentProcess(), 
                                    hpWriteOwner,
                                    GetCurrentProcess(), 
                                    &hpWriteDAC,
                                    WRITE_DAC, FALSE, 0) 
                                )
                            { hpWriteDAC = NULL; }
                        }
                    }
                    ::CloseHandle( hpWriteOwner);
                }
                // not truly necessary in this app,
                // but included for completeness
                RestoreTokenPrivilege( htok, tpOld);
            }
            ::CloseHandle( htok);
        }

        if( hpWriteDAC)
        {
            // we've now got a handle that allows us WRITE_DAC permission
            AdjustDacl( hpWriteDAC, AccessRights);

            // now that we've granted ourselves permission to access 
            // the process, ask the system to reevaluate our request,
            // giving us a handle with right permissions
            if ( !DuplicateHandle( 
                    GetCurrentProcess(), 
                    hpWriteDAC,
                    GetCurrentProcess(), 
                    &hProcess,
                    AccessRights, 
                    FALSE, 
                    0) 
                )
            { hProcess = NULL; }
            CloseHandle(hpWriteDAC);
        }
    }
    return hProcess;
}

BOOL EnableTokenPrivilege( IN HANDLE htok, IN LPCTSTR szPrivilege, IN OUT TOKEN_PRIVILEGES &tpOld)
{
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if( LookupPrivilegeValue( NULL, szPrivilege, &tp.Privileges[0].Luid))
    {
        // htok must have been opened with the following permissions:
        // TOKEN_QUERY (to get the old priv setting)
        // TOKEN_ADJUST_PRIVILEGES (to adjust the priv)
        DWORD cbOld = sizeof( tpOld);
        if( AdjustTokenPrivileges( htok, FALSE, &tp, cbOld, &tpOld, &cbOld))
        // Note that AdjustTokenPrivileges may succeed, and yet
        // some privileges weren't actually adjusted.
        // You've got to check GetLastError() to be sure!
            return ( ERROR_NOT_ALL_ASSIGNED != GetLastError());
        else
            return FALSE;
    }
    return FALSE;
}

BOOL RestoreTokenPrivilege( IN HANDLE htok, IN const TOKEN_PRIVILEGES &tpOld)
{
    return AdjustTokenPrivileges( htok, FALSE, const_cast<TOKEN_PRIVILEGES*>(&tpOld), 0, 0, 0);
}

BOOL AdjustDacl( IN HANDLE h, IN DWORD DesiredAccess)
{
    // the WORLD Sid is trivial to form programmatically (S-1-1-0)
    SID world = { SID_REVISION, 1, SECURITY_WORLD_SID_AUTHORITY, 0 };

    EXPLICIT_ACCESS ea =
    {
        DesiredAccess,
        SET_ACCESS,
        NO_INHERITANCE,
        {
            0, NO_MULTIPLE_TRUSTEE,
            TRUSTEE_IS_SID,
            TRUSTEE_IS_USER,
            reinterpret_cast<LPTSTR>(&world)
        }
    };
    PACL pdacl = NULL;
    DWORD err = SetEntriesInAcl( 1, &ea, 0, &pdacl);
    if( err == ERROR_SUCCESS)
    {
        err = SetSecurityInfo( h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, pdacl, 0);
        LocalFree( pdacl);
        return err == ERROR_SUCCESS;
    }
    return FALSE;
}

BOOL SlayProcess( IN DWORD PID)
{
    HANDLE hp = GetProcessHandleWithEnoughRights( PID, PROCESS_TERMINATE);
    if( hp)
    {
        // if all went well, we've now got a handle to the process
        // that grants us PROCESS_TERMINATE permissions
        BOOL bReturn = TerminateProcess( hp, 1);
        ::CloseHandle(hp);
        return bReturn;
    }
    return FALSE;
}


} // namespace commonlib {

