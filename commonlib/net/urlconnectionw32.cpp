//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "urlconnectionw32.h"
#include "argumentexception.h"
#include "ioexception.h"
#include "unsupportedexception.h"

namespace commonlib {
namespace net {

using commonlib::sguard::object_checked;
using commonlib::sguard::is_null_equal;
   
URLConnectionW32::URLConnectionW32 (const URL& url)
 : m_url (url),
   m_hInet (::InternetOpenW (NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0), ::InternetCloseHandle, is_null_equal<HINTERNET, NULL> ())
{
  if (0 >= m_url.toString ().size ())
    throw ArgumentException (L"bad url");
  if (NULL == m_hInet.get ())
    throw IOException (L"init error");
} // URLConnectionW32

URLConnectionW32::~URLConnectionW32 ()
{
  try
  {
    disconnect ();
    m_hInet.free ();
  }
  catch (...)
  {
  }
} // ~URLConnectionW32

void URLConnectionW32::connect () // IOException
{
  if (true == m_hURL.is_free ())
  {
    m_hURL = inet_handle (::InternetOpenUrlW (m_hInet, (m_url.toString ()).c_str (), NULL, 0, INTERNET_FLAG_KEEP_CONNECTION, 0), ::InternetCloseHandle, is_null_equal<HINTERNET, NULL> ());
    if (true == m_hURL.is_free ())
      throw IOException (L"bad url or remote server down");
  }  
} // connect

void URLConnectionW32::disconnect ()
{
  m_hURL.free ();
} // disconnect

size_t URLConnectionW32::read (unsigned char* buffer, size_t size) // return -1 for end of data
{
  if (true == m_hURL.is_free ())
    throw IOException (L"connection closed");
  
  size_t result            = -1;
  DWORD  numberOfBytesRead = 0;
  BOOL   resultRead        = FALSE;
  
  //while (TRUE == (resultRead = InternetReadFile (m_hURL, buffer, static_cast <DWORD> (size), &numberOfBytesRead)) && 0 == numberOfBytesRead);
  resultRead = InternetReadFile (m_hURL, buffer, static_cast <DWORD> (size), &numberOfBytesRead);
  
  if (TRUE == resultRead)
  {
    result = (numberOfBytesRead == 0) ? -1 : numberOfBytesRead;
  }  
  else
  {
    if (ERROR_INSUFFICIENT_BUFFER == GetLastError ())
      result = 0;
    else  
      result = -1;
  }  
      
  return result;    
} // read

size_t URLConnectionW32::write (const unsigned char* buffer, size_t size)
{
  throw UnsupportedException (L"write operation not supported for this connection");
  //if (true == m_hURL.is_free ())
  //  throw IOException (L"connection closed");
  //  
  //int    result               = 0;
  //DWORD  numberOfBytesWritten = 0;
  //BOOL   resultWrite          = FALSE;  
  //
  //resultWrite = InternetWriteFile (m_hURL, buffer, size, &numberOfBytesWritten);
  //if (TRUE == resultWrite)
  //  result = numberOfBytesWritten;
  //else
  //  numberOfBytesWritten = GetLastError ();
  //  
  //return result;
} // write
   
} // namespace net {
} // namespace commonlib {
