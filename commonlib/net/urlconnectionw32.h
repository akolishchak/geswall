//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_net_urlconnection_w32_h_
 #define _commonlib_net_urlconnection_w32_h_

#include <stdafx.h>
#include <wininet.h>

#include "commondefs.h"
#include "url.h"
#include "iurlconnection.h"

namespace commonlib {
namespace net {

class URL;
class URLConnectionW32;

class URLConnectionW32 : public IURLConnection
{
  //
  // types
  //
  public:
  protected:
   typedef BOOL (WINAPI *INTERNETCLOSEHANDLE)(HINTERNET);
   typedef commonlib::sguard::object_checked<HINTERNET, INTERNETCLOSEHANDLE, commonlib::sguard::is_null_equal<HINTERNET, NULL> >   inet_handle;

  private:

  //
  // methods
  //
  public:
            URLConnectionW32 (const URL& url);
   virtual ~URLConnectionW32 ();
   
   virtual  void   connect ();
   virtual  void   disconnect ();
   
   virtual  size_t read (unsigned char* buffer, size_t size); // return -1 for end of data
   virtual  size_t write (const unsigned char* buffer, size_t size);
   
  protected:
               URLConnectionW32 (const URLConnectionW32& right) : m_url (right.m_url) {};
   URLConnectionW32& operator= (const URLConnectionW32& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
   URL           m_url;
   inet_handle   m_hInet;
   inet_handle   m_hURL;
}; // URLConnectionW32

} // namespace net {
} // namespace commonlib {

#endif // _commonlib_net_urlconnection_w32_h_