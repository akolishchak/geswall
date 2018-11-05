//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_net_urlsupport_h_
 #define _commonlib_net_urlsupport_h_

#include <string>

namespace commonlib {
namespace net {

class URLSupport;


class URLSupport
{
  //
  // types
  //
  public:
   typedef std::wstring   wstring;

  protected:
  private:

  //
  // methods
  //
  public:
   static bool parse (const wstring& url, wstring& protocol, wstring& authority, wstring& path, wstring& query, wstring& related);

  protected:
            URLSupport () {};
   virtual ~URLSupport () {};

            URLSupport (const URLSupport& right) {};
   URLSupport& operator= (const URLSupport& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // URLSupport

} // namespace net {
} // namespace commonlib {


#endif // _commonlib_net_urlsupport_h_