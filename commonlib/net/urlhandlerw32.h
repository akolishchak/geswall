//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_net_urlhandler_w32_h_
 #define _commonlib_net_urlhandler_w32_h_

#include "iurlhandler.h" 
#include "urlconnectionw32.h"
 
namespace commonlib {
namespace net {

class URL;

class URLHandlerW32 : public IURLHandler
{
  //
  // types
  //
  public:
   typedef IURLHandler::PtrToIURLConnection PtrToIURLConnection;

  protected:
  private:

  //
  // methods
  //
  public:
            URLHandlerW32 () {};
   virtual ~URLHandlerW32 () {};
   
   virtual  PtrToIURLConnection openConnection (const URL& url)
   {
     return PtrToIURLConnection (new URLConnectionW32 (url));
   } // openConnection

  protected:
               URLHandlerW32 (const URLHandlerW32& right) {};
   URLHandlerW32& operator= (const URLHandlerW32& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // URLHandlerW32

} // namespace net {
} // namespace commonlib {

#endif // _commonlib_net_urlhandler_w32_h_