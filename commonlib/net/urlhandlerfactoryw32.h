//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_net_urlhandlerfactory_w32_h_
 #define _commonlib_net_urlhandlerfactory_w32_h_

#include "iurlhandlerfactory.h"
#include "urlhandlerw32.h"

namespace commonlib {
namespace net {

class IURLConnection;
class URLHandlerFactoryW32;

class URLHandlerFactoryW32 : public IURLHandlerFactory
{
  //
  // types
  //
  public:
  protected:
  private:

  //
  // methods
  //
  public:
            URLHandlerFactoryW32 () {};
   virtual ~URLHandlerFactoryW32 () {};
   
   virtual  IURLHandler& getHandler (const wstring& protocol)
   {
     return m_handler;
   } // getHandler

  protected:
            URLHandlerFactoryW32 (const URLHandlerFactoryW32& right) {};
   URLHandlerFactoryW32& operator= (const URLHandlerFactoryW32& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
   URLHandlerW32  m_handler;
}; // URLHandlerFactoryW32

} // namespace net {
} // namespace commonlib {

#endif // _commonlib_net_urlhandlerfactory_w32_h_