//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _interface_commonlib_net_urlhandlerfactory_h_
 #define _interface_commonlib_net_urlhandlerfactory_h_
 
#include <string> 

namespace commonlib {
namespace net {

class IURLConnection;
class IURLHandlerFactory;
class IURLHandler;

class IURLHandlerFactory
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
            IURLHandlerFactory () {};
   virtual ~IURLHandlerFactory () {};
   
   virtual  IURLHandler& getHandler (const wstring& protocol) = 0;

  protected:
               IURLHandlerFactory (const IURLHandlerFactory& right) {};
   IURLHandlerFactory& operator= (const IURLHandlerFactory& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IURLHandlerFactory

} // namespace net {
} // namespace commonlib {

#endif // _interface_commonlib_net_urlhandlerfactory_h_