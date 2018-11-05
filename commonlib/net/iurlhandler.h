//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _interface_commonlib_net_urlhandler_h_
 #define _interface_commonlib_net_urlhandler_h_

#include <boost/smart_ptr.hpp> 
 
namespace commonlib {
namespace net {

class IURLConnection;
class URL;

class IURLHandler
{
  //
  // types
  //
  public:
   typedef boost::shared_ptr<IURLConnection> PtrToIURLConnection;

  protected:
  private:

  //
  // methods
  //
  public:
            IURLHandler () {};
   virtual ~IURLHandler () {};
   
   virtual  PtrToIURLConnection openConnection (const URL& url) = 0;

  protected:
               IURLHandler (const IURLHandler& right) {};
   IURLHandler& operator= (const IURLHandler& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IURLHandler

} // namespace net {
} // namespace commonlib {

#endif // _interface_commonlib_net_urlhandler_h_