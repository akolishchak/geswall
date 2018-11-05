//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _interface_commonlib_net_urlconnection_h_
 #define _interface_commonlib_net_urlconnection_h_

namespace commonlib {
namespace net {

class IURLConnection;

class IURLConnection
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
            IURLConnection () {};
   virtual ~IURLConnection () {};
    
   virtual  void   connect ()                                       = 0;
   virtual  void   disconnect ()                                    = 0;
   
   virtual  size_t read (unsigned char* buffer, size_t size)        = 0; // return -1 for end of data
   virtual  size_t write (const unsigned char* buffer, size_t size) = 0;
   
  protected:
               IURLConnection (const IURLConnection& right) {};
   IURLConnection& operator= (const IURLConnection& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IURLConnection

} // namespace net {
} // namespace commonlib {

#endif // _interface_commonlib_net_urlconnection_h_