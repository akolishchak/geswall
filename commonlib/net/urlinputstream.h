//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_net_urlinputstream_h_
 #define _commonlib_net_urlinputstream_h_

#include "../stream/iinputstream.h"
#include "iurlconnection.h"

namespace commonlib {
namespace net {

using namespace stream;

class URLInputStream : public IInputStream<unsigned char>
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
   explicit
   URLInputStream (IURLConnection& connection) 
    : stream::IInputStream<unsigned char> (),
      m_connection (connection)
   {

   } // URLInputStream

   virtual ~URLInputStream () 
   {
   } // ~URLInputStream

   virtual  size_t read (ArrayType pVal, size_t size)
   {
     return m_connection.read (pVal, size);
   } // read

   virtual  size_t skip (size_t size)
   {
     return 0;
   } // skip

   virtual  size_t available () const
   {
     return -1;
   } // available

  protected:
  private:
   URLInputStream (const URLInputStream& right) : m_connection (right.m_connection) {}
   URLInputStream& operator= (const URLInputStream& right) { return *this; }
  
  //
  // data
  //
  public:
  protected:
  private:
   IURLConnection& m_connection;
}; // URLInputStream

} // namespace net {
} // namespace commonlib {

#endif // _commonlib_net_urlinputstream_h_

