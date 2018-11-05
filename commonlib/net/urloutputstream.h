//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_net_urloutputstream_h_
 #define _commonlib_net_urloutputstream_h_

#include "../stream/ioutputstream.h"
#include "iurlconnection.h"

namespace commonlib {
namespace net {

using namespace stream;

class URLOutputStream : public IOutputStream<unsigned char>
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
   URLOutputStream (IURLConnection& connection) 
    : IOutputStream<unsigned char> (),
      m_connection (connection)
   {

   } // URLOutputStream

   virtual ~URLOutputStream () 
   {

   } // ~URLOutputStream

   virtual  size_t write (const ArrayType pVal, size_t size)
   {
     return m_connection.write (pVal, size);
   } // write

   virtual  size_t size () const
   {
     return 0;
   } // size

   virtual  size_t capacity () const 
   { 
     return -1;  // unlimit
   } // capacity
 
   virtual  size_t toArray (ArrayType pVal, size_t size) const
   {
     return 0;
   } // toArray
   
   virtual  const ArrayType head () const
   {
     return NULL;
   } // head

  protected:
  private:
   URLOutputStream (const URLOutputStream& right) : m_connection (right.m_connection) {}
   URLOutputStream& operator= (const URLOutputStream& right) { return *this; }
  
  //
  // data
  //
  public:
  protected:
   IURLConnection& m_connection;
}; // URLOutputStream

} // namespace net {
} // namespace commonlib {

#endif // _commonlib_net_urloutputstream_h_

