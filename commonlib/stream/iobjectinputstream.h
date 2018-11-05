//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_iobjectinputstream_h_
 #define _commonlib_stream_iobjectinputstream_h_

#include "iobjectinput.h"
#include "iinputstream.h"
       
namespace commonlib {
namespace stream {

class IObjectInputStream : public IObjectInput, public IInputStream<unsigned char>
{
  //
  // types
  //
  public:
   typedef IInputStream<unsigned char>  BaseStreamType;
   typedef BaseStreamType               StreamType; 

  protected:
  private:

  //
  // methods
  //
  public:
            
   virtual ~IObjectInputStream () {};

  protected:
   IObjectInputStream ()
    : IObjectInput (),
      BaseStreamType ()
   {
   
   } // IObjectInputStream
   
   IObjectInputStream (const IObjectInputStream& right) 
    : IObjectInput (right),
      BaseStreamType (right)
   {
   
   } // IObjectInputStream
   
   IObjectInputStream& operator= (const IObjectInputStream& right) { return *this; }

  protected:
  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // IObjectInputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_iobjectinputstream_h_

