//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_iobjectoutputstream_h_
 #define _commonlib_stream_iobjectoutputstream_h_

#include "iobjectoutput.h"
#include "ioutputstream.h"
       
namespace commonlib {
namespace stream {

class IObjectOutputStream : public IObjectOutput, public IOutputStream<unsigned char>
{
  //
  // types
  //
  public:
   typedef IOutputStream<unsigned char>  BaseStreamType;
   typedef BaseStreamType                StreamType; 

  protected:
  private:

  //
  // methods
  //
  public:
            
   virtual ~IObjectOutputStream () {};

  protected:
   IObjectOutputStream () 
    : IObjectOutput (),
      BaseStreamType ()
   {
   
   } // IObjectOutputStream
   
   IObjectOutputStream (const IObjectOutputStream& right) 
    : IObjectOutput (right),
      BaseStreamType (right)
   {
   
   } // IObjectOutputStream
   
   IObjectOutputStream& operator= (const IObjectOutputStream& right) { return *this; }

  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // IObjectOutputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_iobjectoutputstream_h_

