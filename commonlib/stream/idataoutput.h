//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_idataoutput_h_
 #define _commonlib_stream_idataoutput_h_

#include "idatatype.h"

namespace commonlib {
namespace stream {

class IDataOutput : public IDataType
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
            IDataOutput () {};
            IDataOutput (const IDataOutput& right) {};
   virtual ~IDataOutput () {};

   //
   // types
   //
   virtual  bool  writeBool (bool data)                        = 0;
                                                               
   virtual  bool  writeChar (char data)                        = 0;
   virtual  bool  writeUChar (unsigned char data)              = 0;
                                                               
   virtual  bool  writeShort (short data)                      = 0;
   virtual  bool  writeUShort (unsigned short data)            = 0;
                                                               
   virtual  bool  writeInt (int data)                          = 0;
   virtual  bool  writeUInt (unsigned int data)                = 0;
                                                               
   virtual  bool  writeLong (long data)                        = 0;
   virtual  bool  writeULong (unsigned long data)              = 0;

   virtual  bool  writeLongLong (longlong data)                = 0;
   virtual  bool  writeULongLong (u_longlong data)             = 0;

   //
   // array types
   //
   virtual  size_t writeBool (const bool* data, size_t size)             = 0;

   virtual  size_t writeChar (const char* data, size_t size)             = 0;
   virtual  size_t writeUChar (const unsigned char* data, size_t size)   = 0;

   virtual  size_t writeShort (const short* data, size_t size)           = 0;
   virtual  size_t writeUShort (const unsigned short* data, size_t size) = 0;

   virtual  size_t writeInt (const int* data, size_t size)               = 0;
   virtual  size_t writeUInt (const unsigned int* data, size_t size)     = 0;

   virtual  size_t writeLong (const long* data, size_t size)             = 0;
   virtual  size_t writeULong (const unsigned long* data, size_t size)   = 0;

   virtual  size_t writeLongLong (const longlong* data, size_t size)     = 0;
   virtual  size_t writeULongLong (const u_longlong* data, size_t size)  = 0;

  protected:
   IDataOutput& operator= (const IDataOutput& right) { return *this; }

  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // IDataOutput

} // namespace stream {
} // namespace commonlib {


#endif // _commonlib_stream_idataoutput_h_


