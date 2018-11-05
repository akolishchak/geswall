//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_idatainput_h_
 #define _commonlib_stream_idatainput_h_

#include "idatatype.h"

namespace commonlib {
namespace stream {

class IDataInput : public IDataType
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
            IDataInput () {};
            IDataInput (const IDataInput& right) {};
   virtual ~IDataInput () {};

   //
   // types
   //
   virtual  bool             readBool ()                = 0;
                                                        
   virtual  char             readChar ()                = 0;
   virtual  unsigned char    readUChar ()               = 0;
                                                        
   virtual  short            readShort ()               = 0;
   virtual  unsigned short   readUShort ()              = 0;
                                                        
   virtual  int              readInt ()                 = 0;
   virtual  unsigned int     readUInt ()                = 0;
                                                        
   virtual  long             readLong ()                = 0;
   virtual  unsigned long    readULong ()               = 0;
                                                        
   virtual  longlong         readLongLong ()            = 0;
   virtual  u_longlong       readULongLong ()           = 0;

   //
   // array types
   //
   virtual  size_t           readBool (bool* data, size_t size)             = 0;
                                                                         
   virtual  size_t           readChar (char* data, size_t size)             = 0;
   virtual  size_t           readUChar (unsigned char* data, size_t size)   = 0;
                                                                         
   virtual  size_t           readShort (short* data, size_t size)           = 0;
   virtual  size_t           readUShort (unsigned short* data, size_t size) = 0;
                                                                         
   virtual  size_t           readInt (int* data, size_t size)               = 0;
   virtual  size_t           readUInt (unsigned int* data, size_t size)     = 0;
                                                                         
   virtual  size_t           readLong (long* data, size_t size)             = 0;
   virtual  size_t           readULong (unsigned long* data, size_t size)   = 0;
                            
   virtual  size_t           readLongLong (longlong* data, size_t size)     = 0;
   virtual  size_t           readULongLong (u_longlong* data, size_t size)  = 0;

  protected:
   IDataInput& operator= (const IDataInput& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IDataInput

} // namespace stream {
} // namespace commonlib {


#endif // _commonlib_stream_idatainput_h_

