//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_ioutputstream_h_
 #define _commonlib_stream_ioutputstream_h_

namespace commonlib {
namespace stream {

// write methods return -1 if end of stream reached (stream closed)

template <class Type>
class IOutputStream
{
  //
  // types
  //
  public:
   typedef Type              TokenType;
   typedef TokenType*        ArrayType;

  protected:
  private:

  //
  // methods
  //
  public:
            IOutputStream () {};
            IOutputStream (const IOutputStream& right) {};
   virtual ~IOutputStream () { };

   virtual  size_t write (TokenType val)
   {
     return write (&val, 1);
   } // write

   virtual  size_t available () const 
   { 
     return (capacity () < 0 ? capacity () : (capacity () - size ())); 
   } // available

   virtual  size_t write (const ArrayType pVal, size_t size)   = 0;
   virtual  size_t size () const                               = 0;
   virtual  size_t capacity () const                           = 0;

   virtual  size_t toArray (ArrayType pVal, size_t size) const = 0;
   virtual  const ArrayType head () const                      = 0;

  protected:
   IOutputStream& operator= (const IOutputStream& right) { return *this; }

  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // IOutputStream

} // namespace stream {
} // namespace commonlib {


#endif // _commonlib_stream_ioutputstream_h_


