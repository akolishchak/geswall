//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_iinputstream_h_
 #define _commonlib_stream_iinputstream_h_

namespace commonlib {
namespace stream {

// read methods return -1 if end of stream reached (stream closed)

template <class Type>
class IInputStream
{
  //
  // types
  //
  public:
   typedef Type          TokenType;
   typedef TokenType*    ArrayType;

  protected:
  private:

  //
  // methods
  //
  public:
            IInputStream () {};
            IInputStream (const IInputStream& right) {};
   virtual ~IInputStream () {};

   virtual  size_t read (TokenType& val)
   {
     return read (&val, 1);
   } //read

   virtual  bool isEmpty () const 
   { 
     return (0 == available ()); 
   } // empty

   virtual  size_t read (ArrayType pVal, size_t size) = 0;
   virtual  size_t skip (size_t size)                 = 0;
   virtual  size_t available () const                 = 0;

  protected:
   IInputStream& operator= (const IInputStream& right) { return *this; }

  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // IInputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_iinputstream_h_

