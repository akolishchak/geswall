//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_objectinputstream_h_
 #define _commonlib_stream_objectinputstream_h_

#include "commonlib/ioexception.h"
#include "iobjectinputstream.h"

#include "iserializable.h"

namespace commonlib {
namespace stream {

class ObjectInputStream : public IObjectInputStream
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
  
   explicit ObjectInputStream (StreamType& stream) 
    : IObjectInputStream (),
      m_stream (stream)
   {
   } // ObjectInputStream
   
   ObjectInputStream (const ObjectInputStream& right) 
    : IObjectInputStream (),
      m_stream (right.m_stream)
   {
   } // ObjectInputStream
   
   virtual ~ObjectInputStream () 
   {
   } // ~ObjectInputStream

   //ObjectInputStream& operator= (const ObjectInputStream& right)
   //{
   //  if (this != &right)
   //    ObjectInputStream (right).swap (*this);
   //  return *this;
   //} // operator=

   virtual bool readObject (ISerializable& object)
   {
     return object.readObject (*this);
   } // readObject

   //
   // read types
   //
   virtual  bool readBool ()
   {
     size_t ch1 = read ();
     if (0 > ch1)
       throw IOException (L"end of stream");
     return (1 == ch1);
   } // readBool

   virtual  char readChar ()
   {
     size_t ch1 = read ();
     if (0 > ch1)
       throw IOException (L"end of stream");
     return static_cast<char> (ch1);
   } // readChar

   virtual  unsigned char readUChar ()
   {
     size_t ch1 = read ();
     if (0 > ch1)
       throw IOException (L"end of stream");
     return static_cast<unsigned char> (ch1);
   } // readUChar

   virtual  short readShort ()
   {
     size_t ch1 = read ();
     size_t ch2 = read ();
     if (0 > (ch1 | ch2))
       throw IOException (L"end of stream");
     return static_cast<short> ((ch1 << 8) + (ch2 << 0));
   } // readShort

   virtual  unsigned short readUShort ()
   {
     size_t ch1 = read ();
     size_t ch2 = read ();
     if (0 > (ch1 | ch2))
       throw IOException (L"end of stream");
     return static_cast<unsigned short> ((ch1 << 8) + (ch2 << 0));
   } // readUShort

   virtual  int readInt ()
   {
     size_t ch1 = read();
     size_t ch2 = read();
     size_t ch3 = read();
     size_t ch4 = read();
     if (0 > (ch1 | ch2 | ch3 | ch4))
       throw IOException (L"end of stream");
     return static_cast<int> ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
   } // readInt

   virtual  unsigned int readUInt ()
   {
     size_t ch1 = read();
     size_t ch2 = read();
     size_t ch3 = read();
     size_t ch4 = read();
     if (0 > (ch1 | ch2 | ch3 | ch4))
       throw IOException (L"end of stream");
     return static_cast<unsigned int> ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
   } // readUInt

   virtual  long readLong ()
   {
     return readInt ();
   } // readLong

   virtual  unsigned long readULong ()
   {
     return readUInt ();
   } // readULong

   virtual  longlong readLongLong ()
   {
     size_t ch1 = read();
     size_t ch2 = read();
     size_t ch3 = read();
     size_t ch4 = read();
     size_t ch5 = read();
     size_t ch6 = read();
     size_t ch7 = read();
     size_t ch8 = read();
     
     if (0 > (ch1 | ch2 | ch3 | ch4 | ch5 | ch6 | ch7 | ch8))
       throw IOException (L"end of stream");
     return (
        (static_cast<longlong> (ch1) << 56) + 
        (static_cast<longlong> (ch2 & 255) << 48) + 
        (static_cast<longlong> (ch3 & 255) << 40) + 
        (static_cast<longlong> (ch4 & 255) << 32) + 
        (static_cast<longlong> (ch5 & 255) << 24) + 
        ((ch6 & 255) << 16) + 
        ((ch7 & 255) << 8) + 
        ((ch8 & 255) << 0)
     );
   } // readLongLong

   virtual  u_longlong readULongLong ()
   {
     size_t ch1 = read();
     size_t ch2 = read();
     size_t ch3 = read();
     size_t ch4 = read();
     size_t ch5 = read();
     size_t ch6 = read();
     size_t ch7 = read();
     size_t ch8 = read();
     
     if (0 > (ch1 | ch2 | ch3 | ch4 | ch5 | ch6 | ch7 | ch8))
       throw IOException (L"end of stream");
     return (
        (static_cast<u_longlong> (ch1) << 56) + 
        (static_cast<u_longlong> (ch2 & 255) << 48) + 
        (static_cast<u_longlong> (ch3 & 255) << 40) + 
        (static_cast<u_longlong> (ch4 & 255) << 32) + 
        (static_cast<u_longlong> (ch5 & 255) << 24) + 
        ((ch6 & 255) << 16) + 
        ((ch7 & 255) << 8) + 
        ((ch8 & 255) << 0)
     );
   } // readULongLong

   //
   // read array types
   //
   virtual  size_t readBool (bool* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readBool ();
     }

     return size;
   } // readBool

   virtual  size_t readChar (char* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readChar ();
     }

     return size;
   } // readChar

   virtual  size_t readUChar (unsigned char* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readUChar ();
     }

     return size;
   } // readUChar

   virtual  size_t readShort (short* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readShort ();
     }

     return size;
   } // readShort

   virtual  size_t readUShort (unsigned short* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readUShort ();
     }

     return size;
   } // readUShort

   virtual  size_t readInt (int* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readInt ();
     }

     return size;
   } // readInt

   virtual  size_t readUInt (unsigned int* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readUInt ();
     }

     return size;
   } // readUInt

   virtual  size_t readLong (long* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readLong ();
     }

     return size;
   } // readLong

   virtual  size_t readULong (unsigned long* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readULong ();
     }

     return size;
   } // readULong

   virtual  size_t readLongLong (longlong* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readLongLong ();
     }

     return size;
   } // readLong

   virtual  size_t readULongLong (u_longlong* data, size_t size)
   {
     for (size_t i=0; i<size; ++i, ++data)
     {
       *data = readULongLong ();
     }

     return size;
   } // readULong

   virtual  bool   isEmpty () const                   { return m_stream.isEmpty (); }
   virtual  size_t read (ArrayType pVal, size_t size) { return m_stream.read (pVal, size); };
   virtual  size_t skip (size_t size)                 { return m_stream.skip (size); };
   virtual  size_t available () const                 { return m_stream.available (); };

  protected:
  private:
   size_t read ()
   {
     size_t                result = -1;
     StreamType::TokenType ch;
     
     if (0 < m_stream.read (ch))
       result = ch;

     return result;
   } // read

   //void swap (ObjectInputStream& right)
   //{
   //  StreamType& stream = m_stream;
   //  m_stream           = right.m_stream;
   //  right.m_stream     = stream;
   //} // swap
  
  //
  // data
  //
  public:
  protected:
   StreamType&   m_stream;

  private:
}; // ObjectInputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_objectinputstream_h_

