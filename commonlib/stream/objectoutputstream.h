//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_objectoutputstream_h_
 #define _commonlib_stream_objectoutputstream_h_

#include "iobjectoutputstream.h"

#include "iserializable.h"

namespace commonlib {
namespace stream {

class ObjectOutputStream : public IObjectOutputStream
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
  
   explicit ObjectOutputStream (StreamType& stream) 
    : IObjectOutputStream (),
      m_stream (stream)
   {
   } // ObjectOutputStream
   
   ObjectOutputStream (const ObjectOutputStream& right) 
    : IObjectOutputStream (right),
      m_stream (right.m_stream)
   {
   } // ObjectOutputStream
   
   virtual ~ObjectOutputStream () 
   {
   } // ~ObjectOutputStream

   //ObjectOutputStream& operator= (const ObjectOutputStream& right)
   //{
   //  if (this != &right)
   //    ObjectOutputStream (right).swap (*this);
   //  return *this;
   //} // operator=

   virtual bool writeObject (const ISerializable& object)
   {
     return object.writeObject (*this);
   } // writeObject

   //
   // write types
   //
   virtual  bool writeBool (bool data)
   {
     return (0 < m_stream.write ((true == data) ? 1 : 0));
   } // writeBool

   virtual  bool writeChar (char data)
   {
     return (0 < m_stream.write (data));
   } // writeChar

   virtual  bool writeUChar (unsigned char data)
   {
     return (0 < m_stream.write (data));
   } // writeUChar

   virtual  bool writeShort (short data)
   {
     return (                                 
       (0 < m_stream.write ((data >> 8) & 255)) &&
       (0 < m_stream.write ((data >> 0) & 255))
     );
   } // writeShort

   virtual  bool writeUShort (unsigned short data)
   {
     return (                                 
       (0 < m_stream.write ((data >> 8) & 255)) &&
       (0 < m_stream.write ((data >> 0) & 255))
     );
   } // writeUShort

   virtual  bool writeInt (int data)
   {
     return (                                 
       (0 < m_stream.write ((data >> 24) & 255)) &&
       (0 < m_stream.write ((data >> 16) & 255)) &&
       (0 < m_stream.write ((data >> 8) & 255)) &&
       (0 < m_stream.write ((data >> 0) & 255))
     );
   } // writeInt

   virtual  bool writeUInt (unsigned int data)
   {
     return (                                 
       (0 < m_stream.write ((data >> 24) & 255)) &&
       (0 < m_stream.write ((data >> 16) & 255)) &&
       (0 < m_stream.write ((data >> 8) & 255)) &&
       (0 < m_stream.write ((data >> 0) & 255))
     );
   } // writeUInt

   virtual  bool writeLong (long data)
   {
     return writeInt (data);
   } // writeLong

   virtual  bool writeULong (unsigned long data)
   {
     return writeUInt (data);
   } // writeULong

   virtual  bool writeLongLong (longlong data)
   {
     return (                                 
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 56) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 48) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 40) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 32) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 24) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 16) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 8) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 0) & 255)))
     );
   } // writeLongLong

   virtual  bool writeULongLong (u_longlong data)
   {
     return (                                 
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 56) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 48) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 40) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 32) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 24) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 16) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 8) & 255))) &&
       (0 < m_stream.write (static_cast<BaseStreamType::TokenType> ((data >> 0) & 255)))
     );
   } // writeULongLong

   //
   // write array types
   //
   virtual  size_t writeBool (const bool* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeBool (*data); ++i, ++data);

     return i;
   } // writeBool

   virtual  size_t writeChar (const char* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeChar (*data); ++i, ++data);

     return i;
   } // writeChar

   virtual  size_t writeUChar (const unsigned char* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeUChar (*data); ++i, ++data);

     return i;
   } // writeUChar

   virtual  size_t writeShort (const short* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeShort (*data); ++i, ++data);

     return i;
   } // writeShort

   virtual  size_t writeUShort (const unsigned short* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeUShort (*data); ++i, ++data);

     return i;
   } // writeUShort

   virtual  size_t writeInt (const int* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeInt (*data); ++i, ++data);

     return i;
   } // writeInt

   virtual  size_t writeUInt (const unsigned int* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeUInt (*data); ++i, ++data);

     return i;
   } // writeUInt

   virtual  size_t writeLong (const long* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeLong (*data); ++i, ++data);

     return i;
   } // writeLong

   virtual  size_t writeULong (const unsigned long* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeULong (*data); ++i, ++data);

     return i;
   } // writeULong

   virtual  size_t writeLongLong (const longlong* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeLongLong (*data); ++i, ++data);

     return i;
   } // writeLongLong

   virtual  size_t writeULongLong (const u_longlong* data, size_t size)
   {
     size_t i = 0;
     
     for (i = 0; i < size && true == writeULongLong (*data); ++i, ++data);

     return i;
   } // writeULongLong

   virtual  size_t available () const                          { return m_stream.available (); }
   virtual  size_t write (const ArrayType pVal, size_t size)   { return m_stream.write (pVal, size); };
   virtual  size_t size () const                               { return m_stream.size (); };
   virtual  size_t capacity () const                           { return m_stream.capacity (); };
   virtual  size_t toArray (ArrayType pVal, size_t size) const { return m_stream.toArray (pVal, size); }
   virtual  const ArrayType head () const                      { return m_stream.head (); }

  protected:
  private:
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
}; // ObjectOutputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_objectoutputstream_h_

