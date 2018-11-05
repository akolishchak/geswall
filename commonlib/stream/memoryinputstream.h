//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_memoryinputstream_h_
 #define _commonlib_stream_memoryinputstream_h_

#include "iinputstream.h"

namespace commonlib {
namespace stream {

template <class Type>
class MemoryInputStream : public IInputStream<Type>
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
   MemoryInputStream (ArrayType pVal, size_t size) 
    : IInputStream<Type> (),
      m_data (pVal), m_size (size), m_position (0)
   {
   } // MemoryInputStream

   MemoryInputStream (const MemoryInputStream& right) 
    : IInputStream<Type> (right),
      m_data (right.m_data), m_size (right.m_size), m_position (right.m_position) 
   {
   } // MemoryInputStream
    
   virtual ~MemoryInputStream () 
   {
     m_data     = NULL;
     m_size     = 0;
     m_position = 0;
   } // ~MemoryInputStream

   MemoryInputStream& operator= (const MemoryInputStream& right)
   {
     if (this != &right)
       MemoryInputStream (right).swap (*this);
     return *this;
   } // operator=

   virtual  size_t read (ArrayType pVal, size_t size)
   {
     size_t result = 0;

     if (NULL != m_data && m_size > m_position)
     {
       if ((m_size - m_position) < size)
         size = m_size - m_position;

       for (result=0; result < size; ++result)
         pVal[result] = m_data[m_position++];
     }
     else
     { // end of stream
       result = -1;
     }
     
     return result;
   } // read

   virtual  size_t skip (size_t size)
   {
     size_t result = 0;

     if (NULL != m_data && m_size > m_position)
     {
       if ((m_size - m_position) < size)
         size = m_size - m_position;

       m_position += size;
       result      = size;
     }
     else
     { // end of stream
       result = -1;
     }
     
     return result;
   } // skip

   virtual  size_t available () const
   {
     size_t result = 0;

     if (NULL != m_data && m_size > m_position)
       result = m_size - m_position;

     return result;
   } // available

  protected:
   MemoryInputStream () 
    : IInputStream<Type> (),
      m_data (NULL), m_size (0), m_position (0)
   {
   } // MemoryInputStream

   void swap (MemoryInputStream& right)
   {
     ArrayType   data     = m_data;
     size_t      size     = m_size;
     size_t      position = m_position;

     m_data               = right.m_data;    
     m_size               = right.m_size;    
     m_position           = right.m_position;

     right.m_data         = data;     
     right.m_size         = size;     
     right.m_position     = position; 
   } // swap

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
   ArrayType   m_data;
   size_t      m_size;
   size_t      m_position;
}; // MemoryInputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_memoryinputstream_h_

