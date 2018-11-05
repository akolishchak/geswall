//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_memoryoutputstream_h_
 #define _commonlib_stream_memoryoutputstream_h_

#include "ioutputstream.h"

namespace commonlib {
namespace stream {

template <class Type>
class MemoryOutputStream : public IOutputStream<Type>
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
   MemoryOutputStream () 
    : IOutputStream<Type> (), 
      m_data (NULL), 
      m_size (0),
      m_position (0), 
      m_capacity (-1),
      m_erase (true) 
   {
   } // MemoryOutputStream

   explicit 
   MemoryOutputStream (size_t capacity) 
    : IOutputStream<Type> (), 
      m_data (NULL), 
      m_size (0),
      m_position (0), 
      m_capacity (capacity),
      m_erase (true)
   {
     if (0 < m_capacity)
     {
       m_data = new Type [m_capacity];
       if (NULL != m_data)
         m_size = m_capacity;
     }
   } // MemoryOutputStream

   MemoryOutputStream (ArrayType data, size_t size) 
    : IOutputStream<Type> (), 
      m_data (data), 
      m_size (size),
      m_position (0), 
      m_capacity (size),
      m_erase (false)
   {
   } // MemoryOutputStream

   MemoryOutputStream (const MemoryOutputStream& right) 
    : IOutputStream<Type> (right),
      m_data (right.m_data), 
      m_size (right.m_size),
      m_position (right.m_position), 
      m_capacity (right.m_capacity),
      m_erase (right.m_erase)
   {
     if (true == m_erase && NULL != m_data)
     {
       m_data = new Type [m_size];
       if (NULL != m_data)
       {
         for (int i=0; i<m_size; ++i)
           m_data[i] = right.m_data[i];
       }
       else
       {
         m_size = 0;
       }
     }  
   } // MemoryOutputStream

   virtual ~MemoryOutputStream () 
   {
     if (true == m_erase)
     {
       if (NULL != m_data)
         delete[] m_data;
       m_data = NULL;
     }
     m_size     = 0;
     m_position = 0;
     m_capacity = 0;
     m_erase    = false;
   } // ~MemoryOutputStream

   MemoryOutputStream& operator= (const MemoryOutputStream& right)
   {
     if (this != &right)
       MemoryOutputStream (right).swap ();
     return *this;
   } // operator=

   virtual  size_t write (const ArrayType pVal, size_t size)
   {
     if (0 <= m_capacity && (size + m_position) > m_capacity)
       size = m_capacity - m_position;

     if (size > (m_size - m_position))
     {
       ArrayType data = new Type [m_position+size];
       if (NULL != data)
       {
         if (NULL != m_data)
         {
           for (size_t i=0; i<m_position; ++i)
             data[i] = m_data[i];
           delete m_data; // no delete[] m_data !!!
         }
         m_size = m_position + size;
         m_data = data;
       }
       else
       {
         size = m_size - m_position;
       }
     } // if (size > (m_size - m_position))

     if (NULL != m_data && 0 < size)
     {
       for (size_t i=0; i<size; ++i)
         m_data[m_position++] = pVal[i];
     }
     else
     { // end of stream
       size = -1;
     }

     return size;
   } // write

   virtual  size_t size () const
   {
     return m_position;
   } // size

   virtual  size_t capacity () const 
   { 
     return m_capacity; 
   } // capacity
 
   virtual  size_t toArray (ArrayType pVal, size_t size) const
   {
     if (NULL != m_data)
     {
       if (size > m_position)
         size = m_position;

       for (size_t i=0; i<size; ++i)
         pVal[i] = m_data[i];
     }
     else
     {
       size = 0;
     }

     return size;
   } // toArray
   
   virtual  const ArrayType head () const
   {
     return m_data;
   } // head

  protected:
   void swap (MemoryOutputStream& right)
   {
     ArrayType   data     = m_data;
     size_t      size     = m_size;
     size_t      position = m_position;
     size_t      capacity = m_capacity;
     bool        erase    = m_erase;

     m_data               = right.m_data;    
     m_size               = right.m_size;    
     m_position           = right.m_position;
     m_capacity           = right.m_capacity;
     m_erase              = right.m_erase;   

     right.m_data         = data;     
     right.m_size         = size;     
     right.m_position     = position; 
     right.m_capacity     = capacity;
     right.m_erase        = erase;
   } // swap

  private:
  
  //
  // data
  //
  public:
  protected:
   ArrayType   m_data;
   size_t      m_size;       // current size of internal buffer
   size_t      m_position;   // index of first free element
   size_t      m_capacity;   // max size, if (0 > m_capacity) then unlimit size
   bool        m_erase;      // if buffer internal then m_erase = true else m_erase = false

  private:
}; // MemoryOutputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_memoryoutputstream_h_

