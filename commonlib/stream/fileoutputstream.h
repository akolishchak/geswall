//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_fileoutputstream_h_
 #define _commonlib_stream_fileoutputstream_h_

#include "ioutputstream.h"
#include <stdio.h>

namespace commonlib {
namespace stream {

template <class Type>
class FileOutputStream : public IOutputStream<Type>
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
   explicit
   FileOutputStream (FILE* file) 
    : IOutputStream<Type> (),
      m_file (file),
      m_erase (false)
   {
   } // FileOutputStream

   virtual ~FileOutputStream () 
   {
     if (true == m_erase)
     {
       if (NULL != m_file)
         ::fclose (m_file);
       m_file = NULL;
     }
     m_erase    = false;
   } // ~FileOutputStream

   virtual  size_t write (const ArrayType pVal, size_t size)
   {
     if (NULL != m_file)
       size = fwrite (pVal, sizeof (Type), size, m_file);
     else
       size = -1;  

     return size;
   } // write

   virtual  size_t size () const
   {
     int size = -1;

     if (NULL != m_file)
       size = ftell (m_file);

     return size;
   } // size

   virtual  size_t capacity () const 
   { 
     return -1;  // unlimit
   } // capacity
 
   virtual  size_t toArray (ArrayType pVal, size_t size) const
   {
     return 0;
   } // toArray
   
   virtual  const ArrayType head () const
   {
     return NULL;
   } // head

  protected:
  private:
   FileOutputStream (const FileOutputStream& right) {}
   FileOutputStream& operator= (const FileOutputStream& right) { return *this; }
  
  //
  // data
  //
  public:
  protected:
   FILE*       m_file;
   bool        m_erase; // if file internal then m_erase = true else m_erase = false

  private:
}; // FileOutputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_fileoutputstream_h_

