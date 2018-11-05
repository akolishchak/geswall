//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_fileinputstream_h_
 #define _commonlib_stream_fileinputstream_h_

#include "iinputstream.h"

namespace commonlib {
namespace stream {

template <class Type>
class FileInputStream : public IInputStream<Type>
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
   FileInputStream (FILE* file) 
    : IInputStream<Type> (),
      m_file (file), 
      m_erase (false)
   {

   } // FileInputStream

   virtual ~FileInputStream () 
   {
     if (true == m_erase)
     {
       if (NULL != m_file)
         ::fclose (m_file);
       m_file = NULL;
     }
     m_erase    = false;
   } // ~FileInputStream

   virtual  size_t read (ArrayType pVal, size_t size)
   {
     if (NULL != m_file)
     {
       if (0 == feof (m_file))
       {
         size = fread (pVal, sizeof (Type), size, m_file);
       }
       else
       {
         size = -1;
       }
     }
     else
     {
       size = -1;
     }

     return size;
   } // read

   virtual  size_t skip (size_t size)
   {
     if (NULL != m_file)
     {
       size_t pos = ftell (m_file);
       if (0 == fseek (m_file, static_cast <long> (size), SEEK_CUR))
         size = ftell (m_file) - pos;
       else
         size = -1;
     }
     else
     {
       size = -1;
     }

     return size;
   } // skip

   virtual  size_t available () const
   {
     if (NULL != m_file)
     {
       size_t pos0 = ftell (m_file);

       fseek (m_file, 0, SEEK_END);

       size_t pos1 = ftell (m_file);

       fseek (m_file, static_cast <long> (pos0), SEEK_SET);

       return pos1 - pos0;
     }

     return -1;
   } // available

  protected:
  private:
   FileInputStream (const FileInputStream& right) {}
   FileInputStream& operator= (const FileInputStream& right) { return *this; }
  
  //
  // data
  //
  public:
  protected:
  private:
   FILE*       m_file;
   bool        m_erase; // if file internal then m_erase = true else m_erase = false
}; // FileInputStream

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_fileinputstream_h_

