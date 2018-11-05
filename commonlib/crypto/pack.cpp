//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "pack.h"

#include <io.h>

#include "commonlib/commondefs.h"
#include "commonlib/argumentexception.h"
#include "commonlib/ioexception.h"
#include "commonlib/outofmemoryexception.h"

#include "commonlib/stream/objectinputstream.h"
#include "commonlib/stream/objectoutputstream.h"
#include "commonlib/stream/iserializable.h"
#include "commonlib/stream/objectstreamsupport.h"
#include "commonlib/stream/memoryinputstream.h"
#include "commonlib/stream/memoryoutputstream.h"
#include "commonlib/stream/fileinputstream.h"
#include "commonlib/stream/fileoutputstream.h"

namespace commonlib {
namespace crypto {

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard_chk;
using commonlib::sguard::is_null_equal;
using commonlib::sguard::is_null_non_equal;

using commonlib::stream::ISerializable;
using commonlib::stream::IInputStream;
using commonlib::stream::IOutputStream;
using commonlib::stream::MemoryInputStream;
using commonlib::stream::MemoryOutputStream;
using commonlib::stream::FileInputStream;
using commonlib::stream::FileOutputStream;
using commonlib::stream::IObjectInputStream;
using commonlib::stream::IObjectOutputStream;
using commonlib::stream::ObjectInputStream;
using commonlib::stream::ObjectOutputStream;

#define ERROR_NS_PREFIX L"commonlib::crypto::"
#define ZLIB_CHUNK      16384


struct file_info : public ISerializable
{
  enum Signature
  { 
    Value = 0x55aa55aa
  };
   
  enum type
  {
    unknown,
    file,
    dir
  }; // Type
  
  file_info ()
   : m_type (unknown),
     m_size (0),
     m_attr (0)
  {
  } // file_info
  
  explicit file_info (const wstring& name, size_t size, type t = file, int attr = 0)
   : m_name (name),
     m_size (size),
     m_type (t),
     m_attr (attr)
  {
  } // file_info

  virtual bool readObject (IObjectInputStream& stream)
  {
    Signature sygn = static_cast <Signature> (stream.readUInt ());
    if (Signature::Value != sygn)
      throw IOException (ERROR_NS_PREFIX L"file_info::readObject (): bad object");
    
    m_type = static_cast <type> (stream.readInt ());
    m_size = static_cast <size_t> (stream.readLongLong ());
    m_attr = stream.readInt ();
    stream::readString (stream, m_name);
    return true;
  } // readObject
  
  virtual bool writeObject (IObjectOutputStream& stream) const
  {
    stream.writeUInt (Signature::Value);
    
    stream.writeInt (m_type);
    stream.writeLongLong (m_size);
    stream.writeInt (m_attr);
    stream::writeString (stream, m_name);
    return true;
  } // writeObject
  
  type      m_type;
  size_t    m_size;
  int       m_attr;
  wstring   m_name;
}; // file_info

struct current_dir_finalizer
{
  void operator () (wchar_t* dir)
  {
    int res = ::_wchdir (dir);
    ::free (dir); 
    
    if (0 > res)
      throw IOException (ERROR_NS_PREFIX L"current_dir_finalizer (): change dir error");
  }
}; // current_dir_finalizer

void   deflate (file_info& current_object_info, const wstring& source_file_mask, FILE* dst_file, pack_level level);
void   inflate (const file_info& current_object_info, FILE* src_file);

void   writeObject (ISerializable& object, FILE* dst_file);
void   readObject (ISerializable& object, FILE* dst_file);
  
void deflate (const wstring& source_file_mask, const wstring& dest_file_name, pack_level level)
{
  if (0 >= source_file_mask.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"deflate (): bad source file mask");
    
  if (0 >= dest_file_name.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"deflate (): bad dest file name");  
    
  try
  {  
    FILE*       dst_file = ::_wfopen (dest_file_name.c_str (), L"wb");
    scope_guard dst_file_guard = make_guard_chk (dst_file, &::fclose, is_null_equal <FILE*, NULL> ());
    
    if (true == dst_file_guard.is_free ())
      throw IOException (ERROR_NS_PREFIX L"deflate (): error create dest file");
    
    wchar_t path_buffer[_MAX_PATH];
    wchar_t drive[_MAX_DRIVE];
    wchar_t dir[_MAX_DIR];
    wchar_t fname[_MAX_FNAME];
    wchar_t ext[_MAX_EXT];
  
    _wsplitpath (source_file_mask.c_str (), drive, dir, fname, ext);
    _wmakepath (path_buffer, drive, dir, L"", L"");
  
    wchar_t* current_dir = _wgetcwd (NULL, _MAX_PATH);
    scope_guard current_dir_guard = make_guard_chk (current_dir, current_dir_finalizer (), is_null_equal <wchar_t*, NULL> ());
  
    if (true == current_dir_guard.is_free ())
      throw OutOfMemoryException (ERROR_NS_PREFIX L"deflate (): no memory for get current directory");
  
    if (0 > ::_wchdir (path_buffer))
      throw IOException (ERROR_NS_PREFIX L"deflate (): change dir error");
      
    ::_wmakepath (path_buffer, L"", L"", fname, ext);
    
    file_info root (L".", 0, file_info::dir, 0);  
    deflate (root, path_buffer, dst_file, level);
  }
  catch (Exception& e)
  {
    _wunlink (dest_file_name.c_str ());
    throw e;
  }
} // deflate

void deflate (file_info& current_object_info, const wstring& source_file_mask, FILE* dst_file, pack_level level)
{
  struct      _wfinddata_t find_data;
  int         res           = 0;
  intptr_t    handle        = ::_wfindfirst (const_cast <wchar_t*> (source_file_mask.c_str ()), &find_data);
  scope_guard handle_guard  = make_guard_chk (handle, &::_findclose, is_null_equal <intptr_t, -1> ());
  size_t      objects_count = 0;
  
  size_t      dir_info_pos = ::ftell (dst_file);
  if (0 > dir_info_pos)
    throw IOException (ERROR_NS_PREFIX L"deflate (): ftell error");
  
  writeObject (current_object_info, dst_file);
  
  size_t      dir_pos_before = ftell (dst_file);
  if (0 > dir_pos_before)
    throw IOException (ERROR_NS_PREFIX L"deflate (): ftell error");
  
  //
  // files pack
  //
  while (false == handle_guard.is_free () && 0 <= res)
  {
    if ((L'.' == find_data.name [0]) &&  (L'\0' == find_data.name [1] || (L'.' == find_data.name [1] && L'\0' == find_data.name [2])))
    {
      ;
    }  
    else
    {
      if (_A_SUBDIR != (find_data.attrib & _A_SUBDIR))
      { // file
        FILE*       src_file       = ::_wfopen (find_data.name, L"rb");
        scope_guard src_file_guard = make_guard_chk (src_file, &::fclose, is_null_equal <FILE*, NULL> ());
        file_info   current_info (find_data.name, 0, file_info::file, find_data.attrib);  
        
        size_t      info_pos = ftell (dst_file);
        if (0 > info_pos)
          throw IOException (ERROR_NS_PREFIX L"deflate (): ftell error");

        writeObject (current_info, dst_file);
        
        size_t      pos_before = ftell (dst_file);
        if (0 > pos_before)
          throw IOException (ERROR_NS_PREFIX L"deflate (): ftell error");
        
        deflate (src_file, dst_file, level);
        
        size_t      pos_after = ftell (dst_file);
        if (0 > pos_after)
          throw IOException (ERROR_NS_PREFIX L"deflate (): ftell error");
          
        if (0 != fseek (dst_file, static_cast <long> (info_pos), SEEK_SET))
          throw IOException (ERROR_NS_PREFIX L"deflate (): fseek error");
          
        current_info.m_size = pos_after - pos_before;
        writeObject (current_info, dst_file);
        
        if (0 != fseek (dst_file, static_cast <long> (pos_after), SEEK_SET))
          throw IOException (ERROR_NS_PREFIX L"deflate (): fseek error");
                
        ++objects_count;
      } // if (_A_SUBDIR != (find_data.attrib & _A_SUBDIR))
    }  
    
    res = _wfindnext (handle, &find_data);
  } // while (false == handle_guard.is_free () && 0 <= res)
  
  handle_guard.free ();
  
  //
  // directories pack
  //
  res = 0;
  intptr_t    handle_dir       = ::_wfindfirst (L"*.*", &find_data);
  scope_guard handle_dir_guard = make_guard_chk (handle_dir, &::_findclose, is_null_equal <intptr_t, -1> ());
  while (false == handle_dir_guard.is_free () && 0 <= res)
  {
    if ((L'.' == find_data.name [0]) &&  (L'\0' == find_data.name [1] || (L'.' == find_data.name [1] && L'\0' == find_data.name [2])))
    {
      ; // skip
    }  
    else
    {
      if (_A_SUBDIR == (find_data.attrib & _A_SUBDIR))
      { // dir
        wchar_t*    current_dir       = _wgetcwd (NULL, _MAX_PATH);
        scope_guard current_dir_guard = make_guard_chk (current_dir, current_dir_finalizer (), is_null_equal <wchar_t*, NULL> ());
  
        if (true == current_dir_guard.is_free ())
          throw OutOfMemoryException (ERROR_NS_PREFIX L"deflate (): no memory for get current directory");
          
        if (0 > ::_wchdir (find_data.name))
          throw IOException (ERROR_NS_PREFIX L"deflate (): change dir error");
      
        file_info current_info (find_data.name, 0, file_info::dir, find_data.attrib);  
        deflate (current_info, source_file_mask, dst_file, level);
        
        ++objects_count;
      }
    }  
    
    res = _wfindnext (handle_dir, &find_data);
  } // while (false == handle_dir_guard.is_free () && 0 <= res)
  
  size_t      dir_pos_after = ftell (dst_file);
  if (0 > dir_pos_after)
    throw IOException (ERROR_NS_PREFIX L"deflate (): ftell error");
  
  if (0 != fseek (dst_file, static_cast <long> (dir_info_pos), SEEK_SET))
    throw IOException (ERROR_NS_PREFIX L"deflate (): fseek error");  
  
  current_object_info.m_size = objects_count;
  writeObject (current_object_info, dst_file);
  
  if (0 != fseek (dst_file, static_cast <long> (dir_pos_after), SEEK_SET))
    throw IOException (ERROR_NS_PREFIX L"deflate (): fseek error");
} // deflate

void inflate (const wstring& source_file_name, const wstring& dest_dir_name)
{
  if (0 >= source_file_name.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"deflate (): bad source file name");
    
  if (0 >= dest_dir_name.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"deflate (): bad dest dir name");  
    
  FILE*       src_file = ::_wfopen (source_file_name.c_str (), L"rb");
  scope_guard src_file_guard = make_guard_chk (src_file, &::fclose, is_null_equal <FILE*, NULL> ());  
  
  if (true == src_file_guard.is_free ())
    throw IOException (ERROR_NS_PREFIX L"inflate (): error open src file");
    
  wchar_t* current_dir = _wgetcwd (NULL, _MAX_PATH);
  scope_guard current_dir_guard = make_guard_chk (current_dir, current_dir_finalizer (), is_null_equal <wchar_t*, NULL> ());
  
  if (true == current_dir_guard.is_free ())
    throw OutOfMemoryException (ERROR_NS_PREFIX L"inflate (): no memory for get current directory");
  
  if (0 > ::_wchdir (dest_dir_name.c_str ()))
    throw IOException (ERROR_NS_PREFIX L"inflate (): change dir error");  
    
  file_info root_info;
  readObject (root_info, src_file);
  inflate (root_info, src_file);
} // inflate

void inflate (const file_info& current_object_info, FILE* src_file)
{
  if (file_info::file == current_object_info.m_type)
  {
    FILE*       dst_file = ::_wfopen (current_object_info.m_name.c_str (), L"wb");
    scope_guard dst_file_guard = make_guard_chk (dst_file, &::fclose, is_null_equal <FILE*, NULL> ());
    
    inflate (src_file, dst_file, current_object_info.m_size);
  }
  else
  {
    if (file_info::dir == current_object_info.m_type)
    {
      wchar_t* current_dir = _wgetcwd (NULL, _MAX_PATH);
      scope_guard current_dir_guard = make_guard_chk (current_dir, current_dir_finalizer (), is_null_equal <wchar_t*, NULL> ());
      
      if (true == current_dir_guard.is_free ())
        throw OutOfMemoryException (ERROR_NS_PREFIX L"inflate (): no memory for get current directory");
      
      if (0 != current_object_info.m_name.compare (L".") && 0 != current_object_info.m_name.compare (L".."))
      {
        if (0 > ::_wmkdir (current_object_info.m_name.c_str ()))
          throw IOException (ERROR_NS_PREFIX L"inflate (): make dir error");  
      
        if (0 > ::_wchdir (current_object_info.m_name.c_str ()))
          throw IOException (ERROR_NS_PREFIX L"inflate (): change dir error");  
      }
       
      for (size_t i = 0; i < current_object_info.m_size; ++i)
      {
        file_info current_info;
        readObject (current_info, src_file);
        inflate (current_info, src_file);
      }
    }
    else
    {
      throw IOException (ERROR_NS_PREFIX L"inflate (): bad file info type");  
    }
  }
} // inflate


/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */
void deflate (FILE* source, FILE* dest, pack_level level)
{
  if (NULL == source)
    throw IOException (ERROR_NS_PREFIX L"deflate (): error source data file");
    
  if (NULL == dest)
    throw IOException (ERROR_NS_PREFIX L"deflate (): error dest data file");

  int           ret;
  int           flush;
  unsigned int  have;
  z_stream      strm;
  unsigned char in [ZLIB_CHUNK];
  unsigned char out [ZLIB_CHUNK];

  /* allocate deflate state */
  strm.zalloc = Z_NULL;
  strm.zfree  = Z_NULL;
  strm.opaque = Z_NULL;
  ret = deflateInit (&strm, level);
  if (ret != Z_OK)
    throw Exception (ERROR_NS_PREFIX L"deflate (): deflateInit error"); // return ret;

  /* compress until end of file */
  do 
  {
    strm.avail_in = static_cast <unsigned int> (fread (in, 1, ZLIB_CHUNK, source));
    if (ferror (source)) 
    {
      (void) deflateEnd (&strm);
      throw IOException (L"deflate (): read data file error"); // return Z_ERRNO;
    }

    flush        = feof (source) ? Z_FINISH : Z_NO_FLUSH;
    strm.next_in = in;

    /* run deflate() on input until output buffer not full, finish
    compression if all of source has been read in */
    do 
    {
      strm.avail_out = ZLIB_CHUNK;
      strm.next_out  = out;
      ret            = deflate(&strm, flush);    /* no bad return value */

      assert(ret != Z_STREAM_ERROR);  /* state not clobbered */

      have = ZLIB_CHUNK - strm.avail_out;
      if (fwrite (out, 1, have, dest) != have || ferror (dest)) 
      {
        (void) deflateEnd (&strm);
        throw IOException (ERROR_NS_PREFIX L"deflate (): write data file error"); // return Z_ERRNO;
      }
    } 
    while (strm.avail_out == 0);

    assert(strm.avail_in == 0);     /* all input will be used */

    /* done when last data in file processed */
  } 
  while (flush != Z_FINISH);

  assert(ret == Z_STREAM_END);        /* stream will be complete */

  /* clean up and return */
  (void) deflateEnd (&strm);
} // deflate

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
void inflate (FILE* source, FILE* dest, size_t size)
{
  if (NULL == source)
    throw IOException (ERROR_NS_PREFIX L"inflate (): error source data file");
    
  if (NULL == dest)
    throw IOException (ERROR_NS_PREFIX L"inflate (): error dest data file");
  
  int           ret;
  unsigned int  have;
  z_stream      strm;
  unsigned char in [ZLIB_CHUNK];
  unsigned char out [ZLIB_CHUNK];
  size_t        block_size = ZLIB_CHUNK;

  /* allocate inflate state */
  strm.zalloc   = Z_NULL;
  strm.zfree    = Z_NULL;
  strm.opaque   = Z_NULL;
  strm.avail_in = 0;
  strm.next_in  = Z_NULL;
  ret = inflateInit (&strm);
  if (ret != Z_OK)
    throw Exception (ERROR_NS_PREFIX L"inflate (): inflateInit error"); // return ret;

  /* decompress until deflate stream ends or end of file */
  do 
  {
    if (0 < size)
    {
      if (size < block_size)
        block_size = size;
    }
    
    strm.avail_in = static_cast <unsigned int> (fread (in, 1, block_size, source)); // ZLIB_CHUNK
    if (ferror(source)) 
    {
      (void)inflateEnd(&strm);
      throw IOException (ERROR_NS_PREFIX L"inflate (): read data file error"); // return Z_ERRNO;
    }
    
    if (strm.avail_in == 0)
      break;
      
    size -= strm.avail_in;
      
    strm.next_in = in;

    /* run inflate() on input until output buffer not full */
    do 
    {
      strm.avail_out = ZLIB_CHUNK;
      strm.next_out  = out;
      ret            = inflate (&strm, Z_NO_FLUSH);
      
      assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      
      switch (ret) 
      {
        case Z_NEED_DICT:
             ret = Z_DATA_ERROR;     /* and fall through */
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
             (void)inflateEnd(&strm);
             throw Exception (ERROR_NS_PREFIX L"inflate (): inflate error"); // return ret;
      }
      
      have = ZLIB_CHUNK - strm.avail_out;
      if (fwrite (out, 1, have, dest) != have || ferror(dest)) 
      {
        (void)inflateEnd(&strm);
        throw IOException (ERROR_NS_PREFIX L"inflate (): write data file error"); // return Z_ERRNO;
      }
    } 
    while (strm.avail_out == 0);
    assert(strm.avail_in == 0);     /* all input will be used */

    /* done when inflate() says it's done */
  } 
  while (ret != Z_STREAM_END && 0 != size);

  /* clean up and return */
  (void)inflateEnd(&strm);
  
  if (Z_STREAM_END != ret)
    throw Exception (ERROR_NS_PREFIX L"inflate (): data error");
} // inflate

void writeObject (ISerializable& object, FILE* dst_file)
{
  FileOutputStream<unsigned char>   stream (dst_file);
  ObjectOutputStream                obj_out (stream);
  
  obj_out.writeObject (object);
} // writeObject

void readObject (ISerializable& object, FILE* dst_file)
{
  FileInputStream<unsigned char>    stream (dst_file);
  ObjectInputStream                 obj_in (stream);
  
  obj_in.readObject (object);
} // readObject

} // namespace crypto {
} // namespace commonlib {
