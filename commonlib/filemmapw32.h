//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _FILE_MEMORY_MAPPING_W32_H_
 #define _FILE_MEMORY_MAPPING_W32_H_

#include <windows.h>

#include <string>

#include "ifilemmap.h"

using namespace std;
 
namespace commonlib {

namespace mmap {

class FileMMapW32 : public IFileMMap
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
            FileMMapW32 (const wstring& fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes = NULL, DWORD creationDisposition = OPEN_EXISTING, DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL);
   virtual ~FileMMapW32 ();
   
   virtual  void      close ();
   virtual  void*     map (void* start = NULL, size_t length = 0, size_t offset = 0);
   virtual  void      unmap (size_t length = 0);
   
   virtual  size_t    viewSize ();
   

  protected:
               FileMMapW32 (const FileMMapW32& right) {};
   FileMMapW32& operator= (const FileMMapW32& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
   size_t m_fileSize;
   HANDLE m_hFile;
   HANDLE m_hFileMap;
   void*  m_viewData;
   size_t m_offsetView;
   size_t m_sizeView;
   DWORD  m_desiredAccess;
}; // FileMMapW32

} // namespace mmap {

} // namespace commonlib {

#endif // _FILE_MEMORY_MAPPING_W32_H_