//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "filemmapw32.h"

using namespace commonlib::mmap;
using namespace std;

FileMMapW32::FileMMapW32 (const wstring& fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes)
 : IFileMMap (),
   m_fileSize (0),
   m_hFile (INVALID_HANDLE_VALUE),
   m_hFileMap (NULL),
   m_viewData (NULL),
   m_offsetView (0),
   m_sizeView (0),
   m_desiredAccess (0)
{
  m_hFile = CreateFile (fileName.c_str (), desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, NULL);
  if (INVALID_HANDLE_VALUE != m_hFile)
  {
    LARGE_INTEGER fsize;
    fsize.LowPart = GetFileSize (m_hFile, reinterpret_cast <DWORD*> (&fsize.HighPart));
    
    m_fileSize = static_cast <size_t> (fsize.QuadPart);
    
    DWORD protect = 0;
    
    if (desiredAccess & GENERIC_READ)
    {
      protect         = PAGE_READONLY;
      m_desiredAccess = FILE_MAP_READ;
    }

    if (desiredAccess & GENERIC_WRITE)
    {
      protect         = PAGE_READWRITE;
      m_desiredAccess = FILE_MAP_WRITE;
    }

    m_hFileMap = CreateFileMapping (m_hFile, 0, protect, 0, 0, NULL);
  }
} // FileMMapW32

FileMMapW32::~FileMMapW32 ()
{
  close ();
} // ~FileMMapW32

void FileMMapW32::close ()
{
  unmap ();

  CloseHandle (m_hFileMap);

  if (INVALID_HANDLE_VALUE != m_hFile)
    CloseHandle (m_hFile);

  m_hFile    = INVALID_HANDLE_VALUE;
  m_hFileMap = NULL;            
} // close ()

void* FileMMapW32::map (void* start, size_t length, size_t offset)
{
  unmap ();

  LARGE_INTEGER offset_w32;

  if (m_fileSize < offset)
    offset = m_fileSize;
  
  if (m_fileSize < (length + offset))
    length = m_fileSize - offset;
  
  if (0 <= length && 0 == offset)
  {
    offset_w32.QuadPart = offset;
    m_viewData = MapViewOfFile (m_hFileMap, m_desiredAccess, offset_w32.HighPart, offset_w32.LowPart, length);
    if (NULL != m_viewData)
    {
      m_offsetView = offset;
      m_sizeView   = (0 == length) ? m_fileSize : length;
    }
  }
    
  return m_viewData;
} // map

void FileMMapW32::unmap (size_t length)
{
  if (NULL != m_viewData)
    UnmapViewOfFile (m_viewData);
  m_viewData   = NULL;
  m_offsetView = 0;
  m_sizeView   = 0;
} // unmap

size_t FileMMapW32::viewSize ()
{
  return m_sizeView;
} // viewSize