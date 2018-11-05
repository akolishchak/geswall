//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "checker.h"

using namespace std;

namespace gswserv {
namespace logs {

Checker::PtrToChecker  Checker::m_checker;

void Checker::start ()
{
  if (NULL != m_checker.get ())
    return;

  PtrToINode node = Configurator::getGswlPolicyNode ();
  if (NULL != node.get ())
  {
    int scanPeriod = DefaultScanPeriod;
    int threshold  = DefaultThreshold;
    
    PtrToINode chkNode = node->getNode (L"LogsChecker", true);
    if (NULL != chkNode.get ())
    {
      scanPeriod = chkNode->getInt (L"ScanPeriod");
      threshold  = chkNode->getInt (L"Threshold");
    }
    
    m_checker = PtrToChecker (new Checker (node->getString (L"AccessLogDir"), scanPeriod, threshold));
  }  
} // start

void Checker::stop ()
{
  if (NULL == m_checker.get ())
    return;

  m_checker.reset ();
} // stop

void Checker::refreshSetting ()
{
  if (NULL == m_checker.get ())
    throw ArgumentException (L"Checker undefined");

  PtrToINode node = Configurator::getGswlPolicyNode ();
  if (NULL != node.get ())
  {
    PtrToINode chkNode = node->getNode (L"LogsChecker", true);
    if (NULL != chkNode.get ())
    {
      m_checker->refreshSetting (node->getString (L"AccessLogDir"), chkNode->getInt (L"ScanPeriod"), chkNode->getInt (L"Threshold"));
    }
  }
} // refreshSetting

Checker& Checker::get ()
{
  if (NULL == m_checker.get ())
    throw ArgumentException (L"Checker undefined");
    
  return *m_checker;
} // get

Checker::Checker (wstring& logDir, int scanPeriod, int threshold) 
 : m_closing (false),
   m_thread (NULL)
{
  refreshSetting (logDir, scanPeriod, threshold);
  m_thread = new thread (thread_stub (*this));
} // Checker

Checker::~Checker () 
{
  try
  {
    {
      Locker locker (m_sync);
      m_closing = true;
      m_sync.notifyAll ();
    }
  
    if (NULL != m_thread)
    {
      m_thread->join ();
      delete m_thread;
      m_thread = NULL;
    }
  }
  catch (...)
  {
  }
} // ~Checker

void Checker::refreshSetting (wstring& logDir, int scanPeriod, int threshold)
{
  Locker locker (m_sync);

  setLogDirectory (logDir);
  m_scanPeriod = scanPeriod;
  m_threshold  = threshold;

  if (0 >= m_scanPeriod)
    m_scanPeriod = DefaultScanPeriod;
    
  if (0 >= m_threshold || 100 <= m_threshold)
    m_threshold = DefaultThreshold;

  m_sync.notifyAll ();
} // refreshSetting

void Checker::workThread ()
{
  Locker locker (m_sync);
  
  wstring       searchPattern;
  FileInfoList  files;
  
  while (false == m_closing)
  {
    searchPattern = m_logDir + L"\\*.txt";

    unsigned __int64 freeSize  = getFreeSpace ();
    unsigned __int64 threshold = (freeSize / 100) * m_threshold;
    
    files.clear ();
    unsigned __int64 filesSize = getFiles (searchPattern, files);
    
    if (filesSize >= threshold && 1 < files.size ())
    {
      files.sort ();
      while (filesSize >= threshold && 1 < files.size ())
      {
        file_info& info = files.front ();
        
        searchPattern = m_logDir + L"\\" + info.m_name;
        
        SetFileAttributesW (searchPattern.c_str (), (GetFileAttributesW (searchPattern.c_str ()) & ~FILE_ATTRIBUTE_READONLY));
        if (TRUE == DeleteFileW (searchPattern.c_str ()))
          filesSize -= info.m_size;
          
        files.pop_front ();  
      }  
    } // if (filesSize >= threshold)
    
    try
    {
      m_sync.wait (m_scanPeriod);
    }
    catch (CancelException&)
    {
      break;
    }
    catch (TimeoutException&)
    {
    }
  } // while (false == m_closing)
} // workThread

void Checker::setLogDirectory (const wstring& logDir)
{
// \SystemRoot\geswall\logs (defs: %SystemRoot%\geswall\logs)
  if (0 >= logDir.size ())
    queryDefaultDirectory (m_logDir);
  else
    m_logDir = logDir;
    
  prepareDirectoryName (m_logDir);
} // setLogDirectory

unsigned __int64 Checker::getFreeSpace ()
{
  unsigned __int64 result = 0;
  
  ULARGE_INTEGER   freeBytesAvailable;
  ULARGE_INTEGER   totalNumberOfBytes;
  ULARGE_INTEGER   totalNumberOfFreeBytes;
  
  if (TRUE == GetDiskFreeSpaceExW (m_logDir.c_str (), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes))
  {
    result = totalNumberOfFreeBytes.QuadPart;
  }
  
  return result;
} // getFreeSpace

void Checker::queryDefaultDirectory (wstring& destStr)
{
  DWORD    count = ExpandEnvironmentStringsW (L"%SystemRoot%\\geswall\\logs", NULL, 0);
  
  if (0 != count)
  {
    PtrToWcharArray buffer (new wchar_t [count]);
    if (NULL != buffer.get ())
    {
      count = ExpandEnvironmentStringsW (L"%SystemRoot%\\geswall\\logs", buffer.get (), count);
      if (0 != count)
        destStr.assign (buffer.get ());
    }
  }
} // queryDefaultDirectory

void Checker::prepareDirectoryName (wstring& destStr)
{
  if (0 == destStr.find (L"\\??\\"))
    destStr.erase(0, lenghtOf (L"\\??\\") - 1);
} // prepareDirectoryName

unsigned __int64 Checker::getFiles (const wstring& searchPattern, FileInfoList& files)
{
  unsigned __int64  size = 0;
  WIN32_FIND_DATAW  findData;
  HANDLE            handle = FindFirstFileW (searchPattern.c_str (), &findData);
  
  if (handle != INVALID_HANDLE_VALUE)
  {
    do 
    {
      if (
             FILE_ATTRIBUTE_DIRECTORY != (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
          && FILE_ATTRIBUTE_REPARSE_POINT != (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) 
         )
      {   
        file_info info (findData);
        size += info.m_size;
        
        files.push_back (info);
      }  
    }
    while (TRUE == FindNextFileW (handle, &findData));
    
    FindClose (handle);
  } // if (handle != INVALID_HANDLE_VALUE)
  
  return size;
} // getFiles

} // namespace logs {
} // namespace gswserv {
