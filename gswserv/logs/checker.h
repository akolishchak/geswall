//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswserv_logs_checker_h_
 #define _gswserv_logs_checker_h_

#include "stdafx.h"

#include <boost/smart_ptr.hpp> 
#include <string>
#include <list>

#include "commondefs.h"
#include "configurator.h"
#include "thread.h"
#include "argumentexception.h"

namespace gswserv {
namespace logs {

class Checker;

class Checker
{
  //
  // types
  //
  public:
  protected:
   typedef boost::shared_ptr<Checker>            PtrToChecker;
   typedef config::Configurator                  Configurator;
   typedef config::Configurator::PtrToINode      PtrToINode;
   typedef std::wstring                          wstring;
   typedef commonlib::thread                     thread;
   typedef commonlib::ArgumentException          ArgumentException;
   typedef commonlib::sync::CancelException      CancelException;
   typedef commonlib::sync::TimeoutException     TimeoutException;
   typedef commonlib::sync::SyncObject           SyncObject;
   typedef commonlib::sync::SyncObject::Locker   Locker;
   typedef commonlib::PtrToWcharArray            PtrToWcharArray;
   
   struct thread_stub
   {
     thread_stub (Checker& checker)
      : m_checker (checker)
     {
     }
     
     void operator () ()
     {
       m_checker.workThread ();
     }
     
     Checker& m_checker;
   }; // thread_stub

   friend struct thread_stub;
   
   enum Const
   {
     DefaultScanPeriod = 60000,
     DefaultThreshold  = 10
   };
   
   struct file_info
   {
     file_info (const WIN32_FIND_DATAW& w32FileInfo)
       : m_name (w32FileInfo.cFileName)
     {
       ULARGE_INTEGER size;
       size.LowPart  = w32FileInfo.nFileSizeLow;
       size.HighPart = w32FileInfo.nFileSizeHigh;
       
       m_size = size.QuadPart;
     } // file_info
     
     bool operator> (const file_info& right) const
     {
       return (0 < m_name.compare (right.m_name));
     } // operator<
     
     bool operator< (const file_info& right) const
     {
       return (0 > m_name.compare (right.m_name));
     } // operator<
   
     wstring          m_name;
     unsigned __int64 m_size;
   }; // file_info
   
   typedef std::list <file_info>          FileInfoList;

  private:

  //
  // methods
  //
  public:
   static void       start ();
   static void       stop ();
   static void       refreshSetting ();
   static Checker&   get ();
   
   virtual          ~Checker ();

          void       refreshSetting (wstring& logDir, int scanPeriod, int threshold);
       
  protected:
                     Checker (wstring& logDir, int scanPeriod, int threshold);

          void       workThread ();

                     Checker (const Checker& right) {};
          Checker&   operator= (const Checker& right) { return *this; }

  private:
    void             setLogDirectory (const wstring& logDir);
    unsigned __int64 getFreeSpace ();
    void             queryDefaultDirectory (wstring& destStr);
    void             prepareDirectoryName (wstring& destStr);
    unsigned __int64 getFiles (const wstring& searchPattern, FileInfoList& files);
  
  //
  // data
  //
  public:
  protected:
  private:
   wstring     m_logDir;  
   int         m_scanPeriod; // into msec
   int         m_threshold;  // into percents from free size
   SyncObject  m_sync;
   bool        m_closing;
   thread*     m_thread;

   static PtrToChecker  m_checker;
}; // Checker

} // namespace logs {
} // namespace gswserv {


#endif // _gswserv_logs_checker_h_