//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "thread.h"

#include <windows.h>
#include <process.h>   

namespace commonlib {

struct thread_stub
{
  public:
   thread_stub (const thread::Handler& handler)
    : m_handler (handler)
   {
   } // thread_stub

   ~thread_stub ()
   {
   } // ~thread_stub

   const thread::Handler m_handler;
}; // thread_stub

extern "C" {
static unsigned int __stdcall thread_proc (void* param)
{
  try
  {
    thread_stub* stub = reinterpret_cast <thread_stub*> (param);
    
    try
    {
      stub->m_handler ();
    }
    catch (...)
    {
    }
    
    delete stub;
//       _endthreadex ();
  }
  catch (...)
  {
  }

  return 0;
} // thread_proc

} // extern "C"

thread::thread ()
  : m_joinable (false)
{
  m_thread = reinterpret_cast<void*> (GetCurrentThread ());
  m_id     = GetCurrentThreadId ();
} // thread

thread::thread (const Handler& handler)
 : m_thread (NULL),
   m_id (0),
   m_joinable (true)
{
  thread_stub* stub = new thread_stub (handler);
  if (NULL != stub)
  {
    m_thread = reinterpret_cast<void*> (_beginthreadex (0, 0, &thread_proc, stub, 0, &m_id));
    if (NULL == m_thread)
      delete stub;
  }  

// if (NULL == m_thread)
//   throw thread_resource_error ();
} // thread

thread::~thread ()
{
  //join ();
  if (NULL != m_thread && true == m_joinable)
  {
    CloseHandle (reinterpret_cast<HANDLE> (m_thread));
    m_thread = NULL;
  }  
} // ~thread

void thread::join ()
{
  if (NULL != m_thread)
  {
    if (WAIT_OBJECT_0 == WaitForSingleObject (reinterpret_cast<HANDLE>(m_thread), INFINITE))
    {
      CloseHandle (reinterpret_cast<HANDLE> (m_thread));
      m_thread = NULL;
    }
  }
} // join

} // namespace commonlib