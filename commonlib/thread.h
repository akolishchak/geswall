//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_thread_h_
 #define _commonlib_thread_h_

#include <boost/function.hpp>

namespace commonlib {

class thread
{
  public:
   typedef boost::function0<void>   Handler;

  public:
            thread ();
   explicit thread (const Handler& handler);
   ~thread ();

   void join ();

  protected:
  private:
   thread (const thread& right) {};
   thread& operator= (const thread& right) { return *this; }

  public:
  protected:
  private:
   void*        m_thread;
   unsigned int m_id;
   bool         m_joinable;
}; // thread

} // namespace commonlib

#endif // _commonlib_thread_h_