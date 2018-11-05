//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_CLIENT_H_
 #define _GUICTRL_CLIENT_H_

#include <boost/smart_ptr.hpp> 
#include <boost/detail/atomic_count.hpp>

#include "syncobject.h"

#include <string>
#include <list>

#include "request.h"

namespace gswserv {
namespace guictrl {

class Client;

class Client
{
  //
  // types
  //
  public:
   enum Const
   {
     infiniteTimeout = -1
   };
   
  protected:
   typedef boost::shared_ptr<Request>            PtrToRequest;
   typedef commonlib::sync::CancelException      CancelException;
   typedef commonlib::sync::TimeoutException     TimeoutException;
   typedef commonlib::sync::SyncObject           SyncObject;
   typedef commonlib::sync::SyncObject::Locker   Locker;
   typedef std::list<PtrToRequest>               RequestQueue;
   typedef std::wstring                          wstring;
   typedef boost::detail::atomic_count           atomic_count;

   struct counter_holder
   {
     counter_holder (atomic_count& counter)
      : m_counter (counter)
     {
       ++m_counter;
     }

     ~counter_holder ()
     {
       --m_counter;
     }

     atomic_count& m_counter;
   }; // counter_holder
   
  private:

  //
  // methods
  //
  public:
   Client (const wstring& authorityHash)
    : m_authorityHash (authorityHash),
      m_waitRequestPendingCount (0)
   {

   } // Client

   virtual ~Client ()
   {
     cancelWait ();
   } // ~Client

   virtual void addRequest (const PtrToRequest& request)
   {
     Locker locker (m_sync);

     if (NULL != request.get ())
     {
       m_requestQueue.push_back (request);
       m_sync.notifyAll ();
     }
   } // addRequest
   
   virtual PtrToRequest delRequest (int id)
   {
     Locker locker (m_sync);

     return getRequestInternal (id);
   } // delRequest

   virtual PtrToRequest waitRequest (int timeout)
   {
     return waitRequest (-1, timeout);
   } // waitRequest

   virtual PtrToRequest waitRequest (int id, int timeout)
   {
     counter_holder ch (m_waitRequestPendingCount);
     Locker         locker (m_sync);

     PtrToRequest result;

     try
     {
       while (NULL == result.get ())
       {
         result = getRequestInternal (id);
         if (NULL == result.get ())
           m_sync.wait (timeout);
       }
     }
     catch (CancelException&)
     {
     }
     catch (TimeoutException&) 
     {      
     }
     
     return result;
   } // waitRequest

   virtual void cancelWait ()
   {
     Locker locker (m_sync);

     m_sync.cancelAll ();
   } // cancelWait
   
//   virtual void clear ()
//   {
//   
//   } // clear
   
//   virtual bool isAlive ()
//   {
//     return true;
//   } // isAlive

   virtual int compareAuthorityHash (const wstring& authorityHash) const 
   {
     return authorityHash.compare (m_authorityHash);
   } // compareAuthorityHash

  protected:
   Client (const Client& right) 
    : m_authorityHash (right.m_authorityHash),
      m_waitRequestPendingCount (0)
   {
   } // Client

   Client& operator= (const Client& right) 
   { 
     if (this != &right)
       Client (right).swap (*this);
     
     return *this; 
   } // operator=

   void swap (Client& right)
   {
     wstring authHash      = m_authorityHash;

     m_authorityHash       = right.m_authorityHash;

     right.m_authorityHash = authHash;
   } // swap
   
   PtrToRequest getRequestInternal (int id)
   {
     PtrToRequest result;

     if (0 < m_requestQueue.size ())
     {
       if (0 > id)
       {
         result = m_requestQueue.front ();
         m_requestQueue.pop_front ();
       }
       else
       {
         for (RequestQueue::iterator i = m_requestQueue.begin (); i != m_requestQueue.end (); ++i)
         {
           if (id == (*i)->getId ())
           {
             result = (*i);
             m_requestQueue.remove (result);
             break;
           }
         }
       }
     } // if (0 < m_requestQueue.size ())

     return result;
   } // getRequestInternal

  private:

  //
  // data
  //
  public:
  protected:
   RequestQueue        m_requestQueue;
   wstring             m_authorityHash;
   atomic_count        m_waitRequestPendingCount;

  private:
   mutable SyncObject  m_sync;
}; // Client

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_CLIENT_H_
