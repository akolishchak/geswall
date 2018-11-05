//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_SMART_CLIENT_MANAGER_H_
 #define _GUICTRL_SMART_CLIENT_MANAGER_H_

#include "clientmanager.h"
#include "thread.h"
#include "commondefs.h"
#include "debug.h"

#include <boost/smart_ptr.hpp> 
#include <boost/detail/atomic_count.hpp>

using namespace std;

namespace gswserv {
namespace guictrl {

template <typename ClientType, 
          typename ClientIdType,
          bool isActive,
          template <class, class> class ClientManagerType>
class SmartClientManager;

template <typename ClientType, 
          typename ClientIdType,
          bool isActive = true,
          template <class, class> class ClientManagerType = ClientManager>
class SmartClientManager : public ClientManagerType<ClientType, ClientIdType>
{
  //
  // types
  //
  public:
   typedef ClientManagerType<ClientType, ClientIdType> ClientManager;
   typedef ClientType                                  Client;
   typedef ClientIdType                                ClientId;
   typedef boost::shared_ptr<Client>                   PtrToClient;
   typedef commonlib::SyncObject                       SyncObject;
   typedef boost::shared_ptr<commonlib::thread>        PtrToThread;
   typedef boost::detail::atomic_count                 atomic_count;
   typedef commonlib::Locker                           Locker;
   typedef commonlib::thread                           thread;
   typedef commonlib::sync::CancelException            CancelException;
   typedef commonlib::sync::TimeoutException           TimeoutException;
   

  protected:
   struct thread_stub
   {
     thread_stub (SmartClientManager& manager)
      : m_manager (manager)
     {
     }

     void operator() ()
     {
       m_manager.workThread ();
     } // operator ()

     SmartClientManager& m_manager;
   }; // thread_stub

   friend struct thread_stub;

  private:

  //
  // methods
  //
  public:
   SmartClientManager ()
    : ClientManager (),
      m_closeFlag (0)
   {
     createThread<isActive> ();
   } // SmartClientManager

   virtual ~SmartClientManager ()
   {
     destroyThread<isActive> ();
   } // ~SmartClientManager

   virtual void registerClient (const ClientId& clientId, const PtrToClient& client) // throw GUICtrlException
   {
     Locker lock (sync ());

     clearDaemons ();
     ClientManager::registerClient (clientId, client);
   } // registerClient

  protected:
   template<bool isActive>   
   inline void createThread ()
   {
   } // createThread

   template<>
   inline void createThread<true> ()
   {
     Locker locker (m_closeSync);

     if (NULL == m_thread.get ())
       m_thread = PtrToThread (new thread (thread_stub (*this)));
   } // createThread

   template<bool isActive>
   inline void destroyThread ()
   { 
   } // destroyThread

   template<>
   inline void destroyThread<true> ()
   {
     {
       Locker locker (m_closeSync);

       ++m_closeFlag;
       m_closeSync.cancel ();
     }

     if (NULL != m_thread.get ())
       m_thread->join ();
   } // destroyThread

   void workThread ()
   {
//commonlib::Debug::Write ("\nworkThread - start");
     while (0 == m_closeFlag)
     {
       try
       {
         Locker locker (m_closeSync);
         m_closeSync.wait (5000);
       }
       catch (CancelException&)
       {
         break;
       }
       catch (TimeoutException&) 
       {      
       }
       
//commonlib::Debug::Write ("\nworkThread - [0]");
       clearDaemons ();
     } // while (0 == m_closeFlag)
//commonlib::Debug::Write ("\nworkThread - end");
   } // workThread

   void clearDaemons ()
   {
     Locker lock (sync ());

     if (0 < size ())
     {
       for (iterator i = begin (); i != end (); ++i)
       {
         PtrToClient client = (*i).second;
//commonlib::Debug::Write ("\nclearDaemons - [0]");
         if (false == client->isAlive ())
         {
//commonlib::Debug::Write ("\nclearDaemons - [1]");
           erase (i);
           client->clear ();
           if (0 >= size ())
             break;
           i = begin ();
           continue;
         }  
       } // for ()
     } // if (0 < m_hashResolver.size ())
   } // clearDaemons

  private:
  
  //
  // data
  //
  public:
  protected:
   PtrToThread        m_thread;
   atomic_count       m_closeFlag;
   mutable SyncObject m_closeSync;

  private:
}; // SmartClientManager

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_SMART_CLIENT_MANAGER_H_
