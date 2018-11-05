//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_CLIENT_MANAGER_H_
 #define _GUICTRL_CLIENT_MANAGER_H_

#include "guictrlexception.h"
#include "request.h"

#include "commonlib.h"

#include <map>

using namespace std;

namespace gswserv {
namespace guictrl {

template <typename ClientType, 
          typename ClientIdType>
class ClientManager;

template <typename ClientType, 
          typename ClientIdType>
class ClientManager
{
  //
  // types
  //
  public:
   typedef ClientType                        Client;
   typedef ClientIdType                      ClientId;
   typedef boost::shared_ptr<Client>         PtrToClient;
   typedef map<const ClientId, PtrToClient>  ClientResolver;
   typedef commonlib::SyncObject             SyncObject;
   typedef commonlib::Locker                 Locker;
   typedef typename ClientResolver::iterator iterator;
   typedef Request::PtrToRequest             PtrToRequest;
   

  protected:
  private:

  //
  // methods
  //
  public:
   ClientManager ()
   {
   } // ClientManager

   virtual ~ClientManager ()
   {
   } // ~ClientManager

   virtual void registerClient (const ClientId& clientId, const PtrToClient& client) // throw GUICtrlException
   {
     Locker lock (m_sync);

     ClientResolver::iterator i = m_resolver.find (clientId);
     if (i != m_resolver.end ())
       throw GUICtrlException (L"client already exist");

     m_resolver [clientId] = client;
   } // registerClient

   virtual PtrToClient unregisterClient (const ClientId& clientId) // throw GUICtrlException
   {
     Locker lock (m_sync);

     PtrToClient client;

     ClientResolver::iterator i = m_resolver.find (clientId);
     if (i != m_resolver.end ())
     {
       client = (*i).second;
       client->clear ();
       m_resolver.erase (clientId);
     }

     return client;
   } // unregisterClient
   
   virtual void unregisterAllClients ()
   {
     Locker lock (m_sync);
     
     if (0 < m_resolver.size ())
     {
       for (ClientResolver::iterator i = m_resolver.begin (); i != m_resolver.end (); ++i)
       {
         PtrToClient client = (*i).second;
         client->clear ();
         m_resolver.erase (i);
         if (0 == m_resolver.size ())
           break;
         i = m_resolver.begin ();  
       } // for ()
     } // if (0 < m_hashResolver.size ())
   } // unregisterAllClients

   virtual PtrToClient getClient (const ClientId& clientId) // throw GUICtrlException
   {
     Locker lock (m_sync);

     PtrToClient client;

     ClientResolver::iterator i = m_resolver.find (clientId);
     if (i != m_resolver.end ())
     {
       client = (*i).second;
       if (false == client->isAlive ())
       {
         m_resolver.erase (clientId);
         client->clear ();
         client.reset ();
       }
     }

     return client;
   } // getClient
         
   virtual void broadcastRequest (const PtrToRequest& request)
   {
     Locker lock (m_sync);

     if (0 < m_resolver.size ())
     {
       for (ClientResolver::iterator i = m_resolver.begin (); i != m_resolver.end (); ++i)
       {
         PtrToClient client = (*i).second;
         client->addRequest (request);
       } // for ()
     } // if (0 < m_hashResolver.size ())
   } // broadcastRequest

  protected:
   virtual size_t size ()
   {
     return m_resolver.size ();
   } // size

   virtual iterator begin ()
   {
     return m_resolver.begin ();
   } // begin
   
   virtual iterator end ()
   {
     return m_resolver.end ();
   } // end
   
   virtual void erase (iterator& i)
   {
     m_resolver.erase (i);
   } // erase
   
   virtual SyncObject& sync ()
   {
     return m_sync;
   } // sync
   
   
                  ClientManager (const ClientManager& right) {};
   ClientManager& operator= (const ClientManager& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
   ClientResolver     m_resolver;

  private:
   mutable SyncObject m_sync;
}; // ClientManager

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_CLIENT_MANAGER_H_
