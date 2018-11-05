//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SQLITE_CONNECTION_FACTORY_H_
 #define _SQLITE_CONNECTION_FACTORY_H_
 
#include "iconnectionfactory.h"
#include "sqliteconnection.h"

#include "commonlib.h"

#include <list>
#include <map>
#include <string>

using namespace std;

namespace sql {

class SQLiteConnectionFactory;

class SQLiteConnectionFactory : public IConnectionFactory
{
  //
  // types
  //
  public:
   typedef IConnectionFactory::PtrToIConnection    PtrToIConnection;
   typedef IConnectionFactory::PtrToINode          PtrToINode;
   typedef boost::shared_ptr<SQLiteConnection>     PtrToSQLiteConnection;
   
  protected:
   typedef commonlib::SyncObject                   SyncObject;
   typedef commonlib::Locker                       Locker;
   
   struct ConnectionInfo
   {
     ConnectionInfo (const PtrToIConnection& connection)
      : m_busy (false),
        m_connection (connection)
     {
     }
     
     ConnectionInfo (const PtrToIConnection& connection, bool busy)
      : m_busy (busy),
        m_connection (connection)
     {
     }
      
     ConnectionInfo (const ConnectionInfo& right)
      : m_busy (right.m_busy),
        m_connection (right.m_connection)
     {
     }   
      
     ConnectionInfo& operator= (ConnectionInfo& right)
     {
       if (this != &right)
         ConnectionInfo (right).swap (*this);
        
       return *this;
     } // operator=

     void swap (ConnectionInfo& right)
     {
       bool             busy       = m_busy;
       PtrToIConnection connection = m_connection;

       m_busy             = right.m_busy;
       m_connection       = right.m_connection;

       right.m_busy       = busy;
       right.m_connection = connection;
     } // swap
      
     bool             m_busy;
     PtrToIConnection m_connection;
   }; // ConnectionInfo
   
   typedef list<ConnectionInfo>                    ConnectionList;
   typedef boost::shared_ptr<ConnectionList>       PtrToConnectionList;
   typedef map<const wstring, PtrToConnectionList> ConnectionPool;
   
  private:

  //
  // methods
  //
  public:
   explicit SQLiteConnectionFactory (const PtrToINode& node);
   explicit SQLiteConnectionFactory (bool usePool = true, int busyTimeout = 60*1000*60);
   virtual ~SQLiteConnectionFactory ();

   virtual  void             freeConnection (const wstring& connectString);                // throw (SQLException)

  protected:
   virtual  PtrToIConnection acquireConnection (const wstring& connectString);             // throw (SQLException)
   virtual  void             releaseConnection (const PtrToIConnection& connection);       // throw (SQLException)
   
            PtrToIConnection acquirePooledConnection (const wstring& connectString);       // throw (SQLException)
            void             releasePooledConnection (const PtrToIConnection& connection); // throw (SQLException)
  
            SQLiteConnectionFactory (const SQLiteConnectionFactory& right) : m_usePool (right.m_usePool) {};
   SQLiteConnectionFactory& operator= (const SQLiteConnectionFactory& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
   int                m_busyTimeout;
   ConnectionPool     m_connPool;
  
   const   bool       m_usePool;
   mutable SyncObject m_sync;
}; // SQLiteConnectionFactory

} // namespace sql {

#endif // _SQLITE_CONNECTION_FACTORY_H_