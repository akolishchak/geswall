//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "sqliteconnectionfactory.h"
#include "config/inode.h"

using namespace std;
using namespace sql;
using namespace config;

SQLiteConnectionFactory::SQLiteConnectionFactory (const PtrToINode& node)
 : IConnectionFactory (),
   m_usePool (node->getBool (wstring (L"usePool"))),
   m_busyTimeout (node->getInt (wstring (L"busyTimeout")))
{

} // SQLiteConnectionFactory

SQLiteConnectionFactory::SQLiteConnectionFactory (bool usePool, int busyTimeout) 
 : IConnectionFactory (),
   m_usePool (usePool),
   m_busyTimeout (busyTimeout)
{

} // SQLiteConnectionFactory

SQLiteConnectionFactory::~SQLiteConnectionFactory () 
{

} // ~SQLiteConnectionFactory

SQLiteConnectionFactory::PtrToIConnection SQLiteConnectionFactory::acquireConnection (const wstring& connectString) // throw (SQLException)
{
  if (false == m_usePool)
  {
    PtrToIConnection conn (new SQLiteConnection (connectString, m_busyTimeout));
  
    if (NULL == conn.get ())
      throw SQLException (L"SQLiteConnectionFactory::acquireConnection (): no memory");
    conn->connect ();  
    
    return conn;
  } // if (false == m_usePool)
  
  return acquirePooledConnection (connectString);
} // getConnection

void SQLiteConnectionFactory::releaseConnection (const PtrToIConnection& connection) // throw (SQLException)
{
  if (false == m_usePool)
  {
    if (NULL != connection.get ())
      connection->closeConnection ();
  }  
  else
  {
    releasePooledConnection (connection);
  }
} // releaseConnection

void SQLiteConnectionFactory::freeConnection (const wstring& connectString) // throw (SQLException)
{
  if (true == m_usePool)
  {
    Locker lock (m_sync);

    PtrToIConnection    connection;
    PtrToConnectionList list;
  
    ConnectionPool::iterator i = m_connPool.find (connectString);
    if (i != m_connPool.end ())
    {
      list = (*i).second;
      if (NULL == list.get ())  
        throw SQLException (L"SQLiteConnectionFactory::freeConnection (): no memory for connection list");

      list->clear ();
      m_connPool.erase (i);
    }
  } // if (true == m_usePool)
} // freeConnection

SQLiteConnectionFactory::PtrToIConnection SQLiteConnectionFactory::acquirePooledConnection (const wstring& connectString) // throw (SQLException)
{
  Locker lock (m_sync);
  
  PtrToIConnection    connection;
  PtrToConnectionList list;
  bool                newList = false;
  
  ConnectionPool::iterator i = m_connPool.find (connectString);
  if (true == (newList = (i == m_connPool.end ())))
    list = PtrToConnectionList (new ConnectionList ());
  else  
    list = (*i).second;
    
  if (NULL == list.get ())  
    throw SQLException (L"SQLiteConnectionFactory::acquirePooledConnection (): no memory for connection list");
    
  if (true == newList)  
    m_connPool [connectString] = list;

  for (ConnectionList::iterator i = list->begin (); i != list->end (); ++i)
  {
    ConnectionInfo& info = (*i);
    if (false == info.m_busy)
    {
      info.m_busy = true;
      connection = info.m_connection;
      PtrToSQLiteConnection sqliteConn (connection, boost::detail::static_cast_tag ());
      if (sqliteConn->getBusyTimeout () != m_busyTimeout)
        sqliteConn->setBusyTimeout (m_busyTimeout);
      break;
    }
  } // for (...)
  
  if (NULL == connection.get ())  
  {
    connection = PtrToIConnection (new SQLiteConnection (connectString, m_busyTimeout));
    if (NULL == connection.get ())  
      throw SQLException (L"SQLiteConnectionFactory::acquirePooledConnection (): no memory for new connection");
    connection->connect ();    
      
    list->push_back (ConnectionInfo (connection, true));
  }
  
  return connection;
} // acquirePooledConnection

void SQLiteConnectionFactory::releasePooledConnection (const PtrToIConnection& connection) // throw (SQLException)
{
  Locker lock (m_sync);
  
  if (NULL == connection.get ())  
    throw SQLException (L"SQLiteConnectionFactory::releasePooledConnection (): bad connection");
  
  PtrToSQLiteConnection sqliteConn (connection, boost::detail::static_cast_tag ());
  
  ConnectionPool::iterator i = m_connPool.find (sqliteConn->getDbFileName ());
  if (i != m_connPool.end ())
  {
    PtrToConnectionList list = (*i).second;
    for (ConnectionList::iterator i = list->begin (); i != list->end (); ++i)
    {
      ConnectionInfo& info = (*i);
      if (connection.get () == info.m_connection.get ())
      {
        info.m_busy = false;
        sqliteConn->release ();
        break;
      }
    } // for (...)
  }  
} // releasePooledConnection
