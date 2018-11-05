//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "sqliteconnection.h"
#include "sqlitestatement.h"

using namespace std;
using namespace sql;

SQLiteConnection::SQLiteConnection () 
 : IConnection (),
   m_db (NULL),
   m_busyTimeout (60*1000*60),
   m_transactionStarted (false)
{

} // SQLiteConnection

SQLiteConnection::SQLiteConnection (const wstring& dbfileName, int busyTimeout) 
 : IConnection (), 
   m_dbfileName (dbfileName),
   m_db (NULL),
   m_busyTimeout (busyTimeout),
   m_transactionStarted (false)
{

} // SQLiteConnection

SQLiteConnection::~SQLiteConnection () 
{
  Locker lock (m_sync);
  
  try
  {
    closeConnection ();
  }
  catch (...)
  {
  }
} // ~SQLiteConnection

void SQLiteConnection::setDbFileName (const wstring& dbfileName)
{
  Locker lock (m_sync);
  m_dbfileName = dbfileName;
} // setDbFileName

const wstring& SQLiteConnection::getDbFileName () const
{
  return m_dbfileName;
} // getDbFileName

void SQLiteConnection::setBusyTimeout (int busyTimeout)
{
  Locker lock (m_sync);
  m_busyTimeout = busyTimeout;
  if (NULL != m_db)
    sqlite3_busy_timeout (m_db, m_busyTimeout);
} // setBusyTimeout

int SQLiteConnection::getBusyTimeout () const
{
  return m_busyTimeout;
} // getBusyTimeout

void SQLiteConnection::release () // throw (SQLException)
{
  Locker lock (m_sync);

  if (true == m_transactionStarted)
    rollback ();
  else
    closeAllStatements ();
} // release

void xTrace(void*context,const char*sqlstr)
{
	static FILE *f = NULL;
	if ( f == NULL ) f = fopen("c:\\it\\sqlite.log", "w+");
	fprintf(f, "%s\n", sqlstr);
}

void SQLiteConnection::connect () // throw (SQLException)
{
  Locker lock (m_sync);
  
  if (true == m_dbfileName.empty ())
    throw SQLException (L"SQLiteConnection::connect (): m_dbfileName.empty ()");
  
  int result = sqlite3_open16 (m_dbfileName.c_str (), &m_db);
  if (SQLITE_OK != result || NULL == m_db)
    throw SQLException (L"SQLiteConnection::connect (): error sqlite3_open ()", result);
    
  sqlite3_busy_timeout (m_db, m_busyTimeout);
  //sqlite3_trace(m_db, xTrace, NULL);
} // connect

void SQLiteConnection::closeConnection () // throw (SQLException)
{
  Locker lock (m_sync);
  
  closeAllStatements ();
    
  if (NULL != m_db)
  {
    int result = sqlite3_close (m_db); 
    if (SQLITE_OK != result)
      throw SQLException (wstring (L"SQLiteConnection::closeConnection (): error sqlite3_close () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_db))), result);
  }
  
  m_db = NULL;  
} // closeConnection

SQLiteConnection::PtrToIStatement SQLiteConnection::createStatement () // throw (SQLException)
{
  Locker lock (m_sync);
  
  if (NULL == m_db)
    throw SQLException (L"SQLiteConnection::createStatement: error NULL == m_db");
   
  PtrToIStatement statement (new SQLiteStatement (shared_from_this ()));  
  if (NULL == statement.get ())
    throw SQLException (L"SQLiteConnection::createStatement (): no memory");
    
  m_statements.push_back (statement.get ());  
  
  return statement;
} // createStatement

SQLiteConnection::PtrToIPreparedStatement SQLiteConnection::createPreparedStatement (const wstring& sql) // throw (SQLException)
{
  Locker lock (m_sync);
  
  if (NULL == m_db)
    throw SQLException (L"SQLiteConnection::createPreparedStatement: error NULL == m_db");

  PtrToIPreparedStatement statement (new SQLiteStatement (shared_from_this (), sql));
  if (NULL == statement.get ())
    throw SQLException (L"SQLiteConnection::createPreparedStatement (): no memory");
      
  m_statements.push_back (statement.get ());  
  
  return statement;
} // createPreparedStatement

void SQLiteConnection::begin () // throw (SQLException
{
  Locker lock (m_sync);
  
  if (NULL == m_db)
    throw SQLException (L"SQLiteConnection::begin: error NULL == m_db");
  
  PtrToIStatement stmt = createStatement ();
  stmt->execute (wstring (L"begin;"));   
  m_transactionStarted = true;
} // begin

void SQLiteConnection::commit () // throw (SQLException
{
  Locker lock (m_sync);
  
  if (NULL == m_db)
    throw SQLException (L"SQLiteConnection::commit: error NULL == m_db");
  
  closeAllStatements ();
  
  PtrToIStatement stmt = createStatement ();
  stmt->execute (wstring (L"commit;"));   
  m_transactionStarted = false;
} // commit

void SQLiteConnection::rollback () // throw (SQLException
{
  Locker lock (m_sync);
  
  if (NULL == m_db)
    throw SQLException (L"SQLiteConnection::rollback: error NULL == m_db");
    
  closeAllStatements ();  
    
  PtrToIStatement stmt = createStatement ();
  stmt->execute (wstring (L"rollback;"));     
  m_transactionStarted = false;
} // rollback

//void SQLiteConnection::closeStatementNotification (const PtrToIStatement& statement)
void SQLiteConnection::closeStatementNotification (IStatement* statement)
{
  Locker lock (m_sync);
  //m_statements.remove (statement.get ());
  m_statements.remove (statement);
} // closeStatementNotification

void SQLiteConnection::closeAllStatements () // throw (SQLException)
{
  Locker lock (m_sync);
  
  while (false == m_statements.empty ())
  {
    //PtrToIStatement statement = m_statements.front ();
    IStatement* statement = m_statements.front ();
    statement->close ();
    //m_statements.pop_front ();
  } // while
} // closeAllStatements
