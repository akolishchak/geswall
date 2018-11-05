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
#include "sqliteresultset.h"
#include "sqlexception.h"

#ifdef WIN32 
 #include <windows.h>
#endif // WIN32 

using namespace sql;
using namespace std;

SQLiteStatement::SQLiteStatement (PtrToSQLiteConnection& connection) 
 : m_connection (connection)
{
  if (!m_connection)
    throw SQLException (L"SQLiteStatement::SQLiteStatement (): invalid parameter - m_connection");
} // SQLiteStatement

SQLiteStatement::SQLiteStatement (PtrToSQLiteConnection& connection, const wstring& sql)
 : m_connection (connection),
   m_sql (sql)
{
  if (!m_connection)
    throw SQLException (L"SQLiteStatement::SQLiteStatement (): invalid parameter - m_connection");
    
  prepareNativeStatement ();
} // SQLiteStatement

SQLiteStatement::~SQLiteStatement () 
{
  try 
  {
    close ();
  }
  catch (...)
  {
  }
} // ~SQLiteStatement

void SQLiteStatement::close () // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  //m_connection->closeStatementNotification (shared_from_this ());
  m_connection->closeStatementNotification (this);
  
  finalizeNativeStatement ();
  m_sql.erase ();
} // close

void SQLiteStatement::setSql (const wstring& sql) // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  finalizeNativeStatement ();
  
  m_sql = sql;
  prepareNativeStatement ();
} // setSql

const wstring& SQLiteStatement::getSql () const
{
  return m_sql;
} // getSql

SQLiteStatement::PtrToIConnection SQLiteStatement::getConnection ()
{
  return m_connection;
} // getConnection

void  SQLiteStatement::execute (const wstring& sql) // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  setSql (sql);
  execute ();
  close ();
} // execute

SQLiteStatement::PtrToIResultSet SQLiteStatement::executeQuery () // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::executeQuery (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
  
  resetNativeStatement ();  
  //int result = stepNativeStatement (m_nativeStatementArray [0]);  
  //if (SQLITE_ROW != result)
  //  throw SQLException (L"SQLiteStatement::executeQuery (): no row selected");
    
  return PtrToIResultSet (new SQLiteResultSet (shared_from_this ()));
} // executeQuery

void  SQLiteStatement::execute () // throw SQLException
{
  Locker lock (m_connection->getSync ());
  //resetNativeStatement ();
  stepNativeStatement ();
  //prepareAndStepNativeStatement ();
} // execute

SQLiteStatement::RowId SQLiteStatement::executeUpdate () // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  RowId rowId = 0;
  if (SQLITE_DONE == stepNativeStatement ())
    rowId = sqlite3_last_insert_rowid (m_connection->getNativeDB ());
  
  return rowId;
} // executeUpdate

void  SQLiteStatement::setInt (int value, int index) // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::setInt (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
  
  int result = sqlite3_bind_int (m_nativeStatementArray [0], index, value);
  if (SQLITE_OK != result)
    throw SQLException (wstring (L"SQLiteStatement::setInt (): error sqlite3_bind_int () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ()))), result);
} // setInt

void  SQLiteStatement::setFloat (double value, int index) // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::setFloat (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
  
  int result = sqlite3_bind_double (m_nativeStatementArray [0], index, value);
  if (SQLITE_OK != result)
    throw SQLException (wstring (L"SQLiteStatement::setFloat (): error sqlite3_bind_double () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ()))), result);
} // setFloat

void  SQLiteStatement::setText (const wstring& text, int index) // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::setText (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
  
  int result = sqlite3_bind_text16 (m_nativeStatementArray [0], index, text.c_str (), static_cast <int> (text.size () * sizeof (wstring::value_type)), SQLITE_TRANSIENT);
  if (SQLITE_OK != result)
    throw SQLException (wstring (L"SQLiteStatement::setText (): error sqlite3_bind_text () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ()))), result);
} // setText

void SQLiteStatement::setDate (const SQLDate& date, int index) // throw SQLException
{
 #ifdef WIN32 
  ULARGE_INTEGER time;
  FILETIME       fileTime;
  SYSTEMTIME     sysTime;
  wchar_t        sysDate [32];
  
  time.QuadPart = date.getDate ();
  
  fileTime.dwHighDateTime = time.HighPart;
  fileTime.dwLowDateTime  = time.LowPart;
  
  FileTimeToSystemTime (&fileTime, &sysTime);
  
  swprintf (sysDate, L"%04d-%02d-%02d", sysTime.wYear, sysTime.wMonth, sysTime.wDay);
    
  setText (wstring (sysDate), index);
 #else
  #error this hardware platform not supported yet
 #endif // WIN32 
} // setDate

void SQLiteStatement::setBlob (const unsigned char* buffer, size_t bufSize, int index) // throw (SQLException)
{
  if (NULL == buffer || 0 >= bufSize)
  {
    setNull (index);
    return;
  }

  size_t    arraySize = 2*bufSize+1;
  CharArray charArray (new wchar_t[arraySize]); 
  if (NULL == charArray.get ())
    throw SQLException (L"SQLiteStatement::setBlob (): no memory for charArray");
  
  size_t result = bin2hex (buffer, bufSize, charArray.get (), arraySize);
  if (0 > result)  
    throw SQLException (L"SQLiteStatement::setBlob (): error blob conversion");
  
  setText (wstring (charArray.get (), static_cast <size_t> (result)), index);
} // setBlob

void  SQLiteStatement::setNull (int index) // throw (SQLException)
{
  Locker lock (m_connection->getSync ());
  
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::setNull (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
  
  int result = sqlite3_bind_null (m_nativeStatementArray [0], index);
  if (SQLITE_OK != result)
    throw SQLException (wstring (L"SQLiteStatement::setNull (): error sqlite3_bind_null () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ()))), result);
} // setNull

//
// protected methods NOT SYNC
//

void SQLiteStatement::prepareNativeStatement () // throw (SQLException)
{
  if (0 >= m_sql.size ())
    throw SQLException (L"SQLiteStatement::prepareNativeStatement (): 0 >= m_sql.size ()");
  
  size_t         size    = m_sql.size ();
  const wchar_t* pzBegin = m_sql.c_str ();    
  const wchar_t* pzEnd   = pzBegin + size;
  const wchar_t* pzTail  = NULL;  
  
  while (pzBegin < pzEnd)
  {
    sqlite3_stmt* nativeStatement = NULL;
    int result = sqlite3_prepare16 (m_connection->getNativeDB (), pzBegin, static_cast <int> (size * sizeof (wchar_t)), &nativeStatement, reinterpret_cast <const void**> (&pzTail));
    if (SQLITE_OK != result || NULL == nativeStatement)
    {
      wstring errMsg (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ())));
      finalizeNativeStatement ();
      throw SQLException (wstring (L"SQLiteStatement::prepareNativeStatement (): error sqlite3_prepare () - ") + wstring (pzBegin, size) + wstring (L", ") + errMsg, result);  
    }  
      
    size    = pzEnd - pzTail;
    pzBegin = pzTail;    
    m_nativeStatementArray.push_back (nativeStatement);
  } // while (pzBegin < pzEnd)
} // prepareNativeStatement

void SQLiteStatement::finalizeNativeStatement () // throw (SQLException)
{
  size_t size = m_nativeStatementArray.size ();
  
  if (0 < size)
  {
    for (size_t i=0; i<size; ++i)  
    {
      if (NULL != m_nativeStatementArray [i])
        finalizeNativeStatement (m_nativeStatementArray [i]);
      m_nativeStatementArray [i] = NULL;
    }  
    
    m_nativeStatementArray.clear ();
  }
} // finalizeNativeStatement

void SQLiteStatement::finalizeNativeStatement (sqlite3_stmt* nativeStatement) // throw (SQLException)
{
  if (NULL == nativeStatement)
    throw SQLException (L"SQLiteStatement::finalizeNativeStatement (): NULL == nativeStatement");
    
  int result = sqlite3_finalize (nativeStatement);
  if (SQLITE_OK != result)
    throw SQLException (wstring (L"SQLiteStatement::finalizeNativeStatement (): error sqlite3_finalize () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ()))), result);
} // finalizeNativeStatement

void SQLiteStatement::resetNativeStatement () // throw (SQLException)
{
  size_t size = m_nativeStatementArray.size ();
  
  if (0 >= size)
    throw SQLException (L"SQLiteStatement::resetNativeStatement (): 0 >= m_nativeStatementArray.size ()");
    
  for (size_t i=0; i<size; ++i)  
  {
    resetNativeStatement (m_nativeStatementArray [i]);
  } // for (...)  
} // resetNativeStatement

void SQLiteStatement::resetNativeStatement (sqlite3_stmt* nativeStatement) // throw (SQLException)
{
  if (NULL == nativeStatement)
    throw SQLException (L"SQLiteStatement::resetNativeStatement (): NULL == nativeStatement");
    
  int result = sqlite3_reset (nativeStatement);
  if (SQLITE_OK != result)
    throw SQLException (wstring (L"SQLiteStatement::resetNativeStatement (): error sqlite3_reset () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ()))), result);
} // resetNativeStatement


int SQLiteStatement::stepNativeStatement () // throw (SQLException)
{
  size_t size = m_nativeStatementArray.size ();
  
  if (0 >= size)
    throw SQLException (L"SQLiteStatement::stepNativeStatement (): 0 >= m_nativeStatementArray.size ()");
  
  int result = SQLITE_DONE;
  
  for (size_t i =0; i<size; ++i)  
  {
    if (NULL != m_nativeStatementArray [i])
    {
      result = stepNativeStatement (m_nativeStatementArray [i]);
      //finalizeNativeStatement (m_nativeStatementArray [i]);  
    }
  } // for (...)
  
  return result;
} // stepNativeStatement

int SQLiteStatement::stepNativeStatement (sqlite3_stmt* nativeStatement) // throw (SQLException)
{
  if (NULL == nativeStatement)
    throw SQLException (L"SQLiteStatement::stepNativeStatement (): NULL == nativeStatement");
  
  int result = sqlite3_step (nativeStatement);
  if (SQLITE_DONE != result && SQLITE_ROW != result)
    throw SQLException (wstring (L"SQLiteStatement::stepNativeStatement (...): error sqlite3_step () - ") + wstring (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ()))), result);    
    
  if (SQLITE_DONE == result)  
    resetNativeStatement (nativeStatement);
    
  return result;  
} // stepNativeStatement

void SQLiteStatement::prepareAndStepNativeStatement () // throw (SQLException)
{
  if (0 >= m_sql.size ())
    throw SQLException (L"SQLiteStatement::prepareNativeStatement (): 0 >= m_sql.size ()");
  
  size_t         size    = m_sql.size ();
  const wchar_t* pzBegin = m_sql.c_str ();    
  const wchar_t* pzEnd   = pzBegin + size;
  const wchar_t* pzTail  = NULL;  
  
  while (pzBegin < pzEnd)
  {
    sqlite3_stmt* nativeStatement = NULL;
    int result = sqlite3_prepare16 (m_connection->getNativeDB (), pzBegin, static_cast <int> (size * sizeof (wchar_t)), &nativeStatement, reinterpret_cast <const void**> (&pzTail));
    if (SQLITE_OK != result || NULL == nativeStatement)
    {
      wstring errMsg (reinterpret_cast <const wchar_t*> (sqlite3_errmsg16 (m_connection->getNativeDB ())));
      finalizeNativeStatement ();
      throw SQLException (wstring (L"SQLiteStatement::prepareNativeStatement (): error sqlite3_prepare ()") + errMsg, result);  
    }
    
    stepNativeStatement (nativeStatement);  
    finalizeNativeStatement (nativeStatement);
      
    size    = pzEnd - pzTail;
    pzBegin = pzTail;    
  } // while (pzBegin < pzEnd)
} // prepareNativeStatement


int SQLiteStatement::getColumnCount () const // throw (SQLException)
{
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::getColumnCount (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
    
  sqlite3_stmt* nativeStatement = m_nativeStatementArray [0];
  if (NULL == nativeStatement)
    throw SQLException (L"SQLiteStatement::getColumnCount (): NULL == nativeStatement");
  
  int result = sqlite3_column_count (nativeStatement);
  
  if (0 >= result)
    throw SQLException (L"SQLiteStatement::getColumnCount (): 0 >= sqlite3_column_count ()");
  
  return result;
} // getColumnCount

int SQLiteStatement::getColumnType (int index) const // throw (SQLException)
{
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::getColumnType (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
    
  sqlite3_stmt* nativeStatement = m_nativeStatementArray [0];
  if (NULL == nativeStatement)
    throw SQLException (L"SQLiteStatement::getColumnType (): NULL == nativeStatement");
    
  int result = sqlite3_column_type (nativeStatement, index);
  
  if (SQLITE_INTEGER > result || SQLITE_NULL < result)
    throw SQLException (L"SQLiteStatement::getColumnType (): sqlite3_column_type () - bad type");
  
  return result;  
} // getColumnType

const wchar_t* SQLiteStatement::getColumnName (int index) const // throw (SQLException)
{
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::getColumnName (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
    
  sqlite3_stmt* nativeStatement = m_nativeStatementArray [0];
  if (NULL == nativeStatement)
    throw SQLException (L"SQLiteStatement::getColumnName (): NULL == nativeStatement");
    
  const wchar_t* result = reinterpret_cast <const wchar_t*> (sqlite3_column_name16 (nativeStatement, index));
  
  if (NULL == result)
    throw SQLException (L"SQLiteStatement::getColumnName (): NULL == sqlite3_column_name ()");
  
  return result;  
} // getColumnName

const wchar_t* SQLiteStatement::getColumnValue (int index) const // throw (SQLException)
{
  size_t size = m_nativeStatementArray.size ();
  if (0 >= size || 1 < size)
    throw SQLException (L"SQLiteStatement::getColumnValue (): 0 >= m_nativeStatementArray.size () or 1 < m_nativeStatementArray.size ()");
    
  sqlite3_stmt* nativeStatement = m_nativeStatementArray [0];
  if (NULL == nativeStatement)
    throw SQLException (L"SQLiteStatement::getColumnValue (): NULL == nativeStatement");
    
  const wchar_t* result = reinterpret_cast <const wchar_t*> (sqlite3_column_text16 (nativeStatement, index));
  
  //if (NULL == result)
  //  throw SQLException (L"SQLiteStatement::getColumnValue (): NULL == sqlite3_column_text ()");
  
  return result;  
} // getColumnValue

size_t SQLiteStatement::bin2hex (const unsigned char* bin, size_t binLength, wchar_t* str, size_t strLength) 
{ 
  if (strLength < (binLength*2+1)) 
    return -1; 

  static wchar_t hexMap[] = {
                              L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', 
                              L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F'
                            }; 
  wchar_t* p = str; 
  
  for (size_t i=0; i < binLength; ++i)  
  { 
    *p++ = hexMap[*bin >> 4];  
    *p++ = hexMap[*bin & 0xf]; 
    ++bin;
  } 
  *p = 0; 

  return p - str; 
} // bin2hex
