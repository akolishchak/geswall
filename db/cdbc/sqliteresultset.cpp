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

#include <stdlib.h>

#ifdef WIN32 
 #include <windows.h>
#endif // WIN32 

using namespace sql;
using namespace std;


SQLiteResultSet::SQLiteResultSet (PtrToSQLiteStatement& statement)
 : m_statement (statement),
   m_columnCount (m_statement->getColumnCount ()),
   m_columnTypes (new int [m_columnCount]),
   m_columnNames (new PtrToString [m_columnCount]),
   m_columnValues (new PtrToString [m_columnCount]),
   m_firstNext (true)
{
  if (
         0 == m_columnCount 
      || NULL == m_columnTypes.get () 
      || NULL == m_columnNames.get () 
      || NULL == m_columnValues.get ()
     )
    throw SQLException (L"SQLiteResultSet::SQLiteResultSet (): 0 == m_columnCount");
} // SQLiteResultSet

SQLiteResultSet::~SQLiteResultSet ()
{

} // ~SQLiteResultSet

bool SQLiteResultSet::next () // throw (SQLException)
{
  bool result = (SQLITE_ROW == m_statement->stepNativeStatement ());
  
  if (true == result)
  {
    if (true == m_firstNext)
    {
      m_firstNext = false;
      for (int i=0; i<m_columnCount; ++i)  
      {
        m_columnTypes[i] = m_statement->getColumnType (i);
        m_columnNames[i] = PtrToString (new wstring (m_statement->getColumnName (i)));
      }
    }
    queryValues ();
  } // if (true == result)
    
  return result;
} // next

int SQLiteResultSet::getColumnCount () // throw (SQLException)
{
  return m_columnCount;
} // getColumnCount

int SQLiteResultSet::getColumnIndex (const wstring& name) // throw (SQLException)
{
  int result = -1;
  
  for (int i=0; i<m_columnCount && result < 0; ++i)  
  {
    if (NULL != m_columnNames[i].get () && 0 == name.compare (*(m_columnNames[i])))
      result = i;
  }
  
  return result;
} // getColumnIndex

int SQLiteResultSet::getColumnType (int index)
{
  if (m_columnCount <= index || 0 > index)
    throw SQLException (L"SQLiteResultSet::getColumnType (): m_columnCount <= index || 0 > index");
    
  return m_columnTypes[index];  
} // getColumnType
   
int SQLiteResultSet::getInt (int index) // throw (SQLException)
{
  if (m_columnCount <= index || 0 > index)
    throw SQLException (L"SQLiteResultSet::getInt (): m_columnCount <= index || 0 > index");
    
  //if (SQLITE_INTEGER != m_columnTypes[index])
  //  throw SQLException (L"SQLiteResultSet::getInt (): SQLITE_INTEGER != columnType");
    
  return _wtoi (m_columnValues[index]->c_str ());  
} // getInt

double SQLiteResultSet::getFloat (int index) // throw (SQLException)
{
  if (m_columnCount <= index || 0 > index)
    throw SQLException (L"SQLiteResultSet::getFloat (): m_columnCount <= index || 0 > index");
    
  if (SQLITE_FLOAT != m_columnTypes[index])
    throw SQLException (L"SQLiteResultSet::getFloat (): SQLITE_FLOAT != columnType");  
    
  return _wtof (m_columnValues[index]->c_str ());
} // getFloat

wstring SQLiteResultSet::getText (int index) // throw (SQLException)
{
  if (m_columnCount <= index || 0 > index)
    throw SQLException (L"SQLiteResultSet::getText (): m_columnCount <= index || 0 > index");
  
  return *(m_columnValues[index]); 
} // getText

size_t SQLiteResultSet::getBlob (int index, unsigned char* buffer, size_t bufSize) // throw (SQLException)
{
  if (m_columnCount <= index || 0 > index)
    throw SQLException (L"SQLiteResultSet::getBlob (): m_columnCount <= index || 0 > index");
    
  //if (SQLITE_BLOB != m_columnTypes[index] && SQLITE_TEXT != m_columnTypes[index])
  //  throw SQLException (L"SQLiteResultSet::getBlob (): SQLITE_BLOB (SQLITE_TEXT) != columnType");    
    
  size_t result = hex2bin (m_columnValues[index]->c_str (), m_columnValues[index]->size (), buffer, bufSize) ;
  if (0 > result)  
    throw SQLException (L"SQLiteResultSet::getBlob (): error blob conversion");
    
  return result;  
} // getBlob

SQLDate SQLiteResultSet::getDate (int index) // throw (SQLException)
{
  wstring date = *(m_columnValues[index]);
  if (10 > date.size ()) // "yyyy-mm-dd"
    return SQLDate ();
  
 #ifdef WIN32 
  ULARGE_INTEGER time;
  FILETIME       fileTime;
  SYSTEMTIME     sysTime;
  
  int year  = 0;
  int month = 0;
  int day   = 0;
  swscanf (date.c_str (), L"%04d-%02d-%02d", &year, &month, &day);
  
  memset (&sysTime, 0, sizeof (sysTime));
  sysTime.wDay   = day;
  sysTime.wMonth = month;
  sysTime.wYear  = year;
  
  if (TRUE == SystemTimeToFileTime (&sysTime, &fileTime))
  {
    time.HighPart = fileTime.dwHighDateTime;
    time.LowPart  = fileTime.dwLowDateTime;
    return SQLDate (time.QuadPart);
  }
 #else
  #error this hardware platform not supported yet
 #endif // WIN32 
 
  return SQLDate ();
} // getDate

void SQLiteResultSet::queryValues () // throw (SQLException)
{
  for (int i=0; i<m_columnCount; ++i)  
  {
    const wchar_t* value = m_statement->getColumnValue (i);
    if (NULL == value)
      m_columnValues[i] = PtrToString (new wstring ()); //(reinterpret_cast <wstring*> (NULL));
    else  
      m_columnValues[i] = PtrToString (new wstring (value));
  }
} // queryValues

size_t SQLiteResultSet::hex2bin (const wchar_t* str, size_t strLength, unsigned char* bin, size_t binLength) 
{ 
  if (binLength < (strLength/2)) 
    return -1; 

  static unsigned char hexMap[] = 
                         {
                           0, 1,  2,  3,  4,  5,  6,  7, 
                           8, 9, 10, 11, 12, 13, 14, 15
                         }; 
  unsigned char*   p = bin; 
  wchar_t sym;
  
  for (size_t i=0; i < strLength; ++i)  
  { 
    sym = 0;
    if (L'0' <= *str && L'9' >= *str)
    {
      sym = hexMap [*str - L'0'];
    }
    else
    {
      if (L'a' <= *str && L'f' >= *str)
      {
        sym = hexMap [*str - 'a' + 10];
      }
      else
      {
        if (L'A' <= *str && L'F' >= *str)
          sym = hexMap [*str - 'A' + 10];
      }
    }
    
    if (!(i & 1))
    {
      *p = sym << 4;
    }  
    else
    {  
      *p += sym;
      ++p;
    }  
    
    ++str;
  } 

  return p - bin; 
} // bin2hex