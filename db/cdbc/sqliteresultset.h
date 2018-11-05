//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SQLITE_RESULT_SET_H_
 #define _SQLITE_RESULT_SET_H_
 
#include "sqldate.h" 
#include "sqlexception.h"
#include "iresultset.h"
#include "sqlitestatement.h"

#include <string>
#include <boost/smart_ptr.hpp>  

using namespace std;

namespace sql {

class SQLiteResultSet;

class SQLiteResultSet : public IResultSet
{
  //
  // types
  //
  public:
   typedef boost::shared_ptr<SQLiteStatement>    PtrToSQLiteStatement;
   typedef boost::scoped_array<int>              ColumnTypeArray;
   typedef boost::shared_ptr<wstring>            PtrToString;
   typedef boost::scoped_array<PtrToString>      ColumnNameArray;
   typedef boost::scoped_array<PtrToString>      ColumnValueArray;

  protected:
  private:

  //
  // methods
  //
  public:
            SQLiteResultSet (PtrToSQLiteStatement& statement);
   virtual ~SQLiteResultSet ();
   
   virtual  bool      next ();                   // throw (SQLException)
                                               
   virtual  int       getColumnCount ();         // throw (SQLException)
   virtual  int       getColumnIndex (const wstring& name); // throw (SQLException)
   virtual  int       getColumnType (int index); // throw (SQLException)
   
   virtual  int       getInt (int index);        // throw (SQLException)
   virtual  double    getFloat (int index);      // throw (SQLException)
   virtual  wstring   getText (int index);       // throw (SQLException)
   virtual  SQLDate   getDate (int index);       // throw (SQLException)
   virtual  size_t    getBlob (int index, unsigned char* buffer, size_t bufSize); // throw (SQLException)

  protected:
            SQLiteResultSet (const SQLiteResultSet& right) : m_columnCount (0) {};
   SQLiteResultSet& operator= (const SQLiteResultSet& right) { return *this; }
           
            void      queryValues ();            // throw (SQLException)

  private:
   static   size_t           hex2bin (const wchar_t* str, size_t strLength, unsigned char* bin, size_t binLength);
    
  //
  // data
  //
  public:
  protected:
   PtrToSQLiteStatement  m_statement;
   const int             m_columnCount;
   ColumnTypeArray       m_columnTypes;
   ColumnNameArray       m_columnNames;
   ColumnValueArray      m_columnValues;
   bool                  m_firstNext;
   bool                  m_firstNextResult;

  private:
}; // SQLiteResultSet

} // namespace sql {

#endif // _SQLITE_RESULT_SET_H_