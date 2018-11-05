//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SQLITE_STATEMENT_H_
 #define _SQLITE_STATEMENT_H_
 
#include "ipreparedstatement.h"

#include <string>
#include <vector>

#include <boost/smart_ptr.hpp>  
#include <boost/enable_shared_from_this.hpp>

#include "commonlib.h"

using namespace std;

namespace sql {

class SQLiteConnection;

class SQLiteStatement : public IPreparedStatement, public boost::enable_shared_from_this<SQLiteStatement>
{
  friend class SQLiteResultSet;
  //
  // types
  //
  public:
   typedef commonlib::Locker                      Locker;

   typedef boost::shared_ptr<SQLiteConnection>    PtrToSQLiteConnection;
   typedef std::vector<sqlite3_stmt*>             NativeStatementArray;
   typedef boost::scoped_array<wchar_t>           CharArray;
   typedef SQLDate::DateT                         DateT;
    
  protected:
  private:

  //
  // methods
  //
  public:
   explicit SQLiteStatement (PtrToSQLiteConnection& connection);
            SQLiteStatement (PtrToSQLiteConnection& connection, const wstring& sql);
   virtual ~SQLiteStatement ();
        
   virtual  void             close ();                                // throw SQLException
   virtual  PtrToIConnection getConnection ();
   virtual  void             execute (const wstring& sql);            // throw SQLException
   virtual  PtrToIResultSet  executeQuery ();                         // throw SQLException
   virtual  void             execute ();                              // throw SQLException
   virtual  RowId            executeUpdate ();                        // throw (SQLException)
   virtual  void             setInt (int value, int index);           // throw SQLException
   virtual  void             setFloat (double value, int index);      // throw SQLException
   virtual  void             setText (const wstring& text, int index);// throw SQLException
   virtual  void             setBlob (const unsigned char* buffer, size_t bufSize, int index);   // throw SQLException
   virtual  void             setDate (const SQLDate& date, int index);// throw SQLException
   virtual  void             setNull (int index);                     // throw SQLException

  protected:
               SQLiteStatement (const SQLiteStatement& right) {};
   SQLiteStatement& operator= (const SQLiteStatement& right) { return *this; }
   
            void             setSql (const wstring& sql);             // throw (SQLException)
            const wstring&   getSql () const;
            
            void             prepareNativeStatement ();               // throw (SQLException)
            void             finalizeNativeStatement ();              // throw (SQLException)
            void             finalizeNativeStatement (sqlite3_stmt* nativeStatement); // throw (SQLException)
            void             resetNativeStatement ();                 // throw (SQLException)
            void             resetNativeStatement (sqlite3_stmt* nativeStatement);    // throw (SQLException)
            int              stepNativeStatement ();                  // throw (SQLException)
            int              stepNativeStatement (sqlite3_stmt* nativeStatement);     // throw (SQLException)
            void             prepareAndStepNativeStatement ();        // throw (SQLException)
            
            int              getColumnCount () const;                 // throw (SQLException)
            int              getColumnType (int index) const;         // throw (SQLException)
            const wchar_t*   getColumnName (int index) const;         // throw (SQLException)
            const wchar_t*   getColumnValue (int index) const;        // throw (SQLException)

  private:
   static   size_t           bin2hex (const unsigned char* bin, size_t binLength, wchar_t* str, size_t strLength);
  
  //
  // data
  //
  public:
  protected:
   PtrToSQLiteConnection m_connection;
   wstring               m_sql;
   NativeStatementArray  m_nativeStatementArray;
  private:
}; // SQLiteStatement

} // namespace sql 
 
#endif // _SQLITE_STATEMENT_H_
