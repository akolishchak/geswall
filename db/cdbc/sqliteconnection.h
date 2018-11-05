//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SQLITE_CONNECTION_H_
 #define _SQLITE_CONNECTION_H_
 
#include "iconnection.h"
#include "istatement.h"

#include <boost/enable_shared_from_this.hpp>

#include "commonlib.h"

#include <string>
#include <list>
#include <sqlite3.h>

using namespace std;

namespace sql {

class SQLiteStatement;
class SQLiteConnection;

class SQLiteConnection : public IConnection, public boost::enable_shared_from_this<SQLiteConnection>
{
  friend class SQLiteStatement;
  //
  // types
  //
  public:
   typedef commonlib::SyncObject                   SyncObject;
   typedef commonlib::Locker                       Locker;
   typedef boost::shared_ptr<SQLiteStatement>      PtrToSQLiteStatement;
   //typedef boost::weak_ptr<SQLiteStatement>        WeakPtrToSQLiteStatement;
   //typedef list<PtrToSQLiteStatement>            OpenedStatements;
   typedef list<IStatement*>                       OpenedStatements;
   
  protected:
  private:

  //
  // methods
  //
  public:
   explicit SQLiteConnection (const wstring& dbfileName, int busyTimeout); // 60*1000*60
   virtual ~SQLiteConnection (); 

            void                    setDbFileName (const wstring& dbfileName);
            const wstring&          getDbFileName () const;
            
            void                    setBusyTimeout (int busyTimeout);
            int                     getBusyTimeout () const;

            void                    release ();                 // throw (SQLException)
            
   virtual  void                    connect ();                 // throw (SQLException)
   virtual  void                    closeConnection ();         // throw (SQLException)
   virtual  PtrToIStatement         createStatement ();         // throw (SQLException)
   virtual  PtrToIPreparedStatement createPreparedStatement (const wstring& sql); // throw (SQLException)
   
   virtual  void                    begin ();                   // throw (SQLException
   virtual  void                    commit ();                  // throw (SQLException
   virtual  void                    rollback ();                // throw (SQLException

  protected:
            SQLiteConnection ();
            SQLiteConnection (const SQLiteConnection& right) {};
   SQLiteConnection& operator= (const SQLiteConnection& right) { return *this; }
   
            SyncObject& getSync () { return m_sync; };
            sqlite3*    getNativeDB () { return m_db; };
            //void        closeStatementNotification (const PtrToIStatement& statement);
            void        closeStatementNotification (IStatement* statement);
            void        closeAllStatements ();      // throw (SQLException)
  private:
  
  //
  // data
  //
  public:
  protected:
   wstring          m_dbfileName;
   sqlite3*         m_db;
   int              m_busyTimeout;
   OpenedStatements m_statements;
   bool             m_transactionStarted;

  private:
   mutable SyncObject m_sync;
}; // SQLiteConnection

} // namespace sql {

#endif // _SQLITE_CONNECTION_H_