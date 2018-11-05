//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <conio.h>
#include <new.h>

#include "sqlexception.h"
#include "iconnection.h"
#include "sqliteconnection.h"
#include "sqlitestatement.h"
#include "sqliteresultset.h"

#include <string>

using namespace sql;
using namespace std;

int main (int nCountArg, char *lpszArg[], char *lpszEnv[])
{
  //
  // sql tests
  //
  
  try
  {
    static unsigned char hexMap[] = 
                         {
                           0, 1,  2,  3,  4,  5,  6,  7, 
                           8, 9, 10, 11, 12, 13, 14, 15
                         }; 
                         
    static unsigned char resultHexMap[16];                      
                         
    SQLiteConnection::PtrToIConnection ptrConn (new SQLiteConnection (wstring (L"test.db")));
    
    ptrConn->connect ();
    
    SQLiteConnection::PtrToIStatement         stmt      = ptrConn->createStatement ();
    stmt->execute (wstring (L"begin;")); 
    
    SQLiteConnection::PtrToIPreparedStatement prep_stmt = ptrConn->createPreparedStatement (wstring (L"insert into test values (1, 2, ?, ?);"));
    prep_stmt->setBlob (hexMap, sizeof (hexMap), 1);
    prep_stmt->setText (wstring (L"2004-05-11"), 2);
    prep_stmt->execute (); 
    prep_stmt->close ();
    
    //SQLiteConnection::PtrToIPreparedStatement prep_stmt = ptrConn->createPreparedStatement (string ("insert into test values (1, 2, 'test_description_"__TIME__"');insert into test values (1, 2, 'test_description_"__TIME__"-"__DATE__"');"));
    //prep_stmt->execute (); 
    //prep_stmt->execute ();
    //prep_stmt->execute ();
    //prep_stmt->execute ();
    //prep_stmt->close ();
    
    stmt->execute (wstring (L"end;")); // commit;end;
    //stmt->close ();
    
    SQLiteConnection::PtrToIPreparedStatement query_stmt = ptrConn->createPreparedStatement (wstring (L"select * from test;"));
    SQLiteStatement::PtrToIResultSet res_set = query_stmt->executeQuery ();
    
    int i = 0;
    while (true == res_set->next ())
    {
      int r1    = res_set->getInt (0);
      int r2    = res_set->getInt (1);
      wstring r3 = res_set->getText (2);
      
      size_t res = res_set->getBlob (2, resultHexMap, sizeof (resultHexMap));
      
      SQLDate r4 = res_set->getDate (3);
      
      
      wprintf (L"\nrow %d => %d, %d, %S", ++i, r1, r2, r3.c_str ());
    } // while (true == res_set->next ())
    
    
    //res_set->next ();
    //
    //i = 0;
    //while (true == res_set->next ())
    //{
    //  int r1    = res_set->getInt (0);
    //  int r2    = res_set->getInt (1);
    //  string r3 = res_set->getText (2);
    //  
    //  printf ("\nrow %d => %d, %d, %s", ++i, r1, r2, r3.c_str ());
    //} // while (true == res_set->next ())
    
    //query_stmt->close ();

    ptrConn->closeConnection ();
  }
  catch (SQLException& e)
  {
    wprintf (L"\nException => %S", e.getMessageTextAndCode ());
  }
  catch (...)  
  {
    wprintf (L"\nException => unknown");
  }
  

  return 0;
} // main


