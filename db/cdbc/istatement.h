//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _INTERFACE_SQL_STATEMENT_H_
 #define _INTERFACE_SQL_STATEMENT_H_
 
#include "sqlexception.h"

#include <string> 
#include <boost/smart_ptr.hpp> 


using namespace std;

namespace sql {

class IStatement;
class IConnection;

class IStatement
{
  //
  // types
  //
  public:
   typedef boost::shared_ptr<IConnection>   PtrToIConnection;
   
  protected:
  private:

  //
  // methods
  //
  public:
            IStatement () {};
   virtual ~IStatement () {};
   
   virtual  void             close ()                     = 0; // throw (SQLException)
   virtual  PtrToIConnection getConnection ()             = 0;
   virtual  void             execute (const wstring& sql) = 0; // throw (SQLException)
   

  protected:
               IStatement (const IStatement& right) {};
   IStatement& operator= (const IStatement& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IStatement

} // namespace sql {

#endif // _INTERFACE_SQL_STATEMENT_H_