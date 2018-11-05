//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _INTERFACE_DATA_BASE_CONNECTION_H_
 #define _INTERFACE_DATA_BASE_CONNECTION_H_
 
#include "sqlexception.h"
 
#include <string>  
#include <boost/smart_ptr.hpp> 

using namespace std;

namespace sql {

class IStatement;
class IPreparedStatement;
class IConnection;

class IConnection
{
  //
  // types
  //
  public:
   typedef boost::shared_ptr<IStatement>           PtrToIStatement;
   typedef boost::shared_ptr<IPreparedStatement>   PtrToIPreparedStatement;
   typedef boost::shared_ptr<IConnection>          PtrToIConnection;
   
  protected:
  private:

  //
  // methods
  //
  public:
            IConnection () {};
   virtual ~IConnection () {};

   virtual  void                    connect ()                 = 0; // throw (SQLException)
   virtual  void                    closeConnection ()         = 0; // throw (SQLException)

   virtual  PtrToIStatement         createStatement ()         = 0; // throw (SQLException)
   virtual  PtrToIPreparedStatement createPreparedStatement (const wstring& sql) = 0; // throw (SQLException)
   
   virtual  void                    begin ()                   = 0; // throw (SQLException
   virtual  void                    commit ()                  = 0; // throw (SQLException
   virtual  void                    rollback ()                = 0; // throw (SQLException

  protected:
                IConnection (const IConnection& right) {};
   IConnection& operator= (const IConnection& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IConnection

} // namespace sql {

#endif // _INTERFACE_DATA_BASE_CONNECTION_H_