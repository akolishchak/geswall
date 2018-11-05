//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _INTERFACE_SQL_PREPARED_STATEMENT_H_
 #define _INTERFACE_SQL_PREPARED_STATEMENT_H_
 
#include "istatement.h"
#include "sqldate.h"

#include <string>
#include <boost/smart_ptr.hpp>

using namespace std;

namespace sql {

class IResultSet;

class IPreparedStatement : public IStatement
{
  //
  // types
  //
  public:
   typedef boost::shared_ptr<IResultSet>   PtrToIResultSet;
#if defined(_MSC_VER) || defined(__BORLANDC__)
   typedef __int64                         RowId;
#else
   typedef long long int                   RowId;
#endif
   
   
  protected:
  private:

  //
  // methods
  //
  public:
            IPreparedStatement () {};
   virtual ~IPreparedStatement () {};
   
   virtual  PtrToIResultSet executeQuery ()                         = 0;   // throw (SQLException)
   virtual  void            execute ()                              = 0;   // throw (SQLException)
   virtual  RowId           executeUpdate ()                        = 0;   // throw (SQLException)
   virtual  void            setInt (int value, int index)           = 0;   // throw (SQLException)
   virtual  void            setFloat (double value, int index)      = 0;   // throw (SQLException)
   virtual  void            setText (const wstring& text, int index) = 0;  // throw (SQLException)
   virtual  void            setBlob (const unsigned char* buffer, size_t bufSize, int index) = 0; // throw (SQLException)
   virtual  void            setDate (const SQLDate& date, int index)= 0;   // throw (SQLException)
   virtual  void            setNull (int index)                     = 0;   // throw (SQLException)

  protected:
               IPreparedStatement (const IPreparedStatement& right) {};
   IPreparedStatement& operator= (const IPreparedStatement& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IPreparedStatement

} // namespace sql 
 
#endif // _INTERFACE_SQL_PREPARED_STATEMENT_H_
