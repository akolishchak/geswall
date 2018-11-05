//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _INTERFACE_SQL_RESULT_SET_H_
 #define _INTERFACE_SQL_RESULT_SET_H_
 
namespace sql {

class IPreparedStatement;
class IResultSet;

class IResultSet
{
  //
  // types
  //
  public:
  protected:
  private:

  //
  // methods
  //
  public:
            IResultSet () {};
   virtual ~IResultSet () {};
   
   virtual  bool    next ()                   = 0; // throw (SQLException)
   
   virtual  int     getColumnCount ()         = 0; // throw (SQLException)
   virtual  int     getColumnIndex (const wstring& name) = 0; // throw (SQLException)
   virtual  int     getColumnType (int index) = 0; // throw (SQLException)
   
   
   virtual  int     getInt (int index)        = 0; // throw (SQLException)
   virtual  double  getFloat (int index)      = 0; // throw (SQLException)
   virtual  wstring getText (int index)       = 0; // throw (SQLException)
   virtual  SQLDate getDate (int index)       = 0; // throw (SQLException)
   virtual  size_t  getBlob (int index, unsigned char* buffer, size_t bufSize) = 0; // throw (SQLException)
   

  protected:
               IResultSet (const IResultSet& right) {};
   IResultSet& operator= (const IResultSet& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IResultSet

} // namespace sql {

#endif // _INTERFACE_SQL_RESULT_SET_H_