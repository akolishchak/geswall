//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SQL_EXCEPTION_H_
 #define _SQL_EXCEPTION_H_

#include "commonlib/exception.h"
 
namespace sql {

enum {
    ErrorUnknown    = 0
};

class SQLException;

class SQLException : public commonlib::Exception
{
  //
  // types
  //
  public:
   typedef commonlib::Exception  base_type;
   typedef base_type::string     string;
   typedef base_type::wstring    wstring;

  protected:
  private:

  //
  // methods
  //
  public:
   SQLException () 
    : base_type (ErrorUnknown) 
   {
   
   } // SQLException
   
   explicit SQLException (const wstring& message) 
    : base_type (message, ErrorUnknown)
   {
   
   } // SQLException
   
   explicit SQLException (const wchar_t* message) 
    : base_type (message, ErrorUnknown)
   {
   
   } // SQLException
   
   explicit SQLException (int code) 
    : base_type (code) 
   {
   
   } // SQLException
   
   SQLException (const wstring& message, int code) 
    : base_type (message, code) 
   {
   
   } // SQLException
   
   SQLException (const wchar_t* message, int code) 
    : base_type (message, code) 
   {
   
   } // SQLException
   
   SQLException (const SQLException& right) 
    : base_type (right) 
   {
   
   } // SQLException
   
   virtual ~SQLException () {};
   
   SQLException& operator= (const SQLException& right) 
   { 
     if (this != &right)
       SQLException (right).swap (*this);
     
     return *this; 
   } // operator=

  protected:
  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // SQLException

} // namespace sql {

#endif // _SQL_EXCEPTION_H_