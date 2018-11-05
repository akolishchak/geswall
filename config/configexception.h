//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _CONFIG_EXCEPTION_H_
 #define _CONFIG_EXCEPTION_H_
 
#include "commonlib/exception.h"

namespace config {

class ConfigException;

class ConfigException : public commonlib::Exception
{
  //
  // types
  //
  public:
   typedef Exception             base_type;
   typedef base_type::string     string;
   typedef base_type::wstring    wstring;

  protected:
  private:

  //
  // methods
  //
  public:
   ConfigException () 
    : base_type () 
   {
   
   } // SQLException
   
   explicit ConfigException (const wstring& message) 
    : base_type (message)
   {
   
   } // ConfigException
   
   explicit ConfigException (const wchar_t* message) 
    : base_type (message)
   {
   
   } // ConfigException
   
   explicit ConfigException (int code) 
    : base_type (code) 
   {
   
   } // ConfigException
   
   ConfigException (const wstring& message, int code) 
    : base_type (message, code)
   {
   
   } // ConfigException
   
   ConfigException (const wchar_t* message, int code) 
    : base_type (message, code)
   {
   
   } // ConfigException
   
   ConfigException (const ConfigException& right) 
    : base_type (right)
   {
   
   } // ConfigException
   
   virtual ~ConfigException () 
   {
   } //~ConfigException
   
   ConfigException& operator= (const ConfigException& right) 
   { 
     if (this != &right)
       ConfigException (right).swap (*this);
     
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
}; // ConfigException

} // namespace sql {

#endif // _CONFIG_EXCEPTION_H_