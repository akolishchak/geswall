//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_argument_exception_h_
 #define _commonlib_argument_exception_h_
 
#include "exception.h"

namespace commonlib {

class ArgumentException;

class ArgumentException : public Exception
{
  //
  // types
  //
  public:
   typedef Exception::string     string;
   typedef Exception::wstring    wstring;

  protected:
  private:

  //
  // methods
  //
  public:
   ArgumentException () 
    : Exception ()   
   {
   
   } // ArgumentException
   
   explicit ArgumentException (const wstring& message) 
    : Exception (message) 
   {
   
   } // ArgumentException
   
   explicit ArgumentException (int code) 
    : Exception (code)
   {
   
   } // ArgumentException
   
   ArgumentException (const wstring& message, int code) 
    : Exception (message, code) 
   {
   
   } // ArgumentException
   
   ArgumentException (const ArgumentException& right) 
    : Exception (right)
   {
   
   } // ArgumentException
   
   virtual ~ArgumentException () 
   {

   } // ~ArgumentException
   
   ArgumentException& operator= (const ArgumentException& right) 
   { 
     if (this != &right)
       ArgumentException (right).swap (*this);
     
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
}; // ArgumentException

} // namespace commonlib {

#endif // _commonlib_argument_exception_h_