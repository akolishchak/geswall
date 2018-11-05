//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_unsupported_exception_h_
 #define _commonlib_unsupported_exception_h_
 
#include "exception.h"

namespace commonlib {

class UnsupportedException;

class UnsupportedException : public Exception
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
   UnsupportedException () 
    : Exception ()   
   {
   
   } // UnsupportedException
   
   explicit UnsupportedException (const wstring& message) 
    : Exception (message) 
   {
   
   } // UnsupportedException
   
   explicit UnsupportedException (int code) 
    : Exception (code)
   {
   
   } // UnsupportedException
   
   UnsupportedException (const wstring& message, int code) 
    : Exception (message, code) 
   {
   
   } // UnsupportedException
   
   UnsupportedException (const UnsupportedException& right) 
    : Exception (right)
   {
   
   } // UnsupportedException
   
   virtual ~UnsupportedException () 
   {

   } // ~UnsupportedException
   
   UnsupportedException& operator= (const UnsupportedException& right) 
   { 
     if (this != &right)
       UnsupportedException (right).swap (*this);
     
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
}; // UnsupportedException

} // namespace commonlib {

#endif // _commonlib_unsupported_exception_h_