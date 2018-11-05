//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_io_eofexception_h_
 #define _commonlib_io_eofexception_h_
 
#include "exception.h"

namespace commonlib {

class EOFException;

class EOFException : public Exception
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
   EOFException () 
    : Exception ()   
   {
   
   } // EOFException
   
   explicit EOFException (const wstring& message) 
    : Exception (message) 
   {
   
   } // EOFException
   
   explicit EOFException (int code) 
    : Exception (code)
   {
   
   } // EOFException
   
   EOFException (const wstring& message, int code) 
    : Exception (message, code) 
   {
   
   } // EOFException
   
   EOFException (const EOFException& right) 
    : Exception (right)
   {
   
   } // EOFException
   
   virtual ~EOFException () 
   {

   } // ~EOFException
   
   EOFException& operator= (const EOFException& right) 
   { 
     if (this != &right)
       EOFException (right).swap (*this);
     
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
}; // EOFException

} // namespace commonlib {

#endif // _commonlib_io_eofexception_h_