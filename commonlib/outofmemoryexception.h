//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_outofmemory_exception_h_
 #define _commonlib_outofmemory_exception_h_
 
#include "exception.h"

namespace commonlib {

class OutOfMemoryException;

class OutOfMemoryException : public Exception
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
   OutOfMemoryException () 
    : Exception ()   
   {
   
   } // OutOfMemoryException
   
   explicit OutOfMemoryException (const wstring& message) 
    : Exception (message) 
   {
   
   } // OutOfMemoryException
   
   explicit OutOfMemoryException (int code) 
    : Exception (code)
   {
   
   } // OutOfMemoryException
   
   OutOfMemoryException (const wstring& message, int code) 
    : Exception (message, code) 
   {
   
   } // OutOfMemoryException
   
   OutOfMemoryException (const OutOfMemoryException& right) 
    : Exception (right)
   {
   
   } // OutOfMemoryException
   
   virtual ~OutOfMemoryException () 
   {

   } // ~OutOfMemoryException
   
   OutOfMemoryException& operator= (const OutOfMemoryException& right) 
   { 
     if (this != &right)
       OutOfMemoryException (right).swap (*this);
     
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
}; // OutOfMemoryException

} // namespace commonlib {

#endif // _commonlib_outofmemory_exception_h_