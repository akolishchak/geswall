//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_io_exception_h_
 #define _commonlib_io_exception_h_
 
#include "exception.h"

namespace commonlib {

class IOException;

class IOException : public Exception
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
   IOException () 
    : Exception ()   
   {
   
   } // IOException
   
   explicit IOException (const wstring& message) 
    : Exception (message) 
   {
   
   } // IOException
   
   explicit IOException (int code) 
    : Exception (code)
   {
   
   } // IOException
   
   IOException (const wstring& message, int code) 
    : Exception (message, code) 
   {
   
   } // IOException
   
   IOException (const IOException& right) 
    : Exception (right)
   {
   
   } // IOException
   
   virtual ~IOException () 
   {

   } // ~IOException
   
   IOException& operator= (const IOException& right) 
   { 
     if (this != &right)
       IOException (right).swap (*this);
     
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
}; // IOException

} // namespace commonlib {

#endif // _commonlib_io_exception_h_