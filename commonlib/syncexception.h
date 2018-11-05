//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SYNC_EXCEPTION_H_
 #define _SYNC_EXCEPTION_H_
 
#include "exception.h"

using namespace std;
 
namespace commonlib {
namespace sync {

class SyncException;

class SyncException : public Exception
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
   SyncException () 
    : Exception () 
   {
   
   } // SyncException
   
   explicit SyncException (const wstring& message) 
    : Exception (message)
   {
   
   } // SyncException
   
   explicit SyncException (int code) 
    : Exception (code) 
   {
   
   } // SyncException
   
   SyncException (const wstring& message, int code) 
    : Exception (message, code)
   {
   
   } // SyncException
   
   SyncException (const SyncException& right) 
    : Exception (right)
   {
   
   } // SyncException
   
   virtual ~SyncException () 
   {
   
   } // ~SyncException
   
   SyncException& operator= (const SyncException& right) 
   { 
     if (this != &right)
       SyncException (right).swap (*this);
     
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
}; // SyncException

} // namespace sync {
} // namespace commonlib {

#endif // _SYNC_EXCEPTION_H_