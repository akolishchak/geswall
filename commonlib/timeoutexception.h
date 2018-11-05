//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _TIMEOUT_EXCEPTION_H_
 #define _TIMEOUT_EXCEPTION_H_
 
#include "syncexception.h"

using namespace std;
 
namespace commonlib {
namespace sync {

class TimeoutException;

class TimeoutException : public SyncException
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
   TimeoutException () 
    : SyncException ()   
   {
   
   } // TimeoutException
   
   explicit TimeoutException (const wstring& message) 
    : SyncException (message)
   {
   
   } // TimeoutException
   
   explicit TimeoutException (int code) 
    : SyncException (code) 
   {
   
   } // TimeoutException
   
   TimeoutException (const wstring& message, int code) 
    : SyncException (message, code)
   {
   
   } // TimeoutException
   
   TimeoutException (const TimeoutException& right) 
    : SyncException (right) 
   {
   
   } // TimeoutException
   
   virtual ~TimeoutException () {};
   
   TimeoutException& operator= (const TimeoutException& right) 
   { 
     if (this != &right)
       TimeoutException (right).swap (*this);
     
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
}; // TimeoutException

} // namespace sync {
} // namespace commonlib {

#endif // _TIMEOUT_EXCEPTION_H_