//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _CANCEL_EXCEPTION_H_
 #define _CANCEL_EXCEPTION_H_
 
#include "syncexception.h"

using namespace std;
 
namespace commonlib {
namespace sync {

class CancelException;

class CancelException : public SyncException
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
   CancelException () 
    : SyncException ()   
   {
   
   } // CancelException
   
   explicit CancelException (const wstring& message) 
    : SyncException (message)
   {
   
   } // CancelException
   
   explicit CancelException (int code) 
    : SyncException (code) 
   {
   
   } // CancelException
   
   CancelException (const wstring& message, int code) 
    : SyncException (message, code)
   {
   
   } // CancelException
   
   CancelException (const CancelException& right) 
    : SyncException (right) 
   {
   
   } // CancelException
   
   virtual ~CancelException () {};
   
   CancelException& operator= (const CancelException& right) 
   { 
     if (this != &right)
       CancelException (right).swap (*this);
     
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
}; // CancelException

} // namespace sync {
} // namespace commonlib {

#endif // _CANCEL_EXCEPTION_H_