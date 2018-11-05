//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _OWNERSHIP_EXCEPTION_H_
 #define _OWNERSHIP_EXCEPTION_H_
 
#include "syncexception.h"

using namespace std;
 
namespace commonlib {
namespace sync {

class OwnershipException;

class OwnershipException : public SyncException
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
   OwnershipException () 
    : SyncException ()   
   {
   
   } // OwnershipException
   
   explicit OwnershipException (const wstring& message) 
    : SyncException (message)
   {
   
   } // OwnershipException
   
   explicit OwnershipException (int code) 
    : SyncException (code) 
   {
   
   } // OwnershipException
   
   OwnershipException (const wstring& message, int code) 
    : SyncException (message, code)
   {
   
   } // OwnershipException
   
   OwnershipException (const OwnershipException& right) 
    : SyncException (right) 
   {
   
   } // OwnershipException
   
   virtual ~OwnershipException () {};
   
   OwnershipException& operator= (const OwnershipException& right) 
   { 
     if (this != &right)
       OwnershipException (right).swap (*this);
     
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
}; // OwnershipException

} // namespace sync {
} // namespace commonlib {

#endif // _OWNERSHIP_EXCEPTION_H_