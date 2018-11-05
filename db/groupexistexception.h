//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_GROUPEXIST_EXCEPTION_H_
 #define _STORAGE_GROUPEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class GroupExistException;

class GroupExistException : public StorageException
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
   GroupExistException () 
    : StorageException (ErrorGroupExists)
   {
   
   } // GroupExistException
   
   explicit GroupExistException (const wstring& message) 
    : StorageException (message, ErrorGroupExists)
   {
   
   } // GroupExistException
   
   explicit GroupExistException (const wchar_t* message) 
    : StorageException (message, ErrorGroupExists)
   {
   
   } // GroupExistException
   
   explicit GroupExistException (int code) 
    : StorageException (code) 
   {
   
   } // GroupExistException
   
   GroupExistException (const wstring& message, int code) 
    : StorageException (message, code) 
   {
   
   } // GroupExistException

   GroupExistException (const GroupExistException& right) 
    : StorageException (right)
   {
   
   } // GroupExistException
   
   virtual ~GroupExistException () {};
   
   GroupExistException& operator= (const GroupExistException& right) 
   { 
     if (this != &right)
       GroupExistException (right).swap (*this);
     
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
}; // GroupExistException

} // namespace Storage {

#endif // _STORAGE_GROUPEXIST_EXCEPTION_H_