//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_GROUPNOTEMPTY_EXCEPTION_H_
 #define _STORAGE_GROUPNOTEMPTY_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class GroupNotEmptyException;

class GroupNotEmptyException : public StorageException
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
   GroupNotEmptyException () 
    : StorageException (ErrorGroupNotEmpty)
   {
   
   } // GroupNotEmptyException
   
   explicit GroupNotEmptyException (const wstring& message) 
    : StorageException (message, ErrorGroupNotEmpty)
   {
   
   } // GroupNotEmptyException
   
   explicit GroupNotEmptyException (const wchar_t* message) 
    : StorageException (message, ErrorGroupNotEmpty)
   {
   
   } // GroupNotEmptyException
   
   GroupNotEmptyException (const GroupNotEmptyException& right) 
    : StorageException (right)
   {
   
   } // GroupNotEmptyException
   
   virtual ~GroupNotEmptyException () {};
   
   GroupNotEmptyException& operator= (const GroupNotEmptyException& right) 
   { 
     if (this != &right)
       GroupNotEmptyException (right).swap (*this);

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
}; // GroupNotEmptyException

} // namespace Storage {

#endif // _STORAGE_GROUPNOTEMPTY_EXCEPTION_H_