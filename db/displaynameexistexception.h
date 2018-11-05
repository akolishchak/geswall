//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_DISPLAYNAMEEXIST_EXCEPTION_H_
 #define _STORAGE_DISPLAYNAMEEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class DisplayNameExistException;

class DisplayNameExistException : public StorageException
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
   DisplayNameExistException () 
    : StorageException (ErrorDisplayNameExists)
   {
   
   } // DisplayNameExistException
   
   explicit DisplayNameExistException (const wstring& message) 
    : StorageException (message, ErrorDisplayNameExists)
   {
   
   } // DisplayNameExistException
   
   explicit DisplayNameExistException (const wchar_t* message) 
    : StorageException (message, ErrorDisplayNameExists)
   {
   
   } // DisplayNameExistException
   
   DisplayNameExistException (const DisplayNameExistException& right) 
    : StorageException (right)
   {
   
   } // DisplayNameExistException
   
   virtual ~DisplayNameExistException () {};
   
   DisplayNameExistException& operator= (const DisplayNameExistException& right) 
   { 
     if (this != &right)
       DisplayNameExistException (right).swap (*this);
     
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
}; // DisplayNameExistException

} // namespace Storage {

#endif // _STORAGE_DISPLAYNAMEEXIST_EXCEPTION_H_