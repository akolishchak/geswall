//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_IDENTITYEXIST_EXCEPTION_H_
 #define _STORAGE_IDENTITYEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class IdentityExistException;

class IdentityExistException : public StorageException
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
   IdentityExistException () 
    : StorageException (ErrorIdentityExists)
   {
   
   } // IdentityExistException
   
   explicit IdentityExistException (const wstring& message) 
    : StorageException (message, ErrorIdentityExists)
   {
   
   } // IdentityExistException
   
   explicit IdentityExistException (const wchar_t* message) 
    : StorageException (message, ErrorIdentityExists)
   {
   
   } // IdentityExistException
   
   IdentityExistException (const IdentityExistException& right) 
    : StorageException (right)
   {
   
   } // IdentityExistException
   
   virtual ~IdentityExistException () {};
   
   IdentityExistException& operator= (const IdentityExistException& right) 
   { 
     if (this != &right)
       IdentityExistException (right).swap (*this);
     
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
}; // IdentityExistException

} // namespace Storage {

#endif // _STORAGE_IDENTITYEXIST_EXCEPTION_H_