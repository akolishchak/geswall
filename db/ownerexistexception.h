//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_OWNEREXIST_EXCEPTION_H_
 #define _STORAGE_OWNEREXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class OwnerExistException;

class OwnerExistException : public StorageException
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
   OwnerExistException () 
    : StorageException ()
   {
   
   } // OwnerExistException
   
   explicit OwnerExistException (const wstring& message) 
    : StorageException (message)
   {
   
   } // OwnerExistException
   
   explicit OwnerExistException (const wchar_t* message) 
    : StorageException (message)
   {
   
   } // OwnerExistException
   
   explicit OwnerExistException (int code) 
    : StorageException (code) 
   {
   
   } // OwnerExistException
   
   OwnerExistException (const wstring& message, int code) 
    : StorageException (message, code) 
   {
   
   } // OwnerExistException
   
   OwnerExistException (const wchar_t* message, int code) 
    : StorageException (message, code) 
   {
   
   } // OwnerExistException
   
   OwnerExistException (const OwnerExistException& right) 
    : StorageException (right)
   {
   
   } // OwnerExistException
   
   virtual ~OwnerExistException () {};
   
   OwnerExistException& operator= (const OwnerExistException& right) 
   { 
     if (this != &right)
       OwnerExistException (right).swap (*this);
     
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
}; // OwnerExistException

} // namespace Storage {

#endif // _STORAGE_OWNEREXIST_EXCEPTION_H_