//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_SECURITYCLASSEXIST_EXCEPTION_H_
 #define _STORAGE_SECURITYCLASSEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class SecurityClassExistException;

class SecurityClassExistException : public StorageException
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
   SecurityClassExistException () 
    : StorageException ()
   {
   
   } // SecurityClassExistException
   
   explicit SecurityClassExistException (const wstring& message) 
    : StorageException (message)
   {
   
   } // SecurityClassExistException
   
   explicit SecurityClassExistException (const wchar_t* message) 
    : StorageException (message)
   {
   
   } // SecurityClassExistException
   
   explicit SecurityClassExistException (int code) 
    : StorageException (code) 
   {
   
   } // SecurityClassExistException
   
   SecurityClassExistException (const wstring& message, int code) 
    : StorageException (message, code) 
   {
   
   } // SecurityClassExistException
   
   SecurityClassExistException (const wchar_t* message, int code) 
    : StorageException (message, code) 
   {
   
   } // SecurityClassExistException
   
   SecurityClassExistException (const SecurityClassExistException& right) 
    : StorageException (right)
   {
   
   } // SecurityClassExistException
   
   virtual ~SecurityClassExistException () {};
   
   SecurityClassExistException& operator= (const SecurityClassExistException& right) 
   { 
     if (this != &right)
       SecurityClassExistException (right).swap (*this);
     
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
}; // SecurityClassExistException

} // namespace Storage {

#endif // _STORAGE_SECURITYCLASSEXIST_EXCEPTION_H_