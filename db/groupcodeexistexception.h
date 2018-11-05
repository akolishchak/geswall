//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_GROUPCODEEXIST_EXCEPTION_H_
 #define _STORAGE_GROUPCODEEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class GroupCodeExistException;

class GroupCodeExistException : public StorageException
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
   GroupCodeExistException () 
    : StorageException ()
   {
   
   } // GroupCodeExistException
   
   explicit GroupCodeExistException (const wstring& message) 
    : StorageException (message)
   {
   
   } // GroupCodeExistException
   
   explicit GroupCodeExistException (const wchar_t* message) 
    : StorageException (message)
   {
   
   } // GroupCodeExistException
   
   explicit GroupCodeExistException (int code) 
    : StorageException (code) 
   {
   
   } // GroupCodeExistException
   
   GroupCodeExistException (const wstring& message, int code) 
    : StorageException (message, code) 
   {
   
   } // GroupCodeExistException
   
   GroupCodeExistException (const wchar_t* message, int code) 
    : StorageException (message, code) 
   {
   
   } // GroupCodeExistException
   
   GroupCodeExistException (const GroupCodeExistException& right) 
    : StorageException (right)
   {
   
   } // GroupCodeExistException
   
   virtual ~GroupCodeExistException () {};
   
   GroupCodeExistException& operator= (const GroupCodeExistException& right) 
   { 
     if (this != &right)
       GroupCodeExistException (right).swap (*this);
     
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
}; // GroupCodeExistException

} // namespace Storage {

#endif // _STORAGE_GROUPCODEEXIST_EXCEPTION_H_