//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_PATHEXIST_EXCEPTION_H_
 #define _STORAGE_PATHEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class PathExistException;

class PathExistException : public StorageException
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
   PathExistException () 
    : StorageException (ErrorPathExists)
   {
   
   } // PathExistException
   
   explicit PathExistException (const wstring& message) 
    : StorageException (message, ErrorPathExists)
   {
   
   } // PathExistException
   
   explicit PathExistException (const wchar_t* message) 
    : StorageException (message, ErrorPathExists)
   {
   
   } // PathExistException
   
   PathExistException (const PathExistException& right) 
    : StorageException (right)
   {
   
   } // PathExistException
   
   virtual ~PathExistException () {};
   
   PathExistException& operator= (const PathExistException& right) 
   { 
     if (this != &right)
       PathExistException (right).swap (*this);
     
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
}; // PathExistException

} // namespace Storage {

#endif // _STORAGE_PATHEXIST_EXCEPTION_H_