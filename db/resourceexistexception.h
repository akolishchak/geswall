//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_RESOURCEEXIST_EXCEPTION_H_
 #define _STORAGE_RESOURCEEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {
           
class ResourceExistException;

class ResourceExistException : public StorageException
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
   ResourceExistException () 
    : StorageException (ErrorResourceExists)
   {
   
   } // ResourceExistException
   
   explicit ResourceExistException (const wstring& message) 
    : StorageException (message, ErrorResourceExists)
   {
   
   } // ResourceExistException
   
   explicit ResourceExistException (const wchar_t* message) 
    : StorageException (message, ErrorResourceExists)
   {    
   
   } // ResourceExistException
   
   ResourceExistException (const ResourceExistException& right) 
    : StorageException (right)
   {
   
   } // ResourceExistException
   
   virtual ~ResourceExistException () {};
   
   ResourceExistException& operator= (const ResourceExistException& right) 
   { 
     if (this != &right)
       ResourceExistException (right).swap (*this);
     
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
}; // ResourceExistException

} // namespace Storage {

#endif // _STORAGE_RESOURCEEXIST_EXCEPTION_H_