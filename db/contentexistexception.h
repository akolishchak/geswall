//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_CONTENTEXIST_EXCEPTION_H_
 #define _STORAGE_CONTENTEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class ContentExistException;

class ContentExistException : public StorageException
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
   ContentExistException () 
    : StorageException (ErrorContentExists)
   {
   
   } // ContentExistException
   
   explicit ContentExistException (const wstring& message) 
    : StorageException (message, ErrorContentExists)
   {
   
   } // ContentExistException
   
   explicit ContentExistException (const wchar_t* message) 
    : StorageException (message, ErrorContentExists)
   {
   
   } // ContentExistException
   
   ContentExistException (const ContentExistException& right) 
    : StorageException (right)
   {
   
   } // ContentExistException
   
   virtual ~ContentExistException () {};
   
   ContentExistException& operator= (const ContentExistException& right) 
   { 
     if (this != &right)
       ContentExistException (right).swap (*this);
     
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
}; // ContentExistException

} // namespace Storage {

#endif // _STORAGE_CONTENTEXIST_EXCEPTION_H_