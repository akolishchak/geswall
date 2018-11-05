//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_EXCEPTION_H_
 #define _STORAGE_EXCEPTION_H_
 
#include "commonlib/exception.h"

namespace Storage {

enum {
    ErrorUnknown            = 0,
    ErrorIdentityExists     = -1,
    ErrorPathExists         = -2,
    ErrorGroupNotEmpty      = -3,
    ErrorGroupExists        = -4,
    ErrorGroupCodeExists    = -5,
    ErrorDisplayNameExists  = -6,
    ErrorDigestExists       = -7,
    ErrorContentExists      = -8,
    ErrorResourceExists     = -9
};

class StorageException;

class StorageException : public commonlib::Exception
{
  //
  // types
  //
  public:
   typedef commonlib::Exception  base_type;
   typedef base_type::string     string;
   typedef base_type::wstring    wstring;


  protected:
  private:

  //
  // methods
  //
  public:
   StorageException () 
    : base_type (ErrorUnknown)   
   {
   
   } // StorageException
   
   explicit StorageException (const wstring& message) 
    : base_type (message, ErrorUnknown) 
   {
   
   } // StorageException
   
   explicit StorageException (const wchar_t* message) 
    : base_type (message, ErrorUnknown) 
   {
   
   } // StorageException
   
   explicit StorageException (int code) 
    : base_type (code)   
   {
   
   } // StorageException
   
   StorageException (const wstring& message, int code) 
    : base_type (message, code)
   {
   
   } // StorageException
   
   StorageException (const wchar_t* message, int code) 
    : base_type (message, code)
   {
   
   } // StorageException
   
   StorageException (const StorageException& right) 
    : base_type (right)
   {
   
   } // StorageException
   
   virtual ~StorageException () 
   {
   
   } // ~StorageException
   
   StorageException& operator= (const StorageException& right) 
   { 
     if (this != &right)
       StorageException (right).swap (*this);
     
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
}; // StorageException

} // namespace storage {

#endif // _STORAGE_EXCEPTION_H_