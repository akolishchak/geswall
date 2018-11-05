//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_DIGESTEXIST_EXCEPTION_H_
 #define _STORAGE_DIGESTEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class DigestExistException;

class DigestExistException : public StorageException
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
   DigestExistException () 
    : StorageException (ErrorDigestExists)
   {
   
   } // DigestExistException
   
   explicit DigestExistException (const wstring& message) 
    : StorageException (message, ErrorDigestExists)
   {
   
   } // DigestExistException
   
   explicit DigestExistException (const wchar_t* message) 
    : StorageException (message, ErrorDigestExists)
   {
   
   } // DigestExistException
   
   DigestExistException (const DigestExistException& right) 
    : StorageException (right)
   {
   
   } // DigestExistException
   
   virtual ~DigestExistException () {};
   
   DigestExistException& operator= (const DigestExistException& right) 
   { 
     if (this != &right)
       DigestExistException (right).swap (*this);
     
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
}; // DigestExistException

} // namespace Storage {

#endif // _STORAGE_DIGESTEXIST_EXCEPTION_H_