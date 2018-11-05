//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _STORAGE_CERTIFICATEEXIST_EXCEPTION_H_
 #define _STORAGE_CERTIFICATEEXIST_EXCEPTION_H_
 
#include "storageexception.h"

namespace Storage {

class CertificateExistException;

class CertificateExistException : public StorageException
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
   CertificateExistException () 
    : StorageException ()
   {
   
   } // CertificateExistException
   
   explicit CertificateExistException (const wstring& message) 
    : StorageException (message)
   {
   
   } // CertificateExistException
   
   explicit CertificateExistException (const wchar_t* message) 
    : StorageException (message)
   {
   
   } // CertificateExistException
   
   explicit CertificateExistException (int code) 
    : StorageException (code) 
   {
   
   } // CertificateExistException
   
   CertificateExistException (const wstring& message, int code) 
    : StorageException (message, code) 
   {
   
   } // CertificateExistException
   
   CertificateExistException (const wchar_t* message, int code) 
    : StorageException (message, code) 
   {
   
   } // CertificateExistException
   
   CertificateExistException (const CertificateExistException& right) 
    : StorageException (right)
   {
   
   } // CertificateExistException
   
   virtual ~CertificateExistException () {};
   
   CertificateExistException& operator= (const CertificateExistException& right) 
   { 
     if (this != &right)
       CertificateExistException (right).swap (*this);
     
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
}; // CertificateExistException

} // namespace Storage {

#endif // _STORAGE_CERTIFICATEEXIST_EXCEPTION_H_