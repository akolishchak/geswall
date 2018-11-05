//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_crypto_cryptoexception_h_
 #define _commonlib_crypto_cryptoexception_h_
 
#include "commonlib/exception.h"

namespace commonlib {
namespace crypto {

class CryptoException;

class CryptoException : public commonlib::Exception
{
  //
  // types
  //
  public:
   typedef Exception::string     string;
   typedef Exception::wstring    wstring;

  protected:
  private:

  //
  // methods
  //
  public:
   CryptoException () 
    : Exception ()   
   {
   
   } // CryptoException
   
   explicit CryptoException (const wstring& message) 
    : Exception (message) 
   {
   
   } // CryptoException
   
   explicit CryptoException (int code) 
    : Exception (code)
   {
   
   } // CryptoException
   
   CryptoException (const wstring& message, int code) 
    : Exception (message, code) 
   {
   
   } // CryptoException
   
   CryptoException (const CryptoException& right) 
    : Exception (right)
   {
   
   } // CryptoException
   
   virtual ~CryptoException () 
   {

   } // ~CryptoException
   
   CryptoException& operator= (const CryptoException& right) 
   { 
     if (this != &right)
       CryptoException (right).swap (*this);
     
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
}; // CryptoException

} // namespace crypto {
} // namespace commonlib {

#endif // _commonlib_crypto_cryptoexception_h_