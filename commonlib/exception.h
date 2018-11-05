//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_exception_h_
 #define _commonlib_exception_h_
 
#include <exception> 
#include <string>

namespace commonlib {

class Exception;

class Exception : public std::exception
{
  //
  // types
  //
  public:
   typedef std::string     string;
   typedef std::wstring    wstring;
   typedef std::exception  exception;

  protected:
  private:

  //
  // methods
  //
  public:
   Exception () 
    : exception (),
      m_code (0) 
   {
   
   } // Exception
   
   explicit Exception (const wstring& message) 
    : exception (), 
      m_message (message),
      m_code (0) 
   {
   
   } // Exception
   
   explicit Exception (int code) 
    : exception (), 
      m_code (code) 
   {
   
   } // Exception
   
   Exception (const wstring& message, int code) 
    : exception (), 
      m_message (message),
      m_code (code) 
   {
   
   } // Exception
   
   Exception (const Exception& right) 
    : exception (right), 
      m_message (right.m_message),
      m_code (right.m_code),
      m_messageAndCode (right.m_messageAndCode)
   {
   
   } // Exception
   
   virtual ~Exception () {};
   
   Exception& operator= (const Exception& right) 
   { 
     if (this != &right)
       Exception (right).swap (*this);
     
     return *this; 
   } // operator=

   virtual const char* what () const
   {
     return "";//getMessageText ();
   } // what
   
   const wstring& getMessage () const
   {
     return m_message;
   } // getMessage
   
   const wchar_t* getMessageText () const
   {
     return m_message.c_str ();
   } // getMessageText
   
   int getCode () const
   {
     return m_code; 
   } // getCode
   
   const wstring& getMessageAndCode () const
   {
     if (0 <= m_messageAndCode.size ())
     {
       wchar_t   szCode[64];
       swprintf (szCode, L", code = %d", m_code);
       m_messageAndCode = m_message;
       m_messageAndCode += szCode;
     }
     
     return m_messageAndCode;
   } // getMessageAndCode
   
   const wchar_t* getMessageTextAndCode () const
   {
     return getMessageAndCode ().c_str ();
   } // getMessageText

  protected:
   void swap (Exception& right)
   {
     wstring   message = m_message;
     int       code    = m_code;

     m_message         = right.m_message;
     m_code            = right.m_code;

     right.m_message   = message;
     right.m_code      = code;   
   } // swap

  private:
  
  //
  // data
  //
  public:
  protected:
   wstring   m_message;
   int       m_code;
   
  private:
   mutable wstring   m_messageAndCode;
}; // Exception

} // namespace commonlib {

#endif // _commonlib_exception_h_