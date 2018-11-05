//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_EXCEPTION_H_
 #define _GUICTRL_EXCEPTION_H_
 
#include "commonlib/exception.h"

namespace gswserv {
namespace guictrl {


class GUICtrlException;

class GUICtrlException : public commonlib::Exception
{
  //
  // types
  //
  public:
   typedef Exception             base_type;
   typedef base_type::string     string;
   typedef base_type::wstring    wstring;

  protected:
  private:

  //
  // methods
  //
  public:
   GUICtrlException () 
    : base_type () 
   {
   
   } // GUICtrlException
   
   explicit GUICtrlException (const wstring& message) 
    : base_type (message)
   {
   
   } // GUICtrlException
   
   explicit GUICtrlException (int code) 
    : base_type (code) 
   {
   
   } // GUICtrlException
   
   GUICtrlException (const wstring& message, int code) 
    : base_type (message, code)
   {
   
   } // GUICtrlException
   
   GUICtrlException (const GUICtrlException& right) 
    : base_type (right)
   {
   
   } // GUICtrlException
   
   virtual ~GUICtrlException () {};
   
   GUICtrlException& operator= (const GUICtrlException& right) 
   { 
     if (this != &right)
       GUICtrlException (right).swap (*this);
     
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
}; // GUICtrlException

} // namespace guictrl {
} // namespace gswserv {

#endif // _CONFIG_EXCEPTION_H_