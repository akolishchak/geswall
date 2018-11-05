//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SQL_DATE_H_
 #define _SQL_DATE_H_
 
#include <string>

using namespace std;
 
namespace sql {

class SQLDate;

class SQLDate
{
  //
  // types
  //
  public:
   typedef __int64 DateT;
   
  protected:
  private:

  //
  // methods
  //
  public:
   SQLDate () 
    : m_date (0)
   {
   
   } // SQLDate
   
   //explicit SQLDate (const wstring& date) 
   // : m_date (date)
   //{
   //
   //} // SQLDate
   //
   //explicit SQLDate (const wchar_t* date) 
   // : m_date (date)
   //{
   //
   //} // SQLDate
   
   explicit SQLDate (DateT date) 
    : m_date (date)
   {
     
   } // SQLDate
   
   //SQLDate (int year, int month, int day, const wchar_t* format)
   //{
   //  wchar_t    sysDate [32];
   //  swprintf (sysDate, format, year, month, day);
   //  m_date.assign (sysDate);
   //} // SQLDate
   
   SQLDate (const SQLDate& right) 
    : m_date (right.m_date)
   {
   
   } // SQLDate
   
   virtual ~SQLDate () {};
   
   SQLDate& operator= (const SQLDate& right) 
   { 
     if (this != &right)
     {
       this->~SQLDate ();
       new (this) SQLDate (right);
     } // if (this != &right)
     
     return *this; 
   } // operator=

   virtual void setDate (DateT date)
   {
     m_date = date;
   } // setDate
   
   virtual DateT getDate () const
   {
     return m_date;
   } // setDate

  protected:
  private:
  
  //
  // data
  //
  public:
  protected:
   //wstring   m_date;
   DateT   m_date;
   
  private:
}; // SQLDate

} // namespace sql {

#endif // _SQL_DATE_H_