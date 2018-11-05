//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_sync_atomicconter_h_
 #define _commonlib_sync_atomicconter_h_

#include <windows.h>

namespace commonlib {
namespace sync {

template <typename ValueHolder>
class AtomicCounter;

class IntrusiveValue
{
  public:
   typedef long      value_type;

  public:
   IntrusiveValue ()
    : m_value (0)
   {
   } // IntrusiveValue

   explicit IntrusiveValue (value_type value)
    : m_value (value)
   {
   } // IntrusiveValue

   value_type& value_ref ()
   {
     return m_value;
   } // value_ref

   value_type value ()
   {
     return m_value;
   } // value

  private:
   value_type m_value;
}; // IntrusiveValue

class ExternalValue
{
  public:
   typedef long      value_type;

  public:
   ExternalValue (value_type& value)
    : m_value (value)
   {
   } // ExternalValue

   value_type& value_ref ()
   {
     return m_value;
   } // value_ref

   value_type value ()
   {
     return m_value;
   } // value

  private:
   value_type& m_value;
}; // ExternalValue


template <typename ValueHolder>
class AtomicCounter
{
  //
  // types
  //
  public:
   typedef typename ValueHolder::value_type   value_type;
   
  protected:
   typedef ValueHolder                        Value;
   

  private:

  //
  // methods
  //
  public:
   explicit AtomicCounter ()
    : m_value (Value (0))
   {

   } // AtomicCounter

   explicit AtomicCounter (Value& value)
    : m_value (value)
   {

   } // AtomicCounter

   explicit AtomicCounter (value_type& value)
    : m_value (Value (value))
   {

   } // AtomicCounter

   //virtual ~AtomicCounter ()
   //{

   //} // ~AtomicCounter

   value_type increment ()
   {
     return InterlockedIncrement (&m_value.value_ref ());
   } // Increment

   value_type decrement ()
   {
     return InterlockedDecrement (&m_value.value_ref ());
   } // Decrement

   value_type exchange (value_type value)
   {
     return InterlockedExchange (&m_value.value_ref (), value);
   } // Exchange

   Value exchange (const Value& value)
   {
     return Value (InterlockedExchange (&m_value.value_ref (), value.value ()));
   } // Exchange
 
   value_type value ()
   {
     return m_value.value ();
   } // Value

   value_type operator++ ()
   {
     return increment ();
   } // operator++

   value_type operator-- ()
   {
     return decrement ();
   } // operator--

   value_type operator= (value_type value)
   {
     return exchange (value);
   } // operator=

  protected:
               AtomicCounter (const AtomicCounter& right) {};
   AtomicCounter& operator= (const AtomicCounter& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
   Value  m_value;

  private:
}; // AtomicCounter

typedef class AtomicCounter<IntrusiveValue> IntrusiveAtomicCounter;
typedef class AtomicCounter<ExternalValue>  ExternalAtomicCounter;

} // namespace sync {
} // namespace commonlib {

#endif //_commonlib_sync_atomicconter_h_
