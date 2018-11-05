//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GSW_COMMON_DEFS_H_
 #define _GSW_COMMON_DEFS_H_

#include <boost/smart_ptr.hpp> 
#include <boost/enable_shared_from_this.hpp> 
#include <boost/detail/atomic_count.hpp>
#include <boost/bind.hpp>
//#include <boost/type_traits/is_reference.hpp>
//#include <boost/mpl/if.hpp>

#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define __WARNING__ __FILE__ "("__STR1__(__LINE__)") : "
#define __ERROR__ __FILE__ "("__STR1__(__LINE__)") : "

//#include <boost/thread/mutex.hpp>
#include "exception.h"
#include "syncobject.h"
#include "atomicconter.h"

 
namespace commonlib {

template<class T, size_t N>
char(&lenghtOf(T(&)[N]))[N];

#define lenghtOf(arr) sizeof(commonlib::lenghtOf(arr))

typedef boost::shared_array<unsigned char> PtrToUCharArray;
typedef boost::shared_array<BYTE>          PtrToByte;
typedef boost::shared_array<wchar_t>       PtrToWcharArray;


//
// sync object typedefs
//

//typedef boost::mutex                       SyncObject;
//typedef boost::mutex::scoped_lock          Locker;
typedef boost::detail::atomic_count        AtomicCounter;

typedef sync::SyncObject                   SyncObject;
typedef sync::SyncObject::Locker           Locker;
typedef sync::IntrusiveAtomicCounter       IntrusiveAtomicCounter;
typedef sync::ExternalAtomicCounter        ExternalAtomicCounter;

//
// sync object typedefs end
//

template <typename ObjectType>
class AbstractLocker
{
  public:
   AbstractLocker (ObjectType& sync)
    : m_sync (sync)
   {
     m_sync.lock ();
   }

   ~AbstractLocker ()
   {
     m_sync.unlock ();
   }

  protected:
           AbstractLocker (const AbstractLocker& right) {};
   AbstractLocker& operator= (const AbstractLocker& right) { return *this; }

  private:
   ObjectType& m_sync;
}; // AbstractLocker

namespace sguard {

template <typename type>
struct is_null_ref
{
  bool operator() (const type& _object) const
  {
    return false;
  } // operator()
}; // is_null_ref

template <
  typename type, 
  typename type value
>
struct is_null_equal
{
  bool operator() (const type& _object) const
  {
    return (value == _object);
  } // operator()
}; // is_null_equal

template <
  typename type, 
  typename type value
>
struct is_null_non_equal
{
  bool operator() (const type& _object) const
  {
    return (value != _object);
  } // operator()
}; // is_null_equal

class object_base
{
  public:
   bool is_free () const
   { 
     return m_released;
   } // isReleased
   
   void release ()
   {
     m_released = true;
   } // release
   
   virtual void free () = 0;
   
  protected: 
   object_base ()
    : m_released (true)
   {
   
   } // object_base
   
   object_base (object_base& right)
    : m_released (true)
   {
     swap (right);
   } // object_base
   
   virtual ~object_base ()
   {
   
   } // ~object_base
   
   object_base& operator= (object_base& right) 
   { 
     return swap (right);
   } // operator=
  
   object_base& swap (object_base& right)
   {
     if (this != &right)
     {
       bool      released = right.m_released;
       right.m_released   = m_released;
       m_released         = released;
     }
     
     return *this;
   } // swap
   
  protected:
   mutable bool m_released;
}; // object_base

template <
  typename type, 
  typename function
>
class object : public object_base
{
  public:
   object ()
    : object_base ()
   {
   
   } // object
   
   object (const function& termFunc)
    : object_base (),
      m_termFunc (termFunc)
   {
   
   } // object
   
   object (const type& _object, const function& termFunc)
    : object_base (),
      m_object (_object),
      m_termFunc (termFunc)
   {
     m_released = false;
   } // object
   
   object (object& right)
    : object_base (right)
   {
     swap (right);
   } // object

   ~object ()
   {
     try
     {
       free ();
     }
     catch (...)
     {
     }
   } // ~object
   
   object& operator= (object& right) 
   { 
     return swap (right);
   } // operator=

   object& swap (object& right)
   {
     object_base::swap (right);
     if (this != &right)
     {
       type      object   = right.m_object;
       function  termFunc = right.m_termFunc;
     
       right.m_object     = m_object;
       right.m_termFunc   = m_termFunc;
     
       m_object           = object;
       m_termFunc         = termFunc;
     }
     
     return *this;
   } // swap
   
   void free ()
   {
     if (false == m_released)
     {
       m_released = true;
       m_termFunc (m_object);
     }  
   } // free
   
   type get () const
   {
     if (true == m_released)
       throw Exception (L"object<>::get (): bad object");
       
     return m_object;
   } // get
   
   operator type () const
   {
     return get ();
   } // operator type

  protected:

  protected:
   type       m_object;
   function   m_termFunc;
}; // object

template <
  typename type, 
  typename function, 
  typename is_null
>
class object_checked : public object <type, function>
{
  public:
   object_checked ()
    : object <type, function> ()
   {
   
   } // object_checked
   
   object_checked (const function& termFunc)
    : object <type, function> (termFunc)
   {
   
   } // object_checked
   
   object_checked (const type& _object, const function& termFunc, const is_null& null_checker)
    : object <type, function> (_object, termFunc)
   {
     m_released = null_checker (m_object);
   } // object
   
   object_checked (object& right)
    : object <type, function> (right)
   {
     swap (right);
   } // object

   ~object_checked ()
   {

   } // ~object_checked
   
   object_checked& operator= (object_checked& right) 
   { 
     swap (right);
     return *this;
   } // operator=

  protected:
  private:
}; // object

template <
  typename type, 
  typename function, 
  typename type_traits
>
object_checked <type, function, type_traits>
make_guard_chk (const type& parm, const function& fun, const type_traits& traits)
{
  return object_checked <type, function, type_traits> (parm, fun, traits);
} // make_guard_chk

template <
  typename type, 
  typename function
>
object <type, function>
make_guard (const type& parm, const function& fun)
{
  return object <type, function> (parm, fun);
} // make_guard

typedef object_base& scope_guard;

} // namespace sguard {

} // namespace commonlib {

#endif // _GSW_COMMON_DEFS_H_