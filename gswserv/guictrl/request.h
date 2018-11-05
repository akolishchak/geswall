//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_REQUEST_H_
 #define _GUICTRL_REQUEST_H_

#include <boost/smart_ptr.hpp> 
#include <boost/detail/atomic_count.hpp>

namespace gswserv {
namespace guictrl {

class Request;

class Request 
{
  public: 
   typedef boost::shared_ptr<Request>            PtrToRequest;
   typedef boost::detail::atomic_count           atomic_count;
  
  public:
   Request ()
    : m_id (static_cast <int> (++m_idCounter))//,
//      m_parentRequestId (-1)
   {
   } // Request

//   Request (int parentRequestId)
//    : m_id (static_cast <int> (++m_idCounter)),
//      m_parentRequestId (parentRequestId)
//   {
//   } // Request

   Request (const Request& right) 
    : m_id (right.m_id)//,
//      m_parentRequestId (right.m_parentRequestId)
   {
   } // Request

   Request& operator= (const Request& right) 
   { 
     if (this != &right)
       Request (right).swap (*this);
     
     return *this; 
   } // operator=

   virtual ~Request ()
   {
   } // ~Request

   int getId () const
   {
     return m_id;
   } // getId

//   int getParentRequestId () const // for response only
//   {
//     return m_parentRequestId;
//   } // getRequestId

  protected:
   void swap (Request& right)
   {
     int id     = m_id;
               
     m_id       = right.m_id;

     right.m_id = id;
   } // swap

  private:
   int          m_id;
//   const  int          m_parentRequestId; // for response only
   static atomic_count m_idCounter;
}; // Request

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_REQUEST_H_
