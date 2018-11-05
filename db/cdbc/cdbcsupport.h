//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _CDBC_SUPPORT_H_
 #define _CDBC_SUPPORT_H_
 
#include <string>
#include <boost/tuple/tuple.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/static_assert.hpp>

#include "iconnection.h"
#include "ipreparedstatement.h"
#include "iresultset.h"
#include "sqldate.h"

using namespace std;
using namespace boost::tuples;
using boost::tuples::cons;
 
namespace sql {

class CDBCSupport;

class CDBCSupport
{
  //
  // types
  //
  public:
   typedef IConnection::PtrToIStatement         PtrToIStatement;
   typedef IConnection::PtrToIPreparedStatement PtrToIPreparedStatement;
   typedef IConnection::PtrToIConnection        PtrToIConnection;
   typedef boost::shared_ptr<IResultSet>        PtrToIResultSet;
   typedef IPreparedStatement::RowId            RowId;
   
   struct blob
   {
     blob (void* buffer, size_t size)
      : m_buffer (reinterpret_cast <unsigned char*> (buffer)), 
        m_size (size),
        m_sizeResult (m_size)
     {
     }
     
     blob (const void* buffer, size_t size)
      : m_buffer (reinterpret_cast <unsigned char*> (const_cast <void*> (buffer))), 
        m_size (size),
        m_sizeResult (m_size)
     {
     }
     
     //blob (unsigned char* buffer, size_t size)
     // : m_buffer (buffer), 
     //   m_size (size),
     //   m_sizeResult (m_size)
     //{
     //}
     
     blob (unsigned char* buffer, size_t size, size_t& sizeResult)
      : m_buffer (buffer), 
        m_size (size),
        m_sizeResult (sizeResult)
     {
     }
     
     unsigned char* m_buffer;
     size_t         m_size;
     size_t&        m_sizeResult;
   }; // blob
   
   struct wstr
   {
     wstr (wchar_t* buffer, size_t size)
      : m_buffer (buffer), 
        m_size (size)
     {
     }
     
     wstr (const wchar_t* buffer, size_t size)
      : m_buffer (const_cast <wchar_t*> (buffer)), 
        m_size (size)
     {
     }
     
     wchar_t* m_buffer;
     size_t   m_size;
   }; // wstr
   
   struct Index
   {
              Index () {};
     virtual ~Index () {};
     
     virtual  int  query ()          = 0;
     virtual  int  get ()            = 0;
     virtual  void set (int index)   = 0;
   }; // Index
   
   struct BinderIndex : public Index
   {
      explicit BinderIndex (int index = 0)
       : Index (),
         m_index (index)
      {
      } // BinderIndex
      
      int query ()
      {
        return ++m_index;
      } // query
      
      int get ()
      {
        return m_index;
      } // get
      
      void set (int index)
      {
        m_index = index;
      } // get
      
     protected:
      int  m_index;
   }; // BinderIndex
   
   struct GetterIndex : public Index
   {
      explicit GetterIndex (int index = -1)
       : Index (),
         m_index (index)
      {
      } // GetterIndex
      
      int query ()
      {
        return ++m_index;
      } // query
      
      int get ()
      {
        return m_index;
      } // get
      
      void set (int index)
      {
        m_index = index;
      } // get
      
     protected:
      int  m_index;
   }; // GetterIndex
   
   struct UserIndex : public Index
   {
      explicit UserIndex (int index = 0)
       : Index (),
         m_index (index)
      {
      } // BinderIndex
      
      int query ()
      {
        return m_index;
      } // query
      
      int get ()
      {
        return m_index;
      } // get
      
      void set (int index)
      {
        m_index = index;
      } // get
      
     protected:
      int  m_index;
   }; // UserIndex

  protected:
  private:

  //
  // methods
  //
  public:
   //CDBCSupport () 
   //{
   //
   //} // CDBCSupport
   //
   //CDBCSupport (const CDBCSupport& right) 
   //{
   //
   //} // CDBCSupport
   //
   //virtual ~CDBCSupport () {};
   //
   //CDBCSupport& operator= (const CDBCSupport& right) 
   //{ 
   //  if (this != &right)
   //  {
   //    this->~CDBCSupport ();
   //    new (this) CDBCSupport (right);
   //  } // if (this != &right)
   //  
   //  return *this; 
   //} // operator=
   
   template <typename Tuple>
   PtrToIResultSet executeQuery (PtrToIConnection& conn, const wstring& sql, const Tuple& params)
   {
     BinderIndex index;
     
     PtrToIPreparedStatement stmt = conn->createPreparedStatement (sql);
     bind<Tuple::head_type, Tuple::tail_type> (cons<Tuple::head_type, Tuple::tail_type> (params.get_head (), params.get_tail ()), stmt, index);
     
     PtrToIResultSet resultSet = stmt->executeQuery ();
  
     if (true == resultSet->next ())
       return resultSet;
  
     return PtrToIResultSet ();
   } // executeQuery

   PtrToIResultSet executeQuery (PtrToIConnection& conn, const wstring& sql)
   {
     PtrToIPreparedStatement stmt = conn->createPreparedStatement (sql);
     
     PtrToIResultSet resultSet = stmt->executeQuery ();
  
     if (true == resultSet->next ())
       return resultSet;
  
     return PtrToIResultSet ();
   } // executeQuery
   
   template <typename Tuple>
   void queryResult (PtrToIResultSet& resultSet, Tuple& paramsOut)
   {
     GetterIndex index;
     
     if (NULL != resultSet.get ())
       get<Tuple::head_type, Tuple::tail_type> (cons<Tuple::head_type, Tuple::tail_type> (paramsOut.get_head (), paramsOut.get_tail ()), resultSet, index);
   } // queryResult
   
   template <typename Tuple>
   RowId executeUpdate (PtrToIConnection& conn, const wstring& sql, const Tuple& params)
   {
     BinderIndex index;
     
     PtrToIPreparedStatement stmt = conn->createPreparedStatement (sql);
     bind<Tuple::head_type, Tuple::tail_type> (cons<Tuple::head_type, Tuple::tail_type> (params.get_head (), params.get_tail ()), stmt, index);
     
     return stmt->executeUpdate ();
   } // execute
   
   //
   // bind support
   //
   
   template <class T>
   inline void bind (T, PtrToIPreparedStatement&, Index&)
   {
     BOOST_STATIC_ASSERT (false);
   } // bind
   
   template <>
   inline void bind<int> (int value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setInt (value, index.query ());
   } // bind
   
   template <>
   inline void bind<unsigned int> (unsigned int value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setInt (value, index.query ());
   } // bind
   
   template <>
   inline void bind<float> (float value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setFloat (value, index.query ());
   } // bind
   
   template <>
   inline void bind<double> (double value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setFloat (value, index.query ());
   } // bind
   
   template <>
   inline void bind<wstring&> (wstring& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setText (value, index.query ());
   } // bind
   
   template <>
   inline void bind<const wstring&> (const wstring& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setText (value, index.query ());
   } // bind
   
   template <>
   inline void bind<wstr&> (wstr& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setText (wstring (value.m_buffer), index.query ());
   } // bind
   
   template <>
   inline void bind<const wstr&> (const wstr& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setText (wstring (value.m_buffer), index.query ());
   } // bind
   
   template <>
   inline void bind<SQLDate&> (SQLDate& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setDate (value, index.query ());
   } // bind

   template <>
   inline void bind<const SQLDate&> (const SQLDate& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setDate (value, index.query ());
   } // bind
   
   template <>
   inline void bind<blob&> (blob& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setBlob (value.m_buffer, value.m_size, index.query ());
   } // bind
   
   template <>
   inline void bind<const blob&> (const blob& value, PtrToIPreparedStatement& stmt, Index& index)
   {
     stmt->setBlob (value.m_buffer, value.m_size, index.query ());
   } // bind

   //
   // get support
   //
   
   template <class T>
   inline void get (T, PtrToIResultSet&, Index&)
   {
     BOOST_STATIC_ASSERT (false);
   } // get

   template <>
   inline void get<int&> (int& value, PtrToIResultSet& rs, Index& index)
   {
     value = rs->getInt (index.query ());
   } // get
   
   template <>
   inline void get<unsigned int&> (unsigned int& value, PtrToIResultSet& rs, Index& index)
   {
     value = rs->getInt (index.query ());
   } // get
   
   template <>
   inline void get<float&> (float& value, PtrToIResultSet& rs, Index& index)
   {
     value = static_cast <float> (rs->getFloat (index.query ()));
   } // get
   
   template <>
   inline void get<double&> (double& value, PtrToIResultSet& rs, Index& index)
   {
     value = rs->getFloat (index.query ());
   } // get
   
   template <>
   inline void get<wstring&> (wstring& value, PtrToIResultSet& rs, Index& index)
   {
     value = rs->getText (index.query ());
   } // get
   
   template <>
   inline void get<wstr&> (wstr& value, PtrToIResultSet& rs, Index& index)
   {
     wstring str = rs->getText (index.query ());
     wcsncpy (value.m_buffer, str.c_str (), value.m_size);
   } // get
   
   template <>
   inline void get<SQLDate&> (SQLDate& value, PtrToIResultSet& rs, Index& index)
   {
     value = rs->getDate (index.query ());
   } // get

   template <>
   inline void get<blob&> (blob& value, PtrToIResultSet& rs, Index& index)
   {
     value.m_sizeResult = rs->getBlob (index.query (), value.m_buffer, value.m_size);
   } // get

 protected: 
   inline void bind (const null_type&, PtrToIPreparedStatement&, Index&) 
   {
   } // bind

   template <class H, class T>
   inline void bind (const cons<H, T>& x, PtrToIPreparedStatement& stmt, Index& index) 
   { 
     bind <cons<H, T>::stored_head_type> (x.get_head (), stmt, index);
     bind (x.get_tail(), stmt, index); 
   } // bind
 
 
   inline void get (const null_type&, PtrToIResultSet&, Index&) 
   {
   } // bind

   template <class H, class T>
   inline void get (const cons<H, T>& x, PtrToIResultSet& rs, Index& index) 
   { 
     get <cons<H, T>::stored_head_type> (x.get_head (), rs, index);
     get (x.get_tail(), rs, index); 
   } // get

  protected:
  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // CDBCSupport

} // namespace sql {

#endif // _CDBC_SUPPORT_H_