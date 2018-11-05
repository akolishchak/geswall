//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _INTERFACE_DATA_BASE_CONNECTION_FACTORY_H_
 #define _INTERFACE_DATA_BASE_CONNECTION_FACTORY_H_
 
#include "sqlexception.h"
 
#include <string>  
#include <boost/smart_ptr.hpp> 

#include "config/inode.h"

using namespace std;
using namespace config;

namespace sql {

class IConnection;
class IConnectionFactory;

class IConnectionFactory
{
  //
  // types
  //
  public:
   typedef boost::shared_ptr<INode>                PtrToINode;
   typedef boost::shared_ptr<IConnection>          PtrToIConnection;
   typedef boost::shared_ptr<IConnectionFactory>   PtrToIConnectionFactory;
   
   class ConnectionHolder
   {
     public:
      ConnectionHolder (IConnectionFactory& connectionFactory, const wstring& connectString) // throw (SQLException)
       : m_connectionFactory (connectionFactory),
         m_connection (connectionFactory.acquireConnection (connectString))
      {
        if (NULL == m_connection.get ())
          throw SQLException (L"ConnectionHolder::ConnectionHolder (): no memory");
      } // ConnectionHolder
      
      virtual ~ConnectionHolder ()
      {
        m_connectionFactory.releaseConnection (m_connection);
      } // ~ConnectionHolder
      
      PtrToIConnection connection () const
      {
        return m_connection;
      } // connection
      
//      operator PtrToIConnection ()
//      {
//        return m_connection;
//      } // operator PtrToIConnection 
      
//      PtrToIConnection& operator* () const
//      {
//        return m_connection;
//      } // operator*
      
      PtrToIConnection operator-> () const
      {
        return m_connection;
      } // operator*
     
     private:
      ConnectionHolder (const ConnectionHolder& right) 
       : m_connectionFactory (right.m_connectionFactory),
         m_connection (right.m_connection)
      {
      } // ConnectionHolder
      
      ConnectionHolder& operator= (const ConnectionHolder& right) 
      { 
        return *this; 
      } // operator=
     
     protected:
      IConnectionFactory& m_connectionFactory;
      PtrToIConnection    m_connection;
   }; // ConnectionHolder

  friend class ConnectionHolder;
     
  protected:
  private:

  //
  // methods
  //
  public:
   static PtrToIConnectionFactory newInstance (const PtrToINode& node);
   static PtrToIConnectionFactory newInstance (const wstring& type);

   virtual ~IConnectionFactory () {};

   virtual  void             freeConnection (const wstring& connectString)          = 0; // throw (SQLException)

  protected:
            IConnectionFactory () {};

   virtual  PtrToIConnection acquireConnection (const wstring& connectString)       = 0; // throw (SQLException)
   virtual  void             releaseConnection (const PtrToIConnection& connection) = 0; // throw (SQLException)

              IConnectionFactory (const IConnectionFactory& right) {};
   IConnectionFactory& operator= (const IConnectionFactory& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IConnectionFactory

} // namespace sql {

#endif // _INTERFACE_DATA_BASE_CONNECTION_FACTORY_H_