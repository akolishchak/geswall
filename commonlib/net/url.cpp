//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "url.h"
#include "urlsupport.h"

#include "argumentexception.h"

#ifdef WIN32
 #include "urlhandlerfactoryw32.h"
#else
 ;
#endif // WIN32


namespace commonlib {
namespace net {

URL::PtrToIURLHandlerFactory URL::m_handlerFactory (new URLHandlerFactoryW32 ());

URL::URL (const wstring& url)
{
  URLSupport::parse (url, m_protocol, m_authority, m_path, m_query, m_related);
  m_url = url;
  
  if (0 >= m_protocol.size ())
    throw ArgumentException (L"unknown protocol");
} // URL

URL::URL (const URL& right)
 : m_url (right.m_url),
   m_protocol (right.m_protocol),
   m_authority (right.m_authority),
   m_file (right.m_file),
   m_host (right.m_host),
   m_port (right.m_port),
   m_query (right.m_query),
   m_path (right.m_path),
   m_userinfo (right.m_userinfo),
   m_related (right.m_related)
{

} // URL

URL::~URL ()
{
} // ~URL

URL& URL::operator= (const URL& right)
{
  if (this != &right)
    URL (right).swap (*this);
  
  return *this;
} // operator=

const URL::wstring& URL::toString () const
{
  return m_url;
} // toString

URL::PtrToIURLConnection URL::openConnection ()
{
  PtrToIURLConnection connection = (m_handlerFactory->getHandler (m_protocol)).openConnection (*this);
  if (NULL != connection.get ())
    connection->connect ();
  return connection;
} // openConnection

} // namespace net {
} // namespace commonlib {
