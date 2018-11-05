//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_net_url_h_
 #define _commonlib_net_url_h_

#include <boost/smart_ptr.hpp> 
#include <string>

#include "iurlhandlerfactory.h"
#include "iurlhandler.h"
#include "iurlconnection.h"

namespace commonlib {
namespace net {

class URL;

class URL
{
  //
  // types
  //
  public:
   typedef IURLHandler::PtrToIURLConnection      PtrToIURLConnection; 
   
  protected:
   typedef boost::shared_ptr<IURLHandlerFactory> PtrToIURLHandlerFactory;
   
   typedef std::wstring                          wstring;
   

  private:

  // sample URL: "http://user:pwd@www.site.com:80/test?_query_"
  // protocol:   http
  // authority:  user:pwd@www.site.com:80
  // file:       /test?_query_
  // host:       www.site.com
  // port:       80
  // query:      _query_
  // path:       /test
  // userinfo:   user:pwd
  //
  // regexp:     ^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
  // result:     scheme    = $2
  //             authority = $4
  //             path      = $5
  //             query     = $7
  //             fragment  = $9
  // regexp ex.: http://www.ics.uci.edu/pub/ietf/uri/#Related
  // result:     $1 = http:
  //             $2 = http
  //             $3 = //www.ics.uci.edu
  //             $4 = www.ics.uci.edu
  //             $5 = /pub/ietf/uri/
  //             $6 = <undefined> (?query)
  //             $7 = <undefined> (query)
  //             $8 = #Related
  //             $9 = Related



  //
  // methods
  //
  public:
            URL (const wstring& url);
            URL (const URL& right);
   virtual ~URL ();
   
            URL&                operator= (const URL& right);
   
            const wstring&      toString () const;
            PtrToIURLConnection openConnection ();
   
  protected:
   void swap (URL& right)
   {
     m_url.swap (right.m_url);
     m_protocol.swap (right.m_protocol); 
     m_authority.swap (right.m_authority);
     m_file.swap (right.m_file);
     m_host.swap (right.m_host);
     m_port.swap (right.m_port);
     m_query.swap (right.m_query);
     m_path.swap (right.m_path);
     m_userinfo.swap (right.m_userinfo);
     m_related.swap (right.m_related);
   } // swap
              

  private:
  
  //
  // data
  //
  public:
  protected:
   wstring        m_url;
   wstring        m_protocol;
   wstring        m_authority;
   wstring        m_file;
   wstring        m_host;
   wstring        m_port;
   wstring        m_query;
   wstring        m_path;
   wstring        m_userinfo;
   wstring        m_related;
   
  private:
   static PtrToIURLHandlerFactory m_handlerFactory;
}; // URL

} // namespace net {
} // namespace commonlib {

#endif // _commonlib_net_url_h_