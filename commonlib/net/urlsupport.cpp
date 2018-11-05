//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "urlsupport.h"

#ifndef BOOST_REGEX_NO_LIB
 #define BOOST_REGEX_NO_LIB
#endif // BOOST_REGEX_NO_LIB 
#include <boost/regex.hpp>

#include "argumentexception.h"
#include "debug.h"

namespace commonlib {
namespace net {

static boost::wregex url_pattern (L"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?");

bool URLSupport::parse (const wstring& url, wstring& protocol, wstring& authority, wstring& path, wstring& query, wstring& related)
{
  bool           result = false;
  boost::wsmatch what;
  
  if (true == (result = boost::regex_match (url, what, url_pattern, boost::match_default)))
  {
    for (unsigned int i = 0; i < what.size (); ++i)
    {
debugString ((L"\n%u, = %s", i, (wstring (what [i].first, what [i].second)).c_str ()));
      switch (i)
      {
//        case 0:
//             m_url = wstring (what [i].first, what [i].second);
        case 2: // protocol  = $2
             protocol = wstring (what [i].first, what [i].second);
             break;
        case 4: // authority = $4
             authority = wstring (what [i].first, what [i].second);
             break;
        case 5: // path      = $5
             path = wstring (what [i].first, what [i].second); 
             break;
        case 7: // query     = $7
             query = wstring (what [i].first, what [i].second);
             break;
        case 9: // fragment  = $9
             related = wstring (what [i].first, what [i].second);
             break;
      }
    }
  }
  else
  {
    throw ArgumentException (L"bad url syntax");
  }

  return result;
} // URL

} // namespace net {
} // namespace commonlib {
