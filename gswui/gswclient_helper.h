//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_gswclient_helper_h__
 #define __gswui_gswclient_helper_h__

#include "stdafx.h"

#include "gswclient.h"

#include <string>
 
namespace gswui {
namespace gswclient_helper {

typedef std::wstring            wstring;


GswClient& get_client ();
wstring&   get_authority ();

} // namespace gswclient_helper {
} // namespace gswui {

#endif // __gswui_gswclient_helper_h__