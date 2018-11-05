//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "gswclient_helper.h"
#include "commonlib/commondefs.h"

namespace gswui {
namespace gswclient_helper {

typedef commonlib::PtrToByte    ptr_to_byte;

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

GswClient  m_client;
wstring    m_authority_hash;

GswClient& get_client ()
{
    return m_client;
} // get_client

wstring& get_authority ()
{
    return m_authority_hash;
} // get_authority

} // namespace gswclient_helper {
} // namespace gswui {

