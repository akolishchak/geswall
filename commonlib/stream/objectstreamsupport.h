//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_objectstreamsupport_h_
 #define _commonlib_stream_objectstreamsupport_h_

#include "idatatype.h"
#include "iobjectinputstream.h"
#include "iobjectoutputstream.h"

#include <string>

namespace commonlib {
namespace stream {

typedef std::wstring  wstring;
        
void    readString (IObjectInputStream& stream, wstring& data);
void    writeString (IObjectOutputStream& stream, const wstring& data);

} // namespace stream {
} // namespace commonlib {


#endif // _commonlib_stream_objectstreamsupport_h_

