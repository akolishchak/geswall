//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "objectstreamsupport.h"
#include "commonlib/outofmemoryexception.h"

#include <boost/smart_ptr.hpp> 

namespace commonlib {
namespace stream {

typedef boost::scoped_array<wchar_t> PtrToWCharArray;

void readString (IObjectInputStream& stream, wstring& data)
{
  size_t length = stream.readInt ();
  if (0 < length)
  {
    PtrToWCharArray buffer (new wchar_t [length]);
    if (NULL == buffer.get ())
      throw OutOfMemoryException (L"commonlib::stream::readString (): no memory");

    length = stream.readUShort (buffer.get (), length);
    if (0 < length)
    {
      while (0 < length && 0 == buffer [length-1])
        --length;
      data.append (buffer.get (), length);
    }
  }
} // readString

void writeString (IObjectOutputStream& stream, const wstring& data)
{
  size_t length = data.size ();
  stream.writeInt (static_cast <int> (length));
  if (0 < length)
    stream.writeUShort (data.c_str (), length);
} // writeString

} // namespace stream {
} // namespace commonlib {
