//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_idatatype_h_
 #define _commonlib_stream_idatatype_h_

namespace commonlib {
namespace stream {

class IDataType
{
  //
  // types
  //
  public:
   typedef __int64            longlong;
   typedef unsigned __int64   u_longlong;

  protected:
  private:

  //
  // methods
  //
  public:
            IDataType () {};
            IDataType (const IDataType& right) {};
   virtual ~IDataType () {};

  protected:
   IDataType& operator= (const IDataType& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IDataType

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_idatatype_h_

