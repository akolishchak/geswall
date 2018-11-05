//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_iobjectinput_h_
 #define _commonlib_stream_iobjectinput_h_

#include "idatainput.h"

namespace commonlib {
namespace stream {

class ISerializable;

class IObjectInput : public IDataInput
{
  //
  // types
  //
  public:
  protected:
  private:

  //
  // methods
  //
  public:
            IObjectInput () : IDataInput () {};
            IObjectInput (const IDataInput& right) : IDataInput (right) {};
   virtual ~IObjectInput () {};

   virtual bool readObject (ISerializable& object) = 0;

  protected:
   IObjectInput& operator= (const IObjectInput& right) { return *this; }

  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // IObjectInput

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_iobjectinput_h_

