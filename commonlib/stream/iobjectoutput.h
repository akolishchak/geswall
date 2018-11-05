//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_iobjectoutput_h_
 #define _commonlib_stream_iobjectoutput_h_

#include "idataoutput.h"

namespace commonlib {
namespace stream {

class ISerializable;

class IObjectOutput : public IDataOutput
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
            IObjectOutput () : IDataOutput () {};
            IObjectOutput (const IObjectOutput& right) : IDataOutput (right) {};
   virtual ~IObjectOutput () {};

   virtual bool writeObject (const ISerializable& object) = 0;

  protected:
   IObjectOutput& operator= (const IObjectOutput& right) { return *this; }

  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // IObjectOutput

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_iobjectoutput_h_

