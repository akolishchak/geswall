//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_stream_iserializable_h_
 #define _commonlib_stream_iserializable_h_

namespace commonlib {
namespace stream {

class IDataType;
class IObjectInputStream;
class IObjectOutputStream;

class ISerializable
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
   virtual ~ISerializable () {};

   virtual bool readObject (IObjectInputStream& stream)         = 0;
   virtual bool writeObject (IObjectOutputStream& stream) const = 0;

  protected:
   ISerializable () {};
   ISerializable (const ISerializable& right) {};
   ISerializable& operator= (const ISerializable& right) { return *this; }

  private:

  
  //
  // data
  //
  public:
  protected:
  private:
}; // ISerializable

} // namespace stream {
} // namespace commonlib {

#endif // _commonlib_stream_iserializable_h_

