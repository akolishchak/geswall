//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _INTERFACE_FILE_MEMORY_MAPPING_H_
 #define _INTERFACE_FILE_MEMORY_MAPPING_H_
 
namespace commonlib {

namespace mmap {


class IFileMMap
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
            IFileMMap () {};
   virtual ~IFileMMap () {};
   
   virtual  void      close ()                                        = 0;
   virtual  void*     map (void* start, size_t length, size_t offset) = 0;
   virtual  void      unmap (size_t length)                           = 0;
   
   virtual  size_t    viewSize ()                                     = 0;
   

  protected:
               IFileMMap (const IFileMMap& right) {};
   IFileMMap& operator= (const IFileMMap& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // IFileMMap

} // namespace mmap {

} // namespace commonlib {

#endif // _INTERFACE_FILE_MEMORY_MAPPING_H_