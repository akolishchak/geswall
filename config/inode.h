//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _INTERFACE_CONFIG_NODE_H_
 #define _INTERFACE_CONFIG_NODE_H_

#include <string>
#include <vector>
#include <boost/smart_ptr.hpp> 

#include "configexception.h"

using namespace std;
 
namespace config {

class INode;

class INode
{
  //
  // types
  //
  public:
   typedef boost::shared_ptr<INode>   PtrToINode;

  protected:
  private:

  //
  // methods
  //
  public:
            INode () {};
   virtual ~INode () {};

   virtual  void       close ()                                                = 0;

   virtual  void       deleteValue (const wstring& name)                       = 0;
   virtual  bool	   checkValue (const wstring& name)						   = 0;
   virtual  void       deleteNode (const wstring& name)                        = 0;
   
   virtual  void       setString (const wstring& name, const wstring& value)   = 0;
   virtual  wstring    getString (const wstring& name) const                   = 0;

   virtual  void	   setStrings (const wstring& name, const vector<wstring>& value) = 0;
   virtual  void	   getStrings (const wstring& name, vector<wstring>& value) = 0;

   virtual  void       setBool (const wstring& name, bool value)               = 0;
   virtual  bool       getBool (const wstring& name) const                     = 0;
   
   virtual  void       setInt (const wstring& name, int value)                 = 0;
   virtual  int        getInt (const wstring& name) const                      = 0;

   virtual  void       setUInt (const wstring& name, unsigned int value)       = 0;
   virtual  unsigned int getUInt (const wstring& name) const                   = 0;

   virtual  void       setBinary (const wstring& name, const unsigned char* buffer, size_t bufSize) = 0; 
   virtual  size_t     getBinary (const wstring& name, unsigned char* buffer, size_t bufSize) const = 0;

   virtual  PtrToINode getNode (const wstring& name, bool create_if_not_exist) = 0;
   
  protected:
              INode (const INode& right) {};
   INode& operator= (const INode& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // INode

} // namespace config {

#endif // _INTERFACE_CONFIG_NODE_H_