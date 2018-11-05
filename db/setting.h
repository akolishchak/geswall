//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __storage_setting_h__
#define __storage_setting_h__

#include "cdbc/iconnectionfactory.h"
#include "config/inode.h"

#include <string>

using namespace sql;
using namespace std;
using namespace config;

namespace Storage {

class Setting
{
  public:
   typedef IConnectionFactory::PtrToIConnectionFactory  PtrToIConnectionFactory;
   typedef INode::PtrToINode                            PtrToINode;

  public:
   static void init (const PtrToINode& node);

   static void setConnectonFactory (const wstring& factory);
   static void setConnectString (const wstring& connectString);
   static void freeConnection ();

   static IConnectionFactory& getConnectonFactory ();
   static wstring&            getConnectString ();

  protected:
            Setting () {};
   virtual ~Setting () {};

            Setting (const Setting& right) {};
   Setting& operator= (const Setting& right) { return *this; }

  protected:
   static PtrToIConnectionFactory m_connFactory;
   static wstring                 m_connectString;
}; // Setting

} // namespace Storage {

#endif // __storage_setting_h__