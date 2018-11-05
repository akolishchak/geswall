//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "iconnectionfactory.h"
#include "sqliteconnectionfactory.h"

using namespace std;
using namespace config;

namespace sql {

static const wstring ConfigFactoryType (L"type");

IConnectionFactory::PtrToIConnectionFactory IConnectionFactory::newInstance (const PtrToINode& node)
{
  if (NULL == node.get ())
    throw SQLException (L"IConnectionFactory::newInstance (): bad config node");

  wstring type = node->getString (ConfigFactoryType);

  if (type.compare (L"SQLiteConnectionFactory"))
  {
    return PtrToIConnectionFactory (new SQLiteConnectionFactory (node));
  }

  //throw SQLException (L"IConnectionFactory::newInstance (): bad data base factory type");
  return PtrToIConnectionFactory (new SQLiteConnectionFactory (node));
} // newInstance

IConnectionFactory::PtrToIConnectionFactory IConnectionFactory::newInstance (const wstring& type)
{
  if (type.compare (L"SQLiteConnectionFactory"))
  {
    return PtrToIConnectionFactory (new SQLiteConnectionFactory ());
  }

  //throw SQLException (L"IConnectionFactory::newInstance (): bad data base factory type");
  return PtrToIConnectionFactory (new SQLiteConnectionFactory ());
} // newInstance

} // namespace sql {