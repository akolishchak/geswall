//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "setting.h"

using namespace std;
using namespace config;

namespace Storage {

Setting::PtrToIConnectionFactory Setting::m_connFactory (IConnectionFactory::newInstance (wstring (L"SQLiteConnectionFactory")));
wstring                          Setting::m_connectString (L"geswall.dat");

void Setting::init (const PtrToINode& node)
{
  m_connFactory = IConnectionFactory::newInstance (node);
  setConnectString (node->getString (wstring (L"connectString")));
} // init

void Setting::setConnectonFactory (const wstring& factory)
{
  m_connFactory = IConnectionFactory::newInstance (factory);
} // setConnectonFactory

void Setting::setConnectString (const wstring& connectString)
{
  freeConnection ();
  m_connectString = connectString;
} // setConnectString

void Setting::freeConnection ()
{
  m_connFactory->freeConnection (m_connectString);
} // freeConnection


IConnectionFactory& Setting::getConnectonFactory ()
{
  return *m_connFactory;
} // getConnectonFactory

wstring& Setting::getConnectString ()
{
  return m_connectString;
} // getConnectString

} // namespace Storage {