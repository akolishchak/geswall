//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "w32registrynode.h"
#include "commonlib.h"

#include <map>

using namespace std;
using namespace commonlib;

namespace config {

W32RegistryNode::W32RegistryNode (HKEY openedKey, bool close_after_use)
 : INode (),
   m_key (openedKey),
   m_close_after_use (close_after_use)
{
  if (NULL == m_key)
    throw ConfigException (L"W32RegistryNode::W32RegistryNode (): openedKey is NULL");
} // W32RegistryNode

W32RegistryNode::W32RegistryNode (const wstring& keyName, bool create_if_not_exist)
 : INode (),
   m_key (NULL),
   m_close_after_use (true)
{
  m_key = queryKey (keyName, LongToHandle (GetCurrentProcessId ()), create_if_not_exist);
} // W32RegistryNode

W32RegistryNode::W32RegistryNode (const wstring& parentKeyName, const wstring& name, bool create_if_not_exist)
 : INode (),
   m_key (NULL),
   m_close_after_use (true)
{
  W32RegistryNode parent (queryKey (parentKeyName, LongToHandle (GetCurrentProcessId ()), create_if_not_exist), create_if_not_exist);
  m_key = open (parent.getNativeKey (), name, create_if_not_exist);
} // W32RegistryNode

W32RegistryNode::W32RegistryNode (const W32RegistryNode& parentKey, const wstring& name, bool create_if_not_exist)
 : INode (),
   m_key (NULL),
   m_close_after_use (true)
{
  m_key = open (parentKey.getNativeKey (), name, create_if_not_exist);
} // W32RegistryNode

W32RegistryNode::W32RegistryNode (HKEY parentKey, const wstring& name, bool create_if_not_exist)
 : INode (),
   m_key (NULL),
   m_close_after_use (true)
{
  m_key = open (parentKey, name, create_if_not_exist);
} // W32RegistryNode

W32RegistryNode::~W32RegistryNode ()
{
  try
  {
    close ();
  }
  catch (...)
  {
  }
} // ~W32RegistryNode

void W32RegistryNode::close ()
{
  if (true == m_close_after_use)
  {
    if (NULL != m_key)
      RegCloseKey (m_key);
  }

  m_key = NULL;
} // close

void W32RegistryNode::deleteValue (const wstring& name)
{
  RegDeleteValue (m_key, name.c_str ());
} // deleteValue

bool W32RegistryNode::checkValue (const wstring& name)
{
  DWORD type     = 0;
  DWORD dataSize = 0;
  return ERROR_SUCCESS == RegQueryValueEx(m_key, name.c_str(), 0, &type, NULL, &dataSize);
} // checkValue

void W32RegistryNode::cascadeDelete(HKEY hKey)
{
	wchar_t SubKey[300];
	DWORD Index = 0;

	while ( true ) {
		FILETIME LastWriteTime;
		DWORD Length = sizeof SubKey / sizeof SubKey[0];
		LONG rc = RegEnumKeyEx(hKey, Index, SubKey, &Length, NULL, NULL, NULL, &LastWriteTime);
		if ( rc == ERROR_SUCCESS ) {
			HKEY hSubKey;
			rc = RegOpenKeyEx(hKey, SubKey, 0, DELETE | KEY_ENUMERATE_SUB_KEYS, &hSubKey);
			if ( rc == ERROR_SUCCESS ) {
				cascadeDelete(hSubKey);
				RegDeleteKey (hKey, SubKey);
				RegCloseKey(hSubKey);
				Index = 0;
				continue;
			}
		}
		else
			if ( rc == ERROR_NO_MORE_ITEMS ) break;

		Index++;
	}
}

void W32RegistryNode::deleteNode (const wstring& name)
{
  HKEY hkey = open (m_key, name, false);
  cascadeDelete(hkey);
  LONG result = RegDeleteKey (m_key, name.c_str ());
  if (ERROR_SUCCESS != result)
    throw ConfigException (L"W32RegistryNode::deleteNode (): error", result);  
} // deleteNode

bool W32RegistryNode::checkNode (const wstring& name)
{
  HKEY hKey = NULL;
  
  try 
  {
    hKey = open(m_key, name, false);
  } 
  catch ( ... ) 
  {
    return false;
  }
  
  RegCloseKey(hKey);
  
  return true;
} // checkNode

void W32RegistryNode::setString (const wstring& name, const wstring& value)
{
  setString(name, value, REG_SZ);
} // setString

void W32RegistryNode::setString (const wstring& name, const wstring& value, DWORD type)
{
  LONG  result   = ERROR_SUCCESS;
  DWORD dataSize = static_cast <DWORD> ((value.size () + 1) * sizeof (wstring::value_type));
   
  if (ERROR_SUCCESS != (result = RegSetValueEx (m_key, name.c_str (), 0, type, reinterpret_cast <const BYTE*> (value.c_str ()), dataSize)))
    throw ConfigException (L"W32RegistryNode::setString (): error", result);  
} // setString

wstring W32RegistryNode::getString (const wstring& name) const
{
  wstring result;

  DWORD type     = 0;
  DWORD dataSize = 0;
  
  if (
         ERROR_SUCCESS == RegQueryValueEx (m_key, name.c_str (), 0, &type, NULL, &dataSize) 
      && 0 != dataSize
      && (REG_EXPAND_SZ == type || REG_MULTI_SZ == type || REG_SZ == type)
     )
  {
    PtrToWCharArray data (new wchar_t [dataSize]);
    if (NULL != data.get ())
    {
      if (ERROR_SUCCESS == RegQueryValueEx (m_key, name.c_str (), 0, &type, reinterpret_cast <LPBYTE> (data.get ()), &dataSize))
      {
        result.append (data.get ());
      } // if (...)
    } // if (NULL != data.get ())
  } // if (ERROR_SUCCESS == RegQueryValueEx (resultKey, ...) ...)

  return result;
} // getString

void W32RegistryNode::setStrings (const wstring& name, const vector<wstring>& value)
{
  LONG  result   = ERROR_SUCCESS;
  DWORD dataSize = 1;
  for ( vector<wstring>::const_iterator i = value.begin(); i != value.end(); i++ ) {
	dataSize += static_cast <DWORD> (i->size () + 1);
  }

  PtrToWCharArray data (new wchar_t [dataSize]);
  wchar_t *Strings = data.get ();
  for ( i = value.begin(); i != value.end(); i++ ) {
    wcscpy(Strings, i->c_str());
	Strings += i->size() + 1;
  }
  *Strings = 0;

  dataSize *= sizeof wstring::value_type;
   
  if (ERROR_SUCCESS != (result = RegSetValueEx (m_key, name.c_str (), 0, REG_MULTI_SZ, reinterpret_cast <const BYTE*> (data.get ()), dataSize)))
    throw ConfigException (L"W32RegistryNode::setStrings (): error", result);  
} // setStrings

void W32RegistryNode::getStrings (const wstring& name, vector<wstring>& value)
{
  DWORD type     = 0;
  DWORD dataSize = 0;
  
  if (
         ERROR_SUCCESS == RegQueryValueEx (m_key, name.c_str (), 0, &type, NULL, &dataSize) 
      && 0 != dataSize
      && REG_MULTI_SZ == type
     )
  {
    PtrToWCharArray data (new wchar_t [dataSize]);
    if (NULL != data.get ())
    {
      if (ERROR_SUCCESS == RegQueryValueEx (m_key, name.c_str (), 0, &type, reinterpret_cast <LPBYTE> (data.get ()), &dataSize))
      {
	    wchar_t *Strings = data.get ();
		while ( *Strings != 0 ) {
			wstring str(Strings);
			value.push_back(str);
			Strings += str.size() + 1;
		}
      } // if (...)
    } // if (NULL != data.get ())
  } // if (ERROR_SUCCESS == RegQueryValueEx (resultKey, ...) ...)
} // getStrings

void W32RegistryNode::setBool (const wstring& name, bool value)
{
  setUInt (name, static_cast <unsigned int> (value));
} // setBool

bool W32RegistryNode::getBool (const wstring& name) const
{
  return (0 != getUInt (name));
} // getBool

void W32RegistryNode::setInt (const wstring& name, int value)
{
  setUInt (name, static_cast <unsigned int> (value));
} // setInt

int W32RegistryNode::getInt (const wstring& name) const
{
  return static_cast <int> (getUInt (name));
} // getInt

void W32RegistryNode::setUInt (const wstring& name, unsigned int value)
{
  DWORD type     = REG_DWORD;
  LONG  result   = ERROR_SUCCESS;
  DWORD dataSize = sizeof (value);
   
  if (ERROR_SUCCESS != (result = RegSetValueEx (m_key, name.c_str (), 0, type, reinterpret_cast <const BYTE*> (&value), dataSize)))
    throw ConfigException (L"W32RegistryNode::setUInt (): error", result);  
} // setUInt

unsigned int W32RegistryNode::getUInt (const wstring& name) const
{
  unsigned int result = 0;

  DWORD type     = 0;
  DWORD dataSize = 0;
  
  if (
         ERROR_SUCCESS == RegQueryValueEx (m_key, name.c_str (), 0, &type, NULL, &dataSize) 
      && sizeof (unsigned int) == dataSize
      && REG_DWORD == type
     )
  {
    RegQueryValueEx (m_key, name.c_str (), 0, &type, reinterpret_cast <LPBYTE> (&result), &dataSize);
  } // if (ERROR_SUCCESS == RegQueryValueEx (resultKey, ...) ...)

  return result;
} // getUInt

void W32RegistryNode::setBinary (const wstring& name, const unsigned char* buffer, size_t bufSize)
{
  DWORD type     = REG_BINARY;
  LONG  result   = ERROR_SUCCESS;
  DWORD dataSize = static_cast <DWORD> (bufSize);
   
  if (
         0 > bufSize
      || NULL == buffer
      || ERROR_SUCCESS != (result = RegSetValueEx (m_key, name.c_str (), 0, type, reinterpret_cast <const BYTE*> (buffer), dataSize))
     )
    throw ConfigException (L"W32RegistryNode::setBinary (): error", result);  
} // setBinary

size_t W32RegistryNode::getBinary (const wstring& name, unsigned char* buffer, size_t bufSize) const
{
  size_t result   = 0;

  DWORD  type     = 0;
  DWORD  dataSize = 0;
  
  if (
         0 < bufSize
      && NULL != buffer
      && ERROR_SUCCESS == RegQueryValueEx (m_key, name.c_str (), 0, &type, NULL, &dataSize) 
      && 0 < dataSize
      && REG_BINARY == type
     )
  {
    dataSize = static_cast <DWORD> ((dataSize < bufSize ? dataSize : bufSize));
    if (ERROR_SUCCESS == RegQueryValueEx (m_key, name.c_str (), 0, &type, reinterpret_cast <LPBYTE> (buffer), &dataSize))
      result = dataSize;
  } // if (ERROR_SUCCESS == RegQueryValueEx (resultKey, ...) ...)

  return result;
} // getBinary
 
W32RegistryNode::PtrToINode W32RegistryNode::getNode (const wstring& name, bool create_if_not_exist)
{
  return PtrToINode (new W32RegistryNode (open (m_key, name, create_if_not_exist), true));
} // getNode

HKEY W32RegistryNode::open (const HKEY parentKey, const wstring& name, bool create_if_not_exist)
{
  if (NULL == parentKey)
    throw ConfigException (L"W32RegistryNode::open (): parentKey is NULL");

  HKEY  key         = NULL;
  LONG  result      = ERROR_SUCCESS;
  DWORD disposition = 0;
  
  if (true == create_if_not_exist)
  {
    if (ERROR_SUCCESS != (result = RegCreateKeyEx (parentKey, name.c_str (), 0, NULL, REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, &key, &disposition)))
      throw ConfigException (wstring (L"W32RegistryNode::open (): RegCreateKeyEx error: ") + name, result);
  }  
  else
  {
    if (ERROR_SUCCESS != (result = RegOpenKeyEx (parentKey, name.c_str (), 0, MAXIMUM_ALLOWED, &key)))
      throw ConfigException (wstring (L"W32RegistryNode::open (): RegOpenKeyEx error: ") + name, result);
  }

  return key;
} // open

HKEY W32RegistryNode::queryKey (const wstring& data, HANDLE processId, bool create_if_not_exist)
{
  typedef map<const wstring, HKEY>    KeyResolver;
  
  static KeyResolver::value_type keys [] =
  {
    KeyResolver::value_type (wstring (L"HKCR"),                  HKEY_CLASSES_ROOT),
    KeyResolver::value_type (wstring (L"HKEY_CLASSES_ROOT"),     HKEY_CLASSES_ROOT),
    KeyResolver::value_type (wstring (L"HKCC"),                  HKEY_CURRENT_CONFIG),
    KeyResolver::value_type (wstring (L"HKEY_CURRENT_CONFIG"),   HKEY_CURRENT_CONFIG),
    KeyResolver::value_type (wstring (L"HKCU"),                  HKEY_USERS), //HKEY_CURRENT_USER),
    KeyResolver::value_type (wstring (L"HKEY_CURRENT_USER"),     HKEY_USERS), //HKEY_CURRENT_USER),
    KeyResolver::value_type (wstring (L"HKLM"),                  HKEY_LOCAL_MACHINE),
    KeyResolver::value_type (wstring (L"HKEY_LOCAL_MACHINE"),    HKEY_LOCAL_MACHINE),
    KeyResolver::value_type (wstring (L"HKU"),                   HKEY_USERS),
    KeyResolver::value_type (wstring (L"HKEY_USERS"),            HKEY_USERS),
    KeyResolver::value_type (wstring (L"HKPD"),                  HKEY_PERFORMANCE_DATA),
    KeyResolver::value_type (wstring (L"HKEY_PERFORMANCE_DATA"), HKEY_PERFORMANCE_DATA),
    KeyResolver::value_type (wstring (L""),                      HKEY_LOCAL_MACHINE) // for correct init map need empty last element
  };
  
  static KeyResolver  keyResolver (&keys [0], &keys [sizeof (keys) / sizeof (KeyResolver::value_type) - 1]); // 11
  
  wstring key;
  wstring path;
  
  size_t beginKeyIndex = 0;
  size_t endKeyIndex   = 0;
  
  if (wstring::npos != (endKeyIndex = data.find (L'\\', beginKeyIndex)))  
  {
    key  = data.substr (beginKeyIndex, endKeyIndex-beginKeyIndex);
    path = data.substr (endKeyIndex+1);
  }
  else
  {
    key  = data;
  }

  HKEY resultKey = NULL;
  
  if (0 != key.size ())
  {
    KeyResolver::iterator i = keyResolver.find (key);
    if (i != keyResolver.end ())
    {
      if (0 == ((*i).first).compare (L"HKCU") || 0 == ((*i).first).compare (L"HKEY_CURRENT_USER"))
      {
        wstring sid = querySid (processId);
        path = sid + wstring (L"\\") + path;
      }
      
      HKEY  rootKey  = (*i).second;
      LONG  result   = ERROR_SUCCESS;
      
      if (0 != path.size ())
      {
        resultKey = open (rootKey, path, create_if_not_exist);
      }
      else
      {
        resultKey = rootKey;
      }  
    } // if (i != keyResolver.end ())
    else
    {
      throw ConfigException (L"W32RegistryNode::queryParentKey (): bad parent key name");
    }
  } // if (0 != key.size () && 0 != path.size () && 0 != value.size ())
  else
  {
    throw ConfigException (L"W32RegistryNode::queryParentKey (): bad parent key name");
  }

  return resultKey;
} // queryKey

}; // namespace config {