//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _CONFIG_W32_REGISTRY_NODE_H_
 #define _CONFIG_W32_REGISTRY_NODE_H_

#include <windows.h>

#include "inode.h"

#include <vector>

using namespace std;
 
namespace config {

class W32RegistryNode;


class W32RegistryNode : public INode
{
  //
  // types
  //
  public:
   typedef INode::PtrToINode            PtrToINode;
   typedef boost::shared_array<wchar_t> PtrToWCharArray;

  protected:
  private:

  //
  // methods
  //
  public:
   explicit W32RegistryNode (HKEY openedKey, bool close_after_use = true);
   explicit W32RegistryNode (const wstring& keyName, bool create_if_not_exist);
            W32RegistryNode (const wstring& parentKeyName, const wstring& name, bool create_if_not_exist);
            W32RegistryNode (const W32RegistryNode& parentKey, const wstring& name, bool create_if_not_exist);
            W32RegistryNode (HKEY parentKey, const wstring& name, bool create_if_not_exist = true);
   virtual ~W32RegistryNode ();
   
   virtual  void       close ();

   virtual  void       deleteValue (const wstring& name);
   virtual  bool	   checkValue (const wstring& name);
   virtual  void       deleteNode (const wstring& name);
   virtual  bool	   checkNode (const wstring& name);

   virtual  void       setString (const wstring& name, const wstring& value);
   virtual  void       setString (const wstring& name, const wstring& value, DWORD type);
   virtual  wstring    getString (const wstring& name) const;

   virtual  void	   setStrings (const wstring& name, const vector<wstring>& value);
   virtual  void	   getStrings (const wstring& name, vector<wstring>& value);

   virtual  void       setBool (const wstring& name, bool value);
   virtual  bool       getBool (const wstring& name) const;
   
   virtual  void       setInt (const wstring& name, int value);
   virtual  int        getInt (const wstring& name) const;

   virtual  void       setUInt (const wstring& name, unsigned int value);
   virtual  unsigned int getUInt (const wstring& name) const;

   virtual  void       setBinary (const wstring& name, const unsigned char* buffer, size_t bufSize); 
   virtual  size_t     getBinary (const wstring& name, unsigned char* buffer, size_t bufSize) const;

   virtual  PtrToINode getNode (const wstring& name, bool create_if_not_exist);
   
            const HKEY getNativeKey () const { return m_key; };
            
  protected:
              W32RegistryNode (const W32RegistryNode& right) {};
   W32RegistryNode& operator= (const W32RegistryNode& right) { return *this; }

            HKEY       open (const HKEY parentKey, const wstring& name, bool create_if_not_exist);
            HKEY       queryKey (const wstring& data, HANDLE processId, bool create_if_not_exist);

  private:
  
  //
  // data
  //
  public:
  protected:
   HKEY   m_key;
   bool   m_close_after_use;

  private:
	static void cascadeDelete(HKEY hKey);
}; // W32RegistryNode

} // namespace config {

#endif // _CONFIG_W32_REGISTRY_NODE_H_