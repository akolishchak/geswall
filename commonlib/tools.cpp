//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <winsock2.h>
#include <ws2tcpip.h>

#include <sddl.h>
#include <lm.h>
#include "tools.h"
#include "gswdrv.h"
#include "macroresolver.h"
#include "commonlib.h" 
#include "verinfo.h"
#include "nttools.h"
#include "app/application.h"
#include "config/w32registrynode.h"
#include <psapi.h>

#include <utility>
#include <map>

using namespace std;
using namespace nttools;
using namespace macro;
using namespace commonlib;

namespace commonlib {
namespace Tools {

typedef boost::shared_array<wchar_t>       PtrToWCharArray;
typedef boost::shared_array<unsigned char> PtrToUCharArray;

class TokenHandler
{
  protected:
   enum Action
   {
     Nothing,
     CallFunc,
     ReturnValue
   };
   
  public:
   TokenHandler () 
    : m_pFun (NULL),
      m_action (Nothing)
   {
   } // TokenHandler
   
   explicit TokenHandler (const wstring& value) 
    : m_value (value),
      m_action (ReturnValue)
   {
      
   } // TokenHandler
   
   explicit TokenHandler (bool (*pFun) (const wstring&, wstring&, HANDLE)) 
    : m_pFun (pFun),
      m_action (CallFunc)
   {
      
   } // TokenHandler
      
   bool operator () (const wstring& macro, wstring& result, HANDLE processId) const 
   { 
     if (CallFunc == m_action)
       return (*m_pFun) (macro, result, processId); 
     
     if (ReturnValue == m_action)
     {  
       result.append (m_value);  
       return true;
     }
     
     return false;
   } // operator ()
   
  private:
   
  private:
   Action    m_action;
   bool    (*m_pFun) (const wstring&, wstring&, HANDLE);
   wstring   m_value;
}; // TokenHandler

typedef map<const wstring, TokenHandler>    TokenResolver;

bool   onCurrentUserResolver (const wstring& macro, wstring& result, HANDLE processId);
bool   onCurrentControlSetResolver (const wstring& macro, wstring& result, HANDLE processId);

size_t processToken (wstring& result, const wstring& data, HANDLE processId, unsigned int deep, TokenResolver& resolver);

//******************************************************************************//
//******************************************************************************//
//******************************************************************************//

wstring FullNameToDOSName (const wstring& fullName)
{
  wstring dosName;
  FullNameToDOSName (dosName, fullName);
  return dosName;
} // FullNameToDOSName

size_t FullNameToDOSName (wstring& dosName, const wstring& fullName)
{
  size_t  nameSize    = fullName.size ();
  size_t  dosNameSize = dosName.size ();
  DWORD   size        = GetLogicalDriveStrings (NULL, 0);

  if (0 != size)
  {
    PtrToWCharArray buffer (new wchar_t [size+1]);
    if (NULL != buffer.get ())
    {
      size = GetLogicalDriveStrings (size, buffer.get ());
      if (0 != size)
      {
        wchar_t* link = buffer.get ();
        while (0 != *link)
        {
          size_t  linkSize = wcslen (link);
          wstring linkStr;
          
          linkStr.append (link, linkSize - 1);
          
          wstring linkTarget = DOSNameToFullName (linkStr);
          size_t  targetSize = linkTarget.size ();
          if (0 < targetSize && 0 == linkTarget.compare (0, min (targetSize, nameSize), fullName, 0, min (targetSize, nameSize)))
          {
            dosName.append (linkStr);
            dosName.append (fullName.c_str () + min (targetSize, nameSize));
            break;
          }
          link += (linkSize + 1);
        } // while (0 != *link)
      } // if (0 != size)
    } // if (NULL != buffer)
  } // if (0 != size)

  if ( dosName.size () == 0 && fullName.find(L"\\??\\") == 0 ) {
	  dosName = fullName;
	  dosName.erase(0, 4);
  }

  return (dosName.size () - dosNameSize);
} // FullNameToDOSName

wstring FullNameToUNCName (const wstring& fullName)
{
  wstring uncName;
  FullNameToUNCName (uncName, fullName);
  return uncName;
} // FullNameToUNCName

size_t FullNameToUNCName (wstring& uncName, const wstring& fullName)
{
  static wstring  uncPrefix (L"\\Device\\LanmanRedirector");
  static size_t   uncPrefixSize = sizeof (L"\\Device\\LanmanRedirector") / sizeof (wchar_t) - 1;
  
  size_t  nameSize    = fullName.size ();
  size_t  uncNameSize = uncName.size ();
  
  if (0 == fullName.compare (0, min (uncPrefixSize, nameSize), uncPrefix, 0, min (uncPrefixSize, nameSize)))
  {
    uncName.append (L"\\");
    uncName.append (fullName.c_str () + min (uncPrefixSize, nameSize));
  }
  
  return (uncName.size () - uncNameSize);
} // FullNameToUNCName

size_t DOSNameToFullName (const wstring& rootDir, wstring& fullName, const wstring& dosName)
{
  size_t  fullNameSize = fullName.size ();
  wstring name         = rootDir;
  
  size_t  firstIndex  = 0;
  size_t  lastIndex   = 0;
  size_t  dosNameSize = dosName.size ();
  size_t  token_size  = 0;
  while (true)
  {
    lastIndex = dosName.find (L'\\', firstIndex);
    
    if (wstring::npos == lastIndex && dosNameSize > firstIndex)
      token_size = dosNameSize - firstIndex;
    else  
      token_size = lastIndex - firstIndex;
    
    if (0 < token_size)
    {
      wstring object = dosName.substr (firstIndex, token_size);
      wstring type   = QueryObjectType (name, object);
      
      if (0 >= type.size ())
        break;
      
      if (L'\\' != (name.c_str ()) [name.size () - 1])
        name.append (L"\\");
        
      if (0 == type.compare (L"Directory"))
      {
        name.append (object);
      }  
      else
      {
        if (0 == type.compare (L"SymbolicLink"))
        {
          name.append (object);
          name = QuerySymLinkTarget (name);
          
          if (wstring::npos != lastIndex)
            name.append (L"\\").append (dosName.substr (lastIndex + 1));

          return DOSNameToFullName (wstring (L"\\"), fullName, name);
        }
        else
        {
          name.append (dosName.substr (firstIndex));
          fullName = name;
          break;
        }
      }
    } // if (0 < token_size)
    
    if (wstring::npos == lastIndex)
      break;
    
    firstIndex = lastIndex + 1;
  } // while (...)
  
  return (fullName.size () - fullNameSize);
} // DOSNameToFullName

wstring DOSNameToFullName (const wstring& dosName)
{
  wstring fullName;
  DOSNameToFullName (fullName, dosName);
  return fullName;
} // DOSNameToFullName

size_t DOSNameToFullName (wstring& fullName, const wstring& dosName)
{
  size_t size = 0;
  
  size = DOSNameToFullName (wstring (L"\\GLOBAL??"), fullName, dosName);
  if (0 == size)
    size = DOSNameToFullName (wstring (L"\\??"), fullName, dosName);
  
  return size;
} // DOSNameToFullName

wstring UNCNameToFullName (const wstring& uncName)
{
  wstring fullName;
  UNCNameToFullName (fullName, uncName);
  return fullName;
} // UNCNameToFullName

size_t UNCNameToFullName (wstring& fullName, const wstring& uncName)
{
  static wstring  uncPrefix (L"\\Device\\LanmanRedirector");
  
  size_t  fullNameSize = fullName.size ();
  size_t  uncNameSize  = uncName.size ();
  
  if (3 <= uncNameSize && L'\\' == (uncName.c_str ()) [0] && L'\\' == (uncName.c_str ()) [1])
  {
    fullName.append (uncPrefix).append (uncName.substr (1));
  }
  
  return (fullName.size () - fullNameSize);
} // DOSNameToFullName

wstring LongNameToShortName (const wstring& longName)
{
  wstring shortName;
  LongNameToShortName (shortName, longName);
  return shortName;
} // LongNameToShortName

size_t LongNameToShortName (wstring& shortName, const wstring& longName)
{
  size_t  shortNameSize = shortName.size ();
  wchar_t name [MAX_PATH];
  
  if (0 != GetShortPathName (longName.c_str (), name, sizeof (name) / sizeof (name [0])))
    shortName.append (name);
  
  return (shortName.size () - shortNameSize);
} // LongNameToShortName

wstring ShortNameToLongName (const wstring& shortName)
{
  wstring longName;
  ShortNameToLongName (longName, shortName);
  return longName;
} // ShortNameToLongName

size_t ShortNameToLongName (wstring& longName, const wstring& shortName)
{
  size_t  longNameSize = longName.size ();
  
  wchar_t name [MAX_PATH];
  
  if (0 != GetLongPathName (shortName.c_str (), name, sizeof (name) / sizeof (name [0])))
    longName.append (name);
  
  return (longName.size () - longNameSize);
} // ShortNameToLongName


//wstring RegLinkToRegName (const wstring& link, HANDLE processId)
//{
//  wstring name;
//  RegLinkToRegName (name, link, processId);
//  return name;
//} // RegLinkToRegName
//
//typedef map<const wstring, const wstring>    KeyResolver;
//
//static KeyResolver::value_type reg_keys [] =
//{
//  KeyResolver::value_type (wstring (L"HKCR"),                  wstring (L"\\Registry\\Machine\\Software\\CLASSES")),
//  KeyResolver::value_type (wstring (L"HKEY_CLASSES_ROOT"),     wstring (L"\\Registry\\Machine\\Software\\CLASSES")),
//  KeyResolver::value_type (wstring (L"HKCU"),                  wstring (L"\\Registry\\User\\")),
//  KeyResolver::value_type (wstring (L"HKEY_CURRENT_USER"),     wstring (L"\\Registry\\User\\")),
//  KeyResolver::value_type (wstring (L"HKLM"),                  wstring (L"\\Registry\\Machine")),
//  KeyResolver::value_type (wstring (L"HKEY_LOCAL_MACHINE"),    wstring (L"\\Registry\\Machine")),
//  KeyResolver::value_type (wstring (L"HKU"),                   wstring (L"\\Registry\\User")),
//  KeyResolver::value_type (wstring (L"HKEY_USERS"),            wstring (L"\\Registry\\User")),
//  KeyResolver::value_type (wstring (L""),                      wstring (L"")) // for correct init map need empty last element
//};
//
//static KeyResolver  regKeyResolver (&reg_keys [0], &reg_keys [sizeof (reg_keys) / sizeof (KeyResolver::value_type) - 1]);
//
//size_t RegLinkToRegName (wstring& name, const wstring& link, HANDLE processId)
//{
//  size_t  nameSize  = name.size ();
//  
//  wstring key (link);
//  wstring path;
//  
//  size_t beginKeyIndex = 0;
//  size_t endKeyIndex   = 0;
//  
//  if (wstring::npos != (endKeyIndex = link.find (L'\\', beginKeyIndex)))  
//  {
//    key  = link.substr (beginKeyIndex, endKeyIndex-beginKeyIndex);
//    path = link.substr (endKeyIndex);
//  }
//  
//  if (0 != key.size ())
//  {
//    KeyResolver::iterator i = regKeyResolver.find (key);
//    if (i != regKeyResolver.end ())
//    {
//      if (0 == ((*i).first).compare (L"HKCU") || 0 == ((*i).first).compare (L"HKEY_CURRENT_USER"))
//      {
//        wstring sid = querySid (processId);
//        path = sid + path;
//      }
//      
//      name.append ((*i).second).append (path);
//    } // if (i != regKeyResolver.end ())
//  } // if (0 != key.size ())
//  
//  if (0 == (name.size () - nameSize))
//    name.append (link);
//  
//  return (name.size () - nameSize);
//} // RegLinkToRegName

static TokenResolver::value_type regTokenResolverData [] =
{
  TokenResolver::value_type (L"HKCR",                  TokenHandler (L"\\Registry\\Machine\\Software\\CLASSES")),
  TokenResolver::value_type (L"HKEY_CLASSES_ROOT",     TokenHandler (L"\\Registry\\Machine\\Software\\CLASSES")),
  TokenResolver::value_type (L"HKCU",                  TokenHandler (onCurrentUserResolver)),
  TokenResolver::value_type (L"HKEY_CURRENT_USER",     TokenHandler (onCurrentUserResolver)),
  TokenResolver::value_type (L"HKLM",                  TokenHandler (L"\\Registry\\Machine")),
  TokenResolver::value_type (L"HKEY_LOCAL_MACHINE",    TokenHandler (L"\\Registry\\Machine")),
  TokenResolver::value_type (L"HKU",                   TokenHandler (L"\\Registry\\User")),
  TokenResolver::value_type (L"HKEY_USERS",            TokenHandler (L"\\Registry\\User")),
  TokenResolver::value_type (L"CurrentControlSet",     TokenHandler (onCurrentControlSetResolver)),
  TokenResolver::value_type (L"",                      TokenHandler ()) // for correct init map need empty last element
}; // tokenResolverData
  
static TokenResolver regTokenResolver (&regTokenResolverData [0], &regTokenResolverData [sizeof (regTokenResolverData) / sizeof (TokenResolver::value_type) - 1]);

wstring RegLinkToRegName (const wstring& link, HANDLE processId)
{
  wstring name;
  RegLinkToRegName (name, link, processId);
  return name;
} // RegLinkToRegName

size_t RegLinkToRegName (wstring& name, const wstring& link, HANDLE processId)
{
  return processToken (name, link, processId, 3, regTokenResolver);
} // RegLinkToRegName

bool onCurrentUserResolver (const wstring& macro, wstring& result, HANDLE processId)
{
  result.append (L"\\Registry\\User\\");
  result.append (querySid (processId));
  return true;
} // onDefaultResolver

bool onCurrentControlSetResolver (const wstring& macro, wstring& result, HANDLE processId)
{
  W32RegistryNode node (L"HKEY_LOCAL_MACHINE\\SYSTEM\\Select", false);
  
  int index = node.getInt (L"Current");
  
  wchar_t buffer [20];
  
  swprintf (buffer, L"ControlSet%03u", index);
  result.append (buffer);
  
  return true;
} // onCurrentControlSetResolver

static TokenHandler defaultHandler;

TokenHandler& findTokenHandler (const wstring& data, TokenResolver& resolver)
{
  TokenResolver::iterator i = resolver.find (data);
  if (i != resolver.end ())
    return (*i).second;
  
  return defaultHandler;
} // findTokenHandler

size_t processToken (wstring& result, const wstring& data, HANDLE processId, unsigned int deep, TokenResolver& resolver)
{
  size_t  resultSize = result.size ();
  size_t  startIndex = 0;
  size_t  startIndexPrev = 0;
  
  size_t  firstIndex = 0;
  size_t  lastIndex  = wstring::npos;
  unsigned int i     = 0;

  for (i = 0; i < deep && (wstring::npos != (startIndex = data.find (L'\\', startIndex))); ++i)
  {
    lastIndex = startIndex;
    
    wstring       macro     = data.substr (firstIndex, (lastIndex-firstIndex));
    TokenHandler& handler   = findTokenHandler (macro, resolver);
    bool          processed = handler (macro, result, processId);    
    
    if (true == processed)
      result.append (data, lastIndex, 1);
    else
      result.append (data, firstIndex, lastIndex + 1 - firstIndex);

    firstIndex     = startIndex + 1;
    startIndexPrev = startIndex;
    ++startIndex;
  } // while
  
  lastIndex = data.size ();
  if (0 < (lastIndex - firstIndex))
  {
    if (i < deep)
    {
      wstring       macro     = data.substr (firstIndex, (lastIndex - firstIndex));
      TokenHandler& handler   = findTokenHandler (macro, resolver);
      bool          processed = handler (macro, result, processId);    
      
      if (true == processed)
        result.append (data, lastIndex, 1);
      else
        result.append (data, firstIndex, lastIndex + 1 - firstIndex);
    }
    else
    {
      result.append (data, firstIndex, (lastIndex - startIndexPrev));
    }  
  } // if (0 < (lastIndex - firstIndex))
  
  return (result.size () - resultSize);
} // processToken

wstring QueryObjectContent (const wstring& fullName)
{
  wstring content;
  QueryObjectContent (content, fullName);
  return content;
} // QueryObjectContent

size_t QueryObjectContent (wstring& content, const wstring& fullName)
{
  size_t  contentSize = content.size ();
  App::Application::GetVerinfoIdentity(fullName.c_str(), content);
  return (content.size () - contentSize);
} // QueryObjectContent

bool fillRulesPack(RulePack* rulePack, const RuleRecordList& rulesList)
{
  rulePack->PackVersion = PACK_VERSION;
  rulePack->RulesNumber = 0;
  BYTE*     rulePtr     = reinterpret_cast <BYTE*> (rulePack->Record);

  for (RuleRecordList::const_iterator i = rulesList.begin (); i != rulesList.end (); ++i)
  {
    size_t ruleSize = (FIELD_OFFSET (RuleRecord, Buf)) + (*i)->BufSize;
    memcpy (rulePtr, (*i).get (), ruleSize);
    ++(rulePack->RulesNumber);
    rulePtr += ruleSize;
  } // for (...)

  return true;
}

DWORD getRulesPackLength(const RuleRecordList& rulesList)
{
  DWORD packLength = FIELD_OFFSET(RulePack, Record);
  for (RuleRecordList::const_iterator i = rulesList.begin (); i != rulesList.end (); ++i)
    packLength += FIELD_OFFSET(RuleRecord, Buf) + (*i)->BufSize;

  return packLength;
}

bool createRuleRecord (RuleRecordList &List, PtrToResourceItem& resItem, HANDLE processId, ULONG RuleId)
{
  if ( resItem->Identity.Type == idnPath )
  {
    NtObjectType    objectType = resItem->Identity.GetResourceType ();
    if ( objectType == nttNetwork )
	{
		wstring AddressString = resItem->Identity.Path.Path;
		IP4Address Addr = { 0 };
		size_t size = FIELD_OFFSET (RuleRecord, Buf) + sizeof Addr;
		PtrToRuleRecord rule (reinterpret_cast <RuleRecord*> (new unsigned char [size]));

		memcpy (rule->Label, &GesRule::GswLabel, sizeof (rule->Label));
		rule->RuleId  = RuleId;
		rule->Attr    = resItem->Params.Attributes;
		rule->Type    = resItem->Identity.Path.Type;
		rule->BufType = bufIP4Address;
		rule->BufSize = static_cast <ULONG> (sizeof Addr);
		
		if ( AddressString == L"*" )
		{
			memcpy (rule->Buf, &Addr, sizeof Addr);

			List.push_back(rule);
		}
		else
		{
			// get port
			size_t p = AddressString.find(L":");
			if ( p != wstring::npos )
			{
				//port is defined take it
				Addr.Port = htons(_wtoi(AddressString.substr(p + 1, AddressString.size() - p - 1).c_str()));
				AddressString.erase(p, AddressString.size() - p);
			}

			if ( AddressString == L"*" )
			{
				memcpy (rule->Buf, &Addr, sizeof Addr);

				List.push_back(rule);
			}
			else
			{
				// get address mask
				Addr.Mask = 0xffffffff;
				p = AddressString.find(L"/");
				if ( p != wstring::npos )
				{
					// mask is defined take it
					ULONG MaskBits = _wtoi(AddressString.substr(p + 1, AddressString.size() - p - 1).c_str());
					if ( 0 < MaskBits && MaskBits <= 32 )
						Addr.Mask = Addr.Mask >> (32 - MaskBits);

					AddressString.erase(p, AddressString.size() - p);
				}

				//
				// resolve name to addresses
				//
				int StrLen = 0;
				StrLen = WideCharToMultiByte(CP_UTF8, 0, AddressString.c_str(), (int)AddressString.size(), NULL, StrLen, NULL, NULL);
				char *AddressStringA = new char[StrLen+1];
				WideCharToMultiByte(CP_UTF8, 0, AddressString.c_str(), (int)AddressString.size(), AddressStringA, StrLen, NULL, NULL);
				AddressStringA[StrLen] = 0;

				addrinfo *Res = NULL;
				addrinfo Hints = { 0 };
				Hints.ai_family = AF_INET;
				Hints.ai_socktype = SOCK_STREAM;
				Hints.ai_protocol = IPPROTO_TCP;

				int rc = getaddrinfo(AddressStringA, "", &Hints, &Res);
				if ( rc == 0 )
				{
					for ( addrinfo *AddrInfo = Res; AddrInfo != NULL; AddrInfo = AddrInfo->ai_next )
					{
						Addr.Ip = ((sockaddr_in *)(AddrInfo->ai_addr))->sin_addr.s_addr & Addr.Mask;

						memcpy (rule->Buf, &Addr, sizeof Addr);

						List.push_back(rule);
					}
				}

				if ( AddressStringA != NULL )
					delete[] AddressStringA;
			}
		}
	}
	else
	{
		macro::ResultList ResolvedList;
		size_t      ResolvedStrings = process (ResolvedList, wstring (resItem->Identity.Path.Path), processId);

		for (macro::ResultList::iterator i = ResolvedList.begin (); i != ResolvedList.end (); ++i)
		{
			size_t nameSize   = (*i).size();
			wstring resolveName;
			switch (objectType)
			{
				case nttFile:
					if ( (0 == (nameSize = DOSNameToFullName (resolveName, *i))) &&
						(0 == (nameSize = UNCNameToFullName (resolveName, *i))) ) 
					{
						resolveName = *i;
						// remove double slashes
						DWORD pos;
						while ( ( pos = resolveName.find(L"\\\\") ) != wstring::npos ) {
							resolveName.erase(pos, 1);
						}
						nameSize = resolveName.size();
					}
		      
					break;
				case nttKey:
					nameSize = RegLinkToRegName (resolveName, *i, processId);
					break;
				default:
					resolveName = *i;
					break;
			}

			if (0 < nameSize)
			{
				nameSize = (nameSize + 1) * sizeof (wchar_t); // zero end and by bytes
				size_t          size     = FIELD_OFFSET (RuleRecord, Buf) + nameSize;
				PtrToRuleRecord rule (reinterpret_cast <RuleRecord*> (new unsigned char [size]));

				if (NULL != rule.get ())
				{
					memcpy (rule->Label, &GesRule::GswLabel, sizeof (rule->Label));
					rule->RuleId  = RuleId;
					rule->Attr    = resItem->Params.Attributes;
					rule->Type    = resItem->Identity.Path.Type;
					rule->BufType = bufObjectName;
					rule->BufSize = static_cast <ULONG> (nameSize);
					wcscpy (reinterpret_cast <wchar_t*> (rule->Buf), resolveName.c_str ());

					List.push_back(rule);
				} // if (NULL != rule.get ())  
			} // if (0 < nameSize)
		}
	}
    return true;
  } 
  else
  {
    if ( resItem->Identity.Type == idnOwner )
    {
      byte *Sid;
      size_t SidSize;
      if ( GetSidByName(resItem->Identity.Owner.Owner, Sid, SidSize) )
      {
        size_t          size     = FIELD_OFFSET (RuleRecord, Buf) + SidSize;
        PtrToRuleRecord rule (reinterpret_cast <RuleRecord*> (new unsigned char [size]));

        if (NULL != rule.get ())
        {
          memcpy (rule->Label, &GesRule::GswLabel, sizeof (rule->Label));
          rule->RuleId  = RuleId;
          rule->Attr    = resItem->Params.Attributes;
          rule->Type    = resItem->Identity.Owner.Type;
          rule->BufType = bufOwnerSid;
          rule->BufSize = static_cast <ULONG> (SidSize);
          memcpy(rule->Buf, Sid, SidSize);

          List.push_back(rule);
        } // if (NULL != rule.get ())  
        return true;
      }
    }
  }  

  return false;
} // createRuleRecord

bool GetSidByName(const wchar_t *Name, byte *&Sid, size_t &SidSize)
{
  Sid = NULL;
  SidSize = 0;

  static const wchar_t SidStringStart[] = L"S-";
  if ( !wcsncmp(Name, SidStringStart, sizeof SidStringStart / sizeof SidStringStart[0] - 1) ) {
      ::PSID SidBuf = NULL;
    if ( ConvertStringSidToSid(Name, &SidBuf) ) {
      SidSize = GetLengthSid((PSID)SidBuf);
      Sid = new byte[SidSize];
      memcpy(Sid, SidBuf, SidSize);
      LocalFree(SidBuf);
      return true;
    }
  }

  DWORD dwLevel = 1;
  LPWKSTA_USER_INFO_1 pBuf = NULL;
  NET_API_STATUS nStatus;

  nStatus = NetWkstaUserGetInfo(NULL, dwLevel, (LPBYTE *) &pBuf);
  if (nStatus != NERR_Success) {
      trace("LookupAccountName error: %d\n", nStatus);
      return false;
  }

  char SidBuf[80];
  WCHAR DomainName[100];
  DWORD DomainSize = sizeof DomainName;
  DWORD Size = sizeof SidBuf;
  SID_NAME_USE sid_use;

  if (!LookupAccountName(pBuf->wkui1_logon_server, Name, SidBuf, &Size,
      DomainName, &DomainSize, &sid_use)) {
      trace("LookupAccountName error: %d\n", GetLastError());
      NetApiBufferFree(pBuf);
      return false;
  }

  NetApiBufferFree(pBuf);
  SidSize = GetLengthSid((PSID)SidBuf);
  Sid = new byte[SidSize];
  memcpy(Sid, SidBuf, SidSize);
  return true;
}

DWORD GetProcessIdByName(const wchar_t *ProcessName)
{
	DWORD ProcId[1024];
	DWORD ProcNum;
	BOOL rc = EnumProcesses(ProcId, sizeof ProcId, &ProcNum);
	if ( rc == FALSE ) {
		return 0;
	}
	for ( DWORD i = 0; i < ProcNum; i++ ) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcId[i]);
		if ( hProcess == NULL ) continue;
		HMODULE hModule;
		DWORD ModuleNum;
		rc = EnumProcessModules(hProcess, &hModule, sizeof hModule, &ModuleNum);
		if ( rc == TRUE ) {
			wchar_t Name[MAX_PATH]; 
			if ( GetModuleBaseName(hProcess, hModule, Name, sizeof Name) != 0 && !_wcsicmp(Name, ProcessName) ) {
				CloseHandle(hProcess);
				return ProcId[i];
			}
		}
		CloseHandle(hProcess);
	}
	return 0;
}


} // namespace Tools
} // namespace commonlib
