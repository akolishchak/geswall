//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef BOOST_REGEX_NO_LIB
 #define BOOST_REGEX_NO_LIB
#endif // BOOST_REGEX_NO_LIB 
#include <boost/regex.hpp>

#include "macroresolver.h"
#include "commonlib/commonlib.h"
#include "commonlib/tools.h"
#include "config/w32registrynode.h"

#include <userenv.h>

#include <utility>
#include <map>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/any.hpp>

using namespace std;
using namespace commonlib;
using namespace config;

namespace macro {

//#pragma warning(disable: 4996)  // deprecated

typedef boost::shared_array<wchar_t>       ptr_to_wchar_array;
typedef boost::shared_array<BYTE>          ptr_to_byte_array;

typedef boost::shared_array<unsigned char> ptr_to_uchar_array;
typedef boost::shared_ptr<wstring>         ptr_to_wstring;
typedef std::list<ptr_to_wstring>          wstring_list;

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;


//********************************************************************************************************//
//**************************************** macros support ************************************************//
//********************************************************************************************************//

typedef boost::function5 <size_t, const wstring&, wstring&, const wstring&, HANDLE, const wstring&> MacroHandler;
typedef pair <const wstring, const MacroHandler>                                                    MacroRegExpPair;

typedef map <const wstring, MacroHandler>    MacrosResolver;
typedef list <MacroRegExpPair>               MacrosRegExpResolver;

size_t onDefaultResolver (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onEnvironmentVariable (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onUserProfile (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onRegistryCurrentUser (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onRegistryMachine (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onRegistryUsers (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onRegistryClassesRoot (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onRegistryValue (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onGetProcessName (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onGetDirectory (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onLongNameToShortName (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onShortNameToLongName (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onReadFile (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onRegexpParse (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);
size_t onBootVolume (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName);

static MacrosResolver::value_type macroResData [] =
{
  MacrosResolver::value_type (L"USERPROFILE",        boost::bind (onUserProfile,         _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKCU",               boost::bind (onRegistryCurrentUser, _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKEY_CURRENT_USER",  boost::bind (onRegistryCurrentUser, _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKLM",               boost::bind (onRegistryMachine,     _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKEY_LOCAL_MACHINE", boost::bind (onRegistryMachine,     _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKU",                boost::bind (onRegistryUsers,       _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKEY_USERS",         boost::bind (onRegistryUsers,       _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKCR",               boost::bind (onRegistryClassesRoot, _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"HKEY_CLASSES_ROOT",  boost::bind (onRegistryClassesRoot, _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"getprocessname",     boost::bind (onGetProcessName,      _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"getdir",             boost::bind (onGetDirectory,        _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"shortname",          boost::bind (onLongNameToShortName, _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"longname",           boost::bind (onShortNameToLongName, _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"readfile",           boost::bind (onReadFile,            _1, _2, _3, _4, _5)),
  MacrosResolver::value_type (L"regexp_parse",       boost::bind (onRegexpParse,         _1, _2, _3, _4, _5)),
#ifndef NO_DDK
  MacrosResolver::value_type (L"boot_volume",        boost::bind (onBootVolume,          _1, _2, _3, _4, _5)),
#endif // #ifndef NO_DDK
  MacrosResolver::value_type (L"",                   boost::bind (onDefaultResolver,     _1, _2, _3, _4, _5))
}; // macroResData

static MacroRegExpPair regexpData [] = 
{
  MacroRegExpPair (wstring (L"HK*\\*"), boost::bind (onRegistryValue, _1, _2, _3, _4, _5))
}; // regexpData

static MacrosResolver        macros (&macroResData [0], &macroResData [sizeof (macroResData) / sizeof (MacrosResolver::value_type) - 1]);
static MacrosRegExpResolver  macrosRegExp;

class Initializer
{
  public:
   Initializer ()
   {
     for (int i = 0; i < sizeof (regexpData) / sizeof (MacroRegExpPair); ++i)
     {
       macrosRegExp.push_back (regexpData [i]);
     }
   } // Initializer
}; // Initializer

static Initializer resolverInitializer;

bool   match (const wchar_t* string, const wchar_t* pattern);
bool   find_macros (const wstring& data, MacroHandler& result);
size_t parse_parameters (wstring_list& params_list, const wstring& params_data);
size_t find_parameters (const wstring& data, wstring& params);
ptr_to_wchar_array expand_environment_string (const wchar_t* data, HANDLE process_id);

//********************************************************************************************************//
//*************************************** multimacros support ********************************************//
//********************************************************************************************************//

typedef 
  boost::function6 <
    size_t, 
    ResultList&, 
    const wstring&, 
    const wstring&, 
    const wstring&, 
    HANDLE,
    const wstring&
  >                                              MultiHandler;
typedef map <const wstring, MultiHandler>        MultiResolver;
typedef pair <const wstring, const MultiHandler> MultiRegExpPair;
typedef list <MultiRegExpPair>                   MultiRegExpResolver;

size_t onAnyUserProfileMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName);
size_t onAnyRegistryUserMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName);
size_t onAnyRegistryUserValueMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName);
size_t onDefaultResolverMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName);
size_t onRegexpParse (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName);

static MultiResolver::value_type multiResData [] =
{
  MultiResolver::value_type (L"ANYUSERPROFILE",     boost::bind (onAnyUserProfileMulti,  _1, _2, _3, _4, _5, _6)),
  MultiResolver::value_type (L"ANYHKU",             boost::bind (onAnyRegistryUserMulti, _1, _2, _3, _4, _5, _6)),
  MultiResolver::value_type (L"regexp_parse_x",     boost::bind (onRegexpParse,          _1, _2, _3, _4, _5, _6)),
  MultiResolver::value_type (L"",                   boost::bind (onDefaultResolverMulti, _1, _2, _3, _4, _5, _6))
}; // multiResData

static MultiRegExpPair multiRegexpData [] = 
{
    MultiRegExpPair (wstring (L"ANYHKU\\*"), boost::bind (onAnyRegistryUserValueMulti, _1, _2, _3, _4, _5, _6))
}; // regexpData

static MultiResolver       multiMacros (&multiResData [0], &multiResData [sizeof (multiResData) / sizeof (MultiResolver::value_type) - 1]);
static MultiRegExpResolver multiRegExp;

class InitializerMulti
{
  public:
    InitializerMulti ()
    {
        for (int i = 0; i < sizeof (multiRegexpData) / sizeof (MultiRegExpPair); ++i)
        {
            multiRegExp.push_back (multiRegexpData [i]);
        }
    } // InitializerMulti
}; // InitializerMulti

static InitializerMulti resolverInitializerMulti;

size_t _process (ResultList& result, const wstring& data, HANDLE processId, const wstring& processName);

//********************************************************************************************************//
//*************************************** macros implementation ******************************************//
//********************************************************************************************************//

wstring process (const wstring& data, HANDLE processId)
{
  return process (data, processId, L"");
} // process

wstring process (const wstring& data, HANDLE processId, const wstring& processName)
{
  wstring result;
  process (result, data, processId, processName);
  return result;
} // process

size_t process (wstring& result, const wstring& data, HANDLE processId)
{
  return process (result, data, processId, L"");
} // process

size_t process (wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
  size_t  resultSize = result.size ();
  size_t  startIndex = 0;
  size_t  startIndexPrev = 0;
  
  size_t  firstIndex = wstring::npos;
  size_t  lastIndex  = wstring::npos;

  while (wstring::npos != (startIndex = data.find (L'%', startIndex)))
  {
    if (wstring::npos == firstIndex)
    {
      result.append (data, startIndexPrev, (startIndex - startIndexPrev));
      firstIndex = startIndex + 1;
    } // if (wstring::npos == firstIndex)
    else
    {
      lastIndex = startIndex;
      if (1 < (lastIndex - firstIndex))
      {
        wstring macro = data.substr (firstIndex, (lastIndex-firstIndex));
  
        MacroHandler handler;
        if (false == find_macros (wstring (macro), handler))
          handler = MacroHandler (onEnvironmentVariable);
        
        size_t prevSize = result.size ();
        size_t skip = handler (macro, result, data.substr (lastIndex+1), processId, processName);
        if (0 < (result.size () - prevSize))
        {
          startIndex     = (lastIndex + 1) + skip;
          startIndexPrev = startIndex;
          firstIndex     = wstring::npos;
          continue;
        }
        startIndexPrev = data.size ();
        result.erase (resultSize);
        break;
      } // if (1 < (lastIndex - firstIndex))
      else
      {
        firstIndex = startIndex + 1;
      } // else if (1 < (lastIndex - firstIndex))
    } // else if (wstring::npos == firstIndex)
    startIndexPrev = startIndex;
    ++startIndex;
  } // while
  
  result.append (data, startIndexPrev, (data.size () - startIndexPrev));
  
  return (result.size () - resultSize);
} // process

size_t process (ResultList& result, const wstring& data, HANDLE processId)
{
  return process (result, data, processId, L"");
} // process

size_t process (ResultList& result, const wstring& data, HANDLE processId, const wstring& processName)
{
#pragma message (__WARNING__ "NOTE process (ResultList&, ...): macro ANYUSERPROFILE, ANYHKU may be override by environment variable")

  wstring resultStr;
  
  if (0 < process (resultStr, data, processId, processName))
  {
    size_t resultSize = result.size ();
    result.push_back (resultStr);
    return (result.size () - resultSize);
  }
  
  return _process (result, data, processId, processName);
  //size_t resultSize = _process (result, data, processId, processName);
  //if (0 < resultSize)
  //{
  //  size_t j = resultSize;
  //  for (ResultList::reverse_iterator i = result.rbegin (); j != 0; ++i, --j)
  //  {
  //    resultStr.erase ();
  //    if (0 < process (resultStr, (*i), processId, processName))
  //    {
  //      (*i).assign (resultStr);
  //    }
  //  }
  //} // if (0 < resultSize)
  //
  //return resultSize;
} // process

//********************************************************************************************************//
//****************************************** private methods *********************************************//
//********************************************************************************************************//

size_t onResolveSuccess (const wchar_t* resolveData, wstring& result)
{
    result.append (resolveData);
    return 0;
} // onResolveSuccess

size_t onResolveSuccess (const wstring& resolveData, wstring& result)
{
    result.append (resolveData);
    return 0;
} // onResolveSuccess

size_t onDefaultResolver (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    return 0;
} // onDefaultResolver

size_t onEnvironmentVariable (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    DWORD            size = GetEnvironmentVariable (macro.c_str (), NULL, 0);
    ptr_to_wchar_array  buffer (new wchar_t [size]);

    if (NULL != buffer.get () && 0 != GetEnvironmentVariable (macro.c_str (), buffer.get (), size))
        return onResolveSuccess (buffer.get (), result);

    return onDefaultResolver (macro, result, data, processId, processName);
    //HANDLE hProcess = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong(processId));

    //if (NULL != hProcess)
    //{
    //  HANDLE hToken = NULL;
    //  if (TRUE == OpenProcessToken (hProcess, TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken))
    //  {
    //    wstring envData (L"%");
    //    envData.append (data).append (L"%");
    //    
    //    DWORD size = 256;
    //    for (DWORD size = 256; size <= (256*10); size = 2*size)
    //    {
    //      ptr_to_wchar_array  buffer (new wchar_t [size]);
    //      if (NULL != buffer.get () && TRUE == ExpandEnvironmentStringsForUser (hToken, envData.c_str (), buffer.get (), size))
    //        close_handle_and_return wstring (buffer.get ());
    //    }
    //    CloseHandle (hToken);
    //  }
    //  CloseHandle (hProcess);
    //} // if (NULL != hProcess)
    //
    //return onDefaultResolver (data, processId);
} // onEnvironmentVariable

size_t onUserProfile (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    ObjectHolder hProcess (OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong(processId)));

    if (NULL != hProcess.get ())
    {
        ObjectHolder hToken;
        if (TRUE == OpenProcessToken (hProcess.get (), TOKEN_QUERY, &(hToken.reference ())))
        {
            DWORD size = 0;
            GetUserProfileDirectory (hToken.get (), NULL, &size);
            if (0 != size)
            {
                ptr_to_wchar_array  buffer (new wchar_t [size]);
                if (NULL != buffer.get () && TRUE == GetUserProfileDirectory (hToken.get (), buffer.get (), &size))
                    return onResolveSuccess (buffer.get (), result);
            } // if (0 != size)
        } // if (TRUE == OpenProcessToken (hProcess, TOKEN_QUERY, &hToken))
    } // if (NULL != hProcess)

    return onDefaultResolver (macro, result, data, processId, processName);
} // onUserProfile

size_t onRegistryCurrentUser (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    static const wchar_t* _result [] = 
    {
        L"HKEY_USERS\\",
        L"\\Registry\\User\\"
    };

    wstring sid = querySid (processId);
    if (0 < sid.size ())
    {
        wstring user (_result [0]);
        user.append (sid);
        return onResolveSuccess (user, result);
    }

    return onDefaultResolver (macro, result, data, processId, processName);
} // onRegistryCurrentUser

size_t onRegistryMachine (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    static const wstring _result [] = 
    {
        wstring (L"HKEY_LOCAL_MACHINE"),
        wstring (L"\\Registry\\Machine")
    };

    return onResolveSuccess (_result [0], result);
} // onRegistryMachine

size_t onRegistryUsers (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    static const wstring _result [] = 
    {
        wstring (L"HKEY_USERS"),
        wstring (L"\\Registry\\User")
    };

    return onResolveSuccess (_result [0], result);
} // onRegistryUsers

size_t onRegistryClassesRoot (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    static const wstring _result [] = 
    {
        wstring (L"HKEY_CLASSES_ROOT"),
        wstring (L"\\Registry\\Machine\\Software\\CLASSES")
    };

    return onResolveSuccess (_result [0], result);
} // onRegistryClassesRoot

size_t onRegistryValue (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    typedef map<const wstring, HKEY>    KeyResolver;
  
    static KeyResolver::value_type keys [] =
    {
        KeyResolver::value_type (L"HKCR",                  HKEY_CLASSES_ROOT),
        KeyResolver::value_type (L"HKEY_CLASSES_ROOT",     HKEY_CLASSES_ROOT),
        KeyResolver::value_type (L"HKCC",                  HKEY_CURRENT_CONFIG),
        KeyResolver::value_type (L"HKEY_CURRENT_CONFIG",   HKEY_CURRENT_CONFIG),
        KeyResolver::value_type (L"HKCU",                  HKEY_USERS), //HKEY_CURRENT_USER),
        KeyResolver::value_type (L"HKEY_CURRENT_USER",     HKEY_USERS), //HKEY_CURRENT_USER),
        KeyResolver::value_type (L"HKLM",                  HKEY_LOCAL_MACHINE),
        KeyResolver::value_type (L"HKEY_LOCAL_MACHINE",    HKEY_LOCAL_MACHINE),
        KeyResolver::value_type (L"HKU",                   HKEY_USERS),
        KeyResolver::value_type (L"HKEY_USERS",            HKEY_USERS),
        KeyResolver::value_type (L"HKPD",                  HKEY_PERFORMANCE_DATA),
        KeyResolver::value_type (L"HKEY_PERFORMANCE_DATA", HKEY_PERFORMANCE_DATA),
        KeyResolver::value_type (L"",                      HKEY_LOCAL_MACHINE) // for correct init map need empty last element
    };
  
    static KeyResolver  keyResolver (&keys [0], &keys [sizeof (keys) / sizeof (KeyResolver::value_type) - 1]); // 11

    wstring key;
    wstring path;
    wstring value;

    size_t beginKeyIndex = 0;
    size_t endKeyIndex   = 0;

    if (wstring::npos != (endKeyIndex = macro.find (L'\\', beginKeyIndex)))  
    {
        key = macro.substr (beginKeyIndex, endKeyIndex-beginKeyIndex);

        size_t beginPathIndex = endKeyIndex + 1;
        size_t endPathIndex   = 0;
        if (wstring::npos != (endPathIndex = macro.rfind (L'\\')))
        {
            path = macro.substr (beginPathIndex, endPathIndex-beginPathIndex);
            value = macro.substr (endPathIndex+1);
        }
    }

    if (0 != key.size () && 0 != path.size ())// && 0 != value.size ())
    {
        KeyResolver::iterator i = keyResolver.find (key);
        if (i != keyResolver.end ())
        {
            if (0 == ((*i).first).compare (L"HKCU") || 0 == ((*i).first).compare (L"HKEY_CURRENT_USER"))
            {
                wstring sid = querySid (processId);
                path = sid + wstring (L"\\") + path;
            }

            HKEY rootKey   = (*i).second;
            HKEY resultKey;

            if (ERROR_SUCCESS == RegOpenKeyEx (rootKey, path.c_str (), 0, KEY_QUERY_VALUE, &resultKey))
            {
                scope_guard regkey_finalizer = make_guard (resultKey, &::RegCloseKey);

                DWORD type     = 0;
                DWORD dataSize = 0;

                if (
                       ERROR_SUCCESS == RegQueryValueEx (resultKey, value.c_str (), 0, &type, NULL, &dataSize) 
                    && 0 != dataSize
                    && (REG_EXPAND_SZ == type || REG_MULTI_SZ == type || REG_SZ == type)
                   )
                {
                    ptr_to_wchar_array _data (new wchar_t [dataSize]);
                    if (NULL != _data.get ())
                    {
                        if (ERROR_SUCCESS == RegQueryValueEx (resultKey, value.c_str (), 0, &type, reinterpret_cast <LPBYTE> (_data.get ()), &dataSize))
                        {
                            if (REG_EXPAND_SZ == type || REG_SZ == type)
                            {
                                ptr_to_wchar_array buffer = expand_environment_string (_data.get (), processId);
                                if (NULL != buffer.get ())
                                    return onResolveSuccess (buffer.get (), result);
                            }
                            else
                            {
                                return onResolveSuccess (_data.get (), result);//wstring (_data.get ());
                            }    
                        } // if (...)
                    } // if (NULL != _data.get ())
                } // if (ERROR_SUCCESS == RegQueryValueEx (resultKey, ...) ...)
            } // if (ERROR_SUCCESS == RegOpenKeyEx (rootKey, ...))
        } // if (i != keyResolver.end ())
    } // if (...) 

    return onDefaultResolver (macro, result, data, processId, processName);
} // onRegistryValue

size_t onGetProcessName (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    wstring params; 
    size_t  skip = find_parameters (data, params);

    return skip;
} // onGetDirectory

size_t onGetDirectory (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    wstring params; 
    wstring_list  params_list;
    size_t        skip = find_parameters (data, params);

    parse_parameters (params_list, params);

    if (0 < params.size () && 1 <= params_list.size ())
    {
        if (0 < process (result, *(params_list.front ()), processId, processName))
        {
            size_t endIndex = 0;
            if (wstring::npos != (endIndex = result.rfind (L'\\')))
                result.erase (endIndex);
            return skip;
        }  
    } // if (0 < params.size ())

    return onDefaultResolver (macro, result, data, processId, processName);
} // onGetDirectory

size_t onLongNameToShortName (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    wstring params; 
    wstring _result;
    wstring_list  params_list;
    size_t        skip = find_parameters (data, params);

    parse_parameters (params_list, params);

    if (0 < params.size () && 1 <= params_list.size () && 0 < process (_result, *(params_list.front ()), processId, processName))
    {
        size_t  shortNameSize = result.size ();
        wchar_t name [MAX_PATH];

        if (0 != GetShortPathName (_result.c_str (), name, sizeof (name) / sizeof (name [0])))
            result.append (name);

        if (0 < result.size () - shortNameSize)
            return skip;
    }  

    return onDefaultResolver (macro, result, data, processId, processName);
} // onLongNameToShortName

size_t onShortNameToLongName (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    wstring params; 
    wstring _result;
    wstring_list  params_list;
    size_t        skip = find_parameters (data, params);

    parse_parameters (params_list, params);

    if (0 < params.size () && 1 <= params_list.size () && 0 < process (_result, *(params_list.front ()), processId, processName))
    {
        size_t  longNameSize = result.size ();
        wchar_t name [MAX_PATH];

        if (0 != GetLongPathName (_result.c_str (), name, sizeof (name) / sizeof (name [0])))
            result.append (name);

        if (0 < result.size () - longNameSize)
            return skip;
    }  

    return onDefaultResolver (macro, result, data, processId, processName);
} // onShortNameToLongName

size_t onReadFile (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    wstring       params; 
    wstring       file_name;
    wstring_list  params_list;
    size_t        skip = find_parameters (data, params);

    parse_parameters (params_list, params);

    if (2 <= params_list.size () &&  0 < process (file_name, *(params_list.front ()), processId, processName))
    {
        wstring_list::iterator i         = ++(params_list.begin ());
        const wstring&         file_type = *(*i);


        FILE* file = ::_wfopen (file_name.c_str (), L"rb");
        if (NULL != file)
        {
            scope_guard file_guard = make_guard (file, &::fclose);

            fseek (file, 0, SEEK_END);
            size_t file_length = ftell (file);
            fseek (file, 0, SEEK_SET);

            ptr_to_uchar_array buffer (new unsigned char [file_length]);
            if (NULL != buffer.get () && 0 < fread (buffer.get (), sizeof (unsigned char), file_length, file))
            {
                if (0 == file_type.compare (L"wchar"))
                {
                    result.append (reinterpret_cast <wchar_t*> (buffer.get ()), file_length);
                }
                else 
                { // "char" default
                    string  str (reinterpret_cast <char*> (buffer.get ()), file_length);
                    commonlib::string2wstring (result, str);
                }
            } // if (NULL != buffer.get () && 0 < fread (buffer.get (), sizeof (unsigned char), file_length, file))
        } // if (NULL != file)
    } // if (2 <= params_list.size () &&  0 < process (file_name, *(params_list.front ()), processId, processName))

    return skip;
} // onReadFile

size_t onRegexpParse (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    wstring       params; 
    wstring       regexp;
    wstring       data_for_parse;
    wstring_list  params_list;
    size_t        skip = find_parameters (data, params);

    parse_parameters (params_list, params);

    wstring_list::iterator i = params_list.begin ();

    if (    2 <= params_list.size () 
        &&  0 < process (regexp, **i, processId, processName)
        &&  0 < process (data_for_parse, **(++i), processId, processName)
        )
    {
        boost::wregex                 pattern (regexp, boost::regex::perl | boost::regex::icase);

        std::wstring::const_iterator  start = data_for_parse.begin ();
        std::wstring::const_iterator  end   = data_for_parse.end ();
        boost::match_flag_type        flags = boost::match_default;
        boost::wsmatch                what; 

        if (true == boost::regex_search (start, end, what, pattern, flags))
        {
            if (1 < what.size ())
                result.append (what [1].first, what [1].second);

            //
            // for multiply search
            //

            // update search position: 
            //start = what[0].second; 

            // update flags: 
            //flags |= boost::match_prev_avail; 
            //flags |= boost::match_not_bob; 
        }
    }

    return skip;
} // onRegexpParse

#ifndef NO_DDK

size_t onBootVolume (const wstring& macro, wstring& result, const wstring& data, HANDLE processId, const wstring& processName)
{
    HKEY result_key;
    
    if (ERROR_SUCCESS == ::RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", 0, KEY_QUERY_VALUE, &result_key))
    {
        scope_guard regkey_finalizer = make_guard (result_key, &::RegCloseKey);
        
        DWORD type      = 0;
        DWORD data_size = 0;
        
        if (
                ERROR_SUCCESS == ::RegQueryValueExW (result_key, L"SystemPartition", 0, &type, NULL, &data_size) 
             && 0 != data_size
             && REG_SZ == type
           )
        {
            ptr_to_wchar_array _data (new wchar_t [data_size]);
            if (NULL != _data.get ())
            {
                if (ERROR_SUCCESS == ::RegQueryValueExW (result_key, L"SystemPartition", 0, &type, reinterpret_cast <LPBYTE> (_data.get ()), &data_size))
                {
                    wstring dos_name;
                    commonlib::Tools::FullNameToDOSName (dos_name, _data.get ());
                    return onResolveSuccess (dos_name, result);
                }
            } // if (NULL != _data.get ())
        }     
    } // if (ERROR_SUCCESS == ::RegOpenKeyExW ())

    return onDefaultResolver (macro, result, data, processId, processName);
} // onBootVolume

#endif // #ifndef NO_DDK

//********************************************************************************************************//
//************************************* multimacros implementation ***************************************//
//********************************************************************************************************//

size_t onRegexpParse (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName)
{
  size_t        result_size = result.size ();
  
  wstring       params; 
  wstring       regexp;
  wstring       data_for_parse;
  wstring_list  params_list;
  size_t        skip = find_parameters (postfix, params);
  
  parse_parameters (params_list, params);
  
  wstring_list::iterator i = params_list.begin ();
  
  if (    2 <= params_list.size () 
      &&  0 < process (regexp, **i, processId, processName)
      &&  0 < process (data_for_parse, **(++i), processId, processName)
     )
  {
    boost::wregex                 pattern (regexp, boost::regex::perl | boost::regex::icase);
    
    std::wstring::const_iterator  start = data_for_parse.begin ();
    std::wstring::const_iterator  end   = data_for_parse.end ();
    boost::match_flag_type        flags = boost::match_default;
    boost::wsmatch                what; 
    
    while (true == boost::regex_search (start, end, what, pattern, flags))
    {
      if (1 < what.size ())
        result.push_back (wstring (what [1].first, what [1].second));
      
      //
      // for multiply search
      //
      
      // update search position: 
      start = what[0].second; 
      
      // update flags: 
      flags |= boost::match_prev_avail; 
      flags |= boost::match_not_bob; 
    }
  }
  
  return (result.size () - result_size);
} // onRegexpParse

size_t _process (ResultList& result, const wstring& data, HANDLE processId, const wstring& processName)
{
  size_t  resultSize = result.size ();
  size_t  startIndex = 0;
  size_t  startIndexPrev = 0;
  
  size_t  firstIndex = wstring::npos;
  size_t  lastIndex  = wstring::npos;
  wstring prefix;

  while (wstring::npos != (startIndex = data.find (L'%', startIndex)))
  {
    if (wstring::npos == firstIndex)
    {
      prefix.append (data, startIndexPrev, (startIndex - startIndexPrev));
      firstIndex = startIndex + 1;
    } // if (wstring::npos == firstIndex)
    else
    {
      lastIndex = startIndex;
      if (1 < (lastIndex - firstIndex))
      {
        wstring macro = data.substr (firstIndex, (lastIndex-firstIndex));
  
        MultiHandler handler = boost::bind (onDefaultResolverMulti, _1, _2, _3, _4, _5, _6);
        
        MultiResolver::iterator i = multiMacros.find (macro);
        if (i != multiMacros.end ())
        {
          handler = (*i).second;
        }
        else
        {
          for (MultiRegExpResolver::iterator i = multiRegExp.begin (); i != multiRegExp.end (); ++i)
          {
            if (true == match (macro.c_str (), ((*i).first).c_str ()))
            {
              handler = (*i).second;
              break;
            }
          }
        }  
        
        try
        {
          size_t added = handler (result, macro, prefix, data.substr (lastIndex+1), processId, processName);
        }
        catch (ConfigException&)
        {
        }
        
        break;
      } // if (1 < (lastIndex - firstIndex))
      else
      {
        firstIndex = startIndex + 1;
      } // else if (1 < (lastIndex - firstIndex))
    } // else if (wstring::npos == firstIndex)
    startIndexPrev = startIndex;
    ++startIndex;
  } // while
  
  return (result.size () - resultSize);
} // _process

//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList 
size_t onAnyUserProfileMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName)
{
    W32RegistryNode node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", false);

    size_t   resultSize = result.size ();

    wchar_t  achKey [MAX_PATH]; 
    FILETIME ftLastWriteTime;
    DWORD    keySize;

    for (DWORD i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; ++i) 
    { 
        keySize = MAX_PATH;
        retCode = RegEnumKeyExW (node.getNativeKey (), i, achKey, &keySize, NULL, NULL, NULL, &ftLastWriteTime); 
        if (ERROR_SUCCESS == retCode && 0 != keySize) 
        {
            wstring resultStr;
            wstring dataStr (prefix + (node.getNode (achKey, false))->getString (L"ProfileImagePath") + postfix);
            if (0 < process (resultStr, dataStr, processId, processName))
                result.push_back (resultStr);
            else  
                result.push_back (dataStr);
        }
    } // for (...)

    return (result.size () - resultSize);
} // onAnyUserProfileMulti

size_t onAnyRegistryUserMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName)
{
  W32RegistryNode node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", false);
  
  size_t   resultSize = result.size ();
  
  wchar_t  achKey [MAX_PATH]; 
  FILETIME ftLastWriteTime;
  DWORD    keySize;
  
  for (DWORD i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; ++i) 
  { 
    keySize = MAX_PATH;
    retCode = RegEnumKeyExW (node.getNativeKey (), i, achKey, &keySize, NULL, NULL, NULL, &ftLastWriteTime); 
    if (ERROR_SUCCESS == retCode && 0 != keySize) 
    {
      result.push_back (prefix + wstring (achKey) + postfix);
    }
  } // for (...)

  return (result.size () - resultSize);
} // onAnyRegistryUserMulti

size_t onAnyRegistryUserValueMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName)
{
  wstring path;
  wstring value;
  
  size_t endPathIndex = 0;
  
  if (wstring::npos != (endPathIndex = macro.rfind (L'\\')))
  {
    path  = macro.substr (sizeof (L"ANYHKU") / sizeof (wchar_t) - 1, endPathIndex - sizeof (L"ANYHKU") / sizeof (wchar_t) + 1);
    value = macro.substr (endPathIndex+1);
  }
  
  if (0 == path.size () || 0 == value.size ())
    return 0; 

  W32RegistryNode node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", false);
  
  size_t   resultSize = result.size ();
  
  wchar_t  achKey [MAX_PATH]; 
  FILETIME ftLastWriteTime;
  DWORD    keySize;
  
  for (DWORD i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; ++i) 
  { 
    keySize = MAX_PATH;
    retCode = RegEnumKeyExW (node.getNativeKey (), i, achKey, &keySize, NULL, NULL, NULL, &ftLastWriteTime); 
    if (ERROR_SUCCESS == retCode && 0 != keySize) 
    {
      try
      {
        W32RegistryNode valueKey (wstring (L"HKEY_USERS\\") + wstring (achKey) + path, false);
        result.push_back (prefix + valueKey.getString (value) + postfix);
      }  
      catch (ConfigException&)
      {
      }
    }
  } // for (...)

  return (result.size () - resultSize);
} // onAnyRegistryUserValueMulti

size_t onDefaultResolverMulti (ResultList& result, const wstring& macro, const wstring& prefix, const wstring& postfix, HANDLE processId, const wstring& processName)
{
  return 0;
} // onDefaultResolverMulti

//********************************************************************************************************//
//******************************************** helper methods ********************************************//
//********************************************************************************************************//

bool match (const wchar_t* string, const wchar_t* pattern)
{
  for (; L'*'^*pattern; ++pattern, ++string) 
  {
    if (!*string)
      return (!*pattern);
    if ((*string)^(*pattern) && L'?'^*pattern)
      return false;
  }
  /* two-line patch to prevent *too* much recursiveness: */
  while (L'*' == pattern[1])
    ++pattern;

  do
  {
    if (match (string, pattern + 1))
      return true;
  }
  while (*string++);

  return false;
} // match

bool find_macros (const wstring& data, MacroHandler& result)
{
  MacrosResolver::iterator i = macros.find (data);
  if (i != macros.end ())
  {
    result = (*i).second;
    return true;
  }
  
  for (MacrosRegExpResolver::iterator i = macrosRegExp.begin (); i != macrosRegExp.end (); ++i)
  {
    if (true == match (data.c_str (), ((*i).first).c_str ()))
    {
      result = (*i).second;
      return true;
    }
  }
  
  return false;
} // find_macros

size_t find_parameters (const wstring& data, wstring& params)
{
  size_t i     = 0;
  int    mode  = 0;
  int    count = 0;
  
  for (i = 0; (i < data.size ()) && (2 > mode); ++i)
  {
    switch (data[i])
    {
      case L'\x0009':
      case L'\x000d':
      case L'\x000a':
      case L'\x0020':
           if (0 != mode)
             params += data[i];
           break;
      case L'(':
           if (0 == mode)
             ++mode;
           else
             params += data[i];  
           ++count;
           break;
      case L')':
           --count;
           if (0 == count)
             ++mode;
           else
             params += data[i];  
           break;
      default:
           params += data[i];
           break;     
    } // switch (data[i])
  } // for (size_t i = 0; i < data.size (); ++i)
  
  if (2 != mode)
  {
    params.erase ();
    i = 0;
  }  
  
  return i;
} // find_parameters

size_t parse_parameters (wstring_list& params_list, const wstring& params_data)
{
  size_t  original_size  = params_list.size ();
  
  bool    seen_slash   = false;
  bool    is_data      = false;
  bool    is_quotes    = false;
  size_t  quotes_count = 0;
  size_t  data_size    = params_data.size ();
  wstring parameter;
  
  for (size_t i = 0; i < data_size; ++i)
  {
    switch (params_data[i])
    {
      case L'\x0009':
      case L'\x000d':
      case L'\x000a':
      case L'\x0020':
           if (true == is_data)
             parameter += params_data[i];
             
           seen_slash = false;  
           break;
      case L'\\':
           is_data = true;
           
           if (true == is_quotes)
           {
             if (true == seen_slash)
             {
               parameter += params_data[i];
               seen_slash = false;
             }
             else
             {
               seen_slash = true;
             }
           }
           else
           {
             parameter += params_data[i];
           }
           break;
      case L'\"':
           is_data = true;
           
           if (true == seen_slash)
           {
             parameter += params_data[i];
           }
           else
           {
             ++quotes_count;
              
             if (0 == parameter.size ())
             {
               is_quotes = true;
             }
             else
             { 
               if (2 <= quotes_count && true == is_quotes)
               {
                 if (0 < parameter.size ())
                   params_list.push_back (ptr_to_wstring (new wstring (parameter)));
                     
                 parameter.clear ();
                 is_data      = false;
                 is_quotes    = false;
                 quotes_count = 0;
               }
               else
               {
                 parameter += params_data[i];
               }
             }
           } // if (true == seen_slash)
           
           seen_slash = false;
           break;
      case L',':
           if (true == seen_slash)
           {
             parameter += params_data[i];
           }
           else
           {
             if (false == is_quotes)
             {
               commonlib::trim_self (parameter);
                
               if (0 < parameter.size ())
                 params_list.push_back (ptr_to_wstring (new wstring (parameter)));
                  
               parameter.clear ();
               is_data      = false;
               is_quotes    = false;
               quotes_count = 0;
             }
             else
             {
               is_data = true;
               parameter += params_data[i];
             }
           }
           
           seen_slash = false;
           break;     
      default:
           is_data    = true;
           seen_slash = false;
           parameter += params_data[i];
           break;     
    } // switch (params_data[i])
    
    if (i >= (data_size - 1) && 0 < parameter.size ())
    {
      if (false == is_quotes)
        commonlib::trim_self (parameter);
        
      if (0 < parameter.size ())
        params_list.push_back (ptr_to_wstring (new wstring (parameter)));
    }
  } // for (size_t i = 0; i < data.size (); ++i)
  
  return params_list.size () - original_size;
} // parse_parameters

ptr_to_wchar_array expand_environment_string (const wchar_t* data, HANDLE process_id)
{
    HANDLE process_handle = ::OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong (process_id));
    if (NULL == process_handle)
        return ptr_to_wchar_array (NULL);
    scope_guard process_handle_finalizer = make_guard (process_handle, &::CloseHandle);
    
    HANDLE token_handle = NULL;
    if (FALSE == ::OpenProcessToken (process_handle, TOKEN_IMPERSONATE | TOKEN_QUERY, &token_handle))
        return ptr_to_wchar_array (NULL);
    scope_guard token_handle_finalizer = make_guard (token_handle, &::CloseHandle);
    
    DWORD size = 256;
    for (DWORD size = 256; size <= (256*10); size = 2*size)
    {
        ptr_to_wchar_array buffer (new wchar_t [size]);
        if (NULL != buffer.get () && TRUE == ExpandEnvironmentStringsForUser (token_handle, data, buffer.get (), size))
            return buffer;
    }
    
    return ptr_to_wchar_array (NULL);
} // expand_environment_string

//#pragma warning(default: 4996)

} // namespace macro
