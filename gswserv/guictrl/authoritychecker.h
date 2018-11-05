//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _GUICTRL_AUTHORITY_CHECKER_H_
 #define _GUICTRL_AUTHORITY_CHECKER_H_

#include "stdafx.h"

#include <boost/smart_ptr.hpp> 

#include <map>

#include "commonlib.h"
#include "nttools.h"
#include "gswdrv.h"

using namespace std;

namespace gswserv {
namespace guictrl {

class AuthorityChecker;

class AuthorityChecker
{
  public: 
  protected:
   typedef boost::shared_ptr<wstring>         PtrToHash;
   typedef commonlib::ObjectHolder            ObjectHolder;
   typedef map<const HANDLE, PtrToHash>       HashResolver;
   typedef commonlib::SyncObject              SyncObject;
   typedef commonlib::Locker                  Locker;
   
   enum Const
   {
     AuthorityHashSize = 200
   }; // Const

  private:

  public:
   AuthorityChecker ()
   {
     m_globalSA = initSecurityAttr ();
     m_hGlobalAuthorityObject = ObjectHolder (CreateEvent (m_globalSA, TRUE, FALSE, m_globalAuthorityObjectName));
   } // AuthorityChecker

   virtual ~AuthorityChecker ()
   {

   } // ~AuthorityChecker

   void queryAuthorityObject (HANDLE processId, wstring& objectName)
   {
     Locker lock (m_sync);

     PtrToHash hash;

     HashResolver::const_iterator i = m_hashResolver.find (processId);
     if (i == m_hashResolver.end ())
     {
//#pragma message (__WARNING__ "TODO queryAuthorityObject (): generate object name and create object")
       objectName = m_globalAuthorityObjectName; // generate object name and create object
     }
   } // queryAuthorityObject

   bool queryAuthorityHash (HANDLE processId, HANDLE objectHandle, wstring& authorityHash)
   {
     Locker lock (m_sync);

     bool result = false;
     
     if (true == isValidProcess (processId, objectHandle))
     { // generate authority hash and save pointer to map
       PtrToHash hash = generateAuthorityHash ();
       if (NULL != hash.get ())
       {
         clearDaemons ();
         m_hashResolver [processId] = hash;
         authorityHash = *hash; 
         result = true;
       }
     }

     return result;
   } // queryAuthorityHash

   void releaseAuthorityHash (const wstring& authorityHash, HANDLE processId)
   {
     Locker lock (m_sync);

     HashResolver::iterator i = m_hashResolver.find (processId);
     if (i != m_hashResolver.end () && 0 == authorityHash.compare (*((*i).second)))
     {
       m_hashResolver.erase (i);
     }
   } // releaseAuthorityHash

  protected:
   AuthorityChecker (const AuthorityChecker& right) 
   {
   } // AuthorityChecker

   AuthorityChecker& operator= (const AuthorityChecker& right) 
   { 
     if (this != &right)
       AuthorityChecker (right).swap (*this);
     
     return *this; 
   } // operator=

   void swap (AuthorityChecker& right)
   {
   } // swap

   PSECURITY_ATTRIBUTES initSecurityAttr ()
   {
     m_sd  = reinterpret_cast <PSECURITY_DESCRIPTOR> (m_sdBuffer);
     
     PSECURITY_ATTRIBUTES sa = NULL;
     
     if (
            TRUE == InitializeSecurityDescriptor(m_sd, SECURITY_DESCRIPTOR_REVISION)
         && TRUE == SetSecurityDescriptorDacl (m_sd, TRUE, (PACL) NULL, FALSE)
        )
     {
       m_sa.nLength              = sizeof (m_sa);
       m_sa.lpSecurityDescriptor = m_sd;
       m_sa.bInheritHandle       = TRUE;
       sa = &m_sa;
     }
     
     return sa;
   } // initSecurityAttr
   
   void clearDaemons ()
   {
     if (0 < m_hashResolver.size ())
     {
       for (HashResolver::iterator i = m_hashResolver.begin (); i != m_hashResolver.end (); ++i)
       {
         if (true ==  isProcessFinished ((*i).first))
         {
           m_hashResolver.erase (i);
           if (0 >= m_hashResolver.size ())
             break;
           i = m_hashResolver.begin ();
           continue;
         }  
       } // for ()
     } // if (0 < m_hashResolver.size ())
   } // clearDaemons
   
   bool isProcessFinished (const HANDLE processId)
   {
     bool result = true;
     
     ObjectHolder hProcess (OpenProcess (SYNCHRONIZE, FALSE, HandleToUlong(processId)));
     if (NULL != hProcess.get ()) 
     {
       result = (WAIT_OBJECT_0 == WaitForSingleObject (hProcess.get (), 0));
     } // if (NULL != hProcess)
     
     return result;
   } // isProcessFinished
   
   bool isValidProcess (HANDLE processId, HANDLE objectHandle)
   {
     if (HandleToUlong(processId) == GetCurrentProcessId()) 
       return false;

     BOOL result = FALSE;
     
     ObjectHolder hProcess (OpenProcess (PROCESS_DUP_HANDLE, FALSE, HandleToUlong(processId)));
     if (NULL != hProcess.get ()) 
     {
       ObjectHolder duphObject;
       result = DuplicateHandle (hProcess.get (), objectHandle, GetCurrentProcess (), &(duphObject.reference ()), 0, FALSE, DUPLICATE_SAME_ACCESS);

       //
       // check object name
       //
       if ( nttools::QueryObjectName(duphObject.get()) != L"\\BaseNamedObjects\\GesWallAuthorityObject" ) 
         return false;
     
       //
       // check that process
       CGswDrv          Drv;
       EntityAttributes Attributes;
       ULONG            RuleId;

       if (   
              Drv.GetSubjAttributes(HandleToUlong(processId), &Attributes, &RuleId) 
           && Attributes.Param[GesRule::attIntegrity] == GesRule::modTCB 
           && Attributes.Param[GesRule::attOptions] == GesRule::oboGeSWall 
          ) 
       {
         result = TRUE;
       }
     } // if (NULL != hProcess)
     
     return (FALSE != result);
   } // isValidProcess

   PtrToHash generateAuthorityHash ()
   {
//#pragma message (__WARNING__ "TODO generateAuthorityHash (): generate authority hash")
     unsigned char array [AuthorityHashSize];
     if (false == queryAuthorityHash (array))
       return PtrToHash ();
     
     wchar_t hash [2*AuthorityHashSize + 1];
     commonlib::bin2hex (array, AuthorityHashSize, hash, sizeof (hash) / sizeof (wchar_t));
     
     return PtrToHash (new wstring (hash));
   } // generateAuthorityHash

   bool queryAuthorityHash (unsigned char* array)
   {
     bool result = false;

     HCRYPTPROV hProv;
     
     if (
            !CryptAcquireContext (&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET))
         && !CryptAcquireContext (&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET)
        )
       return result; // error

     result = (TRUE == CryptGenRandom (hProv, AuthorityHashSize, array));

     CryptReleaseContext (hProv, 0);
     
     return result;
   } // queryAuthorityHash

  private:

  public: 
  protected:
   HashResolver         m_hashResolver;
   ObjectHolder         m_hGlobalAuthorityObject;
   PSECURITY_ATTRIBUTES m_globalSA;
   
   unsigned char        m_sdBuffer [SECURITY_DESCRIPTOR_MIN_LENGTH];
   PSECURITY_DESCRIPTOR m_sd;
   SECURITY_ATTRIBUTES  m_sa;
   
  private:
   mutable SyncObject   m_sync;
   
   static const wchar_t* m_globalAuthorityObjectName;
}; // AuthorityChecker

} // namespace guictrl
} // namespace gswserv 

#endif //_GUICTRL_AUTHORITY_CHECKER_H_
