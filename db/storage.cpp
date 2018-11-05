//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "storage.h"

#include "commonlib.h"

#include "cdbc/iconnectionfactory.h"
#include "cdbc/iconnection.h"
#include "cdbc/istatement.h"
#include "cdbc/ipreparedstatement.h"
#include "cdbc/iresultset.h"
#include "cdbc/cdbcsupport.h"

#include "config/inode.h"
#include "gesruledef.h"

#include "setting.h"

#include <boost/static_assert.hpp>
#include <boost/tuple/tuple.hpp>

using namespace sql;
using namespace std;
using namespace config;
using namespace boost::tuples;

namespace Storage {

//*****************************************************************************//
//*****************************************************************************//
//*****************************************************************************//

void SetDBSetting (const PtrToINode& node)
{
  Setting::init (node);
} // SetDBSetting

void SetDBConnectString (const wchar_t* connectString)
{
  Setting::setConnectString (connectString);
} // SetDBConnectString

void SetDBConnectString (const wstring& connectString)
{
  Setting::setConnectString (connectString);
} // SetDBConnectString

void close ()
{
  Setting::freeConnection ();
} // close

inline void printSQLException (SQLException& e)
{
#ifdef _DEBUG
  wprintf (L"\nException => %s", e.getMessageTextAndCode ());
#endif  
  throw Storage::StorageException (e.getMessage (), e.getCode ());
} // printSQLException

//
// select @ParamsId = params_id from certificates 
// where (not options & 1) and cert_type = :Type and thumbprint= :Thumbprint and expiration <= :Date
//
// select param1, param2, param3, param4, param5, param6 from params where id = @ParamsId
//
int GetParamsByCertificate(EntityAttributes& Attributes, const CertType Type, const PtrToByteArray& Thumbprint, size_t ThumbprintSize)
{
  int result = 0;
  
  try
  {
    ULARGE_INTEGER time;
    FILETIME       fileTime;
    SYSTEMTIME     sysTime;
    
    time.QuadPart = 0;
    GetLocalTime (&sysTime);
    if (TRUE == SystemTimeToFileTime (&sysTime, &fileTime))
    {
      time.HighPart = fileTime.dwHighDateTime;
      time.LowPart  = fileTime.dwLowDateTime;
    }
  
    SQLDate date (time.QuadPart);
  
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement stmt = conn->createPreparedStatement (wstring (L"select params_id from certificates where (not options & 1) and cert_type = ? and thumbprint= ? and expiration <= ?"));

    stmt->setInt (Type, 1);
    stmt->setBlob (Thumbprint.get (), ThumbprintSize, 2);
    stmt->setDate (date, 3);
  
    IPreparedStatement::PtrToIResultSet resSet = stmt->executeQuery (); 
    if (true == resSet->next ())
    {
      int ParamsId = resSet->getInt (0);
  
      stmt->close ();
    
      stmt = conn->createPreparedStatement (wstring (L"select param1, param2, param3, param4, param5, param6 from params where (not options & 1) and id = ?"));
      stmt->setInt (ParamsId, 1);
      
      resSet = stmt->executeQuery (); 
      
      if (true == resSet->next ())
      {
        for (int i=0; i<AttrNum; ++i)
          Attributes.Param[i] = resSet->getInt (i);
      }
      stmt->close ();
      result = ParamsId;
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return result;
} // GetParamsByCertificate

//
// select @ParamsId = params_id from digests 
// where (not options & 1) and digest_type = :Type and digest= :Digest
//
// select param1, param2, param3, param4, param5, param6 from params where id = @ParamsId
//
int GetParamsByDigest(EntityAttributes& Attributes, const DigestType Type, const PtrToByteArray& Digest, size_t DigestSize)
{
  int result = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement stmt = conn->createPreparedStatement (wstring (L"select params_id from digests where (not options & 1) and digest_type = ? and digest= ?"));

    stmt->setInt (Type, 1);
    stmt->setBlob (Digest.get (), DigestSize, 2);
  
    IPreparedStatement::PtrToIResultSet resSet = stmt->executeQuery (); 
    if (true == resSet->next ())
    {
      int ParamsId = resSet->getInt (0);
  
      stmt->close ();
    
      stmt = conn->createPreparedStatement (wstring (L"select param1, param2, param3, param4, param5, param6 from params where (not options & 1) and id = ?"));
      stmt->setInt (ParamsId, 1);
      
      resSet = stmt->executeQuery (); 
    
      if (true == resSet->next ())
      {
        for (int i=0; i<AttrNum; ++i)
          Attributes.Param[i] = resSet->getInt (i);
      } 
      stmt->close ();
      result = ParamsId;
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetParamsByDigest


//
// select @ParamsId = params_id from pathes 
// where (not options & 1) and res_type = :Type and path = :Path
//
// select param1, param2, param3, param4, param5, param6 from params where id = @ParamsId
//
int GetParamsByPath(EntityAttributes& Attributes, const NtObjectType Type, const wchar_t* Path)
{
  return GetParamsByPath(Attributes, Type, wstring (Path));
} // GetParamsByPath

int GetParamsByPath(EntityAttributes& Attributes, const NtObjectType Type, const wstring& Path)
{
  int result = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement stmt = conn->createPreparedStatement (wstring (L"select params_id from pathes where (not options & 1) and res_type = ? and path = ?"));

    stmt->setInt (Type, 1);
    stmt->setText (Path, 2);
  
    IPreparedStatement::PtrToIResultSet resSet = stmt->executeQuery (); 
    if (true == resSet->next ())
    {
      int ParamsId = resSet->getInt (0);
  
      stmt->close ();
    
      stmt = conn->createPreparedStatement (wstring (L"select param1, param2, param3, param4, param5, param6 from params where (not options & 1) and id = ?"));
      stmt->setInt (ParamsId, 1);
      
      resSet = stmt->executeQuery (); 
    
      if (true == resSet->next ())
      {
        for (int i=0; i<AttrNum; ++i)
          Attributes.Param[i] = resSet->getInt (i);
      }
      
      stmt->close ();  
      result = ParamsId;
    }
  }                                         
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetParamsByPath



//
// select @ParamsId = params_id from owners where (not options & 1) and res_type = :Type, sid = :Sid
//
// select param1, param2, param3, param4, param5, param6 from params where id = @ParamsId
//
int GetParamsByOwner(EntityAttributes& Attributes, const NtObjectType Type, const PSID Sid)
{
  int result = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement stmt = conn->createPreparedStatement (wstring (L"select params_id from owners where (not options & 1) and res_type = ? and sid = ?"));
    
    stmt->setInt (Type, 1);
    stmt->setBlob ((PUCHAR)Sid, GetLengthSid(Sid), 2);
  
    IPreparedStatement::PtrToIResultSet resSet = stmt->executeQuery (); 
    if (true == resSet->next ())
    {
      int ParamsId = resSet->getInt (0);
    
      stmt->close ();
      
      stmt = conn->createPreparedStatement (wstring (L"select param1, param2, param3, param4, param5, param6 from params where (not options & 1) and id = ?"));
      stmt->setInt (ParamsId, 1);
      
      resSet = stmt->executeQuery (); 
      
      if (true == resSet->next ())
      {
        for (int i=0; i<AttrNum; ++i)
          Attributes.Param[i] = resSet->getInt (i);
      }
      
      stmt->close ();
      result = ParamsId;
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetParamsByOwner



//
// select @ParamsId = params_id from contents 
// where (not options & 1) and cont_type = :Type and content= :Content
//
// select param1, param2, param3, param4, param5, param6 from params where id = @ParamsId
//
int GetParamsByContent(EntityAttributes& Attributes, const ContentType Type, const wchar_t *Content)
{
  return GetParamsByContent(Attributes, Type, wstring (Content));
} // GetParamsByContent

int GetParamsByContent(EntityAttributes& Attributes, const ContentType Type, const wstring& Content)
{
  int result = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement stmt = conn->createPreparedStatement (wstring (L"select params_id from contents where (not options & 1) and cont_type = ? and content= ?"));
    
    stmt->setInt (Type, 1);
    stmt->setText (Content, 2);
  
    IPreparedStatement::PtrToIResultSet resSet = stmt->executeQuery (); 
    if (true == resSet->next ())
    {
      int ParamsId = resSet->getInt (0);
  
      stmt->close ();
    
      stmt = conn->createPreparedStatement (wstring (L"select param1, param2, param3, param4, param5, param6 from params where (not options & 1) and id = ?"));
      stmt->setInt (ParamsId, 1);
      
      resSet = stmt->executeQuery (); 
      
      if (true == resSet->next ())
      {
        for (int i=0; i<AttrNum; ++i)
          Attributes.Param[i] = resSet->getInt (i);
      }
      
      stmt->close ();
      result = ParamsId;
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetParamsByContent

//
// select @id = id, model, param1, param2, param3, param4, param5, param6, params_id, description from params
// where (not options & 1) and param_type = 1
//
// For each id do:
//      select id, res_type, sid from owners where params_id = :@id
//
//      select id, res_type, path from pathes where params_id = :@id
//
//      select id, cert_type, thumbprint, issuedto, issuedby, expiration from certificates where params_id = :@id
//
bool GetResourceList(ResourceItemList& ResList)
{
  bool result = false;
  ResourceItemList Pathes;
  ResourceItemList Certificates;
  ResourceItemList Owners;

  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn         = connHolder.connection ();
    IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, options from params where (not options & 1) and param_type = ?"));
    
    paramsStmt->setInt (parResource, 1);
    IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
    
    while (true == paramsResSet->next ())
    {
      ParamsInfo paramsInfo;
      
      paramsInfo.Id          = paramsResSet->getInt (0);
      paramsInfo.Model       = paramsResSet->getInt (1);
      paramsInfo.GroupId     = paramsResSet->getInt (8);
      paramsInfo.Type        = parResource;
	  paramsInfo.Options	 = paramsResSet->getInt (10);
      
      for (int i=0, j=2; i<AttrNum; ++i, ++j)
      {
        paramsInfo.Attributes.Param[i] = paramsResSet->getInt (j);
      }
      
      wstring description = paramsResSet->getText (9);
      wcsncpy (paramsInfo.Description, description.c_str (), sizeof (paramsInfo.Description) / sizeof (wchar_t) - 1);
      
            
      IConnection::PtrToIPreparedStatement ownersStmt = 
        conn->createPreparedStatement (
          L"select id, res_type, sid, param_type, options from owners where (not options & 1) and params_id = ?"
        );
      ownersStmt->setInt (paramsInfo.Id, 1);
      
      IConnection::PtrToIPreparedStatement pathesStmt = 
        conn->createPreparedStatement (
          L"select id, res_type, path, param_type, options from pathes where (not options & 1) and params_id = ?"
        );
      pathesStmt->setInt (paramsInfo.Id, 1);
      
      IConnection::PtrToIPreparedStatement certsStmt  = 
        conn->createPreparedStatement (
          L"select id, cert_type, thumbprint, issuedto, issuedby, expiration, param_type, options from certificates where (not options & 1) and params_id = ?"
        );
      certsStmt->setInt (paramsInfo.Id, 1);
      
      IPreparedStatement::PtrToIResultSet ownersResSet = ownersStmt->executeQuery ();
      IPreparedStatement::PtrToIResultSet pathesResSet = pathesStmt->executeQuery ();
      IPreparedStatement::PtrToIResultSet certsResSet  = certsStmt->executeQuery ();
      
      while (true == pathesResSet->next ())
      {
        PtrToResourceItem itemPathes (new ResourceItem ());
        if (NULL != itemPathes.get ())
        {
          itemPathes->Params = paramsInfo;
          itemPathes->Identity.Type         = idnPath;
          itemPathes->Identity.Path.Id      = pathesResSet->getInt (0);
          itemPathes->Identity.Path.ParentId = paramsInfo.Id;
          itemPathes->Identity.Path.Type    = static_cast <NtObjectType> (pathesResSet->getInt (1)); 
          wcsncpy (itemPathes->Identity.Path.Path, (pathesResSet->getText (2)).c_str (), sizeof (itemPathes->Identity.Path.Path) / sizeof (wchar_t) - 1);
          itemPathes->Identity.Path.param_type = static_cast <ParamsType> (pathesResSet->getInt (3)); 
		  itemPathes->Identity.Path.Options = pathesResSet->getInt (4);
          
          Pathes.push_back (itemPathes);
        }
      } 
      
      while (true == certsResSet->next ())
      {
        PtrToResourceItem itemCerts (new ResourceItem ());
        if (NULL != itemCerts.get ())
        {
          itemCerts->Params = paramsInfo;
          itemCerts->Identity.Type         = idnCertificate;
          itemCerts->Identity.Cert.Id      = certsResSet->getInt (0);
          itemCerts->Identity.Cert.ParentId = paramsInfo.Id;
          itemCerts->Identity.Cert.Type    = static_cast <CertType> (certsResSet->getInt (1)); 
          itemCerts->Identity.Cert.ThumbprintSize = certsResSet->getBlob (2, itemCerts->Identity.Cert.Thumbprint, sizeof (itemCerts->Identity.Cert.Thumbprint));
          wcsncpy (itemCerts->Identity.Cert.IssuedTo, (certsResSet->getText (3)).c_str (), sizeof (itemCerts->Identity.Cert.IssuedTo) / sizeof (wchar_t) - 1);
          wcsncpy (itemCerts->Identity.Cert.IssuedBy, (certsResSet->getText (4)).c_str (), sizeof (itemCerts->Identity.Cert.IssuedBy) / sizeof (wchar_t) - 1);
          itemCerts->Identity.Cert.Expiration = (certsResSet->getDate (5)).getDate ();
          itemCerts->Identity.Cert.param_type = static_cast <ParamsType> (certsResSet->getInt (6)); 
		  itemCerts->Identity.Cert.Options = certsResSet->getInt (7);
          
          Certificates.push_back (itemCerts);
        }
      }

      while (true == ownersResSet->next ())
      {
        PtrToResourceItem itemOwners (new ResourceItem ());
        if (NULL != itemOwners.get ())
        {
          itemOwners->Params = paramsInfo;
          itemOwners->Identity.Type         = idnOwner;
          itemOwners->Identity.Owner.Id     = ownersResSet->getInt (0);
          itemOwners->Identity.Owner.ParentId = paramsInfo.Id;
          itemOwners->Identity.Owner.Type   = static_cast <NtObjectType> (ownersResSet->getInt (1)); 
          wcsncpy (itemOwners->Identity.Owner.Owner, ownersResSet->getText (2).c_str(), sizeof (itemOwners->Identity.Owner.Owner) / sizeof (wchar_t) - 1);
          itemOwners->Identity.Owner.param_type = static_cast <ParamsType> (ownersResSet->getInt (3)); 
		  itemOwners->Identity.Owner.Options = ownersResSet->getInt (4);
          
          Owners.push_back (itemOwners);
        }
      }
    } // while (true == paramsResSet->next ())
    
    paramsStmt->close ();
    //
    // sort resources by their type
    //
    ResourceItemList::iterator i;
    for ( i = Pathes.begin(); i != Pathes.end(); i++ ) ResList.push_back(*i);
    for ( i = Certificates.begin(); i != Certificates.end(); i++ ) ResList.push_back(*i);
    for ( i = Owners.begin(); i != Owners.end(); i++ ) ResList.push_back(*i);
    
    result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetResourceList

void fillApplicationItem (IConnection::PtrToIConnection& conn, const ParamsInfo& paramsInfo, ApplicationItem& appItem)
{
  appItem.Params = paramsInfo;
  
  if (parAppGroup < paramsInfo.Type)
  {
    CDBCSupport::PtrToIResultSet appInfo = CDBCSupport ().executeQuery <tuple <int, int> > (conn, wstring (L"select id, file_name, product_name, file_description, company_name, internal_name, original_file_name, product_version, file_version, legal_copyright, comments, product_url, lang, icon, md5, sha1, sha256, cert_thumbprint, app_options, options from appinfo where app_id = ? and (not options & ?)"), tuple <int, int> (paramsInfo.Attributes.Param [GesRule::attSubjectId], dboDeleted));
    if (NULL != appInfo.get ())
    {
      //CDBCSupport ().queryResult <tuple <int&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, int&, CDBCSupport::blob&, CDBCSupport::blob&, CDBCSupport::blob&, CDBCSupport::blob&, CDBCSupport::blob&, int&> > 
      //  (appInfo, 
      //   tuple <int&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, CDBCSupport::wstr&, int&, CDBCSupport::blob&, CDBCSupport::blob&, CDBCSupport::blob&, CDBCSupport::blob&, CDBCSupport::blob&, int&> 
      //     (appItem.Id, 
      //      CDBCSupport::wstr (appItem.FileName,         sizeof (appItem.FileName) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.ProductName,      sizeof (appItem.ProductName) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.FileDescription,  sizeof (appItem.FileDescription) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.CompanyName,      sizeof (appItem.CompanyName) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.InternalName,     sizeof (appItem.InternalName) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.OriginalFilename, sizeof (appItem.OriginalFilename) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.ProductVersion,   sizeof (appItem.ProductVersion) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.FileVersion,      sizeof (appItem.FileVersion) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.LegalCopyright,   sizeof (appItem.LegalCopyright) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.Comments,         sizeof (appItem.Comments) / sizeof (wchar_t) - 1),
      //      CDBCSupport::wstr (appItem.ProductURL,       sizeof (appItem.ProductURL) / sizeof (wchar_t) - 1),
      //      appItem.Lang,
      //      CDBCSupport::blob (appItem.Icon,             sizeof (appItem.Icon), reinterpret_cast <size_t&> (appItem.IconSize)),
      //      CDBCSupport::blob (appItem.MD5,              sizeof (appItem.MD5)),
      //      CDBCSupport::blob (appItem.SHA1,             sizeof (appItem.SHA1)),
      //      CDBCSupport::blob (appItem.SHA256,           sizeof (appItem.SHA256)),
      //      CDBCSupport::blob (appItem.CertThumbprint,   sizeof (appItem.CertThumbprint)),
      //      appItem.AppOptions
      //     ) 
      //  );
      
      CDBCSupport              cdbcsupport;
      CDBCSupport::GetterIndex index; //-1;
      
      cdbcsupport.get <int&> (appItem.Id, appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.FileName,         sizeof (appItem.FileName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.ProductName,      sizeof (appItem.ProductName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.FileDescription,  sizeof (appItem.FileDescription) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.CompanyName,      sizeof (appItem.CompanyName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.InternalName,     sizeof (appItem.InternalName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.OriginalFilename, sizeof (appItem.OriginalFilename) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.ProductVersion,   sizeof (appItem.ProductVersion) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.FileVersion,      sizeof (appItem.FileVersion) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.LegalCopyright,   sizeof (appItem.LegalCopyright) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.Comments,         sizeof (appItem.Comments) / sizeof (wchar_t) - 1), appInfo, index); 
      cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appItem.ProductURL,       sizeof (appItem.ProductURL) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.get <unsigned int&> (appItem.Lang, appInfo, index);
      cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appItem.Icon,             sizeof (appItem.Icon), reinterpret_cast <size_t&> (appItem.IconSize)), appInfo, index);
      cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appItem.MD5,              sizeof (appItem.MD5)), appInfo, index);
      cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appItem.SHA1,             sizeof (appItem.SHA1)), appInfo, index);
      cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appItem.SHA256,           sizeof (appItem.SHA256)), appInfo, index);
      cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appItem.CertThumbprint,   sizeof (appItem.CertThumbprint)), appInfo, index);
      cdbcsupport.get <unsigned int&> (appItem.AppOptions, appInfo, index);
      cdbcsupport.get <int&> (appItem.Options, appInfo, index);
    } // if (NULL == appInfo.get ())
    
    //IConnection::PtrToIPreparedStatement contentsStmt = conn->createPreparedStatement (wstring (L"select content, file_name from contents where (not options & 1) and params_id = ? and cont_type = ?"));
    //contentsStmt->setInt (paramsInfo.Id, 1);
    //contentsStmt->setInt (cntProductName, 2);
  
    //IPreparedStatement::PtrToIResultSet contentsResSet = contentsStmt->executeQuery ();
  
    //if (true == contentsResSet->next ())
    //{
    //  wstring content = contentsResSet->getText (0);
    //  size_t index = content.find (L";");
    //  if (wstring::npos == index)
    //  {
    //    wcsncpy (appItem.ProductName, content.c_str (), sizeof (appItem.ProductName) / sizeof (wchar_t) - 1);
    //  }
    //  else
    //  {
    //    wcsncpy (appItem.ProductName, content.c_str (), index);
    //    wcsncpy (appItem.CompanyName, &((content.c_str ()) [index + 1]), sizeof (appItem.ProductName) / sizeof (wchar_t) - 1);
    //  }
    //} // if (true == contentsResSet->next ())
  } // if (parAppGroup < paramsInfo.Type)
  
  switch (paramsInfo.Type)
  {
    case parAppContent:     
    {
         IConnection::PtrToIPreparedStatement contentsStmt = 
           conn->createPreparedStatement (
             L"select id, cont_type, content, file_name, param_type, options from contents where (not options & 1) and params_id = ?"
           );
         contentsStmt->setInt (paramsInfo.Id, 1);
         
         IPreparedStatement::PtrToIResultSet contentsResSet = contentsStmt->executeQuery ();
         if (true == contentsResSet->next ())
         {
           appItem.Identity.Type      = idnContent;
           appItem.Identity.Info.Id   = contentsResSet->getInt (0);
           appItem.Identity.Info.ParentId = paramsInfo.Id;
           appItem.Identity.Info.Type = static_cast <ContentType> (contentsResSet->getInt (1));
           wcsncpy (appItem.Identity.Info.Content, (contentsResSet->getText (2)).c_str (), sizeof (appItem.Identity.Info.Content) / sizeof (wchar_t) - 1);
           wcsncpy (appItem.Identity.Info.FileName, (contentsResSet->getText (3)).c_str (), sizeof (appItem.Identity.Info.FileName) / sizeof (wchar_t) - 1);
           appItem.Identity.Info.param_type = static_cast <ParamsType> (contentsResSet->getInt (4));
		   appItem.Identity.Info.Options = contentsResSet->getInt (5);
         }
         break;
    }     
    case parAppPath:   
    { 
         IConnection::PtrToIPreparedStatement pathesStmt = 
           conn->createPreparedStatement (
             L"select id, res_type, path, param_type, options from pathes where (not options & 1) and params_id = ?"
           );
         pathesStmt->setInt (paramsInfo.Id, 1);
         
         IPreparedStatement::PtrToIResultSet     pathesResSet = pathesStmt->executeQuery ();
         if (true == pathesResSet->next ())
         {
           appItem.Identity.Type         = idnPath;
           appItem.Identity.Path.Id      = pathesResSet->getInt (0);
           appItem.Identity.Path.ParentId = paramsInfo.Id;
           appItem.Identity.Path.Type    = static_cast <NtObjectType> (pathesResSet->getInt (1)); 
           wcsncpy (appItem.Identity.Path.Path, (pathesResSet->getText (2)).c_str (), sizeof (appItem.Identity.Path.Path) / sizeof (wchar_t) - 1);
           appItem.Identity.Path.param_type = static_cast <ParamsType> (pathesResSet->getInt (3));
		   appItem.Identity.Path.Options = pathesResSet->getInt (4);
         } 
         break;
    }
    case parAppDigest:   
    {
         IConnection::PtrToIPreparedStatement digestsStmt = 
           conn->createPreparedStatement (
             L"select id, digest_type, digest, file_name, param_type, options from digests where (not options & 1) and params_id = ?"
           );
         digestsStmt->setInt (paramsInfo.Id, 1);
         
         IPreparedStatement::PtrToIResultSet  digestsResSet = digestsStmt->executeQuery ();
         if (true == digestsResSet->next ())
         {
           appItem.Identity.Type           = idnDigest;
           appItem.Identity.Digest.Id      = digestsResSet->getInt (0);
           appItem.Identity.Digest.ParentId = paramsInfo.Id;
           appItem.Identity.Digest.Type    = static_cast <DigestType> (digestsResSet->getInt (1)); 
           appItem.Identity.Digest.DigestSize = digestsResSet->getBlob (2, appItem.Identity.Digest.Digest, sizeof (appItem.Identity.Digest.Digest));
           wcsncpy (appItem.Identity.Digest.FileName, (digestsResSet->getText (3)).c_str (), sizeof (appItem.Identity.Digest.FileName) / sizeof (wchar_t) - 1);
           appItem.Identity.Digest.param_type = static_cast <ParamsType> (digestsResSet->getInt (4));
		   appItem.Identity.Digest.Options = digestsResSet->getInt (5);
         } 
         break;
    }
  } // switch (paramsInfo.Type)
} // fillApplicationItem

//
// select @id = id, model, param1, param2, param3, param4, param5, param6, params_id, description, param_type from params
// where (not options & 1) and param_type > 2 and ( ( :Id = 0 and params_id is null ) or params_id = :Id )
//
// // For each param_type = 3 do:
// //   select @id = id, param1, param2, param3, param4, param5, param6, description, param_type, params_id from params
// //   where (not options & 1) and params_id = :@id
//
// For each param_type > 3 do:
//
//      select content, file_name from contents 
//      where (not options & 1) and params_id = :@id and cont_type = 1
//
// For each param_type = 4 do:
//
//      select id, cont_type, content from contents where (not options & 1) and params_id = :@id
//
// For each param_type = 5 do:
//
//      select id, res_type, path from pathes where (not options & 1) and params_id = :@id
//
// For each param_type = 6 do:
//
//      select id, digest_type, digest, file_name from digests where (not options & 1) and params_id = :@id
//
bool GetApplicationList(int GroupId, ApplicationItemList& AppList)
{
  bool result = false;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn         = connHolder.connection ();
    IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, param_type, options from params where (not options & 1) and param_type > ? and ( ( ? = 0 and group_id is null ) or group_id = ? )"));

    paramsStmt->setInt (parResourceApp, 1);
    paramsStmt->setInt (GroupId, 2);
    paramsStmt->setInt (GroupId, 3);
    IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
    
    while (true == paramsResSet->next ())
    {
      ParamsInfo paramsInfo;
      
      paramsInfo.Id          = paramsResSet->getInt (0);
      paramsInfo.Model       = paramsResSet->getInt (1);
      paramsInfo.GroupId     = paramsResSet->getInt (8);
      paramsInfo.Type        = static_cast <ParamsType> (paramsResSet->getInt (10));
	  paramsInfo.Options	 = paramsResSet->getInt (11);
      
      for (int i=0, j=2; i<AttrNum; ++i, ++j)
      {
        paramsInfo.Attributes.Param[i] = paramsResSet->getInt (j);
      }
      
      wstring description = paramsResSet->getText (9);
      wcsncpy (paramsInfo.Description, description.c_str (), sizeof (paramsInfo.Description) / sizeof (wchar_t) - 1);
      
      PtrToApplicationItem appItem (new ApplicationItem ());
      if (NULL != appItem.get ())
      {
        fillApplicationItem (conn, paramsInfo, (*appItem));
        AppList.push_back (appItem);
      } // if (NULL != appItem.get ())
    } // while (true == paramsResSet->next ())
    
    paramsStmt->close ();
    
    result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetApplicationList

// 
// select @id = id, model, param1, param2, param3, param4, param5, param6, params_id, description, param_type from params 
// where (not options & 1) and param2 = :AppId 
// 
// then for each record 
// select id, params_id, res_type, path from pathes where params_id = :@id 
// 
// 
bool GetApplicationResources(int AppId, ResourceItemList& ResList)
{
  bool result = false;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn         = connHolder.connection ();
    IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, param_type, options from params where (not options & 1) and param2 = ?"));
    
    paramsStmt->setInt (AppId, 1);
    IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
    
    while (true == paramsResSet->next ())
    {
      ParamsInfo paramsInfo;
      
      paramsInfo.Id         = paramsResSet->getInt (0);
      paramsInfo.Model      = paramsResSet->getInt (1);
      paramsInfo.GroupId    = paramsResSet->getInt (8);
      paramsInfo.Type       = static_cast <ParamsType> (paramsResSet->getInt (10));
	  paramsInfo.Options	= paramsResSet->getInt (11);
      
      for (int i=0, j=2; i<AttrNum; ++i, ++j)
      {
        paramsInfo.Attributes.Param[i] = paramsResSet->getInt (j);
      }
      
      wstring description = paramsResSet->getText (9);
      wcsncpy (paramsInfo.Description, description.c_str (), sizeof (paramsInfo.Description) / sizeof (wchar_t) - 1);
    
    
      IConnection::PtrToIPreparedStatement pathesStmt = 
        conn->createPreparedStatement (
          L"select id, res_type, path, param_type, options from pathes where (not options & 1) and params_id = ?"
        );
      pathesStmt->setInt (paramsInfo.Id, 1);
    
      IPreparedStatement::PtrToIResultSet  pathesResSet = pathesStmt->executeQuery ();
      while (true == pathesResSet->next ())
      {
        PtrToResourceItem itemPathes (new ResourceItem ());
        if (NULL != itemPathes.get ())
        {
          itemPathes->Params = paramsInfo;
          itemPathes->Identity.Type         = idnPath;
          itemPathes->Identity.Path.Id      = pathesResSet->getInt (0);
          itemPathes->Identity.Path.ParentId = paramsInfo.Id;
          itemPathes->Identity.Path.Type    = static_cast <NtObjectType> (pathesResSet->getInt (1)); 
          wcsncpy (itemPathes->Identity.Path.Path, (pathesResSet->getText (2)).c_str (), sizeof (itemPathes->Identity.Path.Path) / sizeof (wchar_t) - 1);
          itemPathes->Identity.Path.param_type = static_cast <ParamsType> (pathesResSet->getInt (3)); 
		  itemPathes->Identity.Path.Options = pathesResSet->getInt (4);
        
          ResList.push_back (itemPathes);
        }
      } // while (true == pathesResSet->next ())
    } // while (true == paramsResSet->next ())
    
    result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result ;
} // GetApplicationResources

//
// select id, model, param1, param2, param3, param4, param5, param6, params_id, description, param_type from params
// where (not options & 1) and param_type > ? and param1 = :AppId
//
bool GetApplicationItem (IConnection::PtrToIConnection& conn, int AppId, ApplicationItem& appItem)
{
  bool result = false;
  
  try
  {
    IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, param_type, options from params where (not options & 1) and param_type > ? and param1 = ?"));

    paramsStmt->setInt (parResourceApp, 1);
    paramsStmt->setInt (AppId, 2);
    IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
    
    if (true == paramsResSet->next ())
    {
      ParamsInfo paramsInfo;
      
      paramsInfo.Id         = paramsResSet->getInt (0);
      paramsInfo.Model      = paramsResSet->getInt (1);
      paramsInfo.GroupId    = paramsResSet->getInt (8);
      paramsInfo.Type       = static_cast <ParamsType> (paramsResSet->getInt (10));
	  paramsInfo.Options	= paramsResSet->getInt (11);
      
      for (int i=0, j=2; i<AttrNum; ++i, ++j)
      {
        paramsInfo.Attributes.Param[i] = paramsResSet->getInt (j);
      }
      
      wstring description = paramsResSet->getText (9);
      wcsncpy (paramsInfo.Description, description.c_str (), sizeof (paramsInfo.Description) / sizeof (wchar_t) - 1);
      
      fillApplicationItem (conn, paramsInfo, appItem);
     
      result = true;
    } // if (true == paramsResSet->next ())
    
    paramsStmt->close ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetApplicationItem

bool GetApplicationItem (int AppId, ApplicationItem& appItem)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return GetApplicationItem (conn, AppId, appItem);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // GetApplicationItem

//
// select id, model, param1, param2, param3, param4, param5, param6, params_id, description, param_type from params
// where (not options & 1) and param_type > ? and description = :AppName
//
bool GetApplicationItem (IConnection::PtrToIConnection& conn, wstring &AppName, int GroupId, ApplicationItem& appItem)
{
  bool result = false;
  
  try
  {
    IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, param_type, options from params where (not options & 1) and param_type > ? and description = ? and group_id = ?"));

    paramsStmt->setInt (parResourceApp, 1);
    paramsStmt->setText (AppName, 2);
	paramsStmt->setInt (GroupId, 3);
    IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
    
    if (true == paramsResSet->next ())
    {
      ParamsInfo paramsInfo;
      
      paramsInfo.Id         = paramsResSet->getInt (0);
      paramsInfo.Model      = paramsResSet->getInt (1);
      paramsInfo.GroupId    = paramsResSet->getInt (8);
      paramsInfo.Type       = static_cast <ParamsType> (paramsResSet->getInt (10));
	  paramsInfo.Options	= paramsResSet->getInt (11);
      
      for (int i=0, j=2; i<AttrNum; ++i, ++j)
      {
        paramsInfo.Attributes.Param[i] = paramsResSet->getInt (j);
      }
      
      wstring description = paramsResSet->getText (9);
      wcsncpy (paramsInfo.Description, description.c_str (), sizeof (paramsInfo.Description) / sizeof (wchar_t) - 1);
      
      fillApplicationItem (conn, paramsInfo, appItem);
     
      result = true;
    } // if (true == paramsResSet->next ())
    
    paramsStmt->close ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetApplicationItem

bool GetApplicationItem (wstring &AppName, int GroupId, ApplicationItem& appItem)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return GetApplicationItem (conn, AppName, GroupId, appItem);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // GetApplicationItem

//
//select id, model, param1, param2, param3, param4, param5, param6, params_id, description, param_type from params
//where (not options & 1) and param_type = :Type
//
bool GetApplicationList (ParamsType type, ApplicationItemList& AppList)
{
  bool result = false;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn         = connHolder.connection ();
    IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, param_type, options from params where (not options & 1) and param_type = ?"));

    paramsStmt->setInt (type, 1);
    IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
    
    while (true == paramsResSet->next ())
    {
      ParamsInfo paramsInfo;
      
      paramsInfo.Id         = paramsResSet->getInt (0);
      paramsInfo.Model      = paramsResSet->getInt (1);
      paramsInfo.GroupId    = paramsResSet->getInt (8);
      paramsInfo.Type       = static_cast <ParamsType> (paramsResSet->getInt (10));
	  paramsInfo.Options	= paramsResSet->getInt (11);
      
      for (int i=0, j=2; i<AttrNum; ++i, ++j)
      {
        paramsInfo.Attributes.Param[i] = paramsResSet->getInt (j);
      }
      
      wstring description = paramsResSet->getText (9);
      wcsncpy (paramsInfo.Description, description.c_str (), sizeof (paramsInfo.Description) / sizeof (wchar_t) - 1);
      
      PtrToApplicationItem appItem (new ApplicationItem ());
      if (NULL != appItem.get ())
      {
        fillApplicationItem (conn, paramsInfo, (*appItem));
        AppList.push_back (appItem);
      } // if (NULL != appItem.get ())
    } // while (true == paramsResSet->next ())
    
    paramsStmt->close ();
    
    result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetApplicationList

void GetParamsInfo(CDBCSupport::PtrToIResultSet &paramsStmt, ParamsInfo &paramsInfo)
{
  paramsInfo.Id         = paramsStmt->getInt (0);
  paramsInfo.Model      = paramsStmt->getInt (1);
  paramsInfo.GroupId    = paramsStmt->getInt (8);
  paramsInfo.Type       = static_cast <ParamsType> (paramsStmt->getInt (10));
  paramsInfo.Options	= paramsStmt->getInt (11);
      
  for (int i=0, j=2; i<AttrNum; ++i, ++j)
  {
	paramsInfo.Attributes.Param[i] = paramsStmt->getInt (j);
  }
      
  wstring description = paramsStmt->getText (9);
  wcsncpy (paramsInfo.Description, description.c_str (), sizeof (paramsInfo.Description) / sizeof (wchar_t) - 1);
}

int GetGroupId(const int GroupCode, const GUID &GroupGuid)
{
  int GroupId = 0;
  try {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection conn	 = connHolder.connection ();
	int *Guid = (int *) &GroupGuid; 
	CDBCSupport::PtrToIResultSet groupId = CDBCSupport ().executeQuery <tuple <int, int, int, int, int, int> > (conn, wstring (L"select param1 from params where param2 = ? and param3 = ? and param4 = ? and param5 = ? and param6 = ? and (not options & ?)"), tuple <int, int, int, int, int, int> (GroupCode, Guid[0], Guid[1], Guid[2], Guid[3], dboDeleted));
	if ( NULL != groupId.get () )
	{
		GroupId = groupId->getInt (0);
	}
  } catch ( ... ) { }

  return GroupId;
} // GetGroupItem

void GetSecurityClass(const int Id, ParamsInfo& Info)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection conn      = connHolder.connection ();
	CDBCSupport::PtrToIResultSet paramsStmt = CDBCSupport ().executeQuery <tuple <int, int, int> > (conn, wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, param_type, options from params where (not options & ?) and param_type = ? and id = ?"), tuple <int, int, int> (dboDeleted, parResource, Id));
    if (NULL != paramsStmt.get ())
    {
	  GetParamsInfo(paramsStmt, Info);
	}
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void GetSucurityClassesList(ParamsInfoList &List)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection conn      = connHolder.connection ();
	CDBCSupport::PtrToIResultSet paramsStmt = CDBCSupport ().executeQuery <tuple <int, int> > (conn, wstring (L"select id, model, param1, param2, param3, param4, param5, param6, group_id, description, param_type, options from params where (not options & ?) and param_type = ?"), tuple <int, int> (dboDeleted, parResource));
	if ( NULL != paramsStmt.get () )
	{
		do
		{
		PtrToParamsInfo paramsInfo(new ParamsInfo);
		GetParamsInfo(paramsStmt, *paramsInfo);
		List.push_back(paramsInfo);
		} while ( paramsStmt->next () );
	}
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void GetIdsPatternsList(IdsPatternItemList &List)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection conn      = connHolder.connection ();
	CDBCSupport::PtrToIResultSet paramsStmt = CDBCSupport ().executeQuery <tuple <int> > (conn, wstring (L"select id, options, res_type, pattern_type, pattern, message, flags from idspatterns where (not options & ?)"), tuple <int> (dboDeleted));
	if ( NULL != paramsStmt.get () )
	{
		do
		{
		PtrToIdsPatternItem PatternItem(new IdsPatternItem);
		PatternItem->Id				= paramsStmt->getInt (0);
		PatternItem->Options		= paramsStmt->getInt (1);
		PatternItem->ResType		= static_cast <NtObjectType> (paramsStmt->getInt (2));
		PatternItem->PatternType	= static_cast <IdsPatternType> (paramsStmt->getInt (3));
		wcsncpy(PatternItem->Pattern, paramsStmt->getText (4).c_str(), sizeof PatternItem->Pattern / sizeof PatternItem->Pattern[0] - 1);
		PatternItem->Pattern[sizeof PatternItem->Pattern / sizeof PatternItem->Pattern[0] - 1] = 0;
		wcsncpy(PatternItem->Message, paramsStmt->getText (5).c_str(), sizeof PatternItem->Message / sizeof PatternItem->Message[0] - 1);
		PatternItem->Message[sizeof PatternItem->Message / sizeof PatternItem->Message[0] - 1] = 0;
		PatternItem->Flags = paramsStmt->getInt (6);

		List.push_back(PatternItem);
		} while ( paramsStmt->next () );
	}
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

//
// insert into params (id, model, param_type, description, param1, param2, param3, param4, param5, param6, group_id, guid)
// values ( null, :Model, :Type, :Description, :param1, :param2, :param3, :param4, :param5, :param6, :GroupId, :Guid )
//
int InsertParams(const GUID& guid, IConnection::PtrToIConnection& conn, const ParamsInfo& Info)
{
  int  result = 0;
  
  try
  {
    IConnection::PtrToIPreparedStatement stmt = conn->createPreparedStatement (wstring (L"insert into params (id, model, param_type, description, param1, param2, param3, param4, param5, param6, group_id, guid, options) values ( null, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    
    stmt->setInt (Info.Model, 1);
    stmt->setInt (Info.Type, 2);
    stmt->setText (wstring (Info.Description), 3);
    //:param1, :param2, :param3, param4, param5, param6
    for (int i=0; i<AttrNum; ++i)
    {
      stmt->setInt (Info.Attributes.Param[i], i+4);
    }
    stmt->setInt (Info.GroupId, 10);
    stmt->setBlob ((PUCHAR)&guid, sizeof guid, 11);
	stmt->setInt (static_cast <int> (Info.Options), 12);
    
    result = static_cast <int> (stmt->executeUpdate ()); 
    stmt->close ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
   
#pragma message (__WARNING__ "TODO: if exception is unique violation throw ParamsExists")
  }
  
  return result;
} // InsertParams

int InsertParams(IConnection::PtrToIConnection& conn, const ParamsInfo& Info)
{
  int  result = 0;
  
  GUID guid;
  if ( CoCreateGuid (&guid) != S_OK ) 
    return result;

  return InsertParams (guid, conn, Info);
} // InsertParams

int InsertParams(const ParamsInfo& Info)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return InsertParams (conn, Info);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  return 0;
} // InsertParams

//
// insert into certificates (id, cert_type, thumbprint, issuedto, issuedby, expiration, params_id, guid)
// values ( null, :Type, :Thumbprint, :IssuedTo, :IssuedBy, :Expiration, :ParamsId, :Guid )
//
void InsertCertificate(const GUID& guid, IConnection::PtrToIConnection& conn, const CertInfo& Info, int &Id)
{
  Id = 0;
  
  try
  {
    SQLDate date (Info.Expiration);
    
    IConnection::PtrToIPreparedStatement chkStmt = 
      conn->createPreparedStatement (
        L"select id from certificates where cert_type = ? and thumbprint = ? and issuedto = ? and issuedby = ? and  expiration = ? and options = ?"
      );
    chkStmt->setInt (Info.Type, 1);
    chkStmt->setBlob (Info.Thumbprint, Info.ThumbprintSize, 2);
    chkStmt->setText (wstring (Info.IssuedTo), 3);
    chkStmt->setText (wstring (Info.IssuedBy), 4);
    chkStmt->setDate (date, 5);
	chkStmt->setInt (Info.Options, 6);
    
    IPreparedStatement::PtrToIResultSet  chkResSet = chkStmt->executeQuery ();
    if (false == chkResSet->next ())
    {
      chkStmt->close ();
      
      IConnection::PtrToIPreparedStatement stmt = 
        conn->createPreparedStatement (
          L"insert into certificates (id, cert_type, thumbprint, issuedto, issuedby, expiration, params_id, guid, options, param_type) values ( null, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );

      stmt->setInt (Info.Type, 1);
      stmt->setBlob (Info.Thumbprint, Info.ThumbprintSize, 2);
      stmt->setText (wstring (Info.IssuedTo), 3);
      stmt->setText (wstring (Info.IssuedBy), 4);
      stmt->setDate (date, 5);
      stmt->setInt (Info.ParentId, 6);
      stmt->setBlob ((PUCHAR)&guid, sizeof guid, 7);
	  stmt->setInt (static_cast <int> (Info.Options), 8);
      stmt->setInt (static_cast <int> (Info.param_type), 9);
    
      Id = static_cast <int> (stmt->executeUpdate ()); 
      stmt->close ();
    }
    else 
    {
	  Id = chkResSet->getInt (0);
	  throw CertificateExistException(L"Certificate alreasy present");
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertCertificate

void InsertCertificate(IConnection::PtrToIConnection& conn, const CertInfo& Info, int &Id)
{
  Id = 0;
  GUID guid;
  if ( CoCreateGuid (&guid) != S_OK ) throw StorageException(L"Guid create error");

  InsertCertificate (guid, conn, Info, Id);
} // InsertCertificate

void InsertCertificate(const CertInfo& Info, int &Id)
{
  Id = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return InsertCertificate (conn, Info, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertCertificate

//
// insert into digests (id, digest_type, digest, file_name, params_id)
// values ( null, :Type, :Digest, :DigestSize, :FileName, :ParamsId  )
// 
int InsertDigest(const GUID& guid, IConnection::PtrToIConnection& conn, const DigestInfo& Info)
{
  int  result = 0;
  
  try
  {
    IConnection::PtrToIPreparedStatement chkStmt = 
      conn->createPreparedStatement (
        L"select id from digests where digest_type = ? and digest = ? and options = ?"
      );
    chkStmt->setInt (Info.Type, 1);
    chkStmt->setBlob (Info.Digest, Info.DigestSize, 2);
	chkStmt->setInt (Info.Options, 3);
    
    IPreparedStatement::PtrToIResultSet  chkResSet = chkStmt->executeQuery ();
    if (false == chkResSet->next ())
    {
      chkStmt->close (); 
  
      IConnection::PtrToIPreparedStatement stmt = 
        conn->createPreparedStatement (
          L"insert into digests (id, digest_type, digest, file_name, params_id, guid, options, param_type) values ( null, ?, ?, ?, ?, ?, ?, ? )"
        );

      stmt->setInt (Info.Type, 1);
      stmt->setBlob (Info.Digest, Info.DigestSize, 2);
      stmt->setText (wstring (Info.FileName), 3);
      stmt->setInt (Info.ParentId, 4);
      stmt->setBlob ((PUCHAR)&guid, sizeof guid, 5);
	  stmt->setInt (static_cast <int> (Info.Options), 6);
      stmt->setInt (static_cast <int> (Info.param_type), 7);
    
      result = static_cast <int> (stmt->executeUpdate ()); 
      stmt->close ();
    }else 
    { 
#pragma message (__WARNING__ "TODO: throw exception DigestExists")
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // InsertDigest

int InsertDigest(IConnection::PtrToIConnection& conn, const DigestInfo& Info)
{
  int  result = 0;
  
  GUID guid;
  if ( CoCreateGuid (&guid) != S_OK ) 
    return result;

  return InsertDigest (guid, conn, Info);
} // InsertDigest

int InsertDigest(const DigestInfo& Info)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return InsertDigest (conn, Info);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  return 0;
} // InsertDigest

//
// insert into pathes (id, res_type, path, params_id, guid)
// values ( null, :Type, :Path, :ParamsId, :Guid ) 
//
int InsertPath(const GUID& guid, IConnection::PtrToIConnection& conn, const PathInfo& Info)
{
  int  result = 0;
  
  try
  {
    IConnection::PtrToIPreparedStatement stmt = 
      conn->createPreparedStatement (
        L"insert into pathes (id, res_type, path, params_id, guid, options, param_type) values ( null, ?, ?, ?, ?, ?, ? )"
      );

    stmt->setInt (Info.Type, 1);
    stmt->setText (wstring (Info.Path), 2);
    stmt->setInt (Info.ParentId, 3);
    stmt->setBlob ((PUCHAR)&guid, sizeof guid, 4);
	stmt->setInt (static_cast <int> (Info.Options), 5);
    stmt->setInt (static_cast <int> (Info.param_type), 6);
    
    result = static_cast <int> (stmt->executeUpdate ()); 
    stmt->close ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // InsertPath

int InsertPath(IConnection::PtrToIConnection& conn, const PathInfo& Info)
{
  int  result = 0;
  
  GUID guid;
  if ( CoCreateGuid (&guid) != S_OK ) 
    return result;

  return InsertPath (guid, conn, Info);
} // InsertPath

int InsertPath(const PathInfo& Info)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return InsertPath (conn, Info);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  return 0;
} // InsertPath

//
// insert into owners (id, res_type, sid, params_id, guid)
// values ( null, :Type, :Sid, :ParamsId, :Guid )
//
void InsertOwner(const GUID& guid, IConnection::PtrToIConnection& conn, const OwnerInfo& Info, int &Id)
{
  Id = 0;
  
  try
  { 
    IConnection::PtrToIPreparedStatement chkStmt = 
      conn->createPreparedStatement (
        L"select id from owners where sid = ? and res_type = ? and options = ?"
      );
    chkStmt->setText (wstring (Info.Owner), 1);
    chkStmt->setInt (Info.Type, 2);
	chkStmt->setInt (Info.Options, 3);
    
    IPreparedStatement::PtrToIResultSet  chkResSet = chkStmt->executeQuery ();
    if (false == chkResSet->next ())
    {
      chkStmt->close (); 
      
      IConnection::PtrToIPreparedStatement stmt = 
        conn->createPreparedStatement (
          L"insert into owners (id, sid, res_type, params_id, guid, options, param_type) values ( null, ?, ?, ?, ?, ?, ? )"
        );

      stmt->setText (wstring (Info.Owner), 1);
      stmt->setInt (Info.Type, 2);
      stmt->setInt (Info.ParentId, 3);
      stmt->setBlob ((PUCHAR)&guid, sizeof guid, 4);
	  stmt->setInt (static_cast <int> (Info.Options), 5);
      stmt->setInt (static_cast <int> (Info.param_type), 6);
    
      Id = static_cast <int> (stmt->executeUpdate ()); 
      stmt->close ();
    }
    else 
    { 
	  Id = chkResSet->getInt (0);
	  throw OwnerExistException(L"Owner exists");
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertOwner

void InsertOwner(IConnection::PtrToIConnection& conn, const OwnerInfo& Info, int &Id)
{
  GUID guid;
  if ( CoCreateGuid (&guid) != S_OK ) throw StorageException(L"Guid create error");

  InsertOwner (guid, conn, Info, Id);
} // InsertOwner

void InsertOwner(const OwnerInfo& Info, int &Id)
{
  Id = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return InsertOwner (conn, Info, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertOwner

//
// insert into contents (id, res_type, content, file_name, params_id, guid)
// values ( null, :Type, :Content, :FileName, :ParamsId, :Guid )
//
int InsertContent(const GUID& guid, IConnection::PtrToIConnection& conn, const ContentInfo& Info)
{
  int  result = 0;
  
  try
  {
    CDBCSupport::PtrToIResultSet contentId = 
      CDBCSupport ().executeQuery <tuple <int, const wstring&, int, int, int> > (
        conn, 
        L"select id from contents where cont_type = ? and content = ? and not ( options & ?) and not (? & ?) ", 
        tuple <int, const wstring&, int, int, int> (Info.Type, wstring (Info.Content), dboDeleted, Info.Options, dboDeleted)
      );
    if (NULL == contentId.get ()) // IsContentExist
    {
      IConnection::PtrToIPreparedStatement stmt = 
        conn->createPreparedStatement (
          L"insert into contents (id, cont_type, content, file_name, params_id, guid, options, param_type) values ( null, ?, ?, ?, ?, ?, ?, ? )"
        );

      stmt->setInt (Info.Type, 1);
      stmt->setText (wstring (Info.Content), 2);
      stmt->setText (wstring (Info.FileName), 3);
      stmt->setInt (Info.ParentId, 4);
      stmt->setBlob ((PUCHAR)&guid, sizeof guid, 5);
      stmt->setInt (static_cast <int> (Info.Options), 6);
      stmt->setInt (static_cast <int> (Info.param_type), 7);

      result = static_cast <int> (stmt->executeUpdate ()); 
      stmt->close ();
    }
    else 
    {  
      throw Storage::ContentExistException (L"Content exists");
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // InsertContent

int InsertContent(IConnection::PtrToIConnection& conn, const ContentInfo& Info)
{
  int  result = 0;
  
  GUID guid;
  if ( CoCreateGuid (&guid) != S_OK ) 
    return result;

  return InsertContent (guid, conn, Info);
} // InsertContent

int InsertContent(const ContentInfo& Info)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return InsertContent (conn, Info);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  return 0;
} // InsertContent

bool GroupIsEmpty(int GroupId)
{ 
    try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    
    CDBCSupport::PtrToIResultSet children = CDBCSupport ().executeQuery <tuple <int, int> > (conn, wstring (L"select id from params where group_id = ? and (not options & ?)"), tuple <int, int> (GroupId, dboDeleted));
    return (NULL == children.get ())? TRUE: FALSE; 

  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
 return 0; 
}

void InsertApplication (IConnection::PtrToIConnection& conn, ApplicationItem &AppItem, bool updateAppId, int &AppId)
{
  AppId = 0;
  
  try
  {
	//
	// Check if such identity (application) already present
	//
	CDBCSupport::PtrToIResultSet selectAppId;

	if(AppItem.InternalName[0] == 0 && AppItem.CompanyName[0] == 0 && 
	   AppItem.ProductName[0] == 0 && AppItem.OriginalFilename[0] == 0 )
	{
		selectAppId =  CDBCSupport ().executeQuery <tuple <int, const CDBCSupport::blob&> > 
	  (
        conn, 
        L"select app_id from appinfo where not (? & options) and sha1 = ?", 
        tuple <int,  const CDBCSupport::blob&> (dboDeleted, CDBCSupport::blob (&AppItem.SHA1, sizeof (AppItem.SHA1)))
      );
	}
	else
	if ( AppItem.Params.Type == parAppContent ) {
		if ( AppItem.InternalName[0] != 0 || AppItem.OriginalFilename[0] != 0  )
		{
			selectAppId = CDBCSupport ().executeQuery <tuple <int, const wstring&, const wstring&, const CDBCSupport::blob&> > 
			(
				conn, 
				L"select app_id from appinfo where not (? & options) and ( ( internal_name = ? and original_file_name = ? ) or sha1 = ? )", 
				tuple <int, const wstring&, const wstring&, const CDBCSupport::blob&> (dboDeleted, AppItem.InternalName, AppItem.OriginalFilename, CDBCSupport::blob (&AppItem.SHA1, sizeof (AppItem.SHA1)))
			);
		}
		else
		if ( ( AppItem.ProductName[0] != 0 || AppItem.CompanyName[0] != 0 ) && AppItem.Params.Type == parAppContent )
		{
			selectAppId = CDBCSupport ().executeQuery <tuple <int, const wstring&, const wstring&, const wstring&, const wstring&, const CDBCSupport::blob&> > 
			(
				conn, 
				L"select app_id from appinfo where not (? & options) and ( ( product_name = ? and company_name = ? and internal_name = ? and original_file_name = ? ) or sha1 = ? )", 
				tuple <int, const wstring&, const wstring&, const wstring&, const wstring&, const CDBCSupport::blob&> (dboDeleted, AppItem.ProductName, AppItem.CompanyName, AppItem.InternalName, AppItem.OriginalFilename, CDBCSupport::blob (&AppItem.SHA1, sizeof (AppItem.SHA1)))
			);
		}
	}

	if ( NULL == selectAppId.get () )
	{
         selectAppId = CDBCSupport ().executeQuery <tuple <int, int, const wstring&, int> >
		 (
			conn, 
			L"select params.param1 from pathes join params on pathes.params_id = params.id "
			L"where params.param_type = ? and res_type = ? and path like ? and not (pathes.options & ?)", 
			tuple <int, int, const wstring&, int> 
			(
				parAppPath,
				nttFile,
				AppItem.Params.Type == parAppPath ? AppItem.Identity.Path.Path : AppItem.FileName, 
				dboDeleted
			)
         );
	}

    if (NULL != selectAppId.get () &&  0 == AppItem.Params.Attributes.Param[0])
    { // if exist and not update
		// set Id of found application
		AppId = selectAppId->getInt (0);
		throw Storage::IdentityExistException (L"Application with such identity exists");
    }
	//
	// check for display name conflicts
    CDBCSupport::PtrToIResultSet displayNameCheck = CDBCSupport ().executeQuery <tuple <int, const wstring&, int> > (conn, wstring (L"select id from params where group_id = ? and description = ? and (not options & ?)"), tuple <int, const wstring&, int> (AppItem.Params.GroupId, wstring (AppItem.Params.Description), dboDeleted));
    if (NULL != displayNameCheck.get ()) 
	  throw Storage::DisplayNameExistException (L"Display name exists");
	//
	// No problem encountered, do insert
	//
    switch (AppItem.Params.Type) 
    {
      case parAppContent:
      { 
           CDBCSupport::PtrToIResultSet contentId = 
             CDBCSupport ().executeQuery <tuple <int, const wstring&, int, int> > (
               conn, 
               L"select id from contents where cont_type = ? and content = ? and param_type = ? and (not options & ?)", 
               tuple <int, const wstring&, int, int> (
                 AppItem.Identity.Info.Type, 
                 wstring (AppItem.Identity.Info.Content), 
				 parAppContent,
                 dboDeleted
               )
             );
           if (NULL == contentId.get ())
           {
             int paramsId = InsertParams (conn, AppItem.Params);
             if (0 != paramsId)
             {
               AppItem.Params.Id = paramsId; 
               //AppItem.Params.Attributes.Param[0]= paramsId; 
               CDBCSupport::RowId rowId = paramsId; 
               
               if (true == updateAppId)
               {
                 AppItem.Params.Attributes.Param[0]= paramsId; 
                 rowId = 
                   CDBCSupport ().executeUpdate <tuple <int, int> > (
                     conn, 
                     L"update params set param1 = ? where id = ?", 
                     tuple <int, int> (paramsId, paramsId)
                   );
               }  

               if (0 != rowId)
               {
                 ContentInfo contentInfo = AppItem.Identity.Info;
                 contentInfo.ParentId = paramsId;
				 contentInfo.param_type = AppItem.Params.Type;

                 int contentId = InsertContent (conn, contentInfo);
                 if (0 != contentId)
                 {
                   AppItem.Identity.Info.Id = contentId;
                   AppItem.Identity.Info.ParentId = paramsId;

                   AppId = paramsId;
                 }
               }
             }
           }
           else
           {
             throw Storage::ContentExistException (L"Content exist");
           }
           break;
      }     
      case parAppPath:
      {
           CDBCSupport::PtrToIResultSet pathId = 
             CDBCSupport ().executeQuery <tuple <int, const wstring&, int, int> > (
               conn, 
               L"select id from pathes where res_type = ? and path = ? and param_type = ? and (not options & ?)", 
               tuple <int, const wstring&, int, int> (
                 AppItem.Identity.Path.Type, 
                 wstring (AppItem.Identity.Path.Path),
				 parAppPath,
                 dboDeleted
               )
             );
           if (NULL == pathId.get ())
           {
             int paramsId = InsertParams (conn, AppItem.Params);
             if (0 != paramsId)
             {
               AppItem.Params.Id = paramsId; 
               CDBCSupport::RowId rowId = paramsId; // for check only
               
               if (true == updateAppId)
               {
                 AppItem.Params.Attributes.Param[0]= paramsId; 
                 rowId = 
                   CDBCSupport ().executeUpdate <tuple <int, int> > (
                     conn, 
                     L"update params set param1 = ? where id = ?", 
                     tuple <int, int> (paramsId, paramsId)
                   );
               }  
                 
               if (0 != rowId)
               {
                 PathInfo pathInfo = AppItem.Identity.Path;
                 pathInfo.ParentId = paramsId;
                 pathInfo.param_type = AppItem.Params.Type;
				 int pathId = InsertPath (conn, pathInfo);
                 if (0 != pathId)
                 {
                   AppItem.Identity.Path.Id = pathId;
                   AppItem.Identity.Path.ParentId = paramsId;

                   AppId = paramsId;
                 }
               }
             } // if (0 != paramsId)
           } // if (0 != IsPathExist (conn, AppItem.Identity.Path, !dboDeleted))
           else
           {
             throw Storage::PathExistException (L"Path exists");
           }
           break;
      }
      case parAppDigest:
      {
           CDBCSupport::PtrToIResultSet digestId = 
             CDBCSupport ().executeQuery <tuple <int, const CDBCSupport::blob&, int, int> > (
               conn, 
               L"select id from digests where digest_type = ? and digest = ? and param_type = ? and (not options & ?)", 
               tuple <int, const CDBCSupport::blob&, int, int> (
                 AppItem.Identity.Digest.Type, 
                 CDBCSupport::blob (reinterpret_cast <unsigned char*> (AppItem.Identity.Digest.Digest), AppItem.Identity.Digest.DigestSize), 
				 parAppDigest,
                 dboDeleted
               )
             );
           if (NULL == digestId.get ())
           {
             int paramsId = InsertParams (conn, AppItem.Params);
             if (0 != paramsId)
             {
               AppItem.Params.Id = paramsId; 
               CDBCSupport::RowId rowId = paramsId; // for check only
               
               if (true == updateAppId)
               {
                 AppItem.Params.Attributes.Param[0]= paramsId; 
                 rowId = 
                   CDBCSupport ().executeUpdate <tuple <int, int> > (
                     conn, 
                     L"update params set param1 = ? where id = ?", 
                     tuple <int, int> (paramsId, paramsId)
                   );
               }  
                 
               if (0 != rowId)
               {
                 DigestInfo digestInfo = AppItem.Identity.Digest;
                 digestInfo.ParentId = paramsId;
                 digestInfo.param_type = AppItem.Params.Type;
				 int digestId = InsertDigest (conn, digestInfo);
                 if (0 != digestId)
                 {
                   AppItem.Identity.Digest.Id = digestId;
                   AppItem.Identity.Digest.ParentId = paramsId;

                   AppId = paramsId;
                 }
               }
             } // if (0 != paramsId)
           } // if (0 == IsDigestExist (conn, AppItem.Identity.Digest, !dboDeleted))
           else
           {
             throw Storage::DigestExistException (L"Digest exists");
           }
           break;
      }
    } // switch
    
    if (0 != AppId && true == updateAppId)
    {
      AppItem.Params.Attributes.Param[GesRule::attSubjectId]= AppId; 
      
      GUID guid;
      if (CoCreateGuid (&guid) != S_OK) 
        throw Storage::StorageException (L"create guid for appinfo error");
        
      IConnection::PtrToIPreparedStatement appInfo = conn->createPreparedStatement (wstring (
		  L"insert into appinfo (id, app_id, file_name, product_name, file_description, company_name, internal_name, original_file_name, product_version, file_version, legal_copyright, comments, product_url, lang, icon, md5, sha1, sha256, cert_thumbprint, app_options, guid, options) values ( null, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )"));
      
      CDBCSupport              cdbcsupport;
      CDBCSupport::BinderIndex index; //0;

      cdbcsupport.bind <int> (AppItem.Params.Attributes.Param[GesRule::attSubjectId], appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.FileName,         sizeof (AppItem.FileName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.ProductName,      sizeof (AppItem.ProductName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.FileDescription,  sizeof (AppItem.FileDescription) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.CompanyName,      sizeof (AppItem.CompanyName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.InternalName,     sizeof (AppItem.InternalName) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.OriginalFilename, sizeof (AppItem.OriginalFilename) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.ProductVersion,   sizeof (AppItem.ProductVersion) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.FileVersion,      sizeof (AppItem.FileVersion) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.LegalCopyright,   sizeof (AppItem.LegalCopyright) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.Comments,         sizeof (AppItem.Comments) / sizeof (wchar_t) - 1), appInfo, index); 
      cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (AppItem.ProductURL,       sizeof (AppItem.ProductURL) / sizeof (wchar_t) - 1), appInfo, index);
      cdbcsupport.bind <unsigned int> (AppItem.Lang, appInfo, index);
      cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (AppItem.Icon,             AppItem.IconSize, reinterpret_cast <size_t&> (AppItem.IconSize)), appInfo, index);
      cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (AppItem.MD5,              sizeof (AppItem.MD5)), appInfo, index);
      cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (AppItem.SHA1,             sizeof (AppItem.SHA1)), appInfo, index);
      cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (AppItem.SHA256,           sizeof (AppItem.SHA256)), appInfo, index);
      cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (AppItem.CertThumbprint,   sizeof (AppItem.CertThumbprint)), appInfo, index);
      cdbcsupport.bind <unsigned int> (AppItem.AppOptions, appInfo, index);  
      cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob ((PUCHAR)&guid, sizeof guid), appInfo, index);
      cdbcsupport.bind <int> (AppItem.Params.Options, appInfo, index);  
      
      appInfo->executeUpdate ();
    } // if (0 != result)
  } // try
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertApplication

void InsertApplication (const ApplicationItem &AppItem, int &AppId)
{
  AppId = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
	try 
	{
		InsertApplication (conn, const_cast <ApplicationItem&> (AppItem), true, AppId);
	}
	catch (SQLException& e)
	{
		conn->rollback ();
		throw e;
	}
    conn->commit ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertApplication

void InsertApplicationResource (IConnection::PtrToIConnection& conn, ResourceItem &Res, int &Id)
{
  Id = 0;

  Res.Params.Model      = GesRule::GswLabel;
  Res.Params.Type       = parResourceApp;
  Res.Identity.Type     = idnPath;  
  Res.Identity.Path.param_type = parResourceApp;
  
  memset (Res.Params.Description, 0, sizeof (Res.Params.Description));
  
  Res.Params.GroupId = 0;

  try
  {
       
//    ParamsRecordInfo record;
//    Check if application exists... silly check in fact. should be always true. Remove?
    if (NULL != (CDBCSupport ().executeQuery <tuple <int, int> > (conn, wstring (L"select id from params where param1 = ? and (not options & ?)"), tuple <int, int> (Res.Params.Attributes.Param[GesRule::attObjectId], dboDeleted))).get ())
    {      
      int  paramsId = 0;
      bool addPath  = true;
  
      CDBCSupport::PtrToIResultSet resultParamsId = CDBCSupport ().executeQuery <tuple <int, int, int> > (conn, wstring (L"select id from params where param2 = ? and param6 = ? and (not options & ?)"), tuple <int, int, int> (Res.Params.Attributes.Param[GesRule::attObjectId], Res.Params.Attributes.Param[GesRule::attOptions], dboDeleted));
      if (NULL != resultParamsId.get ())
        paramsId = resultParamsId->getInt (0);
        
      if (0 == paramsId) 
      {
        paramsId = InsertParams (conn, Res.Params);
        addPath = (0 != paramsId);
      }  
      Res.Params.Id = paramsId;

      if (true == addPath)
      {
        // insert ResourceExists exception throw here
        CDBCSupport::PtrToIResultSet checkException = 
          CDBCSupport ().executeQuery <tuple <const wstring& , int, int, int> > (
            conn, 
            L"select id from pathes where path = ? and res_type = ? and params_id in (select id from params where param2 = ?) and (not options & ?)", 
            tuple <const wstring& , int, int, int> (
              Res.Identity.Path.Path, 
              Res.Identity.Path.Type, 
              Res.Params.Attributes.Param[GesRule::attObjectId], dboDeleted
            )
          );
		if (NULL != checkException.get ()) {
		  Id = checkException->getInt (0);
          throw Storage::ResourceExistException (L"Resource exists");
		}
    
        Res.Identity.Path.ParentId = paramsId;
        int pathId = InsertPath (conn, Res.Identity.Path);
        Res.Identity.Path.Id = pathId;
        
        //if (0 != pathId) Id = paramsId;
		if (0 != pathId) Id = pathId;
      }
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertApplicationResource

void InsertApplicationResource (ResourceItem &Res, int &Id)
{
  Id = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
   	try
	{
		InsertApplicationResource (conn, Res, Id);
	}
	catch (SQLException& e)
	{
		conn->rollback ();
		throw e;
	}
	conn->commit ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
} // InsertApplicationResource

void InsertSecurityClass(ParamsInfo& Info, int &Id)
{
  Id = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();

	CDBCSupport::PtrToIResultSet paramsId = 
		CDBCSupport ().executeQuery <tuple <int, int, int, int, int, int, int, int> > 
		(conn, wstring (L"select id from params where param1 = ? and param2 = ? and param3 = ? and param4 = ? and param5 = ? and param6 = ? and param_type = ? and (not options & ?)"), 
		tuple <int, int, int, int, int, int, int, int> (Info.Attributes.Param[0], Info.Attributes.Param[1], Info.Attributes.Param[2], Info.Attributes.Param[3], Info.Attributes.Param[4], Info.Attributes.Param[5], parResource, dboDeleted));

    if (NULL != paramsId.get ())
    {
		Id = paramsId->getInt (0);
		throw SecurityClassExistException(L"Security class exists");
	}

	Id = InsertParams(conn, Info);
	Info.Id = Id;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void InsertGlobalResource(IConnection::PtrToIConnection& conn, ResourceItem &Res, int &Id)
{
  try
  {
	switch ( Res.Identity.Type )
	{
		case idnPath:
			{
				CDBCSupport::PtrToIResultSet pathId = CDBCSupport ().executeQuery <tuple <const wstring&, int, int, int> > 
					(conn, wstring (L"select id from pathes where path like ? and res_type = ? and param_type = ? and (not options & ?)"), 
					tuple <const wstring&, int, int, int> (Res.Identity.Path.Path, Res.Identity.Path.Type, parResource, dboDeleted));
				if (NULL != pathId.get())
				{
					Id = pathId->getInt (0);
					throw PathExistException(L"Resource with given path already exists");
				}
				Id = InsertPath(conn, Res.Identity.Path);
				Res.Identity.Path.Id = Id;
			}
			break;

		case idnOwner:
			InsertOwner(conn, Res.Identity.Owner, Id);
			Res.Identity.Owner.Id = Id;
			break;

		case idnCertificate:
			InsertCertificate(conn, Res.Identity.Cert, Id);
			Res.Identity.Cert.Id = Id;
			break;

		default:
			throw StorageException(L"Unsupported resource type");
	}
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void InsertGlobalResource(ResourceItem &Res, int &Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();

	InsertGlobalResource(conn, Res, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void InsertIdsPattern(IConnection::PtrToIConnection& conn, IdsPatternItem &Item, int &Id)
{
  try
  {
	CDBCSupport::PtrToIResultSet patternId = CDBCSupport ().executeQuery <tuple <int, const wstring&, int> > 
		(conn, wstring (L"select id from idspatterns where res_type = ? and pattern = ? and (not options & ?)"), 
		tuple <int, const wstring&, int> (Item.ResType, Item.Pattern, dboDeleted));
	if (NULL != patternId.get())
	{
		Id = patternId->getInt (0);
		throw PathExistException(L"Pattern already exists");
	}

    GUID guid;
    if (CoCreateGuid (&guid) != S_OK) throw Storage::StorageException (L"create guid for idspattern error");

    IConnection::PtrToIPreparedStatement stmt = 
       conn->createPreparedStatement (
       L"insert into idspatterns (id, res_type, pattern_type, flags, pattern, message, guid, options) values ( null, ?, ?, ?, ?, ?, ?, ? )"
    );

    stmt->setInt (Item.ResType, 1);
	stmt->setInt (Item.PatternType, 2);
	stmt->setInt (Item.Flags, 3);
    stmt->setText (wstring (Item.Pattern), 4);
    stmt->setText (wstring (Item.Message), 5);
    stmt->setBlob ((PUCHAR)&guid, sizeof guid, 6);
    stmt->setInt (static_cast <int> (Item.Options), 7);

    Id = static_cast <int> (stmt->executeUpdate ()); 
	Item.Id = Id;
  }
  catch (SQLException& e)
  {
	printSQLException (e);
  }
}

void InsertIdsPattern(IdsPatternItem &Item, int &Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();

	InsertIdsPattern(conn, Item, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}


bool DeleteApplicationResource (IConnection::PtrToIConnection& conn, int resId) // groupId 
{
  return DeletePath(conn, resId);
}
bool DeleteApplicationResource (int resId)  // resId 
{ 
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    bool result = DeleteApplicationResource (conn, resId);
    
    if (true == result)
      conn->commit ();
    else 
      conn->rollback ();

    return result;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
    
} // DeleteApplicationResource

void DeleteSecurityClass(const int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
	//
	// Do real delete, that is exclusion, only for security classes and idspatterns
	//
    CDBCSupport ().executeUpdate <tuple <int> > (conn, L"delete from params where id = ?", tuple <int> (Id));
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void DeleteGlobalResource(IConnection::PtrToIConnection& conn, const IdentityType Type, const int Id)
{
  try
  {
	switch ( Type )
	{
		case idnPath:
			DeletePath(conn, Id);
			break;

		case idnOwner:
			DeleteOwner(conn, Id);
			break;

		case idnCertificate:
			DeleteCertificate(conn, Id);
			break;

		default:
			throw StorageException(L"Unsupported global resource type");
	}
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void DeleteGlobalResource(const IdentityType Type, const int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();

	DeleteGlobalResource(conn, Type, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

void DeleteIdsPattern(const int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();

	//
	// Do real delete, that is exclusion, only for security classes and idspatterns
	//
    CDBCSupport ().executeUpdate <tuple <int> > (conn, L"delete from idspatterns where id = ?", tuple <int> (Id));
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
}

int UpdateApplicationResource (ResourceItem &Res)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
	try
	{
		DeleteApplicationResource (conn, Res.Identity.Path.Id);
		InsertApplicationResource (conn, Res, Res.Identity.Path.Id);
	}
	catch (SQLException& e)
	{
		conn->rollback ();
		throw e;
	}
    conn->commit ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return Res.Identity.Path.Id;
} // UpdateApplicationResource

int UpdateSecurityClass(const int Id, ParamsInfo& Info)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
	//
	// Do real update, that is exclusion, only security classes and idspatterns
	//
    CDBCSupport ().executeUpdate <tuple <const wstring&, int, int, int, int, int, int, int, int> > (
			conn, 
            L"update params set description = ?, param1 = ?, param2 = ?, param3 = ?, param4 = ?, param5 = ?, param6 = ?, options = ? where id = ?", 
			tuple <const wstring&, int, int, int, int, int, int, int, int> 
			(Info.Description, Info.Attributes.Param[0], Info.Attributes.Param[1], Info.Attributes.Param[2], Info.Attributes.Param[3], Info.Attributes.Param[4], Info.Attributes.Param[5], Info.Options, Id)
    );
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  return Id;
}

int UpdateGlobalResource(const int Id, ResourceItem & Res)
{
  int nId = 0;

  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
	try
	{
		DeleteGlobalResource (conn, Res.Identity.Type, Id);
		InsertGlobalResource (conn, Res, nId);
	}
	catch (SQLException& e)
	{
		conn->rollback ();
		throw e;
	}
    conn->commit ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return nId;
}

int UpdateIdsPattern(const int Id, IdsPatternItem &Item)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
	//
	// Do real update, that is exclusion, only security classes and idspatterns
	//
    CDBCSupport ().executeUpdate <tuple <int, int, int, const wstring&, const wstring&, int, int> > (
			conn, 
            L"update idspatterns set res_type = ?, pattern_type = ?, flags = ?, pattern = ?, message = ?, options = ? where id = ?", 
			tuple <int, int, int, const wstring&, const wstring&, int, int> 
			(Item.ResType, Item.PatternType, Item.Flags, Item.Pattern, Item.Message, Item.Options, Id)
    );
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  return Id;
}

int InsertApplicationGroupNoCheck (const GUID& guid, IConnection::PtrToIConnection& conn, ParamsInfo& Params, bool updateGroupId)
{
  Params.Id    = 0;   
  Params.Model = GesRule::GswLabel; 
  Params.Type  = parAppGroup; 
  // Params.Attributes.Param[1] holds group code, 2-5 - group guid, don't touch them
  Params.Attributes.Param[0] = 0;
  
  conn->begin ();

  // Params.Description must be already set 
  // Params.GroupId must be already set 
  Params.Id = InsertParams (guid, conn, Params);
  if (true == updateGroupId)
  { 
    Params.Attributes.Param[0 ]= Params.Id; 
    CDBCSupport ().executeUpdate <tuple <int, int> > (conn, wstring (L"update params set param1 = ? where id = ?"), tuple <int, int> (Params.Id, Params.Id));
  }  

  if (0 != Params.Id)
    conn->commit ();
  else 
    conn->rollback ();

  return Params.Id;
} // InsertApplicationGroupNoCheck

void InsertApplicationGroup (const GUID& guid, IConnection::PtrToIConnection& conn, ParamsInfo& Params, bool updateGroupId, int &GroupId)
{
  GroupId = 0;
  try
  {
    CDBCSupport::PtrToIResultSet paramId = CDBCSupport ().executeQuery <tuple <int, const wstring&, int, int, int, int, int, int, int> > (conn, wstring (L"select param1, param2, param3, param4, param5, param6 from params where ( ( group_id = ? and description = ? ) or ( param2 <> 0 and param2 = ? ) or ( param3 <> 0 and param3 = ? and param4 = ? and param5 = ? and param6 = ? ) ) and param_type = ? and (not options & ?)"), tuple <int, const wstring&, int, int, int, int, int, int, int> (Params.GroupId, wstring (Params.Description), Params.Attributes.Param[1], Params.Attributes.Param[2], Params.Attributes.Param[3], Params.Attributes.Param[4], Params.Attributes.Param[5], parAppGroup, dboDeleted));
    if (NULL == paramId.get ())
    {
      Params.Id = InsertApplicationGroupNoCheck (guid, conn, Params, updateGroupId);
	  GroupId = Params.Attributes.Param[0];
    }
    else
    {
	  GroupId = paramId->getInt (0);
	  if ( ( Params.Attributes.Param[1] != 0 && Params.Attributes.Param[1] == paramId->getInt(1) ) ||
		   ( Params.Attributes.Param[2] != 0 && 
		     Params.Attributes.Param[2] == paramId->getInt(2) && 
			 Params.Attributes.Param[3] == paramId->getInt(3) && 
			 Params.Attributes.Param[4] == paramId->getInt(4) && 
			 Params.Attributes.Param[5] == paramId->getInt(5)
		    )
		 ) 
		  throw Storage::GroupCodeExistException (L"Group exists");
	  else
		  throw Storage::GroupExistException (L"Group name exists");
    }
  }
  catch (SQLException& e)
  {
    Params.Id = 0;
    printSQLException (e);
  }
} // InsertApplicationGroup

void InsertApplicationGroup (ParamsInfo& Params, bool updateGroupId, int &GroupId)
{ 
  GroupId = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();

    GUID guid;
    if ( CoCreateGuid (&guid) != S_OK ) 
      Params.Id = 0;
    else  
      InsertApplicationGroup (guid, conn, Params, updateGroupId, GroupId);
	  Params.Id = GroupId;
  }
  catch (SQLException& e)
  {
    Params.Id = 0;
    printSQLException (e);
  }
} // InsertApplicationGroup

// Create new application group 
//int InsertApplicationGroup (ParamsInfo& Params, bool updateGroupId)
//{ 
//  try
//  {
//    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
//    IConnection::PtrToIConnection        conn = connHolder.connection ();
//
//    CDBCSupport::PtrToIResultSet paramId = CDBCSupport ().executeQuery <tuple <int, const wstring&, int> > (conn, wstring (L"select id from params where group_id = ? and description = ? and (not options & ?)"), tuple <int, const wstring&, int> (Params.GroupId, wstring (Params.Description), dboDeleted));
//    if (NULL == paramId.get ())
//    {
//      Params.Id    = 0;   
//      Params.Model = GesRule::GswLabel; 
//      Params.Type  = parAppGroup; 
//      memset (Params.Attributes.Param, 0, sizeof (Params.Attributes.Param));
//      
//      conn->begin ();
//
//      // Params.Description must be already set 
//      // Params.GroupId must be already set 
//      Params.Id = InsertParams (conn, Params);
//      if (true == updateGroupId)
//      { 
//        Params.Attributes.Param[0]= Params.Id; 
//        CDBCSupport ().executeUpdate <tuple <int, int> > (conn, wstring (L"update params set param1 = ? where id = ?"), tuple <int, int> (Params.Id, Params.Id));
//      }  
//
//      if (0 != Params.Id)
//        conn->commit ();
//      else 
//        conn->rollback ();
//    }
//    else
//    {
//      throw Storage::GroupExistException (L"Group exists");
//    }
//  }
//  catch (SQLException& e)
//  {
//    Params.Id = 0;
//    printSQLException (e);
//  }
//
//  return Params.Id;
//} // InsertApplicationGroup

int InsertApplicationInfo (const GUID& guid, IConnection::PtrToIConnection& conn, const ApplicationInfo& appInfo)
{
  int result = 0;
  
  try
  {
    IConnection::PtrToIPreparedStatement appStmt = conn->createPreparedStatement (wstring (L"insert into appinfo (id, app_id, file_name, product_name, file_description, company_name, internal_name, original_file_name, product_version, file_version, legal_copyright, comments, product_url, lang, icon, md5, sha1, sha256, cert_thumbprint, app_options, guid, options) values ( null, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )"));
    
    CDBCSupport              cdbcsupport;
    CDBCSupport::BinderIndex index; //0;

    cdbcsupport.bind <int>                      (appInfo.AppId, appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.FileName,         sizeof (appInfo.FileName) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.ProductName,      sizeof (appInfo.ProductName) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.FileDescription,  sizeof (appInfo.FileDescription) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.CompanyName,      sizeof (appInfo.CompanyName) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.InternalName,     sizeof (appInfo.InternalName) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.OriginalFilename, sizeof (appInfo.OriginalFilename) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.ProductVersion,   sizeof (appInfo.ProductVersion) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.FileVersion,      sizeof (appInfo.FileVersion) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.LegalCopyright,   sizeof (appInfo.LegalCopyright) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.Comments,         sizeof (appInfo.Comments) / sizeof (wchar_t) - 1), appStmt, index); 
    cdbcsupport.bind <const CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.ProductURL,       sizeof (appInfo.ProductURL) / sizeof (wchar_t) - 1), appStmt, index);
    cdbcsupport.bind <unsigned int>             (appInfo.Lang, appStmt, index);
    cdbcsupport.bind <const CDBCSupport::blob&> (CDBCSupport::blob (appInfo.Icon,             appInfo.IconSize), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::blob&> (CDBCSupport::blob (appInfo.MD5,              sizeof (appInfo.MD5)), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::blob&> (CDBCSupport::blob (appInfo.SHA1,             sizeof (appInfo.SHA1)), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::blob&> (CDBCSupport::blob (appInfo.SHA256,           sizeof (appInfo.SHA256)), appStmt, index);
    cdbcsupport.bind <const CDBCSupport::blob&> (CDBCSupport::blob (appInfo.CertThumbprint,   sizeof (appInfo.CertThumbprint)), appStmt, index);
    cdbcsupport.bind <unsigned int>             (appInfo.AppOptions, appStmt, index);  
    cdbcsupport.bind <const CDBCSupport::blob&> (CDBCSupport::blob ((PUCHAR)&guid, sizeof guid), appStmt, index);
    cdbcsupport.bind <int>                      (dboNone, appStmt, index);  
    
    result = static_cast <int> (appStmt->executeUpdate ());
  } // try
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return result;    
} // InsertApplicationInfo

bool DeleteApplication (IConnection::PtrToIConnection& conn, int appId, bool cleanupResourses)
{
  bool intermediateResult = false;
  
  try
  {
//    CDBCSupport::PtrToIResultSet r = CDBCSupport ().executeQuery <tuple <int> > (conn, wstring (L"select * from contents where params_id = ? and (not options & 1)"), tuple <int> (appId));
   
    //ApplicationItem appItem;
    //if (true == GetApplicationItem (conn, appId, appItem))
    
    CDBCSupport::PtrToIResultSet app = 
      CDBCSupport ().executeQuery <tuple <int, int> > (
        conn, 
        L"select id, param_type from params where param1 = ? and (not options & ?)", 
        tuple <int, int> (appId, dboDeleted)
      );
    if (NULL != app.get ())
    {
		int id        = app->getInt (0);
		int paramType = app->getInt (1);
		app.reset ();
      
        intermediateResult = true;
		{
			CDBCSupport::PtrToIResultSet record = 
			CDBCSupport ().executeQuery <tuple <int, int> > (
				conn, 
				L"select id from contents where params_id = ? and (not options & ?)", 
				tuple <int, int> (id, dboDeleted)
			);
			if (NULL != record.get ())
			{
				int pId = record->getInt (0);
				record.reset ();
				intermediateResult = DeleteContent (conn, pId);
			}
		}

		{
			CDBCSupport::PtrToIResultSet record = 
			CDBCSupport ().executeQuery <tuple <int, int> > (
				conn, 
				L"select id from pathes where params_id = ? and (not options & ?)", 
				tuple <int, int> (id, dboDeleted)
			);
			if (NULL != record.get ())
			{
				int pId = record->getInt (0);
				record.reset ();
				intermediateResult = DeletePath (conn, pId);
			}
		}

		{
			CDBCSupport::PtrToIResultSet record = 
			CDBCSupport ().executeQuery <tuple <int, int> > (
				conn, 
				L"select id from digests where params_id = ? and (not options & ?)", 
				tuple <int, int> (id, dboDeleted)
			);
			if (NULL != record.get ())
			{
				int pId = record->getInt (0);
				record.reset ();
				intermediateResult = DeleteDigest (conn, pId);
			}  
		}

		if (true == intermediateResult)
		{ 
			intermediateResult = false;
	        
			if (true == cleanupResourses)
			{
			CDBCSupport::PtrToIResultSet resources = 
				CDBCSupport ().executeQuery <tuple <int, int> > (
				conn, 
				L"select id from params where param2 = ? and (not options & ?)", 
				tuple <int, int> (appId, dboDeleted)
				);
			if (NULL != resources.get ())
			{
				do
				{
				int paramId = resources->getInt (0);
				CDBCSupport ().executeUpdate <tuple <int, int, int> > (
					conn, 
					L"update pathes set options = (? | options) where params_id = ? and (not options & ?)", 
					tuple <int, int, int> (dboDeleted, paramId, dboDeleted)
				);
				} 
				while (true == resources->next());
			} // if (NULL != resultSet.get ())
	        
			// Delete Application Resources from params
			CDBCSupport ().executeUpdate <tuple <int, int, int> > (
				conn, 
				L"update params set options = (? | options) where param2 = ? and (not options & ?)", 
				tuple <int, int, int> (dboDeleted, appId, dboDeleted)
			);
	          
			CDBCSupport ().executeUpdate <tuple <int, int, int> > (
				conn, 
				L"update appinfo set options = (? | options) where app_id = ? and (not options & ?)", 
				tuple <int, int, int> (dboDeleted, appId, dboDeleted)
			);
			//CDBCSupport ().executeUpdate <tuple <int, int> > (conn, wstring (L"delete from appinfo where app_id = ? and (not options & ?)"), tuple <int, int> (appId, dboDeleted));
			} // if (true == cleanupResourses)

			intermediateResult = true;
	        
			if (true == intermediateResult)
			intermediateResult = DeleteParams (conn, id/*appItem.Params.Id*/);
		} // if (true == intermediateResult)
    } // if (true == GetApplicationItem (conn, appId, appItem))
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return intermediateResult;
} // DeleteApplication

bool DeleteApplication (int appId)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    //conn->rollback ();
    
    conn->begin ();
    
    bool result = DeleteApplication (conn, appId, true);
    
    if (true == result)
      conn->commit ();
    else 
      conn->rollback ();

    return result;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeleteApplication


bool DeleteApplicationGroup (IConnection::PtrToIConnection& conn, int groupId) // groupId 
{
  bool result = false;
  int paramsId;

  try
  {
    CDBCSupport::PtrToIResultSet resultId = CDBCSupport ().executeQuery <tuple <int, int, int> > (conn, wstring (L"select id from params where param1 = ? and param_type = ? and (not options & ?)"), tuple <int, int, int> (groupId, parAppGroup, dboDeleted));
    if (NULL != resultId.get ())
    {
      paramsId = resultId->getInt (0);
      resultId.reset ();
      if (paramsId != 0)
      {
        CDBCSupport::PtrToIResultSet resultCount = CDBCSupport ().executeQuery <tuple <int, int> > (conn, wstring (L"select id from params where group_id = ? and (not options & ?)"), tuple <int, int> (groupId, dboDeleted));
        if (NULL == resultCount.get ())
        {
          result = DeleteParams (conn, paramsId);
        }          
        else
        {
          throw Storage::GroupNotEmptyException (L"Group is not empty");
        }
      }
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // DeleteApplicationGroup

bool DeleteApplicationGroup (int groupId) // groupId 
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return DeleteApplicationGroup (conn, groupId);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeleteApplicationGroup

bool DeleteObject(IConnection::PtrToIConnection& conn, int Id, const wstring& sql)
{
  bool result = false;
  
  try
  {
    IConnection::PtrToIPreparedStatement stmt = conn->createPreparedStatement (sql);

    stmt->setInt (Id, 1);

    stmt->execute (); 
    result = true;
    
    stmt->close ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // DeleteObject

//
// update params set options = dboDeleted where id = :Id
//
bool DeleteParams (IConnection::PtrToIConnection& conn, int Id)
{
//  try
//  {
//    CDBCSupport ().executeUpdate <tuple <int, int> > (conn, L"update params set options = (? | options) where id = ?", tuple <int, int> (dboDeleted, Id))
//    return true;
//  }
//  catch (SQLException& e)
//  {
//    printSQLException (e);
//  }
//  return false;
  return DeleteObject (conn, Id, wstring (L"update params set options = (1 | options) where id = ?"));
} // DeleteParams

bool DeleteParams(int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return DeleteParams (conn, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeleteParams

//
// update certificates set options = dboDeleted where id = :Id
//
bool DeleteCertificate (IConnection::PtrToIConnection& conn, int Id)
{
  return DeleteObject (conn, Id, wstring (L"update certificates set options = (1 | options) where id = ?"));
} // DeleteCertificate

bool DeleteCertificate (int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return DeleteCertificate (conn, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeleteCertificate

//
// update digests set options = dboDeleted where id = :Id
//
bool DeleteDigest (IConnection::PtrToIConnection& conn, int Id)
{
  return DeleteObject (conn, Id, wstring (L"update digests set options = (1 | options) where id = ?"));
} // DeleteDigest

bool DeleteDigest(int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return DeleteDigest (conn, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeleteDigest

//
// update pathes set options = dboDeleted where id = :Id
//
bool DeletePath (IConnection::PtrToIConnection& conn, int Id)
{
  return DeleteObject (conn, Id, wstring (L"update pathes set options = (1 | options) where id = ?"));
} // DeletePath

bool DeletePath (int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return DeletePath (conn, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeletePath

//
// update owners set options = dboDeleted where id = :Id
//
bool DeleteOwner (IConnection::PtrToIConnection& conn, int Id)
{
  return DeleteObject (conn, Id, wstring (L"update owners set options = (1 | options) where id = ?"));
} // DeleteOwner

bool DeleteOwner (int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return DeleteOwner (conn, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeleteOwner

//
// update contents set options = dboDeleted where id = :Id
//
bool DeleteContent (IConnection::PtrToIConnection& conn, int Id)
{
  return DeleteObject (conn, Id, wstring (L"update contents set options = (1 | options) where id = ?"));
} // DeleteContent

bool DeleteContent (int Id)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    return DeleteContent (conn, Id);
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return false;
} // DeleteContent

bool ContentChanged (IConnection::PtrToIConnection& conn, int Id, ContentInfo &Info)
{
  IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id from contents where cont_type = ? and file_name = ? and content = ? and (not options & 1) and id = ?"));
  
  paramsStmt->setInt (Info.Type, 1);
  paramsStmt->setText (wstring (Info.FileName), 2);
  paramsStmt->setText (wstring (Info.Content), 3);
  paramsStmt->setInt (Id, 4);
   
  IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
  
  return (true == paramsResSet->next ())? FALSE : TRUE;
} // ContentChanged

bool PathChanged (IConnection::PtrToIConnection& conn, int Id, PathInfo &Path)
{
  IConnection::PtrToIPreparedStatement paramsStmt   = conn->createPreparedStatement (wstring (L"select id from pathes where res_type = ? and path = ? and (not options & 1) and id = ?"));
  
  paramsStmt->setInt (Path.Type, 1);
  paramsStmt->setText (wstring (Path.Path), 2);
  paramsStmt->setInt (Id, 3);
   
  IPreparedStatement::PtrToIResultSet  paramsResSet = paramsStmt->executeQuery ();
  
  return (true == paramsResSet->next ())? FALSE : TRUE;
} // PathChanged

bool DigestChanged (IConnection::PtrToIConnection& conn, int Id, DigestInfo &Digest)
{
  CDBCSupport::PtrToIResultSet digestId = CDBCSupport ().executeQuery <tuple <int, const CDBCSupport::blob&, int> > (conn, wstring (L"select id from digests where digest_type = ? and digest = ? and (not options & ?)"), tuple <int, const CDBCSupport::blob&, int> (Digest.Type, CDBCSupport::blob (reinterpret_cast <unsigned char*> (Digest.Digest), Digest.DigestSize), dboDeleted));
  return (NULL == digestId.get ())? TRUE : FALSE;
} // DigestChanged


int UpdateApplication (IConnection::PtrToIConnection& conn, int appId, ApplicationItem& AppItem) 
{
  int paramId = 0;
  
  try
  {
	DeleteApplication (conn, appId, false);
	InsertApplication (conn, AppItem, false, paramId);
  }
  catch (SQLException& e)
  {
    printSQLException (e); return 0;
  }
  
  return paramId;
} // UpdateApplication

int UpdateApplication (int appId, ApplicationItem& AppItem) 
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    int result = 0;
	try 
	{
		result = UpdateApplication (conn, appId, AppItem);
		conn->commit ();
		AppItem.Params.Id = result;
		return result;
	}
	catch ( ... )
	{
	    conn->rollback ();
		throw;
	}
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return 0;
} // UpdateApplication

int UpdateApplicationGroup (IConnection::PtrToIConnection& conn, ParamsInfo& Params) 
{
  try
  {
    // 
    DeleteParams (conn, Params.Id);
    int id = InsertParams (conn, Params);
    if (0 != id)
    {
	  // set new id in passed structure
	  Params.Id = id;
      //query(update params set params_id = id where params_id = Params.Id);
      //CDBCSupport::RowId rowId = CDBCSupport ().executeUpdate <tuple <int, int> > (conn, wstring (L"update params set group_id = ? where group_id = ?"), tuple <int, int> (id, Params.Id));
      //if (0 != rowId)
      return id;
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return 0;
} // UpdateApplicationGroup

int UpdateApplicationGroup (ParamsInfo& Params)
{
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    int result = UpdateApplicationGroup (conn, Params); 
  
    if (0 != result)
      conn->commit ();
    else 
      conn->rollback ();
    
    return result;  
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return 0;
} // UpdateApplicationGroup


//
// update params set options = dboDeleted where id = :Id
//
// insert into params (id, model, param_type, description, param1, param2, param3, param4, param5, param6, params_id, guid)
// values ( null, :Model, :Type, :Description, :param1, :param2, :param3, :param4, :param5, :param6, :GroupId, :Guid )
//
int UpdateParams(int Id, const ParamsInfo& Info)
{
  int nId = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    if ( DeleteParams (conn, Id) )
      nId = InsertParams (conn, Info);
      
    if (0 != nId)  
      conn->commit ();  
    else
      conn->rollback ();    
  }
  catch (SQLException& e)
  {
    nId = 0;
    printSQLException (e);
  }
    
  return nId;
} // UpdateParams

//
// update certificates set options = dboDeleted where id = :Id
//
// insert into certificates (id, cert_type, thumbprint, issuedto, issuedby, expiration, params_id, guid)
// values ( null, :Type, :Thumbprint, :IssuedTo, :IssuedBy, :Expiration, :ParamsId, :Guid )
//
int UpdateCertificate(int Id, const CertInfo& Info)
{
  int nId = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    if ( DeleteCertificate (conn, Id) ) 
        InsertCertificate (conn, Info, nId);
    
    if (0 != nId)  
      conn->commit ();
    else
      conn->rollback ();
  }
  catch (SQLException& e)
  {
    nId = 0;
    printSQLException (e);
  }
  
  return nId;
} // UpdateCertificate

//
// update digests set options = dboDeleted where id = :Id
//
// insert into digests (id, digest_type, digest, file_name, params_id)
// values ( null, :Type, :Digest, :DigestSize, :FileName, :ParamsId  )
// 
int UpdateDigest(int Id, const DigestInfo& Info)
{
  int nId = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    if ( DeleteDigest (conn, Id) )
        nId = InsertDigest (conn, Info);
      
    if (0 != nId)  
      conn->commit ();
    else
      conn->rollback ();
  }
  catch (SQLException& e)
  {
    nId = 0;
    printSQLException (e);
  }
  
  return nId;
} // UpdateDigest

//
// update pathes set options = dboDeleted where id = :Id
//
// insert into pathes (id, path_type, path, params_id, guid)
// values ( null, :Type, :Path, :ParamsId, :Guid ) 
//
int UpdatePath(int Id, const PathInfo& Info)
{
  int nId = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    if ( DeletePath (conn, Id) ) 
        nId = InsertPath (conn, Info);
      
    if (0 != nId)  
      conn->commit ();
    else
      conn->rollback ();
  }    
  catch (SQLException& e)
  {
    nId = 0;
    printSQLException (e);
  }
  
  return nId;
} // UpdatePath

//
// update owners set options = dboDeleted where id = :Id
//
// insert into owners (id, res_type, sid, params_id, guid)
// values ( null, :Type, :Sid, :ParamsId, Guid )
//
int UpdateOwner(int Id, const OwnerInfo& Info)
{
  int nId = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    if ( DeleteOwner (conn, Id) )
        InsertOwner (conn, Info, nId);
      
    if (0 != nId)  
      conn->commit ();
    else
      conn->rollback ();
  }    
  catch (SQLException& e)
  {
    nId = 0;
    printSQLException (e);
  }
      
  return nId;
} // UpdateOwner

//
// update contents set options = dboDeleted where id = :Id
//
// insert into contents (id, cont_type, content, file_name, params_id, guid)
// values ( null, :Type, :Content, :FileName, :ParamsId, Guid )
//
int UpdateContent(int Id, const ContentInfo& Info)
{
  int nId = 0;
  
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
    
    if ( DeleteContent (conn, Id) )
        nId = InsertContent (conn, Info);
      
    if (0 != nId)  
      conn->commit ();
    else
      conn->rollback ();
  }    
  catch (SQLException& e)
  {
    nId = 0;
    printSQLException (e);
  }
      
  return nId;
} // UpdateContent

bool GetSecureTypeList(SECMAP & SecMap)
{
  bool result = false;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement secureStmt   = conn->createPreparedStatement (wstring (L"select id,description from params where (not options & 1) and param_type = 1"));
    
    IPreparedStatement::PtrToIResultSet  secureResSet = secureStmt->executeQuery ();
    
    while (true == secureResSet->next ())
    {
      SecMap.insert ( SECPAIR (secureResSet->getInt (0), secureResSet->getText (1) ) );
    } // while ()
    
    result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // GetSecureType

int GetUpdateVersion ()
{
  int version = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement gswInfo   = conn->createPreparedStatement (wstring (L"select update_ver from gswinfo"));
    
    IPreparedStatement::PtrToIResultSet  gswInfoResSet = gswInfo->executeQuery ();
    
    if (true == gswInfoResSet->next ())
    {
	  version = gswInfoResSet->getInt (0);
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return version;
} // GetUpdateVersion

bool SetUpdateVersion (int version)
{
  bool result = false;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement gswInfo   = conn->createPreparedStatement (wstring (L"update gswinfo set update_ver = ?"));
	gswInfo->setInt (version, 1);

	gswInfo->execute ();
	result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return result;
} // SetUpdateVersion

int GetDbVersion ()
{
  int version = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement gswInfo   = conn->createPreparedStatement (wstring (L"select db_ver from gswinfo"));
    
    IPreparedStatement::PtrToIResultSet  gswInfoResSet = gswInfo->executeQuery ();
    
    if (true == gswInfoResSet->next ())
    {
      version = gswInfoResSet->getInt (0);
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return version;
} // GetDbVersion

bool CleanupForPersonalEdition ()
{
  bool result = false;
  IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
  IConnection::PtrToIConnection        conn = connHolder.connection ();

  try
  {
	conn->begin();

	IConnection::PtrToIPreparedStatement Statement;
	wstring Groups = L"1413564483, 4411977, 5255760, 1128875599, 1145916493, 1196248644, 5325641, 1279869261";

	//
	// delete rules
	//
	Statement = conn->createPreparedStatement(
		L"delete from pathes where params_id in "
		L"(select id from params where param2 in "
		L"(select param1 from params where param1 in (select app_id from appinfo where options & 2 ) or group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  ) ) )"
	);
	Statement->execute ();
	//
	// delete identification records
	//
	Statement = conn->createPreparedStatement(
		L"delete from contents where params_id in "
		L"(select id from params where param1 in (select app_id from appinfo where options & 2 ) or group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  ) )"
	);
	Statement->execute ();
	//
	Statement = conn->createPreparedStatement(
		L"delete from pathes where params_id in "
		L"(select id from params where param1 in (select app_id from appinfo where options & 2 ) or group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  ) )"
	);
	Statement->execute ();
	//
	Statement = conn->createPreparedStatement(
		L"delete from owners where params_id in "
		L"(select id from params where param1 in (select app_id from appinfo where options & 2 ) or group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  ) )"
	);
	Statement->execute ();
	//
	Statement = conn->createPreparedStatement(
		L"delete from digests where params_id in "
		L"(select id from params where param1 in (select app_id from appinfo where options & 2 ) or group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  ) )"
	);
	Statement->execute ();
	//
	// delete rules linkers in params table
	//
	Statement = conn->createPreparedStatement(
		L"delete from params where param2 in "
		L"(select param1 from params where param1 in (select app_id from appinfo where options & 2 ) or group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  ) )"
	);
	Statement->execute ();
	//
	// delete appinfo records
	//
	Statement = conn->createPreparedStatement(
		L"delete from appinfo where (options & 2) or app_id in "
		L"(select param1 from params where group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  ) )"
	);
	Statement->execute ();
	//
	// delete main application records in params table
	//
	Statement = conn->createPreparedStatement(
		L"delete from params where ( options & 2 ) or group_id in "
		L"(select param1 from params where param_type = 3 and param2 in (" + Groups + L")  )"
	);
	Statement->execute ();

	conn->commit();
	result = true;
  }
  catch (SQLException& e)
  {
	conn->rollback();
    printSQLException (e);
  }

  return result;
}

int GetAppsNumber ()
{
  int Number = 0;
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    IConnection::PtrToIPreparedStatement gswInfo   = conn->createPreparedStatement (
		L"select count(*) from appinfo where not (options & 1) and app_id not in "
		L"(select param1 from params where param_type in (4,5,6) and group_id in "
		L"(select param1 from params where param2 in (1414748499, 1280528980, 1280791367) ) )" 
	);
    
    IPreparedStatement::PtrToIResultSet  gswInfoResSet = gswInfo->executeQuery ();
    
    if (true == gswInfoResSet->next ())
    {
      Number = gswInfoResSet->getInt (0);
    }
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }

  return Number;
} // GetDbVersion

void GetAppInfo (ApplicationItem &AppItem, int &AppId)
{
  AppId = 0;
  //bool updateAppId=false;
  //============
  try
  {
    IConnectionFactory::ConnectionHolder connHolder (Setting::getConnectonFactory (), Setting::getConnectString ());
    IConnection::PtrToIConnection        conn = connHolder.connection ();
    
    conn->begin ();
  
  try
  {
	//
	// Check if such identity (application) already present
	//
	CDBCSupport::PtrToIResultSet selectAppId;

	if(AppItem.InternalName[0] == 0 && AppItem.CompanyName[0] == 0 && 
	   AppItem.ProductName[0] == 0 && AppItem.OriginalFilename[0] == 0 )
	{
		selectAppId =  CDBCSupport ().executeQuery <tuple <int, const CDBCSupport::blob&> > 
	  (
        conn, 
        L"select app_id from appinfo where not (? & options) and sha1 = ?", 
        tuple <int,  const CDBCSupport::blob&> (dboDeleted, CDBCSupport::blob (&AppItem.SHA1, sizeof (AppItem.SHA1)))
      );
	}
	else
	if ( AppItem.InternalName[0] != 0 || AppItem.OriginalFilename[0] != 0  )
	{
		selectAppId = CDBCSupport ().executeQuery <tuple <int, const wstring&, const wstring&, const CDBCSupport::blob&> > 
	  (
        conn, 
        L"select app_id from appinfo where not (? & options) and ( ( internal_name = ? and original_file_name = ? ) or sha1 = ? )", 
        tuple <int, const wstring&, const wstring&, const CDBCSupport::blob&> (dboDeleted, AppItem.InternalName, AppItem.OriginalFilename, CDBCSupport::blob (&AppItem.SHA1, sizeof (AppItem.SHA1)))
       );
	}
	else
	if ( AppItem.ProductName[0] != 0 || AppItem.CompanyName[0] != 0  )
	{
		 selectAppId = CDBCSupport ().executeQuery <tuple <int, const wstring&, const wstring&, const wstring&, const wstring&, const CDBCSupport::blob&> > 
	  (
        conn, 
        L"select app_id from appinfo where not (? & options) and ( ( product_name = ? and company_name = ? and internal_name = ? and original_file_name = ? ) or sha1 = ? )", 
        tuple <int, const wstring&, const wstring&, const wstring&, const wstring&, const CDBCSupport::blob&> (dboDeleted, AppItem.ProductName, AppItem.CompanyName, AppItem.InternalName, AppItem.OriginalFilename, CDBCSupport::blob (&AppItem.SHA1, sizeof (AppItem.SHA1)))
       );
	}
	else
	{   selectAppId = CDBCSupport ().executeQuery <tuple <int, const wstring&, const wstring&, const CDBCSupport::blob&> > 
	  (
        conn, 
        L"select app_id from appinfo where not (? & options) and ( ( company_name = ? and product_name = ? ) or sha1 = ? )", 
        tuple <int, const wstring&, const wstring&, const CDBCSupport::blob&> (dboDeleted, AppItem.CompanyName, AppItem.ProductName, CDBCSupport::blob (&AppItem.SHA1, sizeof (AppItem.SHA1)))
       );
	}

	if ( NULL == selectAppId.get () )
	{
         selectAppId = CDBCSupport ().executeQuery <tuple <int, int, const wstring&, int> >
		 (
			conn, 
			L"select params.param1 from pathes join params on pathes.params_id = params.id "
			L"where params.param_type = ? and res_type = ? and path like ? and not (pathes.options & ?)", 
			tuple <int, int, const wstring&, int> 
			(
				parAppPath,
				nttFile,
				AppItem.Params.Type == parAppPath ? AppItem.Identity.Path.Path : AppItem.FileName, 
				dboDeleted
			)
         );
	}
    if (NULL != selectAppId.get () &&  0 == AppItem.Params.Attributes.Param[0])
    { // if exist and not update
		// set Id of found application
		AppId = selectAppId->getInt (0);
		//throw Storage::IdentityExistException (L"Application with such identity exists");
    }
  }


    catch (SQLException& e)
  {
    printSQLException (e);
  }
///===============
	conn->commit ();
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  //============


}
} // namespace Storage 
