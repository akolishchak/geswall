//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "replicate.h"

#include "cdbc/iconnectionfactory.h"
#include "cdbc/iconnection.h"
#include "cdbc/istatement.h"
#include "cdbc/ipreparedstatement.h"
#include "cdbc/iresultset.h"
#include "cdbc/cdbcsupport.h"

#include "setting.h"

#include <map>

using namespace sql;
using namespace std;

namespace Storage {

IPreparedStatement::PtrToIResultSet GetRecord (int id, IConnection::PtrToIConnection& conn, const wstring& checkSql);
IPreparedStatement::PtrToIResultSet GetRecord (const GUID& guid, IConnection::PtrToIConnection& conn, const wstring& checkSql);

extern void printSQLException (SQLException& e);

//
// Replicate support
//

template <typename Info>
struct RecordInfo
{
  RecordInfo ()
   : m_options (dboNone)
  {
    memset (&m_guid, 0, sizeof (m_guid));
  } // RecordInfo

 protected:
  RecordInfo (const RecordInfo& right) {};
  RecordInfo& operator= (const RecordInfo& right) { return *this; };

 public: 
  GUID      m_guid;
  int       m_options;
  Info      m_info;
}; // RecordInfo

typedef RecordInfo<ParamsInfo>      ParamsRecordInfo;
typedef RecordInfo<CertInfo>        CertRecordInfo;
typedef RecordInfo<DigestInfo>      DigestRecordInfo;
typedef RecordInfo<PathInfo>        PathRecordInfo;
typedef RecordInfo<OwnerInfo>       OwnerRecordInfo;
typedef RecordInfo<ContentInfo>     ContentRecordInfo;
typedef RecordInfo<ApplicationInfo> ApplicationRecordInfo;

typedef map<int, int>    IdResolver;

template <typename Record>
void FillRecordInfo (Record& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  BOOST_STATIC_ASSERT (false);
} // FillRecordInfo

template <>
void FillRecordInfo<ParamsRecordInfo> (ParamsRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet);
template <>
void FillRecordInfo<CertRecordInfo> (CertRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet);
template <>
void FillRecordInfo<DigestRecordInfo> (DigestRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet);
template <>
void FillRecordInfo<PathRecordInfo> (PathRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet);
template <>
void FillRecordInfo<OwnerRecordInfo> (OwnerRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet);
template <>
void FillRecordInfo<ContentRecordInfo> (ContentRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet);
template <>
void FillRecordInfo<ApplicationRecordInfo> (ApplicationRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet);

template <typename Record>
void AppendRecord (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, Record& recordInfo)
{
  BOOST_STATIC_ASSERT (false);
} // AppendRecord


template <>
void AppendRecord<ParamsRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, ParamsRecordInfo& info);
template <>
void AppendRecord<CertRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, CertRecordInfo& info);
template <>
void AppendRecord<DigestRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, DigestRecordInfo& info);
template <>
void AppendRecord<PathRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, PathRecordInfo& info);
template <>
void AppendRecord<OwnerRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, OwnerRecordInfo& info);
template <>
void AppendRecord<ContentRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, ContentRecordInfo& info);
template <>
void AppendRecord<ApplicationRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, ApplicationRecordInfo& appInfo);

//
//
//

template <>
void FillRecordInfo<ParamsRecordInfo> (ParamsRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.GroupId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"group_id")));
    
  info.m_info.Model    = resultSet->getInt (resultSet->getColumnIndex (wstring (L"model")));
  info.m_info.Type     = static_cast <ParamsType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"param_type"))));
  
  wstring description = resultSet->getText (resultSet->getColumnIndex (wstring (L"description")));
  wcsncpy (info.m_info.Description, description.c_str (), sizeof (info.m_info.Description) / sizeof (wchar_t));
  
  info.m_info.Attributes.Param [0] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param1")));
  info.m_info.Attributes.Param [1] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param2")));
  info.m_info.Attributes.Param [2] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param3")));
  info.m_info.Attributes.Param [3] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param4")));
  info.m_info.Attributes.Param [4] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param5")));
  info.m_info.Attributes.Param [5] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param6")));
} // FillParamsRecordInfo

template <>
void FillRecordInfo<CertRecordInfo> (CertRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  
  info.m_info.Type     = static_cast <CertType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"cert_type"))));
  info.m_info.ThumbprintSize = resultSet->getBlob (resultSet->getColumnIndex (wstring (L"thumbprint")), info.m_info.Thumbprint, sizeof (info.m_info.Thumbprint));
  
  wstring issuedTo     = resultSet->getText (resultSet->getColumnIndex (wstring (L"issuedto")));
  wcsncpy (info.m_info.IssuedTo, issuedTo.c_str (), sizeof (info.m_info.IssuedTo) / sizeof (wchar_t));
  
  wstring issuedBy     = resultSet->getText (resultSet->getColumnIndex (wstring (L"issuedby")));
  wcsncpy (info.m_info.IssuedBy, issuedBy.c_str (), sizeof (info.m_info.IssuedBy) / sizeof (wchar_t));
  
  info.m_info.Expiration = (resultSet->getDate (resultSet->getColumnIndex (wstring (L"expiration")))).getDate ();
} // FillCertRecordInfo

template <>
void FillRecordInfo<DigestRecordInfo> (DigestRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type     = static_cast <DigestType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"digest_type"))));
  info.m_info.DigestSize = resultSet->getBlob (resultSet->getColumnIndex (wstring (L"digest")), info.m_info.Digest, sizeof (info.m_info.Digest));
  
  wstring file_name    = resultSet->getText (resultSet->getColumnIndex (wstring (L"file_name")));
  wcsncpy (info.m_info.FileName, file_name.c_str (), sizeof (info.m_info.FileName) / sizeof (wchar_t));
} // FillDigestRecordInfo

template <>
void FillRecordInfo<PathRecordInfo> (PathRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type     = static_cast <NtObjectType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"res_type"))));
  
  wstring path         = resultSet->getText (resultSet->getColumnIndex (wstring (L"path")));
  wcsncpy (info.m_info.Path, path.c_str (), sizeof (info.m_info.Path) / sizeof (wchar_t));
} // FillPathRecordInfo

template <>
void FillRecordInfo<OwnerRecordInfo> (OwnerRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type     = static_cast <NtObjectType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"res_type"))));
  
  wstring owner        = resultSet->getText (resultSet->getColumnIndex (wstring (L"sid")));
  wcsncpy (info.m_info.Owner, owner.c_str (), sizeof (info.m_info.Owner) / sizeof (wchar_t));
} // FillOwnerRecordInfo

template <>
void FillRecordInfo<ContentRecordInfo> (ContentRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type           = static_cast <ContentType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"cont_type"))));
  
  wstring content      = resultSet->getText (resultSet->getColumnIndex (wstring (L"content")));
  wcsncpy (info.m_info.Content, content.c_str (), sizeof (info.m_info.Content) / sizeof (wchar_t));
  
  wstring file_name    = resultSet->getText (resultSet->getColumnIndex (wstring (L"file_name")));
  wcsncpy (info.m_info.FileName, file_name.c_str (), sizeof (info.m_info.FileName) / sizeof (wchar_t));

} // FillContentRecordInfo

template <>
void FillRecordInfo<ApplicationRecordInfo> (ApplicationRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.AppId	 = resultSet->getInt (resultSet->getColumnIndex (wstring (L"app_id")));
  
  CDBCSupport            cdbcsupport;
  ApplicationInfo&       appInfo = info.m_info;
  
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.FileName,         sizeof (appInfo.FileName) / sizeof (wchar_t) - 1),         resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"file_name"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.ProductName,      sizeof (appInfo.ProductName) / sizeof (wchar_t) - 1),      resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"product_name"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.FileDescription,  sizeof (appInfo.FileDescription) / sizeof (wchar_t) - 1),  resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"file_description"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.CompanyName,      sizeof (appInfo.CompanyName) / sizeof (wchar_t) - 1),      resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"company_name"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.InternalName,     sizeof (appInfo.InternalName) / sizeof (wchar_t) - 1),     resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"internal_name"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.OriginalFilename, sizeof (appInfo.OriginalFilename) / sizeof (wchar_t) - 1), resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"original_file_name"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.ProductVersion,   sizeof (appInfo.ProductVersion) / sizeof (wchar_t) - 1),   resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"product_version"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.FileVersion,      sizeof (appInfo.FileVersion) / sizeof (wchar_t) - 1),      resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"file_version"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.LegalCopyright,   sizeof (appInfo.LegalCopyright) / sizeof (wchar_t) - 1),   resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"legal_copyright"))));
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.Comments,         sizeof (appInfo.Comments) / sizeof (wchar_t) - 1),         resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"comments")))); 
  cdbcsupport.get <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.ProductURL,       sizeof (appInfo.ProductURL) / sizeof (wchar_t) - 1),       resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"product_url"))));
  cdbcsupport.get <unsigned int&> (appInfo.Lang, resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"lang"))));
  cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.Icon,             sizeof (appInfo.Icon), reinterpret_cast <size_t&> (appInfo.IconSize)), resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"icon"))));
  cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.MD5,              sizeof (appInfo.MD5)),                                     resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"md5"))));
  cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.SHA1,             sizeof (appInfo.SHA1)),                                    resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"sha1"))));
  cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.SHA256,           sizeof (appInfo.SHA256)),                                  resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"sha256"))));
  cdbcsupport.get <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.CertThumbprint,   sizeof (appInfo.CertThumbprint)),                          resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"cert_thumbprint"))));
  cdbcsupport.get <unsigned int&> (appInfo.AppOptions, resultSet, CDBCSupport::UserIndex (resultSet->getColumnIndex (wstring (L"app_options"))));  
} // FillApplicationRecordInfo


//template <typename Record, typename Tuple>
//bool GetRecordInfo (IConnection::PtrToIConnection& conn, Record& record, const wstring& sql, Tuple& params)
//{
//  bool result = false;
//
//  CDBCSupport::PtrToIResultSet resultSet = CDBCSupport ().executeQuery <Tuple> (conn, sql, params);
//  if (NULL != resultSet.get ())
//  {
//    FillRecordInfo<Record> (record, resultSet);
//    result = true;
//  }
//
//  return result;
//} // GetRecordInfo

IPreparedStatement::PtrToIResultSet GetRecord (int id, IConnection::PtrToIConnection& conn, const wstring& checkSql)
{
  IConnection::PtrToIPreparedStatement checkStmt   = conn->createPreparedStatement (checkSql);
  checkStmt->setInt (id, 1);
  
  IPreparedStatement::PtrToIResultSet checkResSet = checkStmt->executeQuery ();
  
  if (true == checkResSet->next ())
    return checkResSet;
  
  return IPreparedStatement::PtrToIResultSet ();
} // GetRecord

IPreparedStatement::PtrToIResultSet GetRecord (const GUID& guid, IConnection::PtrToIConnection& conn, const wstring& checkSql)
{
  IConnection::PtrToIPreparedStatement checkStmt   = conn->createPreparedStatement (checkSql);
  checkStmt->setBlob (reinterpret_cast <unsigned char*> (const_cast <GUID*> (&guid)), sizeof (guid), 1);
  
  IPreparedStatement::PtrToIResultSet checkResSet = checkStmt->executeQuery ();
  
  if (true == checkResSet->next ())
    return checkResSet;
  
  return IPreparedStatement::PtrToIResultSet ();
} // GetRecord

int IsRecordExist (const GUID& guid, IConnection::PtrToIConnection& conn, const wstring& checkSql)
{
  int record_id = 0;
  
  IPreparedStatement::PtrToIResultSet checkResSet = GetRecord (guid, conn, checkSql);
  
  if (NULL != checkResSet.get ())
    record_id = checkResSet->getInt (checkResSet->getColumnIndex (wstring (L"id")));
  
  return record_id;
} // IsRecordExist

int GetDestParamsId (int source_params_id, IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IdResolver& idResolver)
{
  int result = source_params_id;
  
  if (0 != source_params_id)
  {
    IdResolver::iterator i = idResolver.find (source_params_id);
    if (i != idResolver.end ())
    {
      result = (*i).second;
    }  
    else
    {
      IConnection::PtrToIPreparedStatement checkStmt = srcConn->createPreparedStatement (wstring (L"select guid from params where id = ?"));
      checkStmt->setInt (source_params_id, 1);
      
      IPreparedStatement::PtrToIResultSet  checkResSet = checkStmt->executeQuery ();
  
      if (true == checkResSet->next ())
      {
        GUID       source_guid;

        memset (&source_guid, 0, sizeof (source_guid));
        checkResSet->getBlob (0, reinterpret_cast <unsigned char*> (&source_guid), sizeof (source_guid));
        
        result = IsRecordExist (source_guid, destConn, wstring (L"select id from params where guid = ?"));
      }
      else
      {
        result = 0;
      }
    }  
  }  
  
  return result;  
} // GetDestParamsId

int GetDestParamsParam1 (int source_params_param1, int source_params_param2, IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IdResolver& param1Resolver)
{
  int result = 0;
  
  if (0 != source_params_param1)
  {
    IdResolver::iterator i = param1Resolver.find (source_params_param1);
    if (i != param1Resolver.end ())
    {
      result = (*i).second;
    }  
    else
    {
      CDBCSupport::PtrToIResultSet guidRS = CDBCSupport ().executeQuery <tuple <int, int> > (srcConn, wstring (L"select guid from params where param1 = ? and options = ?"), tuple <int, int> (source_params_param2, dboNone));
      if (NULL != guidRS.get ())
      {
        GUID  guid;
        
        guidRS->getBlob (0, reinterpret_cast <unsigned char*> (&guid), sizeof (guid));
        CDBCSupport::PtrToIResultSet param1RS = CDBCSupport ().executeQuery <tuple <CDBCSupport::blob&, int> > (destConn, wstring (L"select param1 from params where guid = ? and options = ?"), tuple <CDBCSupport::blob&, int> (CDBCSupport::blob (&guid, sizeof (guid)), dboNone));
        if (NULL != param1RS.get ())
          result = param1RS->getInt (0);
//IsRecordExist (guid, destConn, wstring (L"select param1 from params where guid = ?"));
      }
    }
  } // if (0 != source_params_param1)
  
  return result;  
} // GetDestParamsParam1

template <>
void AppendRecord<ParamsRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, ParamsRecordInfo& info)
{
//  ParamsRecordInfo info;
  
  FillRecordInfo<ParamsRecordInfo> (info, resultSet);

  int        source_id     = info.m_info.Id;
  int        source_param1 = info.m_info.Attributes.Param[0];
  int        source_param2 = info.m_info.Attributes.Param[1];
  
  info.m_info.GroupId = GetDestParamsId (info.m_info.GroupId, srcConn, destConn, idResolver);
  
  int destination_id = 0;
  
  if (parAppContent == info.m_info.Type || parAppPath == info.m_info.Type || parAppDigest == info.m_info.Type)
  {
    info.m_info.Options = info.m_options;
    destination_id  = InsertParams (info.m_guid, destConn, info.m_info);
    CDBCSupport ().executeUpdate <tuple <int, int> > (destConn, wstring (L"update params set param1 = ? where id = ?"), tuple <int, int> (destination_id, destination_id));
    
    if (0 != destination_id)
      param1Resolver [source_param1] = destination_id;
    
    CDBCSupport::PtrToIResultSet appInfoRS = CDBCSupport ().executeQuery <tuple <int, int> > (srcConn, wstring (L"select * from appinfo where app_id = ? and options <> ?"), tuple <int, int> (source_param1, dboDeleted));
    if (NULL != appInfoRS.get ())
    {
      do
      {
        ApplicationRecordInfo _info;
        AppendRecord<ApplicationRecordInfo> (srcConn, destConn, appInfoRS, idResolver, param1Resolver, _info);
      }
      while (true == appInfoRS->next());
    }  
  }
  else
  {
    if (parResourceApp == info.m_info.Type)
    {
      info.m_info.Attributes.Param[1] = GetDestParamsParam1 (source_param1, source_param2, srcConn, destConn, param1Resolver);
	  info.m_info.Options = info.m_options;
      destination_id = InsertParams (info.m_guid, destConn, info.m_info);
    }
    else
    {
	  info.m_info.Options = info.m_options;
      destination_id  = InsertParams (info.m_guid, destConn, info.m_info);
    }
  } // if (parAppContent == info.Type || parAppPath == info.Type || parAppDigest == info.Type)
  
  if (0 != destination_id)
    idResolver [source_id] = destination_id;
} // AppendRecord

template <>
void AppendRecord<PathRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, PathRecordInfo& info)
{
//  PathRecordInfo info;
  FillRecordInfo<PathRecordInfo> (info, resultSet);
  info.m_info.ParentId = GetDestParamsId (info.m_info.ParentId, srcConn, destConn, idResolver);
  info.m_info.Options = info.m_options;
  InsertPath (info.m_guid, destConn, info.m_info);
} // AppendRecord

template <>
void AppendRecord<OwnerRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, OwnerRecordInfo& info)
{
//  OwnerRecordInfo info;
  FillRecordInfo<OwnerRecordInfo> (info, resultSet);
  info.m_info.ParentId = GetDestParamsId (info.m_info.ParentId, srcConn, destConn, idResolver);
  info.m_info.Options = info.m_options;
  int Id;
  InsertOwner (info.m_guid, destConn, info.m_info, Id);
} // AppendRecord

template <>
void AppendRecord<ContentRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, ContentRecordInfo& info)
{
//  ContentRecordInfo info;
  FillRecordInfo<ContentRecordInfo> (info, resultSet);
  info.m_info.ParentId = GetDestParamsId (info.m_info.ParentId, srcConn, destConn, idResolver);
  info.m_info.Options = info.m_options;
  InsertContent (info.m_guid, destConn, info.m_info);
} // AppendRecord

template <>
void AppendRecord<CertRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, CertRecordInfo& info)
{
//  CertRecordInfo info;
  FillRecordInfo<CertRecordInfo> (info, resultSet);
  info.m_info.ParentId = GetDestParamsId (info.m_info.ParentId, srcConn, destConn, idResolver);
  info.m_info.Options = info.m_options;
  int Id;
  InsertCertificate (info.m_guid, destConn, info.m_info, Id);
} // AppendRecord

template <>
void AppendRecord<DigestRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, DigestRecordInfo& info)
{
//  DigestRecordInfo info;
  FillRecordInfo<DigestRecordInfo> (info, resultSet);
  info.m_info.ParentId = GetDestParamsId (info.m_info.ParentId, srcConn, destConn, idResolver);
  info.m_info.Options = info.m_options;
  InsertDigest (info.m_guid, destConn, info.m_info);
} // AppendRecord

template <>
void AppendRecord<ApplicationRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& destConn, IPreparedStatement::PtrToIResultSet& resultSet, IdResolver& idResolver, IdResolver& param1Resolver, ApplicationRecordInfo& appInfo)
{
  //ApplicationRecordInfo appInfo;
  FillRecordInfo<ApplicationRecordInfo> (appInfo, resultSet);
  
  IdResolver::iterator i = param1Resolver.find (appInfo.m_info.AppId);
  if (i != param1Resolver.end ())
  {
    appInfo.m_info.AppId = (*i).second;

    IConnection::PtrToIPreparedStatement appInfoRS = destConn->createPreparedStatement (wstring (L"insert into appinfo (id, app_id, file_name, product_name, file_description, company_name, internal_name, original_file_name, product_version, file_version, legal_copyright, comments, product_url, lang, icon, md5, sha1, sha256, cert_thumbprint, app_options, guid, options) values ( null, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )"));
    
    CDBCSupport              cdbcsupport;
    CDBCSupport::BinderIndex index; 

    cdbcsupport.bind <int> (appInfo.m_info.AppId, appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.FileName,         sizeof (appInfo.m_info.FileName) / sizeof (wchar_t) - 1),         appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.ProductName,      sizeof (appInfo.m_info.ProductName) / sizeof (wchar_t) - 1),      appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.FileDescription,  sizeof (appInfo.m_info.FileDescription) / sizeof (wchar_t) - 1),  appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.CompanyName,      sizeof (appInfo.m_info.CompanyName) / sizeof (wchar_t) - 1),      appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.InternalName,     sizeof (appInfo.m_info.InternalName) / sizeof (wchar_t) - 1),     appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.OriginalFilename, sizeof (appInfo.m_info.OriginalFilename) / sizeof (wchar_t) - 1), appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.ProductVersion,   sizeof (appInfo.m_info.ProductVersion) / sizeof (wchar_t) - 1),   appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.FileVersion,      sizeof (appInfo.m_info.FileVersion) / sizeof (wchar_t) - 1),      appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.LegalCopyright,   sizeof (appInfo.m_info.LegalCopyright) / sizeof (wchar_t) - 1),   appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.Comments,         sizeof (appInfo.m_info.Comments) / sizeof (wchar_t) - 1),         appInfoRS, index); 
    cdbcsupport.bind <CDBCSupport::wstr&> (CDBCSupport::wstr (appInfo.m_info.ProductURL,       sizeof (appInfo.m_info.ProductURL) / sizeof (wchar_t) - 1),       appInfoRS, index);
    cdbcsupport.bind <unsigned int> (appInfo.m_info.Lang, appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.m_info.Icon,             appInfo.m_info.IconSize, reinterpret_cast <size_t&> (appInfo.m_info.IconSize)), appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.m_info.MD5,              sizeof (appInfo.m_info.MD5)),                                     appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.m_info.SHA1,             sizeof (appInfo.m_info.SHA1)),                                    appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.m_info.SHA256,           sizeof (appInfo.m_info.SHA256)),                                  appInfoRS, index);
    cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (appInfo.m_info.CertThumbprint,   sizeof (appInfo.m_info.CertThumbprint)),                          appInfoRS, index);
    cdbcsupport.bind <unsigned int> (appInfo.m_info.AppOptions, appInfoRS, index);  
    cdbcsupport.bind <CDBCSupport::blob&> (CDBCSupport::blob (&(appInfo.m_guid),               sizeof (appInfo.m_guid)),                                         appInfoRS, index);
    cdbcsupport.bind <int> (dboNone, appInfoRS, index);  
    
    appInfoRS->executeUpdate ();
  }  
} // AppendRecord

template <typename Record>
void DeleteRecord (IConnection::PtrToIConnection& destConn, int destinationId)
{
  
} // DeleteRecord

template <>
void DeleteRecord<ParamsRecordInfo> (IConnection::PtrToIConnection& destConn, int destinationId)
{
  CDBCSupport::PtrToIResultSet appRS = CDBCSupport ().executeQuery <tuple <int, int> > (destConn, wstring (L"select * from params where id = ? and options <> ?"), tuple <int, int> (destinationId, dboDeleted));
  if (NULL != appRS.get ())
  {
    ParamsRecordInfo info;
    FillRecordInfo<ParamsRecordInfo> (info, appRS);
    
    //CDBCSupport ().executeUpdate <tuple <int, int, int> > (conn, wstring (L"update appinfo set options = ? where app_id = ? and options = ?"), tuple <int, int, int> (dboDeleted, appId, dboNone));
    CDBCSupport ().executeUpdate <tuple <int> > (destConn, wstring (L"delete from appinfo where app_id = ?"), tuple <int> (info.m_info.Attributes.Param[0]));
  }
} // DeleteRecord

  
template <typename Record>
void Replicate (IConnection::PtrToIConnection& source, IConnection::PtrToIConnection& destination, IdResolver& idResolver, IdResolver& param1Resolver, const wstring& querySql, const wstring& checkSql, const wstring& delSql)
{
  IConnection::PtrToIPreparedStatement queryStmt   = source->createPreparedStatement (querySql);
  IPreparedStatement::PtrToIResultSet  queryResSet = queryStmt->executeQuery ();

  while (true == queryResSet->next ())
  {
    GUID     source_guid;
    memset (&source_guid, 0, sizeof (source_guid));
    
    queryResSet->getBlob (queryResSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&source_guid), sizeof (source_guid));
    int source_options   = static_cast <int> (queryResSet->getInt (queryResSet->getColumnIndex (wstring (L"options"))));
    
    //IConnection::PtrToIStatement    transaction_stmt = destination->createStatement ();
    //transaction_stmt->execute (wstring (L"begin;")); 

    int      destination_id   = IsRecordExist (source_guid, destination, checkSql);
    if (0 == destination_id)
    {
      // test locked db
      //IConnectionFactory::ConnectionHolder sourceConnHolder (Setting::getConnectonFactory (), wstring (L"geswall.dat"));
      //IConnection::PtrToIConnection        sourceConn        = sourceConnHolder.connection ();
      //AppendRecord<Record> (source, sourceConn, queryResSet, idResolver);
      //
      
      Record _record;
      AppendRecord<Record> (source, destination, queryResSet, idResolver, param1Resolver, _record);
    } // if (0 == destination_id)
    else
    {
      if (dboDeleted == source_options)
      {
        DeleteRecord<Record> (destination, destination_id);
        DeleteObject (destination, destination_id, delSql);
      }
    } // else if (0 == destination_id)
    
    //destination->commit ();
  } // while (true == queryResSet->next ())
} // Replicate

template <typename Record>
void Replicate (const wstring& source, const wstring& destination, IdResolver& idResolver, IdResolver& param1Resolver, const wstring& querySql, const wstring& checkSql, const wstring& delSql)
{
  IConnectionFactory::ConnectionHolder sourceConnHolder (Setting::getConnectonFactory (), source);
  IConnectionFactory::ConnectionHolder destinationConnHolder (Setting::getConnectonFactory (), destination);
  IConnection::PtrToIConnection        destinationConn  = destinationConnHolder.connection ();
  IConnection::PtrToIConnection        sourceConn       = sourceConnHolder.connection ();
    
  //IConnection::PtrToIStatement    transaction_stmt = destinationConn->createStatement ();
  //transaction_stmt->execute (wstring (L"begin;")); 
    
  Replicate <Record> (sourceConn, destinationConn, idResolver, param1Resolver, querySql, checkSql, delSql);
    
  //destinationConn->commit ();
} // Replicate

bool Replicate (const wstring& source, const wstring& destination)
{
  bool        result = false;
  IdResolver  idResolver;
  IdResolver  param1Resolver;
  wchar_t     buf [128];
  
  try
  {
    // params
    Replicate <ParamsRecordInfo> ( 
                                 source, destination, idResolver, param1Resolver,
                                 wstring (L"select * from params order by group_id where param_type != ") + wstring (_itow (parResourceApp, buf, 10)),      // querySql (parAppContent, parAppPath, parAppDigest)
                                 wstring (L"select id from params where guid = ?"),         // checkSql
                                 wstring (L"update params set options = 1 where id = ?")    // delSql
                                );
                                
    Replicate <ParamsRecordInfo> (
                                 source, destination, idResolver, param1Resolver,
                                 wstring (L"select * from params order by group_id where param_type = ") + wstring (_itow (parResourceApp, buf, 10)),      // querySql (parAppContent, parAppPath, parAppDigest)
                                 wstring (L"select id from params where guid = ?"),         // checkSql
                                 wstring (L"update params set options = 1 where id = ?")    // delSql
                                );                                
    
    // pathes
    Replicate <PathRecordInfo> (
                               source, destination, idResolver, param1Resolver,
                               wstring (L"select * from pathes"),                           // querySql
                               wstring (L"select id from pathes where guid = ?"),           // checkSql
                               wstring (L"update pathes set options = 1 where id = ?")      // delSql
                              );                                                              
                                                                                              
    // owners                                                                                 
    Replicate <OwnerRecordInfo> (                                                              
                                source, destination, idResolver, param1Resolver,
                                wstring (L"select * from owners"),                          // querySql
                                wstring (L"select id from owners where guid = ?"),          // checkSql
                                wstring (L"update owners set options = 1 where id = ?")     // delSql
                               );
                   
    // contents
    Replicate <ContentRecordInfo> (
                                  source, destination, idResolver, param1Resolver,
                                  wstring (L"select * from contents"),                      // querySql
                                  wstring (L"select id from contents where guid = ?"),      // checkSql
                                  wstring (L"update contents set options = 1 where id = ?") // delSql
                                 );
               
    // certificates
    Replicate <CertRecordInfo> (
                               source, destination, idResolver, param1Resolver,
                               wstring (L"select * from certificates"),                     // querySql
                               wstring (L"select id from certificates where guid = ?"),     // checkSql
                               wstring (L"update certificates set options = 1 where id = ?")// delSql
                              );
               
    // digests
    Replicate <DigestRecordInfo> (
                                 source, destination, idResolver, param1Resolver,
                                 wstring (L"select * from digests"),                        // querySql
                                 wstring (L"select id from digests where guid = ?"),        // checkSql
                                 wstring (L"update digests set options = 1 where id = ?")   // delSql
                                );
    
    result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // Replicate

void CompareParent (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, int srcParentId, int dstParentId);

template <typename Record>
void CompareRecord (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, Record& srcRecord, Record& dstRecord)
{
  BOOST_STATIC_ASSERT (false);
} // CompareRecord

template <>
void CompareRecord<ParamsRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, ParamsRecordInfo& srcRecord, ParamsRecordInfo& dstRecord)
{
  if (
         srcRecord.m_options                   != dstRecord.m_options
      || srcRecord.m_info.Type                 != dstRecord.m_info.Type
      || srcRecord.m_info.Model                != dstRecord.m_info.Model 
//      || srcRecord.m_info.Attributes.Param [0] != dstRecord.m_info.Attributes.Param [0]
//      || srcRecord.m_info.Attributes.Param [1] != dstRecord.m_info.Attributes.Param [1]
      || srcRecord.m_info.Attributes.Param [2] != dstRecord.m_info.Attributes.Param [2]
      || srcRecord.m_info.Attributes.Param [3] != dstRecord.m_info.Attributes.Param [3]
      || srcRecord.m_info.Attributes.Param [4] != dstRecord.m_info.Attributes.Param [4]
      || srcRecord.m_info.Attributes.Param [5] != dstRecord.m_info.Attributes.Param [5]
      || 0 != wcscmp (srcRecord.m_info.Description, dstRecord.m_info.Description)
      || 0 != memcmp (&srcRecord.m_guid, &dstRecord.m_guid, sizeof (dstRecord.m_guid))
     )
    throw SQLException (L"ParamsRecordInfo compare error");  

  //srcRecord.m_info.Id
  //srcRecord.m_info.ParentId
  if (
         (0 != srcRecord.m_info.Id && srcRecord.m_info.Id == srcRecord.m_info.GroupId)
      || (0 != dstRecord.m_info.Id && dstRecord.m_info.Id == dstRecord.m_info.GroupId)
     )
    throw SQLException (L"recursive parent id error");   
  
  CompareParent (srcConn, dstConn, srcRecord.m_info.GroupId, dstRecord.m_info.GroupId);
} // CompareRecord

template <>
void CompareRecord<PathRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, PathRecordInfo& srcRecord, PathRecordInfo& dstRecord)
{
  if (
         srcRecord.m_options   != dstRecord.m_options
      || srcRecord.m_info.Type != dstRecord.m_info.Type
      || 0 != wcscmp (srcRecord.m_info.Path, dstRecord.m_info.Path)
      || 0 != memcmp (&srcRecord.m_guid, &dstRecord.m_guid, sizeof (dstRecord.m_guid))
     )
    throw SQLException (L"PathRecordInfo compare error");  

  //srcRecord.m_info.Id
  //srcRecord.m_info.ParentId
  CompareParent (srcConn, dstConn, srcRecord.m_info.ParentId, dstRecord.m_info.ParentId);
} // CompareRecord

template <>
void CompareRecord<OwnerRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, OwnerRecordInfo& srcRecord, OwnerRecordInfo& dstRecord)
{
  if (
         srcRecord.m_options   != dstRecord.m_options
      || srcRecord.m_info.Type != dstRecord.m_info.Type
      || 0 != wcscmp (srcRecord.m_info.Owner, dstRecord.m_info.Owner)
      || 0 != memcmp (&srcRecord.m_guid, &dstRecord.m_guid, sizeof (dstRecord.m_guid))
     )
    throw SQLException (L"OwnerRecordInfo compare error");  

  //srcRecord.m_info.Id
  //srcRecord.m_info.ParentId
  CompareParent (srcConn, dstConn, srcRecord.m_info.ParentId, dstRecord.m_info.ParentId);
} // CompareRecord

template <>
void CompareRecord<ContentRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, ContentRecordInfo& srcRecord, ContentRecordInfo& dstRecord)
{
  if (
         srcRecord.m_options   != dstRecord.m_options
      || srcRecord.m_info.Type != dstRecord.m_info.Type
      || 0 != wcscmp (srcRecord.m_info.Content, dstRecord.m_info.Content)
      || 0 != wcscmp (srcRecord.m_info.FileName, dstRecord.m_info.FileName)
      || 0 != memcmp (&srcRecord.m_guid, &dstRecord.m_guid, sizeof (dstRecord.m_guid))
     )
    throw SQLException (L"ContentRecordInfo compare error");  

  //srcRecord.m_info.Id
  //srcRecord.m_info.ParentId
  CompareParent (srcConn, dstConn, srcRecord.m_info.ParentId, dstRecord.m_info.ParentId);
} // CompareRecord

template <>
void CompareRecord<CertRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, CertRecordInfo& srcRecord, CertRecordInfo& dstRecord)
{
  if (
         srcRecord.m_options         != dstRecord.m_options
      || srcRecord.m_info.Type       != dstRecord.m_info.Type
      || srcRecord.m_info.Expiration != dstRecord.m_info.Expiration
      || 0 != wcscmp (srcRecord.m_info.IssuedTo, dstRecord.m_info.IssuedTo)
      || 0 != wcscmp (srcRecord.m_info.IssuedBy, dstRecord.m_info.IssuedBy)
      || 0 != memcmp (&srcRecord.m_guid, &dstRecord.m_guid, sizeof (dstRecord.m_guid))
      || srcRecord.m_info.ThumbprintSize != dstRecord.m_info.ThumbprintSize
      || 0 != memcmp (&srcRecord.m_info.Thumbprint, &dstRecord.m_info.Thumbprint, dstRecord.m_info.ThumbprintSize)
     )
    throw SQLException (L"CertRecordInfo compare error");  

  //srcRecord.m_info.Id
  //srcRecord.m_info.ParentId
  CompareParent (srcConn, dstConn, srcRecord.m_info.ParentId, dstRecord.m_info.ParentId);
} // CompareRecord

template <>
void CompareRecord<DigestRecordInfo> (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, DigestRecordInfo& srcRecord, DigestRecordInfo& dstRecord)
{
  if (
         srcRecord.m_options   != dstRecord.m_options
      || srcRecord.m_info.Type != dstRecord.m_info.Type
      || 0 != wcscmp (srcRecord.m_info.FileName, dstRecord.m_info.FileName)
      || 0 != memcmp (&srcRecord.m_guid, &dstRecord.m_guid, sizeof (dstRecord.m_guid))
      || srcRecord.m_info.DigestSize != dstRecord.m_info.DigestSize
      || 0 != memcmp (&srcRecord.m_info.Digest, &dstRecord.m_info.Digest, dstRecord.m_info.DigestSize)
     )
    throw SQLException (L"DigestRecordInfo compare error");  

  //srcRecord.m_info.Id
  //srcRecord.m_info.ParentId
  CompareParent (srcConn, dstConn, srcRecord.m_info.ParentId, dstRecord.m_info.ParentId);
} // CompareRecord

void CompareParent (IConnection::PtrToIConnection& srcConn, IConnection::PtrToIConnection& dstConn, int srcParentId, int dstParentId)
{
  if ( 
         (0 != srcParentId && 0 == dstParentId)
      || (0 == srcParentId && 0 != dstParentId) 
     )
    throw SQLException (L"CompareParent compare error - no parent 0");
      
  if (0 != srcParentId)
  {
    IPreparedStatement::PtrToIResultSet srcResSet = GetRecord (srcParentId, srcConn, wstring (L"select * from params where id = ?"));
    IPreparedStatement::PtrToIResultSet dstResSet = GetRecord (dstParentId, dstConn, wstring (L"select * from params where id = ?"));
    
    if ( 
           (NULL != srcResSet.get () && NULL == dstResSet.get ())
        || (NULL == srcResSet.get () && NULL != dstResSet.get ()) 
       )
      throw SQLException (L"CompareParent compare error - no parent 2");
    
    if (NULL != srcResSet.get () && NULL != dstResSet.get ())
    {
      ParamsRecordInfo srcParent;
      FillRecordInfo<ParamsRecordInfo> (srcParent, srcResSet);
      
      ParamsRecordInfo dstParent;
      FillRecordInfo<ParamsRecordInfo> (dstParent, dstResSet);
      
      CompareRecord<ParamsRecordInfo> (srcConn, dstConn, srcParent, dstParent);
    }
  } // if (0 != srcRecord.m_info.ParentId)
} // CompareParent

template <typename Record>
void Compare (IConnection::PtrToIConnection& source, IConnection::PtrToIConnection& destination, const wstring& querySql, const wstring& checkSql)
{
  IConnection::PtrToIPreparedStatement srcStmt   = source->createPreparedStatement (querySql);
  IPreparedStatement::PtrToIResultSet  srcResSet = srcStmt->executeQuery ();

  while (true == srcResSet->next ())
  {
    Record srcRecord;
    FillRecordInfo<Record> (srcRecord, srcResSet);
    
    GUID     source_guid;
    memset (&source_guid, 0, sizeof (source_guid));
    
    srcResSet->getBlob (srcResSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&source_guid), sizeof (source_guid));
    
    IPreparedStatement::PtrToIResultSet dstResSet = GetRecord (source_guid, destination, checkSql);
  
    if (NULL == dstResSet.get ())
      throw SQLException (L"compare error - record absent into dest db");  
    
    Record dstRecord;
    FillRecordInfo<Record> (dstRecord, dstResSet);
    
    CompareRecord <Record> (source, destination, srcRecord, dstRecord);
  } // while (true == queryResSet->next ())
} // Compare

template <typename Record>
void Compare (const wstring& source, const wstring& destination, const wstring& querySql, const wstring& checkSql)
{
  IConnectionFactory::ConnectionHolder sourceConnHolder (Setting::getConnectonFactory (), source);
  IConnectionFactory::ConnectionHolder destinationConnHolder (Setting::getConnectonFactory (), destination);
  IConnection::PtrToIConnection        destinationConn  = destinationConnHolder.connection ();
  IConnection::PtrToIConnection        sourceConn       = sourceConnHolder.connection ();
    
  Compare <Record> (sourceConn, destinationConn, querySql, checkSql);
} // Compare

bool Compare (const wstring& source, const wstring& destination)
{
  bool        result = false;
  
  try
  {
    // params
    Compare <ParamsRecordInfo> (
                               source, destination, 
                               wstring (L"select * from params order by group_id"),      // querySql
                               wstring (L"select * from params where guid = ?")           // checkSql
                              );

    // pathes
    Compare <PathRecordInfo> (
                             source, destination,
                             wstring (L"select * from pathes"),                           // querySql
                             wstring (L"select * from pathes where guid = ?")             // checkSql
                            );                                                              
                                                                                              
    // owners                                                                                 
    Compare <OwnerRecordInfo> (                                                              
                              source, destination,                               
                              wstring (L"select * from owners"),                          // querySql
                              wstring (L"select * from owners where guid = ?")            // checkSql
                             );
                 
    // contents
    Compare <ContentRecordInfo> (
                                source, destination, 
                                wstring (L"select * from contents"),                      // querySql
                                wstring (L"select * from contents where guid = ?")        // checkSql
                               );
               
    // certificates
    Compare <CertRecordInfo> (
                             source, destination, 
                             wstring (L"select * from certificates"),                     // querySql
                             wstring (L"select * from certificates where guid = ?")       // checkSql
                            );
               
    // digests
    Compare <DigestRecordInfo> (
                               source, destination,
                               wstring (L"select * from digests"),                        // querySql
                               wstring (L"select * from digests where guid = ?")          // checkSql
                              );

    result = true;
  }
  catch (SQLException& e)
  {
    printSQLException (e);
  }
  
  return result;
} // Compare


} // namespace Storage {