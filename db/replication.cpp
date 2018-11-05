//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"

#include "replication.h"
#include "gesruledef.h"

#include "cdbc/iconnectionfactory.h"
#include "cdbc/iconnection.h"
#include "cdbc/istatement.h"
#include "cdbc/ipreparedstatement.h"
#include "cdbc/iresultset.h"
#include "cdbc/cdbcsupport.h"

#include "setting.h"

#include <list>
#include <map>

using namespace sql;
using namespace std;

namespace Storage {
namespace replication {

//
// type & func defs
//

typedef list<int>              IdList;
typedef map<int, int>          IdResolver;
typedef CDBCSupport::blob      blob;
typedef CDBCSupport::wstr      wstr;
typedef CDBCSupport::UserIndex UserIndex;

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

void replicate (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);
void replicateGroups (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);
void replicateApplications (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);
void replicateAppInfos (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);
void replicateResources (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);
void replicatePathes (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);
void replicateIdentities (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);
void replicateGlobalResources (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions);

void replicateIdentPathes (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, IdList& userIdList);
void replicateIdentContents (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, IdList& userIdList);
void replicateIdentDigests (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, IdList& userIdList);

void replicateGlobalOwners (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn);
void replicateGlobalCertificates (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn);
void replicateGlobalPathes (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn);

void deleteGroups (CDBCSupport::PtrToIResultSet& select2d, IConnection::PtrToIConnection& conn, ParamsRecordInfo& srcParams, IdList& userAppIdList, IdResolver& deletedList);
void addGroups (CDBCSupport::PtrToIResultSet& select2d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, ParamsRecordInfo& srcParams, IdList& userAppIdList, IdResolver& deletedList);

void deleteApplications (CDBCSupport::PtrToIResultSet& select4d, IConnection::PtrToIConnection& conn, ParamsRecordInfo& srcParams, IdList& userAppIdList, IdResolver& deletedList);
void addApplications (CDBCSupport::PtrToIResultSet& select4d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, ParamsRecordInfo& srcParams, IdList& userAppIdList, IdResolver& deletedList);

void deletePathes (CDBCSupport::PtrToIResultSet& select9d, IConnection::PtrToIConnection& conn, PathRecordInfo& srcParams, IdList& userIdList);
void addPathes (CDBCSupport::PtrToIResultSet& select9d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, PathRecordInfo& srcParams, IdList& userIdList);

void deleteIdentPathes (CDBCSupport::PtrToIResultSet& select11d, IConnection::PtrToIConnection& conn, PathRecordInfo& srcParams, IdList& userIdList);
void addIdentPathes (CDBCSupport::PtrToIResultSet& select11d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, PathRecordInfo& srcParams, IdList& userIdList);

void deleteIdentContents (CDBCSupport::PtrToIResultSet& select12d, IConnection::PtrToIConnection& conn, ContentRecordInfo& srcParams, IdList& userIdList);
void addIdentContents (CDBCSupport::PtrToIResultSet& select12d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, ContentRecordInfo& srcParams, IdList& userIdList);

void deleteIdentDigests (CDBCSupport::PtrToIResultSet& select13d, IConnection::PtrToIConnection& conn, DigestRecordInfo& srcParams, IdList& userIdList);
void addIdentDigests (CDBCSupport::PtrToIResultSet& select13d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, DigestRecordInfo& srcParams, IdList& userIdList);

void deleteFromMapByValue (IdResolver& data, int value);
void fillUserIdList (CDBCSupport::PtrToIResultSet select, IdList& userIdList);
int  find (IdList& list, int id);

template <typename Record>
void fillRecordInfo (Record& info, CDBCSupport::PtrToIResultSet& resultSet);
template <>
void fillRecordInfo<ParamsRecordInfo> (ParamsRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet);
template <>
void fillRecordInfo<CertRecordInfo> (CertRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet);
template <>
void fillRecordInfo<DigestRecordInfo> (DigestRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet);
template <>
void fillRecordInfo<PathRecordInfo> (PathRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet);
template <>
void fillRecordInfo<OwnerRecordInfo> (OwnerRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet);
template <>
void fillRecordInfo<ContentRecordInfo> (ContentRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet);
template <>
void fillRecordInfo<ApplicationRecordInfo> (ApplicationRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet);

//
// global data defs
//

IdResolver m_appIdList;
IdResolver m_idList;


//
// public func area
//

bool Replicate (const wstring& source, const wstring& destination, int rplOptions)
{
  bool       result = false;

  try
  {
    IConnectionFactory::ConnectionHolder sourceConnHolder (Setting::getConnectonFactory (), source);
    IConnectionFactory::ConnectionHolder destinationConnHolder (Setting::getConnectonFactory (), destination);
    IConnection::PtrToIConnection        destinationConn  = destinationConnHolder.connection ();
    IConnection::PtrToIConnection        sourceConn       = sourceConnHolder.connection ();

    replicate (sourceConn, destinationConn, rplOptions);
    result = true;
  }
  catch (SQLException& e)
  {
    result = false;
#ifdef _DEBUG
    wprintf (L"\nReplicate Exception => %s", e.getMessageTextAndCode ());
#endif 
    throw Storage::StorageException (e.getMessage (), e.getCode ()); 
  }
  catch (Storage::StorageException& e)
  {
#ifdef _DEBUG
    wprintf (L"\nReplicate Exception => %s", e.getMessageTextAndCode ());
#endif 
    throw e;
  }

  return result;
} // Replicate

//
// private func area
//
void replicate (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  replicateGroups (sourceConn, destinationConn, rplOptions);
  replicateApplications (sourceConn, destinationConn, rplOptions);
  replicateAppInfos (sourceConn, destinationConn, rplOptions);
  replicateResources (sourceConn, destinationConn, rplOptions);
  replicatePathes (sourceConn, destinationConn, rplOptions);
  replicateIdentities (sourceConn, destinationConn, rplOptions);
  replicateGlobalResources (sourceConn, destinationConn, rplOptions);
} // replicate

void replicateGroups (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  IdList      userAppIdList;
  IdList      userIdList;
  IdResolver  deletedList;
  CDBCSupport cdbcSupport;

  if (0 == (rplOptions & rplGroupsUpdates))
  {
//    select1 = select distinct param1 from dest.params where param_type = parAppGroup and options & dboUserCreated
    CDBCSupport::PtrToIResultSet select1 = 
      cdbcSupport.executeQuery <tuple <int, int> > (
        destinationConn, 
        L"select distinct param1 from params where param_type = ? and options & ?", 
        tuple <int, int> (parAppGroup, dboUserCreated)
      );
    fillUserIdList (select1, userAppIdList);
  }  

//  select2 = select * from src.params where param_type = parAppGroup order by id
  CDBCSupport::PtrToIResultSet select2 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from params where param_type = ? order by id", 
      tuple <int> (parAppGroup)
    );
  if (NULL != select2.get ())
  {
    do
    {
      ParamsRecordInfo srcParams;
      fillRecordInfo<ParamsRecordInfo> (srcParams, select2);

//      if exist(select @id = id, @param1 = param1, @options = options from dest.params where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select2d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, param1, options, group_id from params where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select2d.get ())
      { // exist
        // 
        deleteGroups (select2d, destinationConn, srcParams, userAppIdList, deletedList);
      } // if (NULL != select2d.get ())
      else
      { // not exist
        // 
        addGroups (select2d, sourceConn, destinationConn, srcParams, userAppIdList, deletedList);
      }
    }
    while (true == select2->next());
  } // if (NULL != select2.get ())
} // replicateGroups

void replicateApplications (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  IdList      userAppIdList;
  IdList      userIdList;
  IdResolver  deletedList;
  CDBCSupport cdbcSupport;
  
  if (0 == (rplOptions & rplApp))
  {
//    select3 = select distinct param1 from dest.params where param_type in (parAppContent, parAppPath, parAppDigest) and options & dboUserCreated 
    CDBCSupport::PtrToIResultSet select3 = 
      cdbcSupport.executeQuery <tuple <int, int, int, int> > (
        destinationConn, 
        L"select distinct param1 from params where param_type in (?, ?, ?) and options & ?", 
        tuple <int, int, int, int> (parAppContent, parAppPath, parAppDigest, dboUserCreated)
      );
    fillUserIdList (select3, userAppIdList);
  }  
  
//  Select4 = select * from src.params where param_type in (parAppContent, parAppPath, parAppDigest)  order by id
  CDBCSupport::PtrToIResultSet select4 = 
    cdbcSupport.executeQuery <tuple <int, int, int> > (
      sourceConn, 
      L"select * from params where param_type in (?, ?, ?) order by id", 
      tuple <int, int, int> (parAppContent, parAppPath, parAppDigest)
    );
  if (NULL != select4.get ())
  {
    do
    {
      ParamsRecordInfo srcParams;
      fillRecordInfo<ParamsRecordInfo> (srcParams, select4);
      
	
//      if exist(select @id = id, @param1 = param1, @options = options from dest.params where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select4d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, param1, options from params where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select4d.get ())
      { // exist
        // 
        deleteApplications (select4d, destinationConn, srcParams, userAppIdList, deletedList);
      }
      else
      { // not exist
        // 
        addApplications (select4d, sourceConn, destinationConn, srcParams, userAppIdList, deletedList);
      }
    }
    while (true == select4->next());
  } // if (NULL != select4.get ())
} // replicateApplications

void replicateAppInfos (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  CDBCSupport cdbcSupport;
  
//  Select7 = select * from src.appinfo
  CDBCSupport::PtrToIResultSet select7 = cdbcSupport.executeQuery (sourceConn, L"select * from appinfo");
  if (NULL != select7.get ())
  {
    do
    {
      ApplicationRecordInfo srcParams;
      fillRecordInfo<ApplicationRecordInfo> (srcParams, select7);
      
//      if exist(select @id = id, @options = options from dest.appinfo where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select7d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, options from appinfo where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select7d.get ())
      { // exist
        int dstId      = 0;
        int dstOptions = 0;

        cdbcSupport.queryResult <tuple <int&, int&> > (select7d, tuple <int&, int&> (dstId, dstOptions));
        select7d.reset ();
        if (srcParams.m_options & dboDeleted && !(dstOptions & dboDeleted))
        {
          // 
//          update dest.appinfo set options = @options | dboDeleted where id = @id
          cdbcSupport.executeUpdate <tuple <int, int> > (
            destinationConn, 
            L"update appinfo set options = (? | options) where id = ?", 
            tuple <int, int> (dboDeleted, dstId)
          );
        }
      }
      else
      { // not exist
        // 
//        if ( exist (select id from dest.appinfo where not ( options & dboDeleted ) and (( internal_name = rec.internal_name and company_name = rec.company_name ) or sha1 = rec.sha1 or ( file_name = file_name and internal_name = '' ) ) ) ) 
//          continue;
       
	CDBCSupport::PtrToIResultSet select7d1;

	if(wstring(srcParams.m_info.InternalName) == L"" && wstring(srcParams.m_info.CompanyName) == L"" && 
	   wstring(srcParams.m_info.ProductName) == L"" && wstring(srcParams.m_info.OriginalFilename) == L"")
	{
		select7d1 =  CDBCSupport ().executeQuery <tuple <int, const CDBCSupport::blob&, const wstring&> > 
	  (
        destinationConn, 
        L"select app_id from appinfo where not (? & options) and ( sha1 = ?  or  file_name = ?  )", 
        tuple <int,  const CDBCSupport::blob&, const wstring&> (dboDeleted, CDBCSupport::blob (&srcParams.m_info.SHA1, sizeof (srcParams.m_info.SHA1)), srcParams.m_info.FileName)
      );
	}
	else
	{
		 select7d1 = CDBCSupport ().executeQuery <tuple <int, const wstring&, const wstring&, const wstring&, const wstring&, const CDBCSupport::blob&, const wstring&> > 
	  (
        destinationConn, 
        L"select app_id from appinfo where not (? & options) and ( ( internal_name = ? and company_name = ? and product_name = ? and original_file_name = ? ) or sha1 = ?  or  (file_name = ? and internal_name = '') )", 
        tuple <int, const wstring&, const wstring&, const wstring&, const wstring&, const CDBCSupport::blob&, const wstring&> (dboDeleted, srcParams.m_info.InternalName, srcParams.m_info.CompanyName, srcParams.m_info.ProductName, srcParams.m_info.OriginalFilename, CDBCSupport::blob (&srcParams.m_info.SHA1, sizeof (srcParams.m_info.SHA1)), srcParams.m_info.FileName)
       );
	
	}
		  
	/*	  CDBCSupport::PtrToIResultSet select7d1 = 
          cdbcSupport.executeQuery <tuple <int, const wstr&, const wstr&, const blob&, const wstr&> > (
            destinationConn, 
            L"select id from appinfo where not (? & options) and ( (internal_name = ? and company_name = ? and internal_name <> '' ) or sha1 = ? or ( file_name = ? and internal_name = '' ) )", 
            tuple <int, const wstr&, const wstr&, const blob&, const wstr&> (
              dboDeleted, 
              wstr (srcParams.m_info.InternalName, sizeof (srcParams.m_info.InternalName) / sizeof (srcParams.m_info.InternalName [0]) - 1), 
              wstr (srcParams.m_info.CompanyName, sizeof (srcParams.m_info.CompanyName) / sizeof (srcParams.m_info.CompanyName [0]) - 1), 
              blob (srcParams.m_info.SHA1, sizeof (srcParams.m_info.SHA1)), 
              wstr (srcParams.m_info.FileName, sizeof (srcParams.m_info.FileName) / sizeof (srcParams.m_info.FileName [0]) - 1)
            )
          ); 
    */
 
        if (NULL != select7d1.get ())
		{
			continue;
		}
        select7d1.reset ();
        
        int recid = srcParams.m_info.Id;
        srcParams.m_info.Id = 0;  
        
        // 
        int appId = 0;
        IdResolver::iterator i = m_appIdList.find (srcParams.m_info.AppId);
        if (i != m_appIdList.end ())
          appId = (*i).second;
          
        if (0 == appId)  
		{   //
			   continue;
			// throw StorageException (L"replicateAppInfos (): BADBAD : ");
		}
        // 
        srcParams.m_info.AppId = appId;
		srcParams.m_info.Options = srcParams.m_options;
        InsertApplicationInfo (srcParams.m_guid, destinationConn, srcParams.m_info);
      } // if (NULL != select7d.get ())
    }
    while (true == select7->next());
  } // if (NULL != select7.get ())
} // replicateAppInfos

void replicateResources (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  CDBCSupport cdbcSupport;
  
//  Select6 = select * from src.params where param_type = parResourceApp order by id
  CDBCSupport::PtrToIResultSet select6 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from params where param_type = ? order by id", 
      tuple <int> (parResourceApp)
    );
  if (NULL != select6.get ())
  {
    do
    {
      ParamsRecordInfo srcParams;
      fillRecordInfo<ParamsRecordInfo> (srcParams, select6);
      
//      if exist(select @id = id,  @param2 =  param2, @options = options from dest.params where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select6d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, param2, options from params where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select6d.get ())
      { // exist
        int dstId      = 0;
        int dstParam2  = 0;
        int dstOptions = 0;

        cdbcSupport.queryResult <tuple <int&, int&, int&> > (select6d, tuple <int&, int&, int&> (dstId, dstParam2, dstOptions));
        select6d.reset ();
        if (srcParams.m_options & dboDeleted && !(dstOptions & dboDeleted))
        {
//          update dest.params set options = @options | dboDeleted where id = @id
          cdbcSupport.executeUpdate <tuple <int, int> > (
            destinationConn, 
            L"update params set options = (? | options) where id = ?", 
            tuple <int, int> (dboDeleted, dstId)
          );

          // 
          m_idList.erase (srcParams.m_info.Id);
        }
      } // if (NULL != select6d.get ())
      else
      { // not exist
        // 
        // 
        int recid = srcParams.m_info.Id;
        srcParams.m_info.Id = 0;

        // 
        int appId = 0;
        IdResolver::iterator i = m_appIdList.find (srcParams.m_info.Attributes.Param [GesRule::attObjectId]);
        if (i != m_appIdList.end ())
          appId = (*i).second;
          
        if (0 == appId)
        {
//          select @guid = guid from src.params where param1 = rec.param2 and param_type in (parAppContent, parAppPath, parAppDigest) order by id limit 1
          CDBCSupport::PtrToIResultSet selectGuid = 
            cdbcSupport.executeQuery <tuple <int, int, int, int> > (
              sourceConn, 
              L"select guid from params where param1 = ? and param_type in (?, ?, ?) order by id limit 1", 
              tuple <int, int, int, int> (
                srcParams.m_info.Attributes.Param [GesRule::attObjectId], 
                parAppContent, 
                parAppPath, 
                parAppDigest
              )
            );
          if (NULL != selectGuid.get ())
          {
            GUID srcGuid;
            cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
            selectGuid.reset ();
          
//            select @param2 = param1 from dest.params where guid = @guid
            CDBCSupport::PtrToIResultSet selectParam2 = 
              cdbcSupport.executeQuery <tuple <const blob&> > (
                destinationConn, 
                L"select param1 from params where guid = ?", 
                tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
              );
            if (NULL != selectParam2.get ())
            {
              cdbcSupport.queryResult <tuple <int&> > (selectParam2, tuple <int&> (appId));
              srcParams.m_info.Attributes.Param [GesRule::attObjectId] = appId;
              m_appIdList [srcParams.m_info.Attributes.Param [GesRule::attSubjectId]] = appId;
            } // if (NULL != selectParam1 .get ())
          } // if (NULL != selectGuid.get ())
        } // if (0 == appId)
        
        // 
//        select @id = id from dest.params where param2 = @AppId and param6 = rec.param6 and not ( options & dboDeleted)
        int dstId = 0;
        CDBCSupport::PtrToIResultSet selectDstId = 
          cdbcSupport.executeQuery <tuple <int, int, int> > (
            destinationConn, 
            L"select id from params where param2 = ? and param6 = ? and not (? & options)", 
            tuple <int, int, int> (appId, srcParams.m_info.Attributes.Param [GesRule::attOptions], dboDeleted)
          );
        cdbcSupport.queryResult <tuple <int&> > (selectDstId, tuple <int&> (dstId));
        selectDstId.reset ();
        
        if (0 == dstId)
        {
          // 
          srcParams.m_info.Attributes.Param [GesRule::attObjectId] = appId;
          srcParams.m_options &= ~dboUserCreated;
		  srcParams.m_info.Options = srcParams.m_options;
          dstId = Storage::InsertParams (srcParams.m_guid, destinationConn, srcParams.m_info);
        }
        
        if (0 != dstId)
          m_idList [recid] = dstId; 
      } // else if (NULL != select6d.get ())
    }
    while (true == select6->next());
  } // if (NULL != select6.get ())
} // replicateResources

void replicatePathes (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  IdList      userIdList;
  CDBCSupport cdbcSupport;
  
  if (0 == (rplOptions & rplAppResources))
  {
//    select8 = select id from dest.params 
//                        where param_type = parResourceApp and param2 in (select param1 from params where param_type in (parAppContent, parAppPath, parAppDigest) and options & dboUserCreated)
    CDBCSupport::PtrToIResultSet select8 = 
      cdbcSupport.executeQuery <tuple <int, int, int, int, int> > (
        destinationConn, 
        L"select id from params where param_type = ? and param2 in (select param1 from params where param_type in (?, ?, ?) and options & ?)", 
        tuple <int, int, int, int, int> (parResourceApp, parAppContent, parAppPath, parAppDigest, dboUserCreated)
      );
    fillUserIdList (select8, userIdList);
  }
  
//  Select9 = select * from src.pathes where params_id in (select id from params where param_type = parResourceApp)
  CDBCSupport::PtrToIResultSet select9 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from pathes where params_id in (select id from params where param_type = ?)", 
      tuple <int> (parResourceApp)
    );
  if (NULL != select9.get ())
  {
    do
    {
      PathRecordInfo srcParams;
      fillRecordInfo<PathRecordInfo> (srcParams, select9);
      
//      if exist(select @id = id, @params_id = params_id, @options = options from dest.pathes where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select9d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, params_id, options from pathes where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select9d.get ())
      { // exist
        deletePathes (select9d, destinationConn, srcParams, userIdList);
      }
      else
      { // not exist
        addPathes (select9d, sourceConn, destinationConn, srcParams, userIdList);
      }
    }
    while (true == select9->next());
  } // if (NULL != select9.get ())
} // replicatePathes

void replicateIdentities (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  IdList      userIdList;
  IdResolver  deletedList;
  CDBCSupport cdbcSupport;
  
  if (0 == (rplOptions & rplApp))
  {
//    select10 = select id from dest.params where param_type in (parAppContent, parAppPath, parAppDigest) and options & dboUserCreated 
    CDBCSupport::PtrToIResultSet select10 = 
      cdbcSupport.executeQuery <tuple <int, int, int, int> > (
        destinationConn, 
        L"select id from params where param_type in (?, ?, ?) and options & ?", 
        tuple <int, int, int, int> (
          parAppContent, 
          parAppPath, 
          parAppDigest, 
          dboUserCreated
        )
      );
    fillUserIdList (select10, userIdList);
  } // if (0 == (rplOptions & rplApp))
  
  replicateIdentPathes (sourceConn, destinationConn, userIdList);
  replicateIdentContents (sourceConn, destinationConn, userIdList);
  replicateIdentDigests (sourceConn, destinationConn, userIdList);
} // replicateIdentities

void replicateGlobalResources (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, int rplOptions)
{
  if (0 != (rplOptions & rplResource))
  {
    replicateGlobalOwners (sourceConn, destinationConn);
    replicateGlobalCertificates (sourceConn, destinationConn);
    replicateGlobalPathes (sourceConn, destinationConn);
  } // if (0 != (rplOptions & rplResource))
} // replicateGlobalResources

void replicateIdentPathes (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
//  Select11 = select * from src.pathes where param_type = parAppPath
  CDBCSupport::PtrToIResultSet select11 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from pathes where param_type = ?", 
      tuple <int> (parAppPath)
    );
  if (NULL != select11.get ())
  {
    do
    {
      PathRecordInfo srcParams;
      fillRecordInfo<PathRecordInfo> (srcParams, select11);
      
//      if exist(select @id = id, @params_id = params_id, @options = options from dest.pathes where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select11d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, params_id, options from pathes where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select11d.get ())
      { // exist
        deleteIdentPathes (select11d, destinationConn, srcParams, userIdList);
      }
      else
      { // not exist
        addIdentPathes (select11d, sourceConn, destinationConn, srcParams, userIdList);
      }  
    }
    while (true == select11->next());
  } // if (NULL != select11.get ())
} // replicateIdentPathes

void replicateIdentContents (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, IdList& userIdList)
{
  CDBCSupport cdbcSupport;

//  Select12 = select * from src.contents where param_type = parAppContent
  CDBCSupport::PtrToIResultSet select12 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from contents where param_type = ?", 
      tuple <int> (parAppContent)
    );
  if (NULL != select12.get ())
  {
    do
    {
      ContentRecordInfo srcParams;
      fillRecordInfo<ContentRecordInfo> (srcParams, select12);
      
//      if exist(select @id = id, @params_id = params_id, @options = options from dest.contents where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select12d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, params_id, options from contents where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select12d.get ())
      { // exist
        deleteIdentContents (select12d, destinationConn, srcParams, userIdList);
      }
      else
      { // not exist
        addIdentContents (select12d, sourceConn, destinationConn, srcParams, userIdList);
      }
    }
    while (true == select12->next());
  } // if (NULL != select12.get ())
} // replicateIdentContents

void replicateIdentDigests (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, IdList& userIdList)
{
  CDBCSupport cdbcSupport;

//  Select13 = select * from src.digests where param_type = parAppDigest
  CDBCSupport::PtrToIResultSet select13 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from digests where param_type = ?", 
      tuple <int> (parAppDigest)
    );
  if (NULL != select13.get ())
  {
    do
    {
      DigestRecordInfo srcParams;
      fillRecordInfo<DigestRecordInfo> (srcParams, select13);
      
//      if exist(select @id = id, @params_id = params_id, @options = options from dest.digests where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select13d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, params_id, options from digests where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select13d.get ())
      { // exist
        deleteIdentDigests (select13d, destinationConn, srcParams, userIdList);
      }
      else
      { // not exist
        addIdentDigests (select13d, sourceConn, destinationConn, srcParams, userIdList);
      }
    }
    while (true == select13->next());
  } // if (NULL != select13.get ())
} // replicateIdentDigests


void replicateGlobalOwners (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn)
{
  CDBCSupport cdbcSupport;
  
//  Select14 = select * from src.owners where param_type = parResource
  CDBCSupport::PtrToIResultSet select14 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from owners where param_type = ?", 
      tuple <int> (parResource)
    );
  if (NULL != select14.get ())
  {
    do
    {
      OwnerRecordInfo srcParams;
      fillRecordInfo<OwnerRecordInfo> (srcParams, select14);
      
//      if exist(select @id = id, @options = options from dest.owners where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select14d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, options from owners where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select14d.get ())
      { // exist
        int id        = 0;
        int options   = 0;

        cdbcSupport.queryResult <tuple <int&, int&> > (select14d, tuple <int&, int&> (id, options));
        select14d.reset ();
  
        if (srcParams.m_options & dboDeleted && !(options & dboDeleted))
        { // 
//          update dest.owners set options = options | dboDeleted where id = @id
          cdbcSupport.executeUpdate <tuple <int, int> > (
            destinationConn, 
            L"update owners set options = (? | options) where id = ?", 
            tuple <int, int> (dboDeleted, id)
          );
        }
      }
      else
      { // not exist
        // 
        // InsertOwner
        int recid = srcParams.m_info.Id;
        srcParams.m_info.Id = 0;
        
        // 
        srcParams.m_options &= ~dboUserCreated;
		srcParams.m_info.Options = srcParams.m_options;
		int Id;
        InsertOwner (srcParams.m_guid, destinationConn, srcParams.m_info, Id);
      }  
    }
    while (true == select14->next());
  } // if (NULL != select14.get ())
} // replicateGlobalOwners

void replicateGlobalCertificates (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn)
{
  CDBCSupport cdbcSupport;
  
//  Select15 = select * from src.certificates where param_type = parResource
  CDBCSupport::PtrToIResultSet select15 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from certificates where param_type = ?", 
      tuple <int> (parResource)
    );
  if (NULL != select15.get ())
  {
    do
    {
      CertRecordInfo srcParams;
      fillRecordInfo<CertRecordInfo> (srcParams, select15);
      
//      if exist(select @id = id, @options = options from dest.certificates where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select15d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, options from certificates where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select15d.get ())
      { // exist
        int id        = 0;
        int options   = 0;

        cdbcSupport.queryResult <tuple <int&, int&> > (select15d, tuple <int&, int&> (id, options));
        select15d.reset ();
  
        if (srcParams.m_options & dboDeleted && !(options & dboDeleted))
        { // 
//          update dest.certificates set options = options | dboDeleted where id = @id
          cdbcSupport.executeUpdate <tuple <int, int> > (
            destinationConn, 
            L"update certificates set options = (? | options) where id = ?", 
            tuple <int, int> (dboDeleted, id)
          );
        }
      }
      else
      { // not exist
        // 
        // InsertCertificate
        int recid = srcParams.m_info.Id;
        srcParams.m_info.Id = 0;
        
        // 
        srcParams.m_options &= ~dboUserCreated;
		srcParams.m_info.Options = srcParams.m_options;
		int Id;
        InsertCertificate (srcParams.m_guid, destinationConn, srcParams.m_info, Id);
      }  
    }
    while (true == select15->next());
  } // if (NULL != select15.get ())
} // replicateGlobalCertificates

void replicateGlobalPathes (IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn)
{
  CDBCSupport cdbcSupport;
  
//  Select16 = select * from src.pathes where param_type = parResource
  CDBCSupport::PtrToIResultSet select16 = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select * from pathes where param_type = ?", 
      tuple <int> (parResource)
    );
  if (NULL != select16.get ())
  {
    do
    {
      PathRecordInfo srcParams;
      fillRecordInfo<PathRecordInfo> (srcParams, select16);
      
//      if exist(select @id = id, @options = options from dest.pathes where guid = rec.guid)
      CDBCSupport::PtrToIResultSet select16d = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select id, options from pathes where guid = ?", 
          tuple <const blob&> (blob (&(srcParams.m_guid), sizeof (srcParams.m_guid)))
        );
      if (NULL != select16d.get ())
      { // exist
        int id        = 0;
        int options   = 0;

        cdbcSupport.queryResult <tuple <int&, int&> > (select16d, tuple <int&, int&> (id, options));
        select16d.reset ();
  
        if (srcParams.m_options & dboDeleted && !(options & dboDeleted))
        { // 
//          update dest.pathes set options = options | dboDeleted where id = @id
          cdbcSupport.executeUpdate <tuple <int, int> > (
            destinationConn, 
            L"update pathes set options = (? | options) where id = ?", 
            tuple <int, int> (dboDeleted, id)
          );
        }
      }
      else
      { // not exist
        // 
        // InsertPath 
//        if ( exist( select id from dest.pathes where path = rec.path and not (options & dboDeleted) ) ) continue;

        CDBCSupport::PtrToIResultSet existSelect = 
          cdbcSupport.executeQuery <tuple <const wstr&, int> > (
            destinationConn, 
            L"select id from pathes where path = ? and not (? & options)",
            tuple <const wstr&, int> (wstr (srcParams.m_info.Path, sizeof (srcParams.m_info.Path) / sizeof (srcParams.m_info.Path [0]) - 1), dboDeleted)
          );
        if (NULL != existSelect.get ())  
          continue;

        int recid = srcParams.m_info.Id;
        srcParams.m_info.Id = 0;
        
        // 
        srcParams.m_options &= ~dboUserCreated;
		srcParams.m_info.Options = srcParams.m_options;
        InsertPath (srcParams.m_guid, destinationConn, srcParams.m_info);
      }  
    }
    while (true == select16->next());
  } // if (NULL != select16.get ())
} // replicateGlobalPathes

//
// supplementary func area for replicate objects
//

void deleteGroups (CDBCSupport::PtrToIResultSet& select2d, 
IConnection::PtrToIConnection& conn, ParamsRecordInfo& srcParams, IdList& 
userAppIdList, IdResolver& deletedList)
{
  CDBCSupport cdbcSupport;
  
  int id       = 0;
  int param1   = 0;
  int options  = 0;
  int group_id = 0;

  cdbcSupport.queryResult <tuple <int&, int&, int&, int&> > (select2d, tuple <int&, int&, int&, int&> (id, param1, options, group_id));
  select2d.reset ();

  CDBCSupport::PtrToIResultSet checkGroup = 
    cdbcSupport.executeQuery <tuple <int, int, int> > (
      conn, 
      L"select id from params where group_id = ? and options & ? and not options & ?", 
      tuple <int, int, int> (param1, dboUserCreated, dboDeleted)
    );
  if (NULL != checkGroup.get ())
    return;
  checkGroup.reset ();

  if (srcParams.m_options & dboDeleted && 0 == find (userAppIdList, param1))
  {
    if (0 == (options & dboDeleted))
    {
      cdbcSupport.executeUpdate <tuple <int, int, int> > (
        conn, 
        L"update params set options = (options & ? | ? ) where id = ?", 
        tuple <int, int, int> (~dboUserCreated, dboDeleted, id)
      );
    }
    else
    {
      cdbcSupport.executeUpdate <tuple <int, int, int, int> > (
        conn, 
        L"update params set options = (options & ? | ? ) where param1 = ? and not (? & options)", 
        tuple <int, int, int, int> (~dboUserCreated, dboDeleted, param1, dboDeleted)
      );
    }

    // 
    // 
    deletedList [srcParams.m_info.Attributes.Param [GesRule::attSubjectId]] = param1;

    // 
    m_idList.erase (srcParams.m_info.Id);
  } // if (srcParams.m_options & dboDeleted && 0 == find (userAppIdList, param1))
} // deleteGroups



void addGroups (CDBCSupport::PtrToIResultSet& select2d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, ParamsRecordInfo& srcParams, IdList& userAppIdList, IdResolver& deletedList)
{
  CDBCSupport cdbcSupport;
  int         group_id = 0;
  int		  srcAppId = srcParams.m_info.Attributes.Param [GesRule::attSubjectId];

  if (0 != srcParams.m_info.GroupId)
  {
    IdResolver::iterator i = m_appIdList.find (srcParams.m_info.GroupId);
    if (i != m_appIdList.end ())
      group_id = (*i).second;

    if (0 == group_id)
    {
      // 
//      select @guid = guid from src.params where param1 = rec.group_id and param_type = parAppGroup order by id limit 1
      CDBCSupport::PtrToIResultSet selectGuid = 
        cdbcSupport.executeQuery <tuple <int, int> > (
          sourceConn, 
          L"select guid from params where param1 = ? and param_type = ? order by id limit 1", 
          tuple <int, int> (srcParams.m_info.GroupId, parAppGroup)
        );
      if (NULL != selectGuid.get ())
      {
        GUID srcGuid;
        cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
        selectGuid.reset ();
      
//        select @param1 = param1 from dest.params where guid = @guid
        CDBCSupport::PtrToIResultSet selectParam1 = 
          cdbcSupport.executeQuery <tuple <const blob&> > (
            destinationConn, 
            L"select param1 from params where guid = ?", 
            tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
          );
        if (NULL != selectParam1.get ())
        {
          int dstParam1 = 0;
          cdbcSupport.queryResult <tuple <int&> > (selectParam1, tuple <int&> (dstParam1));
          m_appIdList [srcParams.m_info.GroupId] = dstParam1;
		  srcParams.m_info.GroupId = dstParam1;
          
        } // if (NULL != selectParam1 .get ())
      } // if (NULL != selectGuid.get ())
    } // if (0 == group_id)
	else
	{ srcParams.m_info.GroupId = group_id; }
  } // if (0 != srcParams.group_id)

  int recid = srcParams.m_info.Id;
  int id    = 0;
  srcParams.m_info.Id = 0;

  // 
  // 
  // 

  int appId = 0;
  IdResolver::iterator i = deletedList.find (srcParams.m_info.Attributes.Param [GesRule::attSubjectId]);
  if (i != deletedList.end ())
    appId = (*i).second;

  if (0 != appId)
  {
    // 
    if (0 == find (userAppIdList, appId))
    {
      // 
      // 
      srcParams.m_options &= ~dboUserCreated;
      srcParams.m_info.Attributes.Param [GesRule::attSubjectId] = appId;
	  srcParams.m_info.Options = srcParams.m_options;
      id = Storage::InsertParams (srcParams.m_guid, destinationConn, srcParams.m_info);
    } // if (0 == find (userAppIdList, appId))
    else
    {
//      select @id = id from dest.params where param1 = @AppId and not (options & dboDeleted);
      cdbcSupport.queryResult <tuple <int&> > (
        cdbcSupport.executeQuery <tuple <int, int> > (
          destinationConn, 
          L"select id from params where param1 = ?  and not (? & options)", tuple <int, int> (appId, dboDeleted)
        ), 
        tuple <int&> (id)
      );
    }
    
    //! deleteFromMapByValue (deletedList, appId);

  } // if (0 != appId)
  else
  {
    // 
    CDBCSupport::PtrToIResultSet checkId = 
      cdbcSupport.executeQuery <tuple <int, const wstr&, int> > (
        destinationConn, 
        L"select id, param1 from params where group_id = ? and description = ? and (not options & ?)", 
        tuple <int, const wstr&, int> (
          srcParams.m_info.GroupId, 
          wstr (srcParams.m_info.Description, sizeof (srcParams.m_info.Description) / sizeof (srcParams.m_info.Description [0]) - 1), 
          dboDeleted
        )
      );

    if (NULL != checkId.get ())
    {
      cdbcSupport.queryResult <tuple <int&, int&> > (checkId, tuple <int&, int&> (id, appId));
    }
    else
    {  
      // 
      srcParams.m_options &= ~dboUserCreated;
	  srcParams.m_info.Options = srcParams.m_options;
      appId = InsertApplicationGroupNoCheck (srcParams.m_guid, destinationConn, srcParams.m_info, true);
      id    = appId;
	  // 
	  // if(srcParams.m_options & dboDeleted)
	  //  deletedList [srcParams.m_info.Attributes.Param [GesRule::attSubjectId]] = appId;
    
    }
  } // else if (0 != appId)

 // 
  if(srcParams.m_options & dboDeleted)   deletedList [srcAppId] = appId;
  
  m_appIdList [srcAppId] = appId;
  if (0 != id)
    m_idList [recid] = id; 
} // addGroups

void deleteApplications (CDBCSupport::PtrToIResultSet& select4d, IConnection::PtrToIConnection& conn, ParamsRecordInfo& srcParams, IdList& userAppIdList, IdResolver& deletedList)
{
  CDBCSupport cdbcSupport;
  
  int id      = 0;
  int param1  = 0;
  int options = 0;

  cdbcSupport.queryResult <tuple <int&, int&, int&> > (select4d, tuple <int&, int&, int&> (id, param1, options));
  select4d.reset ();
  if (srcParams.m_options & dboDeleted && 0 == find (userAppIdList, param1))
  {
    if (0 == (options & dboDeleted))
    {
      cdbcSupport.executeUpdate <tuple <int, int, int> > (
        conn, 
        L"update params set options = (options & ? | ? ) where id = ?", 
        tuple <int, int, int> (~dboUserCreated, dboDeleted, id)
      );
    }
    else
    {
      // 
      // 
      // 
      
//      update dest.contents set options = options | dboDeleted 
//             where params_id in (select id from dest.params where param1 = @param1 and not (options & dboDeleted))
      cdbcSupport.executeUpdate <tuple <int, int, int, int> > (
        conn, 
        L"update contents set options = (options & ? | ? ) where params_id in (select id from params where param1 = ? and not (? & options))", 
        tuple <int, int, int, int> (~dboUserCreated, dboDeleted, param1, dboDeleted)
      );
    
//      update dest.pathes set options = options | dboDeleted
//           where params_id in (select id from dest.params where param1 = @param1 and not (options & dboDeleted))
      cdbcSupport.executeUpdate <tuple <int, int, int, int> > (
        conn, 
        L"update pathes set options = (options & ? | ? ) where params_id in (select id from params where param1 = ? and not (? & options))", 
        tuple <int, int, int, int> (~dboUserCreated, dboDeleted, param1, dboDeleted)
      );
      
//      update dest.digests set options = options | dboDeleted
//             where params_id in (select id from dest.params where param1 = @param1 and not (options & dboDeleted))
      cdbcSupport.executeUpdate <tuple <int, int, int, int> > (
        conn, 
        L"update digests set options = (options & ? | ? ) where params_id in (select id from params where param1 = ? and not (? & options))", 
        tuple <int, int, int, int> (~dboUserCreated, dboDeleted, param1, dboDeleted)
      );
      
//      update dest.params set options = options | dboDeleted
//           where param1 = @param1 and not (options & dboDeleted)
      cdbcSupport.executeUpdate <tuple <int, int, int, int> > (
        conn, 
        L"update params set options = (options & ? | ? ) where param1 = ? and not (? & options)", 
        tuple <int, int, int, int> (~dboUserCreated, dboDeleted, param1, dboDeleted)
      );
    }
    
    // 
    // 
    deletedList [srcParams.m_info.Attributes.Param [GesRule::attSubjectId]] = param1;
    
    // 
    m_idList.erase (srcParams.m_info.Id);
  } // if (srcParams.m_options & dboDeleted && 0 == find (userAppIdList, param1))
} // deleteApplications

void addApplications (CDBCSupport::PtrToIResultSet& select4d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, ParamsRecordInfo& srcParams, IdList& userAppIdList, IdResolver& deletedList)
{
  CDBCSupport cdbcSupport;
  int         group_id = 0;
  int		  srcAppId = srcParams.m_info.Attributes.Param[GesRule::attSubjectId];

  if (0 != srcParams.m_info.GroupId)
  {
    IdResolver::iterator i = m_appIdList.find (srcParams.m_info.GroupId);
    if (i != m_appIdList.end ())
      group_id = (*i).second;

    if (0 == group_id)
    {
      // 
      //select @guid = guid from src.params where param1 = rec.group_id and param_type = parApp order by id limit 1
      CDBCSupport::PtrToIResultSet selectGuid = 
        cdbcSupport.executeQuery <tuple <int, int> > (
          sourceConn, 
          L"select guid from params where param1 = ? and param_type = ? order by id limit 1", 
          tuple <int, int> (srcParams.m_info.GroupId, parAppGroup)
        );
      if (NULL != selectGuid.get ())
      {
        GUID srcGuid;
        cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
        selectGuid.reset ();
      
        //select @param1 = param1 from dest.params where guid = @guid rec.group_id = @param1
        CDBCSupport::PtrToIResultSet selectParam1 = 
          cdbcSupport.executeQuery <tuple <const blob&> > (
            destinationConn, 
            L"select param1 from params where guid = ?", 
            tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
          );
        if (NULL != selectParam1 .get ())
        {
          int dstParam1 = 0;
          cdbcSupport.queryResult <tuple <int&> > (selectParam1, tuple <int&> (dstParam1));
          m_appIdList [srcParams.m_info.GroupId] = dstParam1;
		  srcParams.m_info.GroupId = dstParam1;
          //m_appIdList [srcParams.m_info.Attributes.Param [GesRule::attSubjectId]] = dstParam1;
        } // if (NULL != selectParam1 .get ())
      } // if (NULL != selectGuid.get ())
    } // if (0 == group_id)
	else { srcParams.m_info.GroupId = group_id; }
  } // if (0 != srcParams.m_info.GroupId)

  int recid = srcParams.m_info.Id;
  int id    = 0;
  srcParams.m_info.Id = 0;
  
  // 
  // 
  // 

  int appId = 0;
  IdResolver::iterator i = deletedList.find (srcParams.m_info.Attributes.Param [GesRule::attSubjectId]);
  if (i != deletedList.end ())
    appId = (*i).second;

  if (0 != appId)
  {
    // 
    if (0 == find (userAppIdList, appId))
    {
      // 
      srcParams.m_info.Attributes.Param [GesRule::attSubjectId] = appId;
	  srcParams.m_options &= ~dboUserCreated;
	  srcParams.m_info.Options = srcParams.m_options;
      id = Storage::InsertParams (srcParams.m_guid, destinationConn, srcParams.m_info);
    } // if (0 == find (userAppIdList, appId))
    else
    {
//      select @id = id from dest.params where param1 = @AppId and not (options & dboDeleted);
      cdbcSupport.queryResult <tuple <int&> > (
        cdbcSupport.executeQuery <tuple <int, int> > (
          destinationConn, 
          L"select id from params where param1 = ?  and not (? & options)", tuple <int, int> (appId, dboDeleted)
        ), 
        tuple <int&> (id)
      );
    }
    
    deleteFromMapByValue (deletedList, appId);
  } // if (0 != appId)
  else
  {
    // 
    // 1. 
    // 2. 

//    select  @internal_name = internal_name, @company_name = company_name, @sha1 = sha1 from src.appinfo 
//            where app_id = rec.param1 and not (options & dboDeleted)
    wstring internal_name;
    wstring company_name;
    byte    sha1 [sha256Size];
    
    memset (sha1, 0, sizeof (sha1));
    CDBCSupport::PtrToIResultSet selectIdent = 
      cdbcSupport.executeQuery <tuple <int, int> > (
        sourceConn, 
        L"select internal_name, company_name, sha1 from appinfo where app_id = ? and not (? & options)", 
        tuple <int, int> (srcParams.m_info.Attributes.Param [GesRule::attSubjectId], dboDeleted)
      );
    if (NULL != selectIdent.get ())
    {
      cdbcSupport.queryResult <tuple <wstring&, wstring&, blob&> > (
        selectIdent, 
        tuple <wstring&, wstring&, blob&> (internal_name, company_name, blob (&sha1, sizeof (sha1)))
      );
      selectIdent.reset ();
    }  
	else 
	{  // 
		return;
	}
    
//    if ( not exist ( select @AppId = app_id from dest.appinfo 
//                            where not (options & dboDeleted) and ( ( internal_name = @internal_name and company_name = @company_name ) or sha1 = sha1 ) ) )
    CDBCSupport::PtrToIResultSet selectAppId = 
      cdbcSupport.executeQuery <tuple <int, const wstring&, const wstring&, const blob&> > (
        destinationConn, 
        L"select app_id from appinfo where not (? & options) and ( ( internal_name = ? and company_name = ? ) or sha1 = ? )", 
        tuple <int, const wstring&, const wstring&, const blob&> (dboDeleted, internal_name, company_name, blob (&sha1, sizeof (sha1)))
      );
    if (NULL == selectAppId.get ())
    { // not exist
      appId = 0;
    }
    else
    {
      cdbcSupport.queryResult <tuple <int&> > (selectAppId, tuple <int&> (appId));
      selectAppId.reset ();
      if (parAppPath == srcParams.m_info.Type)
      {
        wstring path;
        
//        select @path = path from src.pathes where params_id = @recid
        CDBCSupport::PtrToIResultSet selectPath = 
          cdbcSupport.executeQuery <tuple <int> > (
            sourceConn, 
            L"select path from pathes where params_id = ?", 
            tuple <int> (recid)
          );
        if (NULL != selectPath.get ())
        {
          cdbcSupport.queryResult <tuple <wstring&> > (selectPath, tuple <wstring&> (path));
          selectPath.reset ();
        }  
          
//        if ( not exist( select @AppId = param1 from dest.params 
//                               where id in ( select params_id from dest.pathes where path = @path and not ( options & dboDeleted) ) ) )
        selectAppId = 
          cdbcSupport.executeQuery <tuple <wstring&, int> > (
            destinationConn, 
            L"select param1 from params where id in ( select params_id from pathes where path = ? and not (? & options) )", 
            tuple <wstring&, int> (path, dboDeleted)
          );
        if (NULL == selectAppId.get ())
        {
          appId = 0;
        }
        else
        {
          cdbcSupport.queryResult <tuple <int&> > (selectAppId, tuple <int&> (appId));
          selectAppId.reset ();
        }
      }
    } // else if (NULL == selectAppId.get ())
    
    if (0 != appId)
    {
      // 3. 
      // 4. 
      // 
      // 
      
//      select @id = id from dest.params where param1 = @AppId and not ( options & dboDeleted )
      CDBCSupport::PtrToIResultSet selectId = 
        cdbcSupport.executeQuery <tuple <int, int> > (
          destinationConn, 
          L"select id from params where param1 = ? and not (? & options)", 
          tuple <int, int> (appId, dboDeleted)
        );
      if (NULL != selectId.get ())
      {
        cdbcSupport.queryResult <tuple <int&> > (selectId, tuple <int&> (id));
        selectId.reset ();
      }  
      
      if (0 == find (userAppIdList, appId))  
      {
//        update dest.pathes set options = options | dboDeleted where params_id = @id
        cdbcSupport.executeUpdate <tuple <int, int> > (
          destinationConn, 
          L"update pathes set options = (? | options) where params_id = ?", 
          tuple <int, int> (dboDeleted, id)
        );
        
//        update dest.contents set options = options | dboDeleted where params_id = @id
        cdbcSupport.executeUpdate <tuple <int, int> > (
          destinationConn, 
          L"update contents set options = (? | options) where params_id = ?", 
          tuple <int, int> (dboDeleted, id)
        );
        
//        update dest.digests set options = options | dboDeleted where params_id = @id
        cdbcSupport.executeUpdate <tuple <int, int> > (
          destinationConn, 
          L"update digests set options = (? | options) where params_id = ?", 
          tuple <int, int> (dboDeleted, id)
        );
        
//        update dest.params set options = options | dboDeleted where id = @id
        cdbcSupport.executeUpdate <tuple <int, int> > (
          destinationConn, 
          L"update params set options = (? | options) where id = ?", 
          tuple <int, int> (dboDeleted, id)
        );
        
        srcParams.m_options &= ~dboUserCreated;
        srcParams.m_info.Attributes.Param [GesRule::attSubjectId] = appId;
		srcParams.m_info.Options = srcParams.m_options;
        id = Storage::InsertParams (srcParams.m_guid, destinationConn, srcParams.m_info);
      } // if (0 == find (userAppIdList, appId))
    }
    else
    {
      // 
      srcParams.m_options &= ~dboUserCreated;
	  srcParams.m_info.Options = srcParams.m_options;
      id = Storage::InsertParams (srcParams.m_guid, destinationConn, srcParams.m_info);
      if (0 != id)
      {
//        update dest.params set param1 = @id where id = @id
        cdbcSupport.executeUpdate <tuple <int, int> > (
          destinationConn, 
          L"update params set param1 = ? where id = ?", 
          tuple <int, int> (id, id)
        );
      }
      appId = id;
	  // 
	  //if(srcParams.m_options & dboDeleted)
	  // deletedList [srcAppId] = appId;
    }
  } // else if (0 != appId)
  
  m_appIdList [srcAppId] = appId;
  // 
  if(srcParams.m_options & dboDeleted)
   deletedList [srcAppId] = appId;

  if (0 != id)
    m_idList [recid] = id; 
} // addApplications

void deletePathes (CDBCSupport::PtrToIResultSet& select9d, IConnection::PtrToIConnection& conn, PathRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  int id        = 0;
  int params_id = 0;
  int options   = 0;

  cdbcSupport.queryResult <tuple <int&, int&, int&> > (select9d, tuple <int&, int&, int&> (id, params_id, options));
  select9d.reset ();
  if (srcParams.m_options & dboDeleted && !(options & dboDeleted) && 0 == find (userIdList, params_id))
  { // 
//    update dest.pathes set options = options | dboDeleted where id = @id
    cdbcSupport.executeUpdate <tuple <int, int> > (
      conn, 
      L"update pathes set options = (? | options) where id = ?", 
      tuple <int, int> (dboDeleted, id)
    );
  }
} // deletePathes

void addPathes (CDBCSupport::PtrToIResultSet& select9d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, PathRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  // 
  int srcAppId = 0;
//  select @SrcAppId = param2 from src.params where id = rec.params_id ;
  CDBCSupport::PtrToIResultSet selectSrcAppId = 
    cdbcSupport.executeQuery <tuple <int> > (
      sourceConn, 
      L"select param2 from params where id = ?", 
      tuple <int> (srcParams.m_info.ParentId)
    );
  cdbcSupport.queryResult <tuple <int&> > (selectSrcAppId, tuple <int&> (srcAppId));
  selectSrcAppId.reset ();
  
//  @DestAppId = AppIdList.Search[DestAppId]By[SrcAppId](@SrcAppId);
  int dstAppId = 0;
  IdResolver::iterator i = m_appIdList.find (srcAppId);
  if (i != m_appIdList.end ())
    dstAppId = (*i).second;
  
  if (0 == dstAppId)
  {
    // 

//    select @guid = guid from src.params where param1 = @SrcAppId and not (options & dboDeleted)
    CDBCSupport::PtrToIResultSet selectGuid = 
      cdbcSupport.executeQuery <tuple <int, int> > (
        sourceConn, 
        L"select guid from params where param1 = ? and not (? & options)", 
        tuple <int, int> (srcAppId, dboDeleted)
      );
    if (NULL != selectGuid.get ())
    {
      GUID srcGuid;
      cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
      selectGuid.reset ();
    
//      select @DestAppId = param1 from dest.params where guid = @guid
      CDBCSupport::PtrToIResultSet selectDestAppId = 
        cdbcSupport.executeQuery <tuple <const blob&> > (
          destinationConn, 
          L"select param1 from params where guid = ?", 
          tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
        );
      cdbcSupport.queryResult <tuple <int&> > (selectDestAppId, tuple <int&> (dstAppId));
    } // if (NULL != selectGuid.get ())

    if (0 == dstAppId) // 
      return;
  }
  
//  if ( exist( select id from dest.pathes where path = rec.path and res_type = rec.res_type 
//                                               and not (options & dboDeleted) 
//                                               and  params_id in (select id from dest.params where param2 = @DestAppId and param_type = parResourceApp) ) ) 
//    continue;
  if (NULL != ( cdbcSupport.executeQuery <tuple <const wstr&, int, int, int, int> > (
                  destinationConn, 
                  L"select id from pathes where path = ? and res_type = ? and not (? & options) and params_id in (select id from params where param2 = ? and param_type = ?)", 
                  tuple <const wstr&, int, int, int, int> (
                    wstr (srcParams.m_info.Path, sizeof (srcParams.m_info.Path) / sizeof (srcParams.m_info.Path [0]) - 1), 
                    srcParams.m_info.Type, 
                    dboDeleted, 
                    dstAppId, 
                    parResourceApp
                  )
                )
              ).get ()) 
    return;
    
  int recid = srcParams.m_info.Id;
  srcParams.m_info.Id = 0;
  
  // 
  int params_id = 0;
 // i = m_idList.find (srcAppId);
  i = m_idList.find (srcParams.m_info.ParentId);
  if (i != m_idList.end ())
   params_id = (*i).second;
    
  if (0 == params_id)
  {
    // 
//    select @guid = guid from src.params where id = rec.params_id
    CDBCSupport::PtrToIResultSet selectGuid = 
      cdbcSupport.executeQuery <tuple <int> > (
        sourceConn, 
        L"select guid from params where id = ?", 
        tuple <int> (srcParams.m_info.ParentId)
      );
    if (NULL == selectGuid.get ())
      return;
    
    GUID srcGuid;  
    cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
    selectGuid.reset ();
    
    cdbcSupport.queryResult <tuple <int&> > (
      cdbcSupport.executeQuery <tuple <const blob&> > (
        destinationConn, 
        L"select id from params where guid = ?", tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
      ), 
      tuple <int&> (params_id)
    );
    
    if (0 == params_id)
      return;
  } // if (0 == params_id)
  
  // 
  if (0 == find (userIdList, params_id))
  {
    srcParams.m_info.ParentId = params_id;
    srcParams.m_options &= ~dboUserCreated;
	srcParams.m_info.Options = srcParams.m_options;
    InsertPath (srcParams.m_guid, destinationConn, srcParams.m_info);
  } 
} // addPathes

void deleteIdentPathes (CDBCSupport::PtrToIResultSet& select11d, IConnection::PtrToIConnection& conn, PathRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  int id        = 0;
  int params_id = 0;
  int options   = 0;

  cdbcSupport.queryResult <tuple <int&, int&, int&> > (select11d, tuple <int&, int&, int&> (id, params_id, options));
  select11d.reset ();
  if (srcParams.m_options & dboDeleted && 0 == find (userIdList, params_id))
  { // 
    if (!(options & dboDeleted))
    {
//      update dest.pathes set options = options | dboDeleted where id = @id
      cdbcSupport.executeUpdate <tuple <int, int> > (
        conn, 
        L"update pathes set options = (? | options) where id = ?", 
        tuple <int, int> (dboDeleted, id)
      );
    }
    else
    {
      // 
//      update dest.pathes set options = options | dboDeleted where params_id = @params_id
      cdbcSupport.executeUpdate <tuple <int, int> > (
        conn, 
        L"update pathes set options = (? | options) where params_id = ?", 
        tuple <int, int> (dboDeleted, params_id)
      );
    }
  } // if (srcParams.m_options & dboDeleted && 0 == find (userIdList, params_id))
} // deleteIdentPathes

void addIdentPathes (CDBCSupport::PtrToIResultSet& select11d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, PathRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  // 
  // 
  // 
  // 
  int recid = srcParams.m_info.Id;
  srcParams.m_info.Id = 0;
  
  // 
  int params_id = 0;
  IdResolver::iterator i = m_idList.find (srcParams.m_info.ParentId);
  if (i != m_idList.end ())
    params_id = (*i).second;

  if (0 == params_id)
  {
    // 
//    select @guid = guid from src.params where id = rec.params_id
    CDBCSupport::PtrToIResultSet selectGuid = 
      cdbcSupport.executeQuery <tuple <int> > (
        sourceConn, 
        L"select guid from params where id = ?", 
        tuple <int> (srcParams.m_info.ParentId)
      );
    if (NULL == selectGuid.get ())
      return;
    
    GUID srcGuid;  
    cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
    selectGuid.reset ();
    
    cdbcSupport.queryResult <tuple <int&> > (
      cdbcSupport.executeQuery <tuple <const blob&> > (
        destinationConn, 
        L"select id from params where guid = ?", 
        tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
      ), 
      tuple <int&> (params_id)
    );
    
    if (0 == params_id)
      return;
  } // if (0 == params_id)
  
  // 
  if (0 == find (userIdList, params_id))
  {
    srcParams.m_info.ParentId = params_id;
    srcParams.m_options &= ~dboUserCreated;
	srcParams.m_info.Options = srcParams.m_options;
    InsertPath (srcParams.m_guid, destinationConn, srcParams.m_info);
  }
} // addIdentPathes

void deleteIdentContents (CDBCSupport::PtrToIResultSet& select12d, IConnection::PtrToIConnection& conn, ContentRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  int id        = 0;
  int params_id = 0;
  int options   = 0;

  cdbcSupport.queryResult <tuple <int&, int&, int&> > (select12d, tuple <int&, int&, int&> (id, params_id, options));
  select12d.reset ();
  if (srcParams.m_options & dboDeleted && 0 == find (userIdList, params_id))
  { // 
    if (!(options & dboDeleted))
    {
//      update dest.contents set options = options | dboDeleted where id = @id
      cdbcSupport.executeUpdate <tuple <int, int> > (
        conn, 
        L"update contents set options = (? | options) where id = ?", 
        tuple <int, int> (dboDeleted, id)
      );
    }
    else
    {
      // 
//      update dest.contents set options = options | dboDeleted where params_id = @params_id
      cdbcSupport.executeUpdate <tuple <int, int> > (
        conn, 
        L"update contents set options = (? | options) where params_id = ?", 
        tuple <int, int> (dboDeleted, params_id)
      );
    }
  } // if (srcParams.m_options & dboDeleted && 0 == find (userIdList, params_id))
} // deleteIdentContents

void addIdentContents (CDBCSupport::PtrToIResultSet& select12d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, ContentRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  // 
  // 
  // 
  // 
  int recid = srcParams.m_info.Id;
  srcParams.m_info.Id = 0;
  
  // 
  int params_id = 0;
  IdResolver::iterator i = m_idList.find (srcParams.m_info.ParentId);
  if (i != m_idList.end ())
    params_id = (*i).second;

  if (0 == params_id)
  {
    // 
//    select @guid = guid from src.params where id = rec.params_id
    CDBCSupport::PtrToIResultSet selectGuid = 
      cdbcSupport.executeQuery <tuple <int> > (
        sourceConn, 
        L"select guid from params where id = ?", 
        tuple <int> (srcParams.m_info.ParentId)
      );
    if (NULL == selectGuid.get ())
      return;
    
    GUID srcGuid;  
    cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
    selectGuid.reset ();
    
    cdbcSupport.queryResult <tuple <int&> > (
      cdbcSupport.executeQuery <tuple <const blob&> > (
        destinationConn, 
        L"select id from params where guid = ?", 
        tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
      ), 
      tuple <int&> (params_id)
    );
    
    if (0 == params_id)
      return;
  } // if (0 == params_id)
  
  // 
  if (0 == find (userIdList, params_id))
  {
    srcParams.m_info.ParentId = params_id;
    srcParams.m_options &= ~dboUserCreated;
	srcParams.m_info.Options = srcParams.m_options;
    InsertContent (srcParams.m_guid, destinationConn, srcParams.m_info);
  }
} // addIdentContents

void deleteIdentDigests (CDBCSupport::PtrToIResultSet& select13d, IConnection::PtrToIConnection& conn, DigestRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  int id        = 0;
  int params_id = 0;
  int options   = 0;

  cdbcSupport.queryResult <tuple <int&, int&, int&> > (select13d, tuple <int&, int&, int&> (id, params_id, options));
  select13d.reset ();
  if (srcParams.m_options & dboDeleted && 0 == find (userIdList, params_id))
  { // 
    if (!(options & dboDeleted))
    {
//      update dest.digests set options = options | dboDeleted where id = @id
      cdbcSupport.executeUpdate <tuple <int, int> > (
        conn, 
        L"update digests set options = (? | options) where id = ?", 
        tuple <int, int> (dboDeleted, id)
      );
    }
    else
    {
      // 
//      update dest.digests set options = options | dboDeleted where params_id = @params_id
      cdbcSupport.executeUpdate <tuple <int, int> > (
        conn, 
        L"update digests set options = (? | options) where params_id = ?", 
        tuple <int, int> (dboDeleted, params_id)
      );
    }
  } // if (srcParams.m_options & dboDeleted && 0 == find (userIdList, params_id))
} // deleteIdentDigests

void addIdentDigests (CDBCSupport::PtrToIResultSet& select13d, IConnection::PtrToIConnection& sourceConn, IConnection::PtrToIConnection& destinationConn, DigestRecordInfo& srcParams, IdList& userIdList)
{
  CDBCSupport cdbcSupport;
  
  // 
  // 
  // 
  // 
  int recid = srcParams.m_info.Id;
  srcParams.m_info.Id = 0;
  
  // 
  int params_id = 0;
  IdResolver::iterator i = m_idList.find (srcParams.m_info.ParentId);
  if (i != m_idList.end ())
    params_id = (*i).second;

  if (0 == params_id)
  {
    // 
//    select @guid = guid from src.params where id = rec.params_id
    CDBCSupport::PtrToIResultSet selectGuid = 
      cdbcSupport.executeQuery <tuple <int> > (
        sourceConn, 
        L"select guid from params where id = ?", 
        tuple <int> (srcParams.m_info.ParentId)
      );
    if (NULL == selectGuid.get ())
      return;
    
    GUID srcGuid;  
    cdbcSupport.queryResult <tuple <blob&> > (selectGuid, tuple <blob&> (blob (&srcGuid, sizeof (srcGuid))));
    selectGuid.reset ();
    
    cdbcSupport.queryResult <tuple <int&> > (
      cdbcSupport.executeQuery <tuple <const blob&> > (
        destinationConn, 
        L"select id from params where guid = ?", 
        tuple <const blob&> (blob (&srcGuid, sizeof (srcGuid)))
      ), 
      tuple <int&> (params_id)
    );
    
    if (0 == params_id)
      return;
  } // if (0 == params_id)
  
  // 
  if (0 == find (userIdList, params_id))
  {
    srcParams.m_info.ParentId = params_id;
    srcParams.m_options &= ~dboUserCreated;
	srcParams.m_info.Options = srcParams.m_options;
    InsertDigest (srcParams.m_guid, destinationConn, srcParams.m_info);
  }
} // addIdentDigests

//
// private utils func area
//
void deleteFromMapByValue (IdResolver& data, int value)
{
  for (IdResolver::iterator i = data.begin (); i != data.end (); ++i)
  {
    if ((*i).second == value)
    {
      data.erase (i);
      if (0 >= data.size ())
        break;
      i = data.begin ();
      continue;
    } // if ((*i).second == value)
  } // for ()
} // deleteFromMapByValue

void fillUserIdList (CDBCSupport::PtrToIResultSet select, IdList& userIdList)
{
  if (NULL != select.get ())
  {
    do
    {
      int param1 = 0;
      CDBCSupport ().queryResult <tuple <int&> > (select, tuple <int&> (param1));
      userIdList.push_back (param1);
    }
    while (true == select->next());
  } // if (NULL != select.get ())
} // fillUserIdList

int find (IdList& list, int id)
{
  int result = 0;

  for (IdList::const_iterator i = list.begin (); i != list.end (); ++i)
  {
    if ((*i) == id)
    {
      result = id;
      break;
    }  
  } // for (IdList::const_iterator i = list.begin (); i != list.end (); ++i)

  return result;
} // find

template <typename Record>
void fillRecordInfo (Record& info, CDBCSupport::PtrToIResultSet& resultSet)
{
  BOOST_STATIC_ASSERT (false);
} // FillRecordInfo

template <>
void fillRecordInfo<ParamsRecordInfo> (ParamsRecordInfo& info, CDBCSupport::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.GroupId  = resultSet->getInt (resultSet->getColumnIndex (wstring (L"group_id")));
    
  info.m_info.Model    = resultSet->getInt (resultSet->getColumnIndex (wstring (L"model")));
  info.m_info.Type     = static_cast <ParamsType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"param_type"))));
  
  wstring description  = resultSet->getText (resultSet->getColumnIndex (wstring (L"description")));
  wcsncpy (info.m_info.Description, description.c_str (), sizeof (info.m_info.Description) / sizeof (wchar_t));
  
  info.m_info.Attributes.Param [0] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param1")));
  info.m_info.Attributes.Param [1] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param2")));
  info.m_info.Attributes.Param [2] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param3")));
  info.m_info.Attributes.Param [3] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param4")));
  info.m_info.Attributes.Param [4] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param5")));
  info.m_info.Attributes.Param [5] = resultSet->getInt (resultSet->getColumnIndex (wstring (L"param6")));
} // fillParamsRecordInfo

template <>
void fillRecordInfo<ApplicationRecordInfo> (ApplicationRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.AppId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"app_id")));
  
  CDBCSupport            cdbcsupport;
  ApplicationInfo&       appInfo = info.m_info;
  
  cdbcsupport.get <wstr&> (wstr (appInfo.FileName,         sizeof (appInfo.FileName) / sizeof (wchar_t) - 1),         resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"file_name"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.ProductName,      sizeof (appInfo.ProductName) / sizeof (wchar_t) - 1),      resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"product_name"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.FileDescription,  sizeof (appInfo.FileDescription) / sizeof (wchar_t) - 1),  resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"file_description"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.CompanyName,      sizeof (appInfo.CompanyName) / sizeof (wchar_t) - 1),      resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"company_name"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.InternalName,     sizeof (appInfo.InternalName) / sizeof (wchar_t) - 1),     resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"internal_name"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.OriginalFilename, sizeof (appInfo.OriginalFilename) / sizeof (wchar_t) - 1), resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"original_file_name"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.ProductVersion,   sizeof (appInfo.ProductVersion) / sizeof (wchar_t) - 1),   resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"product_version"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.FileVersion,      sizeof (appInfo.FileVersion) / sizeof (wchar_t) - 1),      resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"file_version"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.LegalCopyright,   sizeof (appInfo.LegalCopyright) / sizeof (wchar_t) - 1),   resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"legal_copyright"))));
  cdbcsupport.get <wstr&> (wstr (appInfo.Comments,         sizeof (appInfo.Comments) / sizeof (wchar_t) - 1),         resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"comments")))); 
  cdbcsupport.get <wstr&> (wstr (appInfo.ProductURL,       sizeof (appInfo.ProductURL) / sizeof (wchar_t) - 1),       resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"product_url"))));
  cdbcsupport.get <unsigned int&> (appInfo.Lang, resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"lang"))));
  cdbcsupport.get <blob&> (blob (appInfo.Icon,             sizeof (appInfo.Icon), reinterpret_cast <size_t&> (appInfo.IconSize)), resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"icon"))));
  cdbcsupport.get <blob&> (blob (appInfo.MD5,              sizeof (appInfo.MD5)),                                     resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"md5"))));
  cdbcsupport.get <blob&> (blob (appInfo.SHA1,             sizeof (appInfo.SHA1)),                                    resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"sha1"))));
  cdbcsupport.get <blob&> (blob (appInfo.SHA256,           sizeof (appInfo.SHA256)),                                  resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"sha256"))));
  cdbcsupport.get <blob&> (blob (appInfo.CertThumbprint,   sizeof (appInfo.CertThumbprint)),                          resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"cert_thumbprint"))));
  cdbcsupport.get <unsigned int&> (appInfo.AppOptions, resultSet, UserIndex (resultSet->getColumnIndex (wstring (L"app_options"))));  
} // fillApplicationRecordInfo

template <>
void fillRecordInfo<PathRecordInfo> (PathRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type     = static_cast <NtObjectType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"res_type"))));
  info.m_info.param_type = static_cast <ParamsType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"param_type"))));
  
  wstring path         = resultSet->getText (resultSet->getColumnIndex (wstring (L"path")));
  wcsncpy (info.m_info.Path, path.c_str (), sizeof (info.m_info.Path) / sizeof (wchar_t));
} // fillPathRecordInfo

template <>
void fillRecordInfo<ContentRecordInfo> (ContentRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type     = static_cast <ContentType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"cont_type"))));
  info.m_info.param_type = static_cast <ParamsType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"param_type"))));
  
  wstring content      = resultSet->getText (resultSet->getColumnIndex (wstring (L"content")));
  wcsncpy (info.m_info.Content, content.c_str (), sizeof (info.m_info.Content) / sizeof (wchar_t));
  
  wstring file_name    = resultSet->getText (resultSet->getColumnIndex (wstring (L"file_name")));
  wcsncpy (info.m_info.FileName, file_name.c_str (), sizeof (info.m_info.FileName) / sizeof (wchar_t));
} // fillContentRecordInfo

template <>
void fillRecordInfo<DigestRecordInfo> (DigestRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type     = static_cast <DigestType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"digest_type"))));
  info.m_info.param_type = static_cast <ParamsType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"param_type"))));
  info.m_info.DigestSize = resultSet->getBlob (resultSet->getColumnIndex (wstring (L"digest")), info.m_info.Digest, sizeof (info.m_info.Digest));
  
  wstring file_name    = resultSet->getText (resultSet->getColumnIndex (wstring (L"file_name")));
  wcsncpy (info.m_info.FileName, file_name.c_str (), sizeof (info.m_info.FileName) / sizeof (wchar_t));
} // fillDigestRecordInfo

template <>
void fillRecordInfo<OwnerRecordInfo> (OwnerRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  info.m_info.Type     = static_cast <NtObjectType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"res_type"))));
  info.m_info.param_type = static_cast <ParamsType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"param_type"))));
  
  wstring owner        = resultSet->getText (resultSet->getColumnIndex (wstring (L"sid")));
  wcsncpy (info.m_info.Owner, owner.c_str (), sizeof (info.m_info.Owner) / sizeof (wchar_t));
} // fillOwnerRecordInfo

template <>
void fillRecordInfo<CertRecordInfo> (CertRecordInfo& info, IPreparedStatement::PtrToIResultSet& resultSet)
{
  info.m_options       = static_cast <int> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"options"))));
  resultSet->getBlob (resultSet->getColumnIndex (wstring (L"guid")), reinterpret_cast <unsigned char*> (&(info.m_guid)), sizeof (info.m_guid));

  info.m_info.Id       = resultSet->getInt (resultSet->getColumnIndex (wstring (L"id")));
  info.m_info.ParentId = resultSet->getInt (resultSet->getColumnIndex (wstring (L"params_id")));
  
  info.m_info.Type     = static_cast <CertType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"cert_type"))));
  info.m_info.param_type = static_cast <ParamsType> (resultSet->getInt (resultSet->getColumnIndex (wstring (L"param_type"))));
  info.m_info.ThumbprintSize = resultSet->getBlob (resultSet->getColumnIndex (wstring (L"thumbprint")), info.m_info.Thumbprint, sizeof (info.m_info.Thumbprint));
  
  wstring issuedTo     = resultSet->getText (resultSet->getColumnIndex (wstring (L"issuedto")));
  wcsncpy (info.m_info.IssuedTo, issuedTo.c_str (), sizeof (info.m_info.IssuedTo) / sizeof (wchar_t));
  
  wstring issuedBy     = resultSet->getText (resultSet->getColumnIndex (wstring (L"issuedby")));
  wcsncpy (info.m_info.IssuedBy, issuedBy.c_str (), sizeof (info.m_info.IssuedBy) / sizeof (wchar_t));
  
  info.m_info.Expiration = (resultSet->getDate (resultSet->getColumnIndex (wstring (L"expiration")))).getDate ();
} // fillCertRecordInfo

} // namespace replication
} // namespace Storage
