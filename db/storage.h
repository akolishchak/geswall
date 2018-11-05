//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __storage_h__
#define __storage_h__

#include "gsw/gswioctl.h"

#include <string> 
#include <list> 
#include <hash_map>
#include <boost/smart_ptr.hpp> 

#include "config/inode.h"

#include "cdbc/iconnection.h"

#include "storageexception.h"
#include "groupnotemptyexception.h"
#include "groupexistexception.h"
#include "groupcodeexistexception.h"
#include "displaynameexistexception.h"
#include "identityexistexception.h"
#include "resourceexistexception.h"
#include "contentexistexception.h"
#include "pathexistexception.h"
#include "digestexistexception.h"
#include "certificateexistexception.h"
#include "securityclassexistexception.h"
#include "ownerexistexception.h"

using namespace sql;
using namespace std;
using namespace stdext;
using namespace config;

namespace Storage {

typedef INode::PtrToINode  PtrToINode;

void SetDBSetting (const PtrToINode& node);
void SetDBConnectString (const wchar_t* connectString);
void SetDBConnectString (const wstring& connectString);
void close ();

enum DbOption {
    dboNone         = 0,
    dboDeleted      = 1,
    dboUserCreated  = 2,
    dboUserModified = 4,
	dboLabel1		= 8,
	dboLabel2		= 16,
	dboLabel3		= 32
};

enum {
	InternalDbOptionsMask = dboDeleted,
	ExternalDbOptionsMask = dboUserCreated | dboUserModified
};

enum CertType {
    crtUnknown      = 0,
    crtRootCA       = 1,
    crtMSValidated  = 2
};

enum DigestType {
    dgtUnknown      = 0,
    dgtMD5          = 1,
    dgtSHA1         = 2,
    dgtSHA256       = 3
};

enum ContentType {
    cntUnknown         = 0,
    cntProductName     = 1,
    cntInternalName    = 2
};

enum ParamsType {
    parUnknown          = 0,
    parResource         = 1,
    parResourceApp      = 2,
    parAppGroup         = 3,
    parAppContent       = 4,
    parAppPath          = 5,
    parAppDigest        = 6,
};

enum SecurityClassId {
     sciTrusted         = 1,
     sciUntrusted       = 2,
     sciConfidential    = 3,
     sciThreatGate      = 4
};


const size_t MaxNameSize = 512;

typedef boost::shared_array<byte>    PtrToByteArray;
typedef boost::shared_array<wchar_t> PtrToWCharArray;

int GetParamsByCertificate(EntityAttributes& Attributes, const CertType Type, const PtrToByteArray& Thumbprint, size_t ThumbprintSize);
int GetParamsByDigest(EntityAttributes& Attributes, const DigestType Type, const PtrToByteArray& Digest, size_t DigestSize);
int GetParamsByPath(EntityAttributes& Attributes, const NtObjectType Type, const wchar_t *Path);
int GetParamsByPath(EntityAttributes& Attributes, const NtObjectType Type, const wstring& Path);
int GetParamsByOwner(EntityAttributes& Attributes, const NtObjectType Type, const PSID Sid);
int GetParamsByContent(EntityAttributes& Attributes, const ContentType Type, const wchar_t *Content);
int GetParamsByContent(EntityAttributes& Attributes, const ContentType Type, const wstring& Content);

enum IdentityType {
    idnUnknwon          = 0,
    idnOwner            = 1,
    idnPath             = 2,
    idnCertificate      = 3,
    idnDigest           = 4,
    idnContent          = 5
};

const GUID ZeroGuid = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };

struct DbInfo {  
  int Id;
  int Options;
//  GUID     Guid;
};

struct SupplementaryInfo : DbInfo
{
  int ParentId;
  ParamsType param_type;
}; // SupplementaryInfo

struct CertInfo : public SupplementaryInfo {
    CertType Type;
    size_t ThumbprintSize;
    byte Thumbprint[20];
    wchar_t IssuedTo[100];
    wchar_t IssuedBy[100];
    __int64 Expiration;
};

struct DigestInfo : public SupplementaryInfo {
    DigestType Type;
    size_t DigestSize;
    byte Digest[64];
    wchar_t FileName[255];
};

const size_t MaxContextLength = 255;
struct ContentInfo : public SupplementaryInfo {
    ContentType Type;
    wchar_t Content[MaxContextLength];
    wchar_t FileName[255];
};

struct PathInfo : public SupplementaryInfo {
    NtObjectType Type;
    wchar_t Path[512];
};

struct OwnerInfo : public SupplementaryInfo {
    NtObjectType Type;
    wchar_t Owner[160];
};

struct IdentityItem {
    IdentityType Type;
    union {
        PathInfo Path;
        OwnerInfo Owner;
        CertInfo Cert;
        DigestInfo Digest;
        ContentInfo Info;
    };
    NtObjectType GetResourceType(void)
    {
        if ( Type == idnOwner ) return Owner.Type;
        else
        if ( Type == idnPath ) return Path.Type;
        else
        return nttFile;
    }
	int GetId(void)
	{
        if ( Type == idnOwner ) return Owner.Id;
        else
        if ( Type == idnPath ) return Path.Id;
        else
		if ( Type == idnCertificate ) return Cert.Id;
		else
		if ( Type == idnDigest ) return Digest.Id;
		else
		if ( Type == idnContent ) return Info.Id;
		return 0;
	}
};

struct ParamsInfo : DbInfo {
    int      GroupId;
    EntityAttributes Attributes;
    ULONG Model;
    ParamsType Type;
    wchar_t Description[200];
};

typedef boost::shared_ptr<ParamsInfo> PtrToParamsInfo;
typedef std::vector<PtrToParamsInfo>  ParamsInfoList;


struct ResourceItem {
    ParamsInfo Params;
    IdentityItem Identity;
};

typedef boost::shared_ptr<ResourceItem> PtrToResourceItem;
typedef std::vector<PtrToResourceItem>  ResourceItemList;

bool GetResourceList(ResourceItemList& ResList);

enum AppInfoConst
{
  sha1Size   = 20,
  sha256Size = 32
};

struct ApplicationInfo : public DbInfo {
	int AppId;
    wchar_t FileName[255];
    wchar_t ProductName[100];
    wchar_t FileDescription[100];
    wchar_t CompanyName[50];
    wchar_t InternalName[50];
    wchar_t OriginalFilename[50];
    wchar_t ProductVersion[20];
    wchar_t FileVersion[20];
    wchar_t LegalCopyright[100];
    wchar_t Comments[100];
    wchar_t ProductURL[100];
    unsigned int Lang;
    byte Icon[3000];
    int IconSize;
    byte MD5[16];
    byte SHA1[sha1Size];
    byte SHA256[sha256Size];
    byte CertThumbprint[32];
    unsigned int AppOptions;
};

struct ApplicationItem : ResourceItem, ApplicationInfo {
    ApplicationItem(void) { memset(this, 0, sizeof ApplicationItem); }
};

typedef boost::shared_ptr<ApplicationItem> PtrToApplicationItem;
typedef std::list<PtrToApplicationItem>    ApplicationItemList;

enum IdsPatternType {
	ptnUnknown				= -1,
	ptnMacros				= 0,
	ptnRegexp				= 1,
	ptnMix					= 2
};

struct IdsPatternItem : public DbInfo {
	NtObjectType ResType;
	IdsPatternType PatternType;
	int Flags;
	wchar_t Pattern[512];
	wchar_t Message[512];
};

typedef boost::shared_ptr<IdsPatternItem> PtrToIdsPatternItem;
typedef std::vector<PtrToIdsPatternItem>  IdsPatternItemList;


bool GetApplicationList(int Id, ApplicationItemList& AppList);
bool GetApplicationResources(int AppId, ResourceItemList& ResList);
bool GetApplicationItem(int AppId, ApplicationItem &Item);
bool GetApplicationItem(wstring &AppName, int GroupId, ApplicationItem& appItem);
bool GetApplicationList(ParamsType Type, ApplicationItemList& AppList);
int GetGroupId(const int GroupCode, const GUID &GroupGuid);
void GetSecurityClass(const int Id, ParamsInfo& Info);
void GetSucurityClassesList(ParamsInfoList &List);
void GetIdsPatternsList(IdsPatternItemList &List);

void InsertApplication (const ApplicationItem &AppItem, int &AppId);
void GetAppInfo (ApplicationItem &AppItem, int &AppId);
void InsertApplicationResource (ResourceItem &Res, int &Id);
void InsertApplicationGroup (ParamsInfo& Params, bool updateGroupId, int &GroupId);
int InsertParams(const ParamsInfo& Info);
void InsertCertificate(const CertInfo& Info, int &Id);
int InsertDigest(const DigestInfo& Info);
int InsertPath(const PathInfo& Info);
void InsertOwner(const OwnerInfo& Info, int &Id);
int InsertContent(const ContentInfo& Info);
void InsertSecurityClass(ParamsInfo& Info, int &Id);
void InsertGlobalResource(ResourceItem &Res, int &Id);
void InsertIdsPattern(IdsPatternItem &Item, int &Id);

bool DeleteApplication (int appId);
bool DeleteApplicationResource (int resId);
bool DeleteApplicationGroup (int groupId);
bool DeleteParams(int Id);
bool DeleteCertificate(int Id);
bool DeleteDigest(int Id);
bool DeletePath(int Id);
bool DeleteOwner(int Id);
bool DeleteContent(int Id);
bool DeleteApplicationResource(int Id);
void DeleteSecurityClass(const int Id);
void DeleteGlobalResource(const IdentityType Type, const int Id);
void DeleteIdsPattern(const int Id);

int UpdateApplication (int appId, ApplicationItem& AppItem);
int UpdateApplicationGroup (ParamsInfo& Params);
int UpdateApplicationResource (ResourceItem & Res);
int UpdateParams(int Id, const ParamsInfo& Info);
int UpdateCertificate(int Id, const CertInfo& Info);
int UpdateDigest(int Id, const DigestInfo& Info);
int UpdatePath(int Id, const PathInfo& Info);
int UpdateOwner(int Id, const OwnerInfo& Info);
int UpdateContent(int Id, const ContentInfo& Info);
int UpdateSecurityClass(const int Id, ParamsInfo& Info);
int UpdateGlobalResource(const int Id, ResourceItem & Res);
int UpdateIdsPattern(const int Id, IdsPatternItem &Item);

struct SecureType : public DbInfo {
    wstring Description;
};

typedef boost::shared_ptr<SecureType> PtrToSecureType;
typedef pair <int, wstring> SECPAIR;
typedef stdext::hash_map <int, wstring> SECMAP;
typedef stdext::hash_map <int, wstring>::iterator SECMAP_ITER;

bool GetSecureTypeList(SECMAP& SecMap);
bool GroupIsEmpty(int Id);

int InsertParams (const GUID& guid, IConnection::PtrToIConnection& conn, const ParamsInfo& Info);
void InsertCertificate (const GUID& guid, IConnection::PtrToIConnection& conn, const CertInfo& Info, int &Id);
int InsertDigest (const GUID& guid, IConnection::PtrToIConnection& conn, const DigestInfo& Info);
int InsertPath (const GUID& guid, IConnection::PtrToIConnection& conn, const PathInfo& Info);
void InsertOwner (const GUID& guid, IConnection::PtrToIConnection& conn, const OwnerInfo& Info, int &Id);
int InsertContent (const GUID& guid, IConnection::PtrToIConnection& conn, const ContentInfo& Info);
int InsertApplicationGroupNoCheck (const GUID& guid, IConnection::PtrToIConnection& conn, ParamsInfo& Params, bool updateGroupId);
void InsertApplicationGroup (const GUID& guid, IConnection::PtrToIConnection& conn, ParamsInfo& Params, bool updateGroupId, int &GroupId);
int InsertApplicationInfo (const GUID& guid, IConnection::PtrToIConnection& conn, const ApplicationInfo& appInfo);

bool DeleteObject(IConnection::PtrToIConnection& conn, int Id, const wstring& sql);
bool DeleteParams (IConnection::PtrToIConnection& conn, int Id);
bool DeleteCertificate (IConnection::PtrToIConnection& conn, int Id);
bool DeleteDigest (IConnection::PtrToIConnection& conn, int Id);
bool DeletePath (IConnection::PtrToIConnection& conn, int Id);
bool DeleteOwner (IConnection::PtrToIConnection& conn, int Id);
bool DeleteContent (IConnection::PtrToIConnection& conn, int Id);

int GetUpdateVersion (void);
bool SetUpdateVersion (int version);
int GetDbVersion (void);
bool CleanupForPersonalEdition (void);
int GetAppsNumber (void);

} // namespace Storage {

#endif // __storage_h__