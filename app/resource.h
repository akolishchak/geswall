//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __global_resource_h__
#define __global_resource_h__

#include <boost/smart_ptr.hpp> 
#include "db/storage.h"
#include "gesruledef.h"

namespace App {

class Resource {
public:
	Resource(const Storage::IdentityType Type, const wchar_t *ResourceName, const NtObjectType ObjectType, const int ClassId, const int _Options);
	Resource(Storage::ResourceItem *_Res, const int _Options);
	~Resource();

	void StorageCreate(int &Id);
	void StorageUpdate(void);
	void StorageDelete(void);

	bool IsValid(void) { return bInited; }
	bool IsUserCreated(void);
	bool IsUserModified(void);

	void SetName(const wchar_t *ResourceName);
	const wchar_t *GetName(void);
	void SetClassId(const int ClassId);
	int GetClassId(void);
	void SetClassName(const wchar_t *_ClassName);
	const wchar_t *GetClassName(void);
	NtObjectType GetObjectType(void);
	bool operator== (const Resource &r) const;

	void Dump(int Mode);

private:
	int GetOptions(void);

	bool bInited;
	bool bRelease;
	int Options;
	Storage::ResourceItem *Res;
	wstring ClassName;
};

typedef boost::shared_ptr<Resource> PtrToResource;

class ResourceList {
public:
	enum {
		Empty	= false,
		Preload = true
	};
	ResourceList(bool _Preload);
	void Load(void);
	bool push_back(PtrToResource &Res);
	void remove(const size_t Index);
	PtrToResource Find(const Resource &Res, size_t &FoundIndex);
	PtrToResource & operator[] (size_t Index);
	size_t size() { return List.size(); }
	void clear() { List.clear(); }

private:
	vector<PtrToResource> List;
	Storage::ResourceItemList ResList;
};



}; // namespace App {

#endif // __global_resource_h__