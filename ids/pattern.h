//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __pattern_h__
#define __pattern_h__

#include <boost/smart_ptr.hpp> 
#include "db/storage.h"
#include "gswioctl.h"

namespace Ids {

class Pattern {
public:
	Pattern(const NtObjectType ResType, const Storage::IdsPatternType PatternType, const int Flags, const wchar_t *Pattern, const wchar_t *Message);
	Pattern(Storage::IdsPatternItem *_Item);
	~Pattern();

	void StorageCreate(int &Id);
	void StorageUpdate(void);
	void StorageDelete(void);
	bool IsValid(void) { return bInited; }

	void SetMessage(const wchar_t *Message);
	const wchar_t *GetMessage(void);
	void SetPatternType(const Storage::IdsPatternType PatternType);
	Storage::IdsPatternType GetPatternType(void);
	void SetFlags(const int Flags);
	int GetFlags(void);
	
	NtObjectType GetResType(void);
	const wchar_t *GetPattern(void);
	int GetId(void);

	bool operator== (const Pattern &r) const;

	void Dump(int Mode);

private:
	bool bInited;
	bool bRelease;
	Storage::IdsPatternItem *Item;
};

typedef boost::shared_ptr<Pattern> PtrToPattern;

class PatternList {
public:
	enum {
		Empty	= false,
		Preload = true
	};
	PatternList(bool _Preload);
	void Load(void);
	bool push_back(PtrToPattern &_Pattern);
	void remove(const size_t Index);
	PtrToPattern Find(const Pattern &_Pattern, size_t &FoundIndex);
	PtrToPattern & operator[] (size_t Index);
	size_t size() { return List.size(); }
	void clear() { List.clear(); }

private:
	vector<PtrToPattern> List;
	Storage::IdsPatternItemList PatternItemList;
};

}; // namespace Ids {

#endif // __pattern_h__
