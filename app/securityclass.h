//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __securityclass_h__
#define __securityclass_h__

namespace App {

class SecurityClass {
public:
	SecurityClass(void);
	SecurityClass(int Id);
	SecurityClass(const wchar_t *Name, const EntityAttributes &Attributes);
	SecurityClass(Storage::ParamsInfo *_Params);
	~SecurityClass();

	void StorageCreate(int &Id);
	void StorageUpdate(void);
	void StorageDelete(void);

	bool IsValid(void) { return bInited; }

	void SetName(const wchar_t *Name);
	const wchar_t *GetName(void);
	void SetAttributes(const EntityAttributes &Attributes);
	const EntityAttributes *GetAttributes(void);
	int GetId(void);
	bool operator== (const SecurityClass &r) const;

	void Dump(int Mode);

private:
	bool bInited;
	bool bRelease;
	Storage::ParamsInfo *Params;
};

typedef boost::shared_ptr<SecurityClass> PtrToSecurityClass;

class SecurityClassList {
public:
	enum {
		Empty	= false,
		Preload = true
	};
	SecurityClassList(bool _Preload);
	void Load(void);
	bool push_back(PtrToSecurityClass &Class);
	void remove(const size_t Index);
	PtrToSecurityClass Find(const SecurityClass &Class, size_t &FoundIndex);
	int GetClass(const wchar_t *Name);
	PtrToSecurityClass & operator[] (size_t Index);
	size_t size() { return List.size(); }
	void clear() { List.clear(); }

private:
	vector<PtrToSecurityClass> List;
	Storage::ParamsInfoList ParamsList;
};

}; // namespace App {


#endif // __securityclass_h__