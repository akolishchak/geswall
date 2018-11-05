//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __replicate_h__
#define __replicate_h__

#include "storage.h"

using namespace std;
using namespace stdext;
using namespace config;

namespace Storage {

enum ReplicationOption
{
	rplNone				= 0,
	rplResource			= 1,
    rplGroupsUpdates	= 2,
	rplAppResources		= 4,
	rplApp				= 8
};

bool Replicate (const wstring& source, const wstring& destination);
bool Compare (const wstring& source, const wstring& destination);

} // namespace Storage {

#endif // __replicate_h__