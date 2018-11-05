//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __replication_h__
#define __replication_h__

#include "storage.h"

using namespace std;

namespace Storage {
namespace replication {

enum ReplicationOption
{
    rplNone             = 0,
    rplResource         = 1,
    rplGroupsUpdates    = 2,
    rplApp              = 4,
	rplAppResources     = 8 | rplApp,
	rplAll              = rplResource | rplGroupsUpdates | rplAppResources
};

bool Replicate (const wstring& source, const wstring& destination, int rplOptions = rplNone);

} // namespace replication
} // namespace Storage

#endif // __replication_h__