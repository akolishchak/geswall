//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __trialmanager_h__
#define __trialmanager_h__

namespace TrialManager {

enum EventType {
	eventConsoleStart,
	eventUpdated,
	eventUpdateCheck,
	eventTrayClick
};

bool Handle(EventType Event);
bool HandleExpired(void);

}; // namespace TrialManager {


#endif // __trialmanager_h__