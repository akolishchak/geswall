//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __lock_h__
#define __lock_h__

class CLock {
	public:
		CLock(void) { InitializeCriticalSection(&CriticalSection);  }
		~CLock() { DeleteCriticalSection(&CriticalSection); }
		void Get(void) { EnterCriticalSection(&CriticalSection); }
		void Release(void) { LeaveCriticalSection(&CriticalSection); }
	private:
		CRITICAL_SECTION CriticalSection;
};

#endif // #ifndef __lock_h__