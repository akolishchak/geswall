//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __appstat_h__
#define __appstat_h__

#ifdef _GSWUI_
#include "notification.h"
#endif

#include <vector>

namespace AppStat {
	
#ifdef _GSWUI_
	void AddIsolated(const Notification &drv_notify);
#endif

	struct StatInfo {
		int StartCounter;
		int AppId;
		std::wstring FileName;
		int GroupId;
		bool IsUserCreated;
		std::wstring AppName;
	};

	void GetStatInfo(std::vector<StatInfo> &InfoList);
	void GetTrialApps(std::vector<std::wstring> &Apps);

}; // namespace AppStat {


#endif // __appstat_h__