//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "appstat.h"
#include "config/configurator.h"
#include "app/application.h"
#include "app/group.h"
#include <vector>
#include <string>

namespace AppStat {

const wchar_t Delimiter = '*';

int StringToAppId(const std::wstring &StatString)
{
	for ( size_t e = 0; e < StatString.size(); e++ ) {
		if ( StatString[e] == Delimiter ) {
			return _wtoi(StatString.substr(0, e).c_str());
		}
	}
	return 0;
}

bool StringToStatInfo(const std::wstring &StatString, StatInfo &Info)
{
	size_t b = 0;
	int FieldNum = 0;
	std::wstring FieldValue;
	for ( size_t e = 0; e < StatString.size(); e++ ) {
		if ( StatString[e] == Delimiter ) {
			FieldValue = StatString.substr(b, e-b);
			switch ( FieldNum ) {
				case 0:
					Info.AppId = _wtoi(FieldValue.c_str());
					break;
				case 1:
					Info.StartCounter = _wtoi(FieldValue.c_str());
					break;
				case 2:
					Info.GroupId = _wtoi(FieldValue.c_str());
					break;
				case 3:
					Info.IsUserCreated = _wtoi(FieldValue.c_str()) != 0;
					break;
				case 4:
					Info.FileName = FieldValue;
					break;
				case 5:
					Info.AppName = FieldValue;
					break;
			}
			FieldNum++;
			b = e + 1;
		}
	}

	return FieldNum > 5;
}

void StatInfoToString(const StatInfo &Info, std::wstring &StatString)
{
	wchar_t Buf[50];
	StringCchPrintf(Buf, sizeof Buf / sizeof Buf[0], 
					L"%d%c%d%c%d%c%d%c", Info.AppId, Delimiter, Info.StartCounter, Delimiter, Info.GroupId, Delimiter, 
					Info.IsUserCreated, Delimiter);
	StatString = Buf;
	StatString += Info.FileName;
	StatString += Delimiter;
	StatString += Info.AppName;
	StatString += Delimiter;
}

void GetStatInfo(std::vector<StatInfo> &InfoList)
{
	config::Configurator::PtrToINode Node = config::Configurator::getAppStatNode();
	std::vector<std::wstring> App;
	Node->getStrings(L"List", App);

	for ( std::vector<std::wstring>::iterator i = App.begin(); i != App.end(); i++ ) {
		StatInfo Info;
		if ( StringToStatInfo(*i, Info) ) {
			InfoList.push_back(Info);
		}
	}
}

void GetTrialApps(std::vector<std::wstring> &Apps)
{
	std::vector<StatInfo> InfoList;

	GetStatInfo(InfoList);
	for ( size_t i = 0; i < InfoList.size(); i++ ) {
		if ( InfoList[i].IsUserCreated == false ) {
			//
			// Get group info
			//
			App::Group Group(InfoList[i].GroupId);
			//
			// Do not include web browsers and viewers
			//
			if ( Group.GetGroupUniqueId()->Code == 0 || 
				 Group.GetGroupUniqueId()->Code == 1113020247 || Group.GetGroupUniqueId()->Code == 1464158550 ) continue;
			std::wstring Record = InfoList[i].AppName;
			Record += L" (";
			Record += Group.GetName();
			Record += L")";

			Apps.push_back(Record);
		}
	}
}

#ifdef _GSWUI_

void AddIsolated(const Notification &drv_notify)
{
	if ( drv_notify.get_rule_id() == 0 ) return;

	config::Configurator::PtrToINode Node = config::Configurator::getAppStatNode();
	std::vector<std::wstring> App;
	Node->getStrings(L"List", App);

	StatInfo NewInfo;
	NewInfo.StartCounter = 0;
	NewInfo.AppId = drv_notify.get_app_id();
	NewInfo.FileName = drv_notify.get_process_file_name();
	App::Application AppItem;
	App::Application::GetAppItem(NewInfo.AppId, drv_notify.get_rule_id(), NewInfo.FileName.c_str(), AppItem);
	NewInfo.AppName = AppItem.GetDisplayName();
	if ( AppItem.IsValid() ) {
		NewInfo.GroupId = AppItem.GetGroup();
		NewInfo.IsUserCreated = AppItem.IsUserCreated();
	} else {
		NewInfo.GroupId = -1;
		NewInfo.IsUserCreated = true;
	}
	// get current counter for this app
	for ( std::vector<std::wstring>::iterator i = App.begin(); i != App.end(); i++ ) {
		StatInfo Info;
		if ( StringToAppId(*i) == NewInfo.AppId && StringToStatInfo(*i, Info) ) {
			NewInfo.StartCounter = Info.StartCounter;
			App.erase(i);
			break;
		}
	}

	NewInfo.StartCounter++;
	std::wstring StatString;
	StatInfoToString(NewInfo, StatString);
	App.insert(App.begin(), StatString);

	Node->setStrings(L"List", App);
}

#endif // #ifdef _GSWUI_

} // namespace AppStat {
