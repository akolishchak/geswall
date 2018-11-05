//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "app/common.h"
#include "group.h"
#include <map>

using namespace commonlib;

namespace App {

Group::Group(const wchar_t *GroupName, const int GroupCode, const ULONG _Options)
{
	Options = _Options;
	Params.Id = 0;
	Params.GroupId = 0;
	SetName(GroupName);
	Params.Model = GesRule::GswLabel;
	Params.Type = Storage::parAppGroup;
	Params.Options = 0;
	if ( _Options & UserCreated ) Params.Options |= Storage::dboUserCreated;
	memset(&Params.Attributes, 0, sizeof Params.Attributes);
	Params.Attributes.Param[1] = GroupCode;

	bInited = true;
}

Group::Group(const int GroupId)
{
	Options = 0;
	Storage::ApplicationItem Item;
	try {
		Storage::GetApplicationItem(GroupId, Item);
		Params = Item.Params;
		bInited = true;
	} catch ( ... ) {
		bInited = false;
	}
}

Group::Group(const Storage::ParamsInfo &_Params, const UniqueId *ParentUniqueId, const ULONG _Options)
{
	Options = _Options;
	Params = _Params;
	if ( ParentUniqueId != NULL ) ParentGroupUniqueId = *ParentUniqueId;
	bInited = true;
}

void Group::StorageCreate(int &CreatedGroupId)
{
	CreatedGroupId = 0;
	//
	// fix name conflicts loop
	//
	wstring Name = Params.Description;
	while ( true ) {
		try {
			Storage::InsertApplicationGroup(Params, true, CreatedGroupId);
			Params.Id = CreatedGroupId;
			AddCached(*GetGroupUniqueId(), CreatedGroupId);
		} catch ( Storage::GroupExistException ) {
			if ( Options & FixDisplayName ) {
				Name.insert(0, FixNamePrefix);
				SetName(Name.c_str());
				continue;
			} else {
				throw;
			}
		}
		break;
	}
}

void Group::StorageCreate(const int ParentGroupId, int &CreatedGroupId)
{
	Params.GroupId = ParentGroupId;
	StorageCreate(CreatedGroupId);
}

void Group::StorageMove(const int GroupId)
{
	Params.GroupId = GroupId;
	StorageUpdate();
}

void Group::StorageUpdate(void)
{
	if ( Options & UserModified )
		Params.Options |= Storage::dboUserModified;
	else
		Params.Options &= ~(Storage::dboUserModified |Storage::dboUserCreated);
	int Id = Storage::UpdateApplicationGroup(Params);
	Params.Id = Id;
	DeleteCached(*GetGroupUniqueId());
	AddCached(*GetGroupUniqueId(), Id);
}

static std::map<Group::UniqueId, int> GroupIdCache;

void Group::StorageDelete(void)
{
	int GroupId = Params.Attributes.Param[GesRule::attSubjectId];
	if ( !bInited || GroupId == 0 ) throw Storage::StorageException(Storage::ErrorUnknown);

	Storage::DeleteApplicationGroup(GroupId);
	DeleteCached(*GetGroupUniqueId());
}

void Group::SetName(const wchar_t *GroupName)
{
	StringCchCopy(Params.Description, sizeof Params.Description / sizeof Params.Description[0], GroupName);
}
const wchar_t *Group::GetName(void)
{
	return Params.Description;
}

Group::UniqueId *Group::GetGroupUniqueId(void)
{
	return (UniqueId *) &Params.Attributes.Param[1];
}

void Group::SetParentGroupUniqueId(const UniqueId &Id)
{
	ParentGroupUniqueId = Id;
}

Group::UniqueId *Group::GetParentGroupUniqueId(void)
{
	return &ParentGroupUniqueId;
}

int Group::GetOptions(void)
{
	return Params.Options;
}

int Group::GetGroupId(void)
{
	return Params.Attributes.Param[GesRule::attSubjectId];
}

bool Group::IsUserCreated(void)
{
	if ( !bInited ) return false;
	return ( GetOptions() & Storage::dboUserCreated ) != 0;
}

bool Group::IsUserModified(void)
{
	if ( !bInited ) return false;
	return ( GetOptions() & Storage::dboUserModified ) != 0;
}

void Group::Dump(int Mode)
{
	Debug::Write (Mode, "Group = %S, Code = %x, ParentCode = %x, Options = %x\n", 
				  GetName(), GetGroupUniqueId()->Code, GetParentGroupUniqueId()->Code, GetOptions());
}

int Group::GetGroupId(const UniqueId &Id)
{
	std::map<Group::UniqueId, int>::iterator i = GroupIdCache.find(Id);
    if ( i != GroupIdCache.end() ) return i->second;

	int GroupId = 0;
	try {
		GroupId = Storage::GetGroupId(Id.Code, Id.Guid);
	} catch( ... ) {
	}
	if ( GroupId != 0 ) AddCached(Id, GroupId);

	return GroupId;
}

const wchar_t* Group::GetDefaultName(const int Code)
{
	switch ( Code ) {
		case 1414748499:	return L"System";
		case 1113020247:	return L"Web Browsers";
		case 1279869261:	return L"E-Mail and News";
		case 1413564483:	return L"Chat Messengers";
		case 4411977:		return L"IRC";
		case 5255760:		return L"P2P";
		case 1128875599:	return L"Office";
		case 1145916493:	return L"Multimedia";
		case 1280528980:	return L"Translators";
		case 1280791367:	return L"GeSWall";
		case 1464158550:	return L"Viewers";
		case 1196248644:	return L"Download Managers";
		default:			return L"";
	}
}

void Group::AddCached(const UniqueId &Id, const int GroupId)
{
	GroupIdCache[Id] = GroupId;
}

void Group::DeleteCached(const UniqueId &Id)
{
	std::map<Group::UniqueId, int>::iterator i = GroupIdCache.find(Id);
	if ( i != GroupIdCache.end() ) GroupIdCache.erase(i);
}

void Group::GetGroupList(void)
{		
		

		//int GroupId = App::ApplicationItem->Params.Attributes.Param[GesRule::attSubjectId];
	//int GroupId =0;
	//MessageBox(NULL,L"Before",L"Group",MB_OK);
	//GroupLst.glcount=0;
	GroupIt.GroupId=0;
	ZeroMemory(GroupIt.GroupName,200);
	lstrcpy(GroupIt.GroupName,L"<Root>");
	GroupArray.push_back(GroupIt);
	//GroupLst.glcount++;
	
	//MessageBox(NULL,L"After",L"Group",MB_OK);
	GroupNode(0,L"");
	//MessageBox(NULL,L"Final001",L"Group",MB_OK);
}

void Group::GroupNode(int GroupId, std::wstring staticNode)
{		
		Storage::ApplicationItemList ApplicationList;
		std::wstring currentNode;		

		bool result = Storage::GetApplicationList (GroupId,ApplicationList); //ApplicationItem->Params.Id
        if (true == result)
        { for (Storage::ApplicationItemList::iterator i = ApplicationList.begin (); i != ApplicationList.end (); ++i)
                {
                        if((*i)->Params.Type == Storage::parAppGroup)
                        {	
							//currentNode=staticNode;
							//currentNode+=(*i)->Params.Description;
							//currentNode+=L"\\";
							currentNode=staticNode;
							if (staticNode!=L"") currentNode+=L"\\";
							currentNode+=(*i)->Params.Description;
							
							
							GroupIt.GroupId=(*i)->Params.Attributes.Param[GesRule::attSubjectId];
							ZeroMemory(GroupIt.GroupName,200);
							lstrcpy(GroupIt.GroupName,currentNode.c_str());
							GroupArray.push_back(GroupIt);

							//GroupLst.GroupArray[GroupLst.glcount].GroupId=(*i)->Params.Attributes.Param[GesRule::attSubjectId];
							//ZeroMemory(GroupLst.GroupArray[GroupLst.glcount].GroupName,200);
							//lstrcpy(GroupLst.GroupArray[GroupLst.glcount].GroupName,currentNode.c_str());
							//GroupLst.glcount++;


							//MessageBox(NULL,currentNode.c_str(),L"Group",MB_OK);
							GroupNode((*i)->Params.Attributes.Param[GesRule::attSubjectId],currentNode);				
							
							//currentNode=L"";
							
                        }
                }
        }
}

} // namespace App {

