//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdio.h>
#include <windows.h>
#include "../db/storage.h"

using namespace Storage;

class MyClass {
public:
	MyClass(PtrToResourceItem _Item):pItem(_Item){}
 
private:
PtrToResourceItem pItem;
};



void f()
{
bool result;
ResourceItemList resList;
result = GetResourceList (resList);
if (true == result)
 { for (ResourceItemList::iterator i = resList.begin (); i != resList.end (); ++i)
	
	MyClass *resource = new MyClass(static_cast <PtrToResourceItem> (*i));
 }
}