//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _EXTEND_H
#define _EXTEND_H

struct EXTENSION_NODE
{
    GUID	GUID;
    _TCHAR	szDescription[256];
};

enum EXTENSION_TYPE
{
    NameSpaceExtension,
        ContextMenuExtension, 
        ToolBarExtension,
        PropertySheetExtension,
        TaskExtension,
        DynamicExtension,
	DummyExtension
};

struct EXTENDER_NODE
{
    EXTENSION_TYPE	eType;
    GUID			guidNode;
    GUID			guidExtension;
    _TCHAR			szDescription[256];
};

#endif // _EXTEND_H

