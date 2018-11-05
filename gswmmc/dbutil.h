//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _DBUTIL_H_
#define _DBUTIL_H_
#include "../db/storage.h"

WCHAR *GetParamsTypeString(ParamsType);

WCHAR *GetParamsTypeString(ParamsType Type)
{
	 switch ( Type ) 
	 {
        case parUnknown:
            return L"Unknown";
        case parResource:
            return L"Resource";
        case parResourceApp:
            return L"Application Resource";
        case parAppGroup:
            return L"Application Group";
        case parAppContent:
            return L"Application Content";
        case parAppPath:
            return L"Application Path";
        case parAppDigest:
            return L"Application Digest";
        
     }

    return L"Unknown";
}
#endif