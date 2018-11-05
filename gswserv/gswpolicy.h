//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswpolicy_h__
#define __gswpolicy_h__

namespace GswPolicy {

bool Init(void);
bool IsIsolationRequired(const ThreatPointSubjectReq *Request);

};


#endif // __gswpolicy_h__
