//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __reqgui_h__
#define __reqgui_h__

namespace ReqGui {

bool ThreatPointSubject(ThreatPointSubjectReq *Request, PVOID *Response, SIZE_T *ResponseSize, bool &CacheResult);
bool IsolateTracked(NotIsolateTrackedReq *Request, PVOID *Response, SIZE_T *ResponseSize);
bool AccessSecretFile(AccessSecretFileReq *Request, PVOID *Response, SIZE_T *ResponseSize, bool &CacheResult);

}; // namespace ReqGui {

#endif // __reqgui_h__