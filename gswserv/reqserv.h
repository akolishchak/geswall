//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __reqserv_h__
#define __reqserv_h__

namespace ReqServ {
	bool Init(void);
	void Release(void);
	
	bool HandleProcExec(ProcExecReq *Request, PVOID *Response, SIZE_T *ResponseSize);
	ULONG Handle(RequestData *Request, PVOID *Response, SIZE_T *ResponseSize);
} // namespace ReqServ


#endif // #define __reqserv_h__