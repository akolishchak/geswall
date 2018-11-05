//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __sessions_h__
#define __sessions_h__

namespace Sessions {

	bool Init(void);
	bool GetUserResponse(RequestDataGUI *Request, PVOID *Response, SIZE_T *ResponseSize);
	void Release(void);

};

#endif // #ifndef __sessions_h__