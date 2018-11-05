//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __reqhandle_h__
#define __reqhandle_h__

//
// Callback rule function prototype
//
typedef ULONG (*_HandleProc) (RequestData *Request, PVOID *Response, SIZE_T *ResponseSize);

class CReqHandle {
    public:
        CReqHandle(_HandleProc Proc = NULL);
        ~CReqHandle();
        // 
        // Start handling in current thread
        //
        bool Start(void);
        // 
        // Start handling in backround thread
        //
        bool StartBackground(void);
        // 
        // Normal stop of handling
        //
        void Stop(void);
        // 
        // Stop of handling with authorization
        //
        void AuthorizedStop(void);

		static void *AllocateResponse(SIZE_T Length)
		{
			byte *Buf = new byte[Length+sizeof ResponseData];
			return Buf + sizeof ResponseData;
		}

		static void FreeResponse(PVOID _Buf)
		{
			byte *Buf = (byte *)GetResponseData(_Buf);
			delete[] Buf;
		}

		static ResponseData *GetResponseData(PVOID _Buf)
		{
			return (ResponseData *)((byte *)_Buf - sizeof ResponseData);
		}

    private:
        _HandleProc HandleProc;
        HANDLE hDevice;
        HANDLE hThread;
		HANDLE hDestroyEvent;
        bool bFirstHandle;
};

#endif // __reqhandle_h__