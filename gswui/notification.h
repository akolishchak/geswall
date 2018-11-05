//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __notification_h__
#define __notification_h__

#include "gsw/gswioctl.h"
#include "gsw/gesruledef.h"

class Notification {
public:
    Notification(void)
    {
        Init(INVALID_HANDLE_VALUE);
    }
    Notification(HANDLE _hDevice)
    {
        Init(_hDevice);
    }
    ~Notification()
    {
        if ( bReleaseHandle && hDevice != INVALID_HANDLE_VALUE ) {
            CancelIo(hDevice);
            CloseHandle(hDevice);
        }
		if ( Overlapped.hEvent != NULL ) CloseHandle(Overlapped.hEvent);
    }

    bool StartWait(void)
    {
        if (DeviceIoControl(hDevice, GESWALL_IOCTL_GET_NOTIFICATION, NULL, 0, &Event, sizeof Event, &BytesReturned, &Overlapped))
			return true;

        DWORD rc = GetLastError();
		if (rc == ERROR_IO_PENDING)
			// overlap in progress...o ok
			return true;

        return false;
    }
    
    bool check_result ()
    {
        return (TRUE == GetOverlappedResult (hDevice, &Overlapped, &BytesReturned, TRUE));
    } // check_result
    
    const wchar_t* get_process_file_name () const
    {
        return Event.ProcFileName;
    } // get_process_file_name
    
    int get_app_id () const
    {
        return Event.Attr.Param[GesRule::attSubjectId];
    } // get_app_id

	int get_rule_id () const
	{
		return Event.RuleId;
	}
    
    const wchar_t* get_message () const
    {
        return Event.EventString;
    } // get_message
    
    HANDLE get_process_id () const
    {
        return Event.ProcessId;
    } // get_process_id

  //  wchar_t *Get(void)
  //  {
  //      if ( FALSE == GetOverlappedResult(hDevice, &Overlapped, &BytesReturned, TRUE) ) 
		//	return NULL;
		//return Event.EventString;
  //  }

  //  bool Get(std::wstring &_Message)
  //  {
  //      _Message = Get();
  //      StartWait();
  //      return _Message.size() != 0;
  //  }

    HANDLE GetEvent(void) const
    {
        return Overlapped.hEvent;
    }


private:
    bool Init(const HANDLE _hDevice)
    {

        hDevice = INVALID_HANDLE_VALUE;
        bReleaseHandle = false;
		bool bRet	   = true;
        memset(&Overlapped, 0, sizeof Overlapped);

        if ( hDevice == INVALID_HANDLE_VALUE ) {
			hDevice = CreateFile(GESWALL_USER_DEVICE_NAME, MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
                                OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
            bReleaseHandle = ( hDevice != INVALID_HANDLE_VALUE );
			bRet = bReleaseHandle;

        } else {
            hDevice = _hDevice;
        }

        Overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

        return bRet;
    }


	EventNotification Event;
    OVERLAPPED Overlapped;
    HANDLE hDevice;
    bool bReleaseHandle;
    DWORD BytesReturned;

};

#endif // __notification_h__