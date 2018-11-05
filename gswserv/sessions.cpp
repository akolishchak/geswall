//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "sessions.h"
#include "lock.h"
#include <psapi.h>
#include "reqhandle.h"
#include "reqgui.h"


namespace Sessions {

struct ReqInfo {
	RequestType Type;
	HANDLE hProcess;
	DWORD ProcessId;
	std::wstring Path;
	PVOID Response;
	SIZE_T ResponseSize;
	bool bRes;
};

struct SessionInfo {
	DWORD Id;
	DWORD Counter;
	CLock Lock;
	std::list<ReqInfo *> ReqCache;
};

std::list<SessionInfo *> SessionList;
CLock Lock;

SessionInfo *GetSessionInfo(DWORD SessionId);
void ReleaseSessionInfo(SessionInfo *Session);


bool GetUserResponse(RequestDataGUI *Request, PVOID *Response, SIZE_T *ResponseSize)
{
	//
	// Get session
	//
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, HandleToUlong(Request->ProcessId));
	if ( hProcess == NULL ) {
		trace("Sessions::GetUserResponse: OpenProcess error: %d\n", GetLastError());
		return false;
	}

	HANDLE hToken;
	BOOL rc = OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE, &hToken);
	if ( !rc ) {
	    CloseHandle(hProcess);
		trace("Sessions::GetUserResponse: OpenProcessToken error: %d\n", GetLastError());
		return false;
	}

	DWORD SessionId = 0;
	DWORD Returned;
	rc = GetTokenInformation(hToken, TokenSessionId, &SessionId, sizeof SessionId, &Returned);
	CloseHandle(hToken);
	if ( !rc ) {
	    CloseHandle(hProcess);
		trace("Sessions::GetUserResponse: GetTokeInformation error: %d\n", GetLastError());
		return false;
	}

	bool bRes = false;
	std::wstring Path;
	if ( Request->Type == reqAccessSecretFile ) {
		Path = commonlib::Tools::FullNameToDOSName(((AccessSecretFileReq *) Request)->FileName);
		if ( !( GetFileAttributes(Path.c_str()) & FILE_ATTRIBUTE_DIRECTORY ) ) {
			for (size_t i = Path.size()-1; i >= 0; i-- )
				if ( Path[i] == '\\' ) {
					Path.resize(i+1);
					break;
				}
		}
	}
	//
	// Fill request structure
	//
	SessionInfo *Session = NULL;

	if ( Request->Options & ropCached ) {
		//
		// Check cache
		//
		Session = GetSessionInfo(SessionId);
		Session->Lock.Get();
		for ( std::list<ReqInfo *>::iterator i = Session->ReqCache.begin(); i != Session->ReqCache.end(); i++ ) {
			if ( (*i)->ProcessId == HandleToUlong(Request->ProcessId) && (*i)->Type == Request->Type &&
				( Request->Type != reqAccessSecretFile || 0 == (*i)->Path.compare(0, (*i)->Path.size(), Path, 0, (*i)->Path.size()) ) ) {
				//
				// cache hit, get data
				//
				if ( (*i)->Response != NULL ) {
					*Response = CReqHandle::AllocateResponse((*i)->ResponseSize);
					memcpy(*Response, (*i)->Response, (*i)->ResponseSize);
					*ResponseSize = (*i)->ResponseSize;
				}
				bRes = (*i)->bRes;
				Session->Lock.Release();
				ReleaseSessionInfo(Session);
				CloseHandle(hProcess);
				return bRes;
			}
		}
		//
		// do not release lock if there is no cache hit
		// so we serialize requests
		//
	}
	//
	// Send request to user
	//
	//PopupRequest(&Info);
	bool CacheResult = true;
	switch ( Request->Type ) {
		case reqThreatPointSubject:
			bRes = ReqGui::ThreatPointSubject((ThreatPointSubjectReq *) Request, Response, ResponseSize, CacheResult);
			break;

		case reqNotIsolateTracked:
			bRes = ReqGui::IsolateTracked((NotIsolateTrackedReq *) Request, Response, ResponseSize);
			break;

		case reqAccessSecretFile:
			bRes = ReqGui::AccessSecretFile((AccessSecretFileReq *) Request, Response, ResponseSize, CacheResult);
			break;
	}

	if ( Request->Options & ropCached ) {

		if ( CacheResult == false ) {
			Session->Lock.Release();
			return bRes;
		}
		//
		// Put result to cache
		// lock already acquired
		//
		ReqInfo *Cached = new ReqInfo;
		Cached->Type = (RequestType) Request->Type;
		Cached->hProcess = hProcess;
		Cached->ProcessId = HandleToUlong(Request->ProcessId);
		Cached->Path = Path;
		Cached->bRes = bRes;
		Cached->ResponseSize = *ResponseSize;
		Cached->Response = NULL;

		if ( *Response != NULL ) {
			Cached->Response = new byte[*ResponseSize];
			memcpy(Cached->Response, *Response, *ResponseSize);
		}
		Session->ReqCache.push_back(Cached);
		Session->Lock.Release();
		//
		// Do not release session info, as we added new process
		// and want to increase session counter
		//
		return bRes;
	}

	CloseHandle(hProcess);

	return bRes;
}

SessionInfo *GetSessionInfo(DWORD SessionId)
{
	SessionInfo *Session = NULL;
	Lock.Get();
	for ( std::list<SessionInfo *>::iterator i = SessionList.begin(); i != SessionList.end(); i++ ) {
		//
		// cleanup session by deleting dead processes
		//
		for ( std::list<ReqInfo *>::iterator j = (*i)->ReqCache.begin(); j != (*i)->ReqCache.end(); j++ ) {

			if ( WAIT_TIMEOUT != WaitForSingleObject((*j)->hProcess, 0) ) {
				//
				// Process already terminated, remove it
				//
				CloseHandle((*j)->hProcess);
				if ( (*j)->Response != NULL ) delete[] (*j)->Response;
				delete *j;
				(*i)->ReqCache.erase(j);
				j = (*i)->ReqCache.begin();
				(*i)->Counter--;
				continue;
			}
		}

		if ( (*i)->Id == SessionId ) {
			(*i)->Counter++;
			Lock.Release();
			return *i;
		}

		if ( (*i)->Counter == 0 ) {
			Session = *i;
			SessionList.erase(i);
			delete Session;
			i = SessionList.begin();
		}
	}
	//
	// Unknown session, add it
	//
	Session = new SessionInfo;
	Session->Id = SessionId;
	Session->Counter = 1;
	SessionList.push_back(Session);

	Lock.Release();

	return Session;
}

void ReleaseSessionInfo(SessionInfo *Session)
{
	Lock.Get();
	if ( --Session->Counter == 0 ) {
		SessionList.remove(Session);
		delete Session;
	}
	Lock.Release();
}

HANDLE hThread;
HANDLE hDestroyEvent;
DWORD WINAPI CacheCleanup(void *Context);

bool Init(void)
{
	hDestroyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	DWORD ThreadId;
    hThread = CreateThread(NULL, 0, CacheCleanup, NULL, 0, &ThreadId);

	return true;
}

void Release(void)
{
	SetEvent(hDestroyEvent);
    if ( hThread != INVALID_HANDLE_VALUE ) {
        //
        // Wait for thread completing
        //
        WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
        hThread = INVALID_HANDLE_VALUE;
    }
	CloseHandle(hDestroyEvent);

	Lock.Get();

	for ( std::list<SessionInfo *>::iterator i = SessionList.begin(); i != SessionList.end(); i++ ) {
		//
		// cleanup session by deleting dead processes
		//
		for ( std::list<ReqInfo *>::iterator j = (*i)->ReqCache.begin(); j != (*i)->ReqCache.end(); j++ ) {
			CloseHandle((*j)->hProcess);
			if ( (*j)->Response != NULL ) delete[] (*j)->Response;
			delete *j;
		}
		(*i)->ReqCache.clear();
		delete *i;
	}
	SessionList.clear();
	Lock.Release();
}

DWORD WINAPI CacheCleanup(void *Context)
{
	SessionInfo *Session = NULL;
	while ( true ) {
		if ( WaitForSingleObject(hDestroyEvent, 3000) == WAIT_OBJECT_0 ) break;
		Lock.Get();
		for ( std::list<SessionInfo *>::iterator i = SessionList.begin(); i != SessionList.end(); i++ ) {
			//
			// cleanup session by deleting dead processes
			//
			for ( std::list<ReqInfo *>::iterator j = (*i)->ReqCache.begin(); j != (*i)->ReqCache.end(); j++ ) {

				if ( WAIT_TIMEOUT != WaitForSingleObject((*j)->hProcess, 0) ) {
					//
					// Process already terminated, remove it
					//
					CloseHandle((*j)->hProcess);
					if ( (*j)->Response != NULL ) delete[] (*j)->Response;
					delete *j;
					(*i)->ReqCache.erase(j);
					j = (*i)->ReqCache.begin();
					(*i)->Counter--;
					continue;
				}
			}
		}
		Lock.Release();
	}

	return 0;
}

};
