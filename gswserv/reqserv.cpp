//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "reqserv.h"
#include "reqhandle.h"
#include "sessions.h"
#include "commonlib/tools.h"
#include "storage.h"
#include "gswioctl.h"
#include "commonlib.h" 
#include "paramsmodifier.h"
#include "configurator.h"
#include "gswdrv.h"
#include "gswpolicy.h"


#include <string>
#include <boost/smart_ptr.hpp> 

using namespace std;
using namespace commonlib::Tools;
using namespace Storage;
using namespace commonlib;

namespace ReqServ {

const int HandlersNum = 10;
CReqHandle *Handlers[HandlersNum] = { NULL };
bool HandleProcExec(ProcExecReq Request, PVOID *Response, SIZE_T *ResponseSize);

bool HandleProcExec(ProcExecReq *Request, PVOID *Response, SIZE_T *ResponseSize)
{
  START_COUNTER;
  wstring name;
  size_t  nameSize = 0;
  
  if (0 == (nameSize = FullNameToDOSName (name, Request->FileName)))
    nameSize = FullNameToUNCName (name, Request->FileName);

  if (0 == nameSize)
    return false;
    
  EntityAttributes attr = Request->Attr;
  RuleRecordList   rulesList;
  wstring          content;
  size_t           contentSize = 0;
  if ( attr.Param[GesRule::attIntegrity] > GesRule::modThreatPoint ) 
	  contentSize = QueryObjectContent (content, name);
  if (0 != contentSize)
    GetParamsByContent (attr, cntInternalName, content);
/*
  if (0 == id)
  { 
#pragma message (__WARNING__ "TODO HandleProcExec (): implement code for GetParamsByPath")
    commonlib::PtrToUCharArray digest;
    size_t digestSize = QueryHash (CALG_SHA1, name, digest);
    if (0 < digestSize)
    {
      id = GetParamsByDigest(attr, dgtSHA1, digest, digestSize);
    } // if (0 < digestSize)
  } // if (false == result)
*/
 
  bool result = false;
  ProcExecReply *procExecReply = NULL;
  if ( 0 != attr.Param[GesRule::attSubjectId] )
  {
	if ( content == L"iexplore;IEXPLORE.EXE" ) {
		//
		// For IE always set oboIsolateOnStart. IsolateOnStart is required as IE uses several processes
		// TODO: Remove this when UI in gswmmc is ready
		//
		if ( attr.Param[GesRule::attIntegrity] == GesRule::modTCB && !( attr.Param[GesRule::attOptions] & ( GesRule::oboKeepTrusted | GesRule::oboAutoIsolate ) ) ) {
			attr.Param[GesRule::attOptions] |= GesRule::oboIsolateOnStart;
		}
	}
	if ( content == L"wlcomm.exe;wlcomm.exe" ) {
		//
		// For wlcomm always set oboIsolateOnStart.
		// TODO: Remove this when UI in gswmmc is ready
		//
		if ( attr.Param[GesRule::attIntegrity] == GesRule::modTCB && !( attr.Param[GesRule::attOptions] & ( GesRule::oboKeepTrusted | GesRule::oboAutoIsolate ) ) ) {
			attr.Param[GesRule::attOptions] |= GesRule::oboIsolateOnStart;
		}
	}

    ResourceItemList resList;
	if ( true == GetApplicationResources(attr.Param[GesRule::attSubjectId], resList) )
    {
      for (ResourceItemList::iterator i = resList.begin (); i != resList.end (); ++i)
      {
        switch ((*i)->Identity.Type)
        {
          case idnPath:
               createRuleRecord (rulesList, (*i), Request->ProcessId, Request->RuleId);
               break;
        } // switch
      } // for (...)

      size_t packLength = getRulesPackLength(rulesList);
      size_t bufLength = packLength+FIELD_OFFSET(ProcExecReply, Pack);
      procExecReply = reinterpret_cast <ProcExecReply*> (CReqHandle::AllocateResponse(bufLength));

      procExecReply->Attr = attr;
      result = fillRulesPack(&procExecReply->Pack, rulesList);
      *Response = procExecReply;
      *ResponseSize = bufLength;
    } // if (true == GetApplicatinResources (attr.Param [0], resList))
  }
  //
  // Check modifier
  //
  ModifierType Type = ParamsModifier::Get(HandleToLong(Request->ProcessId), HandleToLong(Request->ThreadId));
  if ( Type != modNone ) {
	  if ( procExecReply == NULL ) {
		size_t packLength = FIELD_OFFSET(RulePack, Record);
		size_t bufLength = packLength+FIELD_OFFSET(ProcExecReply, Pack);
		procExecReply = reinterpret_cast <ProcExecReply*> (CReqHandle::AllocateResponse(bufLength));
		procExecReply->Attr = attr;
		procExecReply->Pack.PackVersion = PACK_VERSION;
		procExecReply->Pack.RulesNumber = 0;
		result = true;
		*Response = procExecReply;
		*ResponseSize = bufLength;
	  }
	  ParamsModifier::Apply(Type, &procExecReply->Attr);
  }

  END_COUNTER(HandleProcExec);
#if _DEBUG
  try {
  if ( *Response == NULL ) return result;
  RulePack *Pack = (RulePack *) &((ProcExecReply *)(*Response))->Pack;
  RuleRecord *Record = Pack->Record;
  for ( ULONG i=0; i < Pack->RulesNumber; i++ ) {

      trace("%c%c%c%c [%x, %x, %x, %x, %x, %x] for %S, ", 
          Record->Label[0], Record->Label[1], Record->Label[2], Record->Label[3],
          Record->Attr.Param[0], Record->Attr.Param[1], Record->Attr.Param[2],
        Record->Attr.Param[3], Record->Attr.Param[4], Record->Attr.Param[5], 
          GetNtTypeString(Record->Type));

      switch ( Record->BufType ) {
          case bufObjectName:
              trace("Name: %S\n", Record->Buf);
              break;

          case bufOwnerSid:
              trace("OwnerSid: %S\n", "Unresolved");
              break;

          default:
              trace("Unknown data\n");
              break;
      }

      Record = (RuleRecord *)((PUCHAR)Record + FIELD_OFFSET(RuleRecord, Buf) + Record->BufSize);
  }
  } catch (...) {
	  trace("exception!!!\n");
  }
#endif
  return result;
} // HandleProcExec

ULONG Handle(RequestData *Request, PVOID *Response, SIZE_T *ResponseSize)
{
    ULONG Res = FALSE;
    *ResponseSize = 0;

	if ( Request->Type == reqThreatPointSubject && !GswPolicy::IsIsolationRequired((ThreatPointSubjectReq *)Request) ) return tpsOnceTrusted;

	if ( Request->Options & ropGUI )
        Res = Sessions::GetUserResponse((RequestDataGUI *)Request, Response, ResponseSize);
    else
    switch ( Request->Type ) {
        case reqProcExec:
		case reqAccessSecretFile: // TODO: remove?
            Res = HandleProcExec((ProcExecReq *)Request, Response, ResponseSize);
            break;

        default:
            break;
    }

    return Res;
}

bool Init(void)
{
	Sessions::Init();
	GswPolicy::Init();

    for (int i = 0; i < HandlersNum; i++) {
        Handlers[i] = new CReqHandle(Handle);
        if ( !Handlers[i]->StartBackground() ) {
            Release();
            return false;
        }
    }

    return true;
}

void Release(void)
{
    for (int i = 0; i < HandlersNum; i++) {
        if ( Handlers[i] != NULL ) Handlers[i]->AuthorizedStop();
    }
    Sessions::Release();
}


} // namespace ReqServ
