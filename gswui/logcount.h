//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_logcount_h__
 #define __gswui_logcount_h__

#include "notification.h"

namespace gswui {
namespace logcount {
typedef std::wstring    wstring;

struct IntLog {   // Declare LOG struct type
   long attacks;
   long notify;
   long isolated;
   long untrusted;
}; 

struct LOGLOG {   // Declare LOGLOG struct type
   wstring source;// Declare member types
   wchar_t date[12];   
   wchar_t attacks[12];
   wchar_t notify[12];
   wchar_t isolated[12];
   wchar_t untrusted[12];
};

void CollectNotify(const Notification &drv_notify,short ntype);
void TotalCount(int attacks,int notify,int isolated,int untrusted);
bool AddNew(int attacks,int notify,int isolated,int untrusted);
void FindOldAndRemove(void);
bool FindIfExistAndAdd(int attacks,int notify,int isolated,int untrusted);
bool ParseLogStr(LOGLOG &logstruct);
bool isOld(short days_limit, wstring sdate);
bool AddToRegistry(wchar_t* regval,long atk,long ntf,long isl, long unt);
void ProcessMessages(void);
char* ConvertLongNumber(long num);
IntLog CalculateLogs (short days_limit);


} // namespace notificator {
} // namespace gswui {
#endif // __gswui_notificator_h__