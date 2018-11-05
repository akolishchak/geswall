//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __netfilter_h__
#define __netfilter_h__

#include "tdiio.h"

namespace NetFilter {

enum TargetDeviceType {
    tdtTcp,
    tdtUdp,
    tdtRawIp,
    tdtMulticast,
    tdtIp
};

#pragma pack(push, 1)

//
// IP address
//
struct Ip4_Address {
    USHORT sin_port;
    union {
        ULONG  in_addr;
        UCHAR  addr[4];
    };
};
#pragma pack(pop)

struct Extension : GswDispatch::Extension {
	TargetDeviceType TargetType;
};

NTSTATUS Init(VOID);
VOID Release(VOID);

NTSTATUS GetObjectName(PVOID FileObject, PVOID RelatedObject, PUNICODE_STRING *ObjectName);

bool CompareIP4(PVOID RelatedObject, IP4Address *Addr);

inline ULONG ntohl (ULONG netlong)
{
	ULONG result = 0;
	((char *)&result)[0] = ((char *)&netlong)[3];
	((char *)&result)[1] = ((char *)&netlong)[2];
	((char *)&result)[2] = ((char *)&netlong)[1];
	((char *)&result)[3] = ((char *)&netlong)[0];
	return result;
}

inline USHORT ntohs (USHORT netshort)
{
	USHORT result = 0;
	((char *)&result)[0] = ((char *)&netshort)[1];
	((char *)&result)[1] = ((char *)&netshort)[0];
	return result;
}

extern PEPROCESS SystemProcess;

}; // namespace NetFilter {

#endif // __netfilter_h__