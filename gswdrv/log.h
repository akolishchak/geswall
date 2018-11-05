//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __log_h__
#define __log_h__

namespace Log {

    enum InfoType {
        typLog,
        typDebug,
		typAccessLog
    };

    enum LogLevel {
        llvDisabled     = 0,
        llvImportant    = 1,
        llvDetails      = 2,
        llvFull         = 3,
        llvFullDetails  = 4
    };

    enum DebugLevel {
        dlvDisabled     = 0,
		llvDebugger     = 1,
        dlvErrors       = 2,
        dlvAll          = 3
    };

    NTSTATUS Init(VOID);
    VOID Release(VOID);
    NTSTATUS Write(LogLevel Level, WCHAR *Format, ... );
	NTSTATUS AccessRecord(PEPROCESS Subject, EntityAttributes *Attr, ULONG RuleId, WCHAR *Format, ... );
    VOID SetLogLevel(LogLevel Level);
    BOOLEAN IsAllowedLogLevel(LogLevel Level);
    NTSTATUS DebugMessage(CHAR *Format, ... );
    VOID SetDebugLevel(DebugLevel Level);
    BOOLEAN IsAllowedDebugLevel(DebugLevel Level);

};


#endif