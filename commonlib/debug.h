//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __debug_h__
#define __debug_h__

namespace commonlib {

namespace Debug {

enum {
	outNone			= 0,
	outDebugger		= 1,
	outFile			= 2,
	outConsole		= 4
};

void SetMode(int _Mode);
void SetLogName(const wchar_t *Name);

void Write (int _Mode, const char *fmt, ...);
void Write (const char *fmt, ...);
void Write (wchar_t* format, ...);
void WriteFile(char *Buf);
void WriteFile(const char *fmt, ...);

#if _DEBUG  
 void _debugString (const wchar_t* format, ...);
 #define debugString(params) commonlib::Debug::_debugString params
#else
 #define debugString(params)
#endif // _DEBUG  

};

}; // namespace commonlib {

#endif // __debug_h__