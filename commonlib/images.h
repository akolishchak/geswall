//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __images_h__
#define __images_h__

#include <windows.h>

namespace commonlib {

HICON GetIcon(const wchar_t *FileName);
size_t GetIcon(const wchar_t *FileName, byte *Buf, size_t BufSize);

size_t Hicon2Bytes(const HICON hIcon, byte *Buf, size_t BufSize);
HICON Bytes2Hicon(byte *Buf, const size_t BufSize);

}; // namespace commonlib {

#endif // __images_h__
