//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswshext_h__
 #define __gswshext_h__

#include <windows.h>

namespace shellext {

void process_attach (HINSTANCE module_instance);
void process_detach ();

unsigned long inc_module_reference ();
unsigned long dec_module_reference ();
unsigned long get_module_reference ();

extern HINSTANCE m_module_instance;

} // namespace shellext

#endif // __gswshext_h__