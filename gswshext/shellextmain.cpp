//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "shellextmain.h"
#include "gswshellext.h"

#include "commonlib/commondefs.h"

namespace shellext {

typedef commonlib::IntrusiveAtomicCounter  AtomicCounter;

HINSTANCE     m_module_instance = NULL;
AtomicCounter m_module_ref_counter;

void process_attach (HINSTANCE module_instance)
{
    m_module_instance = module_instance;
	GswShellExt::GlobalInit();

} // proces_attach

void process_detach ()
{
	GswShellExt::GlobalRelease();
} // process_detach

unsigned long inc_module_reference ()
{
    return m_module_ref_counter.increment ();
} // inc_module_reference

unsigned long dec_module_reference ()
{
    return m_module_ref_counter.decrement ();
} // dec_module_reference

unsigned long get_module_reference ()
{
    return m_module_ref_counter.value ();
} // get_module_reference

} // namespace shellext
