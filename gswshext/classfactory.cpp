//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "classfactory.h"
//#pragma data_seg()

#include "shellextmain.h"
#include "commonlib/debug.h" 

namespace shellext {

ClassFactory::ClassFactory ()
{
    inc_module_reference ();
} // ClassFactory

ClassFactory::~ClassFactory ()
{
    dec_module_reference ();
} // ~ClassFactory

STDMETHODIMP_(ULONG) ClassFactory::AddRef ()
{
    //return m_ref_counter.increment ();
    return commonlib::sync::ExternalAtomicCounter (m_ref_counter).increment ();
} // AddRef

STDMETHODIMP_(ULONG) ClassFactory::Release ()
{
    if (0 != (commonlib::sync::ExternalAtomicCounter (m_ref_counter)).decrement ())
        return m_ref_counter;
    //if (0 != m_ref_counter.decrement ())
    //    return m_ref_counter.value ();

    delete this;

    return 0L;
} // Release

STDMETHODIMP ClassFactory::LockServer (BOOL is_lock)
{
    return NOERROR;
} // LockServer

STDMETHODIMP ClassFactory::QueryInterface (REFIID riid, LPVOID FAR *ppv)
{
    *ppv = NULL;

    // Any interface on this object is the object pointer
    if (TRUE == IsEqualIID (riid, IID_IUnknown) || TRUE == IsEqualIID (riid, IID_IClassFactory))
    {
        *ppv = (void*) this;

        AddRef ();
        return NOERROR;
    }

    return E_NOINTERFACE;
} // QueryInterface

STDMETHODIMP ClassFactory::CreateInstance (LPUNKNOWN pUnkOuter, REFIID riid, LPVOID *ppvObj)
{
    *ppvObj = NULL;

    // Shell extensions typically don't support aggregation (inheritance)
    if (NULL != pUnkOuter)
    {
        return CLASS_E_NOAGGREGATION;
    }

    // Create the main shell extension object.  The shell will then call
    // QueryInterface with IID_IShellExtInit--this is how shell extensions are
    // initialized.
    GswShellExt* menu = new GswShellExt ();
    if (NULL == menu)
    {
        return E_OUTOFMEMORY;
    }
    return menu->QueryInterface (riid, ppvObj);
} // CreateInstance

} // namespace shellext

