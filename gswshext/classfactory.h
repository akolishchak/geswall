//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __shellext_classfactory_h__
 #define __shellext_classfactory_h__

#include "commonlib/commondefs.h"
#include "gswshellext.h"

namespace shellext {

class ClassFactory : public IClassFactory
{
  private:
    typedef commonlib::IntrusiveAtomicCounter  AtomicCounter;

  public:   
    ClassFactory ();
    virtual ~ClassFactory ();

    //IUnknown members
    STDMETHODIMP            QueryInterface (REFIID, LPVOID FAR *);
    STDMETHODIMP_(ULONG)    AddRef ();
    STDMETHODIMP_(ULONG)    Release ();

    //IClassFactory members
    STDMETHODIMP            CreateInstance (LPUNKNOWN, REFIID, LPVOID FAR *);
    STDMETHODIMP            LockServer (BOOL is_lock);

  private:
    //AtomicCounter m_ref_counter;
    long          m_ref_counter;
}; // class ClassFactory

} // namespace shellext

#endif // __shellext_classfactory_h__