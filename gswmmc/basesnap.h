//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _BASESNAP_H_
#define _BASESNAP_H_

enum SnapinMode {
	snmStandAlone,
	snmGPExtension
};

SnapinMode GetSnapinMode(void);

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppvObj);
STDAPI DllCanUnloadNow(void);

extern ULONG g_uObjects;
extern ULONG g_uSrvLock;

class CClassFactory : public IClassFactory
{
private:
    ULONG	m_cref;
    
public:
    enum FACTORY_TYPE {COMPONENT = 0, ABOUT = 1};
    
    CClassFactory(FACTORY_TYPE factoryType);
    ~CClassFactory();
    
    STDMETHODIMP QueryInterface(REFIID riid, LPVOID *ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();
    
    STDMETHODIMP CreateInstance(LPUNKNOWN, REFIID, LPVOID *);
    STDMETHODIMP LockServer(BOOL);
    
private:
    FACTORY_TYPE m_factoryType;
};

#endif _BASESNAP_H_
