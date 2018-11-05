//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <objbase.h>
#include <olectl.h>
#include <initguid.h>
#include "guids.h"
#include "basesnap.h"
#include "Comp.h"
#include "CompData.h"
#include "About.h"
#include "Registry.h"
#include "config/w32registrynode.h"
#include "license/licensemanager.h"

// our globals

ULONG g_uObjects = 0;
ULONG g_uSrvLock = 0;

HINSTANCE g_hinst; 
CComponentData*	g_ComponentData = NULL;
CComponent*		g_Component = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, 
                    DWORD fdwReason, 
                    void* lpvReserved)
{
    
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hinst = hinstDLL;
    } else
	if (fdwReason == DLL_PROCESS_DETACH) {
	}
    
    return TRUE;
}


STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppvObj)
{
    if ((rclsid != CLSID_CComponentData) && (rclsid != CLSID_CSnapinAbout))
        return CLASS_E_CLASSNOTAVAILABLE;
    
    
    if (!ppvObj)
        return E_FAIL;
    
    *ppvObj = NULL;
    
    // We can only hand out IUnknown and IClassFactory pointers.  Fail
    // if they ask for anything else.
    if (!IsEqualIID(riid, IID_IUnknown) && !IsEqualIID(riid, IID_IClassFactory))
        return E_NOINTERFACE;
    
    CClassFactory *pFactory = NULL;
    
    // make the factory passing in the creation function for the type of object they want
    if (rclsid == CLSID_CComponentData)
        pFactory = new CClassFactory(CClassFactory::COMPONENT);
    else if (rclsid == CLSID_CSnapinAbout)
        pFactory = new CClassFactory(CClassFactory::ABOUT);
    
    if (NULL == pFactory)
        return E_OUTOFMEMORY;
    
    HRESULT hr = pFactory->QueryInterface(riid, ppvObj);
    
    return hr;
}

STDAPI DllCanUnloadNow(void)
{
    if (g_uObjects == 0 && g_uSrvLock == 0)
        return S_OK;
    else
        return S_FALSE;
}


CClassFactory::CClassFactory(FACTORY_TYPE factoryType)
: m_cref(0), m_factoryType(factoryType)
{
    OBJECT_CREATED
}

CClassFactory::~CClassFactory()
{
    OBJECT_DESTROYED
}

STDMETHODIMP CClassFactory::QueryInterface(REFIID riid, LPVOID *ppv)
{
    if (!ppv)
        return E_FAIL;
    
    *ppv = NULL;
    
    if (IsEqualIID(riid, IID_IUnknown))
        *ppv = static_cast<IClassFactory *>(this);
    else
        if (IsEqualIID(riid, IID_IClassFactory))
            *ppv = static_cast<IClassFactory *>(this);
        
        if (*ppv)
        {
            reinterpret_cast<IUnknown *>(*ppv)->AddRef();
            return S_OK;
        }
        
        return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CClassFactory::AddRef()
{
    return InterlockedIncrement((LONG *)&m_cref);
}

STDMETHODIMP_(ULONG) CClassFactory::Release()
{
    if (InterlockedDecrement((LONG *)&m_cref) == 0)
    {
        delete this;
        return 0;
    }
    return m_cref;
}

STDMETHODIMP CClassFactory::CreateInstance(LPUNKNOWN pUnkOuter, REFIID riid, LPVOID * ppvObj)
{
    HRESULT  hr;
    void* pObj;
    
    if (!ppvObj)
        return E_FAIL;
    
    *ppvObj = NULL;
    
    // Our object does does not support aggregation, so we need to
    // fail if they ask us to do aggregation.
    if (pUnkOuter)
        return CLASS_E_NOAGGREGATION;
    
    if (COMPONENT == m_factoryType) {
        pObj = new CComponentData();
    } else {
        pObj = new CSnapinAbout();
    }
    
    if (!pObj)
        return E_OUTOFMEMORY;
    
    // QueryInterface will do the AddRef() for us, so we do not
    // do it in this function
    hr = ((LPUNKNOWN)pObj)->QueryInterface(riid, ppvObj);
    
    if (FAILED(hr))
        delete pObj;
    
    return hr;
}

STDMETHODIMP CClassFactory::LockServer(BOOL fLock)
{
    if (fLock)
        InterlockedIncrement((LONG *)&g_uSrvLock);
    else
        InterlockedDecrement((LONG *)&g_uSrvLock);
    
    return S_OK;
}

//
// Snapin mode
//
SnapinMode GetSnapinMode(void)
{
//	config::W32RegistryNode Reg(HKEY_LOCAL_MACHINE, std::wstring(L"SOFTWARE\\Microsoft\\MMC\\SnapIns"));
//	if ( !Reg.checkNode(L"{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}") ) Mode = snmStandAlone;
	//
	// Read license file product info
	//
	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCopy(License);
	license::ProductType Product = License.Product;
	if ( Product == license::gswServer || Product == license::gswEnterprise ) return snmGPExtension;
	return snmStandAlone;
}

//////////////////////////////////////////////////////////
//
// Exported functions
//


//
// Server registration
//
STDAPI DllRegisterServer()
{
    HRESULT hr = SELFREG_E_CLASS;
    _TCHAR szName[256];
    _TCHAR szSnapInName[256];
    
    LoadString(g_hinst, IDS_NAME, szName, (sizeof szName)/(sizeof szName[0]));
    LoadString(g_hinst, IDS_SNAPINNAME, szSnapInName, (sizeof szSnapInName)/(sizeof szSnapInName[0]));
    
    _TCHAR szAboutName[256];
    
    LoadString(g_hinst, IDS_ABOUTNAME, szAboutName, (sizeof szAboutName)/(sizeof szAboutName[0]));
    
    // register our CoClasses
    hr = RegisterServer(g_hinst, 
        CLSID_CComponentData, 
        szName);
    
    if SUCCEEDED(hr)
        hr = RegisterServer(g_hinst, 
        CLSID_CSnapinAbout, 
        szAboutName);
    
    // place the registry information for SnapIns
    if SUCCEEDED(hr)
        hr = RegisterSnapin(CLSID_CComponentData, szSnapInName, CLSID_CSnapinAbout, 
							CLSID_CCGroupPolicy, L"GeSWall Policies", FALSE);
    
    return hr;
}


STDAPI DllUnregisterServer()
{
    if (UnregisterServer(CLSID_CComponentData) == S_OK)
        return UnregisterSnapin(CLSID_CComponentData);
    else
        return E_FAIL;
}

//
// this functions returns the last used Component and ComponentData objects
//

CComponent* MfxGetComponent()
{
	return g_Component;
}

CComponentData* MfxGetComponentData()
{
	return g_ComponentData;
}
