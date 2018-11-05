//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SAMPABOUT_H_
#define _SAMPABOUT_H_

#include <tchar.h>
#include <mmc.h>
#include "license/licensemanager.h"


class CSnapinAbout : public ISnapinAbout
{
private:
    ULONG				m_cref;
    HBITMAP				m_hSmallImage;
    HBITMAP				m_hLargeImage;
    HBITMAP				m_hSmallImageOpen;
    HICON				m_hAppIcon;
	license::LicenseManager::LicenseEssentials License;
    
public:
    CSnapinAbout();
    ~CSnapinAbout();
    
    ///////////////////////////////
    // Interface IUnknown
    ///////////////////////////////
    STDMETHODIMP QueryInterface(REFIID riid, LPVOID *ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();
    
    ///////////////////////////////
    // Interface ISnapinAbout
    ///////////////////////////////
    STDMETHODIMP GetSnapinDescription( 
        /* [out] */ LPOLESTR *lpDescription);
        
        STDMETHODIMP GetProvider( 
        /* [out] */ LPOLESTR *lpName);
        
        STDMETHODIMP GetSnapinVersion( 
        /* [out] */ LPOLESTR *lpVersion);
        
        STDMETHODIMP GetSnapinImage( 
        /* [out] */ HICON *hAppIcon);
        
        STDMETHODIMP GetStaticFolderImage( 
        /* [out] */ HBITMAP *hSmallImage,
        /* [out] */ HBITMAP *hSmallImageOpen,
        /* [out] */ HBITMAP *hLargeImage,
        /* [out] */ COLORREF *cMask);
        
        ///////////////////////////////
        // Private Interface 
        ///////////////////////////////
private:
    HRESULT	CSnapinAbout::AllocOleStr(
        LPOLESTR *lpDest, 
        _TCHAR *szBuffer);
};

#endif _SAMPABOUT_H_
