//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "About.h"
#include "resource.h" 
#include "globals.h"
#include <crtdbg.h>
#include <string>

CSnapinAbout::CSnapinAbout()
: m_cref(0)
{
    OBJECT_CREATED

    m_hSmallImage = (HBITMAP)LoadImage(g_hinst, MAKEINTRESOURCE(IDB_SMBMP), IMAGE_BITMAP, 16, 16, LR_LOADTRANSPARENT);
    m_hLargeImage = (HBITMAP)LoadImage(g_hinst, MAKEINTRESOURCE(IDB_LGBMP), IMAGE_BITMAP, 32, 32, LR_LOADTRANSPARENT);

    //m_hSmallImageOpen = (HBITMAP)LoadImage(g_hinst, MAKEINTRESOURCE(IDB_SMOPEN), IMAGE_BITMAP, 16, 16, LR_LOADTRANSPARENT);
	m_hSmallImageOpen = (HBITMAP)LoadImage(g_hinst, MAKEINTRESOURCE(IDB_SMBMP), IMAGE_BITMAP, 16, 16, LR_LOADTRANSPARENT);

    m_hAppIcon = LoadIcon(g_hinst, MAKEINTRESOURCE(IDI_ICON));

	license::LicenseManager::getLicenseEssentials(License);
}

CSnapinAbout::~CSnapinAbout()
{
    if (m_hSmallImage != NULL)
        FreeResource(m_hSmallImage);

    if (m_hLargeImage != NULL)
        FreeResource(m_hLargeImage);

    if (m_hSmallImageOpen != NULL)
        FreeResource(m_hSmallImageOpen);

    if (m_hAppIcon != NULL)
        FreeResource(m_hAppIcon);

    m_hSmallImage = NULL;
    m_hLargeImage = NULL;
    m_hSmallImageOpen = NULL;
    m_hAppIcon = NULL;

    OBJECT_DESTROYED
}

///////////////////////
// IUnknown implementation
///////////////////////

STDMETHODIMP CSnapinAbout::QueryInterface(REFIID riid, LPVOID *ppv)
{
    if (!ppv)
        return E_FAIL;

    *ppv = NULL;

    if (IsEqualIID(riid, IID_IUnknown))
        *ppv = static_cast<ISnapinAbout *>(this);
    else if (IsEqualIID(riid, IID_ISnapinAbout))
        *ppv = static_cast<ISnapinAbout *>(this);

    if (*ppv)
    {
        reinterpret_cast<IUnknown *>(*ppv)->AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CSnapinAbout::AddRef()
{
    return InterlockedIncrement((LONG *)&m_cref);
}

STDMETHODIMP_(ULONG) CSnapinAbout::Release()
{
    if (InterlockedDecrement((LONG *)&m_cref) == 0)
    {
        // we need to decrement our object count in the DLL
        delete this;
        return 0;
    }
    return m_cref;

}

///////////////////////////////
// Interface ISnapinAbout
///////////////////////////////
STDMETHODIMP CSnapinAbout::GetSnapinDescription(
                                                /* [out] */ LPOLESTR *lpDescription)
{
    //_TCHAR szDesc[MAX_PATH];
    //LoadString(g_hinst, IDS_SNAPINDESC, szDesc, (sizeof szDesc)/(sizeof szDesc[0]));
	std::wstring Str = L"GeSWall Security Policy maintains confidentiality of your data, prevents damage from intrusions and malicious software: viruses, worms, spyware, key loggers and etc.";
	Str += L"\r\n\r\nLicensed to: " + License.LicensedTo;
	//if ( 


	return AllocOleStr(lpDescription, (TCHAR *)Str.c_str());
}


STDMETHODIMP CSnapinAbout::GetProvider(
                                       /* [out] */ LPOLESTR *lpName)
{
    return AllocOleStr(lpName, _T("Copyright (C) GentleSecurity Sarl"));;
}


STDMETHODIMP CSnapinAbout::GetSnapinVersion(
                                            /* [out] */ LPOLESTR *lpVersion)
{
	return AllocOleStr(lpVersion, (TCHAR *)License.Version.c_str());
}


STDMETHODIMP CSnapinAbout::GetSnapinImage(
                                          /* [out] */ HICON *hAppIcon)
{
    *hAppIcon = m_hAppIcon;

    if (*hAppIcon == NULL)
        return E_FAIL;
    else
        return S_OK;
}


STDMETHODIMP CSnapinAbout::GetStaticFolderImage(
                                                /* [out] */ HBITMAP *hSmallImage,
                                                /* [out] */ HBITMAP *hSmallImageOpen,
                                                /* [out] */ HBITMAP *hLargeImage,
                                                /* [out] */ COLORREF *cMask)
{
    *hSmallImage = m_hSmallImage;
    *hLargeImage = m_hLargeImage;

    *hSmallImageOpen = m_hSmallImageOpen;

    *cMask = RGB(0, 128, 128);

    if (*hSmallImage == NULL || *hLargeImage == NULL || *hSmallImageOpen == NULL)
        return E_FAIL;
    else
        return S_OK;
}

// this allocates a chunk of memory using CoTaskMemAlloc and copies our chars into it
HRESULT CSnapinAbout::AllocOleStr(LPOLESTR *lpDest, _TCHAR *szBuffer)
{
        MAKE_WIDEPTR_FROMTSTR_ALLOC(wszStr, szBuffer);
        *lpDest = wszStr;


    return S_OK;
}