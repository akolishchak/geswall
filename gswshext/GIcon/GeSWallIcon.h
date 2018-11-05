//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#pragma once
#include "resource.h"       // main symbols

#include "GIcon.h"


#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
#endif



// CGeSWallIcon

class ATL_NO_VTABLE CGeSWallIcon :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CGeSWallIcon, &CLSID_GeSWallIcon>,
	public IShellIconOverlayIdentifier, 
	public IGeSWallIcon
{
public:
	CGeSWallIcon()
	{
	}

  // IShellIconOverlayIdentifier Methods
  STDMETHOD(GetOverlayInfo)(LPWSTR pwszIconFile, 
           int cchMax,int *pIndex,DWORD* pdwFlags);
  STDMETHOD(GetPriority)(int* pPriority);
  STDMETHOD(IsMemberOf)(LPCWSTR pwszPath,DWORD dwAttrib);

DECLARE_REGISTRY_RESOURCEID(IDR_GESWALLICON)

DECLARE_NOT_AGGREGATABLE(CGeSWallIcon)

BEGIN_COM_MAP(CGeSWallIcon)
	COM_INTERFACE_ENTRY(IGeSWallIcon)
	COM_INTERFACE_ENTRY_IID(IID_IShellIconOverlayIdentifier,IShellIconOverlayIdentifier)
END_COM_MAP()



	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

public:

};

OBJECT_ENTRY_AUTO(__uuidof(GeSWallIcon), CGeSWallIcon)
