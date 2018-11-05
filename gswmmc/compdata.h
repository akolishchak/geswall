//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SAMPCOMPDATA_H_
#define _SAMPCOMPDATA_H_

#include <mmc.h>
#include "DeleBase.h"
#include "StatNode.h"
#include "comp.h"

class CComponentData : public IComponentData, IExtendPropertySheet2, IExtendContextMenu, ISnapinHelp2
{
    friend class CComponent;
     
private:
    ULONG				m_cref;
    LPCONSOLENAMESPACE	m_ipConsoleNameSpace;
    CStaticNode     *m_pStaticNode;
//	CRootFolder		*m_pRootFolder;
	CComponent*		m_pComponent;
	BOOL			m_bInitialExpand;

    HRESULT ExtractObjectTypeGUID( IDataObject* piDataObject, GUID* pguidObjectType );
    HRESULT ExtractSnapInCLSID( IDataObject* piDataObject, CLSID* pclsidSnapin );
    HRESULT ExtractString( IDataObject *piDataObject, CLIPFORMAT cfClipFormat, _TCHAR *pstr, DWORD cchMaxLength);
    HRESULT ExtractData( IDataObject* piDataObject, CLIPFORMAT cfClipFormat, BYTE* pbData, DWORD cbData );

	// clipboard format
    static UINT s_cfDisplayName;
    static UINT s_cfSnapInCLSID;
    static UINT s_cfNodeType;

    // {8FC0B739-A0E1-11D1-A7D3-0000F87571E3}
    static const GUID gpGuid;

public:
	 LPCONSOLE			m_ipConsole;

    CComponentData();
    ~CComponentData();

    LPCONSOLENAMESPACE GetConsoleNameSpace()
    {
        return m_ipConsoleNameSpace;
    }
	const GUID & getPrimaryNodeType() { return gpGuid; }
    //HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);

    ///////////////////////////////
    // Interface IUnknown
    ///////////////////////////////
    STDMETHODIMP QueryInterface(REFIID riid, LPVOID *ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();
    
    ///////////////////////////////
    // Interface IComponentData
    ///////////////////////////////
    HRESULT STDMETHODCALLTYPE Initialize(LPUNKNOWN pUnknown);
        
	HRESULT STDMETHODCALLTYPE CreateComponent(LPCOMPONENT __RPC_FAR *ppComponent);
        
    HRESULT STDMETHODCALLTYPE Notify( 
        /* [in] */ LPDATAOBJECT lpDataObject,
        /* [in] */ MMC_NOTIFY_TYPE event,
        /* [in] */ LPARAM arg,
        /* [in] */ LPARAM param);
        
    HRESULT STDMETHODCALLTYPE Destroy( void);
    
    HRESULT STDMETHODCALLTYPE QueryDataObject( 
        /* [in] */ MMC_COOKIE cookie,
        /* [in] */ DATA_OBJECT_TYPES type,
        /* [out] */ LPDATAOBJECT __RPC_FAR *ppDataObject);
        
    HRESULT STDMETHODCALLTYPE GetDisplayInfo( 
        /* [out][in] */ SCOPEDATAITEM __RPC_FAR *pScopeDataItem);
        
    HRESULT STDMETHODCALLTYPE CompareObjects( 
        /* [in] */ LPDATAOBJECT lpDataObjectA,
        /* [in] */ LPDATAOBJECT lpDataObjectB);
        
        //////////////////////////////////
        // Interface IExtendPropertySheet2
        //////////////////////////////////
    HRESULT STDMETHODCALLTYPE CreatePropertyPages( 
        /* [in] */ LPPROPERTYSHEETCALLBACK lpProvider,
        /* [in] */ LONG_PTR handle,
        /* [in] */ LPDATAOBJECT lpIDataObject);
        
    HRESULT STDMETHODCALLTYPE QueryPagesFor( 
        /* [in] */ LPDATAOBJECT lpDataObject);
        
    HRESULT STDMETHODCALLTYPE GetWatermarks( 
        /* [in] */ LPDATAOBJECT lpIDataObject,
        /* [out] */ HBITMAP __RPC_FAR *lphWatermark,
        /* [out] */ HBITMAP __RPC_FAR *lphHeader,
        /* [out] */ HPALETTE __RPC_FAR *lphPalette,
        /* [out] */ BOOL __RPC_FAR *bStretch);

		///////////////////////////////
        // Interface IExtendContextMenu
        ///////////////////////////////
    HRESULT STDMETHODCALLTYPE AddMenuItems( 
        /* [in] */ LPDATAOBJECT piDataObject,
        /* [in] */ LPCONTEXTMENUCALLBACK piCallback,
        /* [out][in] */ long __RPC_FAR *pInsertionAllowed);
        
    HRESULT STDMETHODCALLTYPE Command( 
        /* [in] */ long lCommandID,
        /* [in] */ LPDATAOBJECT piDataObject);

    HRESULT STDMETHODCALLTYPE GetHelpTopic( 
        /* [out] */ LPOLESTR __RPC_FAR *lpCompiledHelpFile);

    HRESULT STDMETHODCALLTYPE GetLinkedTopics( 
		/* [out] */ LPOLESTR __RPC_FAR *lpCompiledHelpFiles) { return S_FALSE; }
};
CComponentData* MfxGetComponentData(void);

#endif _SAMPCOMPDATA_H_
