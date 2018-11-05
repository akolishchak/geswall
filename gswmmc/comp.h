//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SAMPCOMP_H_
#define _SAMPCOMP_H_

#include <mmc.h>
#include "EnumTASK.h"

class CDataObject;

class CComponent : public IComponent,public IExtendPropertySheet2,public IExtendContextMenu,public IExtendTaskPad
{
private:
    ULONG				m_cref;
    
    public:
		
	IConsole*		m_ipConsole;
	IConsole2*		m_ipConsole2;
	class CComponentData *m_pParent;
    class CComponentData *m_pComponentData;
	class CDelegationBase *m_pLastNode;
  
    IDisplayHelp*	m_ipDisplayHelp;
    
    //store the view type: standard or taskpad
    BOOL m_bTaskpadView;
    //store the user's view type preference.
    BOOL m_bIsTaskpadPreferred;
    
		CComponentData *GetComponentData() { return m_pParent;}

        CComponent(CComponentData *parent);
        ~CComponent();
        ///////////////////////////////
        // Interface IUnknown
        ///////////////////////////////
        STDMETHODIMP QueryInterface(REFIID riid, LPVOID *ppv);
        STDMETHODIMP_(ULONG) AddRef();
        STDMETHODIMP_(ULONG) Release();
        
        ///////////////////////////////
        // Interface IComponent
        ///////////////////////////////
        HRESULT STDMETHODCALLTYPE Initialize(LPCONSOLE lpConsole);
            
        HRESULT STDMETHODCALLTYPE Notify( 
            /* [in] */ LPDATAOBJECT lpDataObject,
            /* [in] */ MMC_NOTIFY_TYPE event,
            /* [in] */ LPARAM arg,
            /* [in] */ LPARAM param);
            
        HRESULT STDMETHODCALLTYPE Destroy(MMC_COOKIE cookie);
            
        HRESULT STDMETHODCALLTYPE QueryDataObject( 
            /* [in] */ MMC_COOKIE cookie,
            /* [in] */ DATA_OBJECT_TYPES type,
            /* [out] */ LPDATAOBJECT __RPC_FAR *ppDataObject);
            
        HRESULT STDMETHODCALLTYPE GetResultViewType( 
            /* [in] */ MMC_COOKIE cookie,
            /* [out] */ LPOLESTR __RPC_FAR *ppViewType,
            /* [out] */ long __RPC_FAR *pViewOptions);
            
        HRESULT STDMETHODCALLTYPE GetDisplayInfo( 
            /* [out][in] */ RESULTDATAITEM __RPC_FAR *pResultDataItem);
            
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

			///////////////////////////////
            // Interface IExtendTaskPad
            ///////////////////////////////
			
			virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE TaskNotify( 
            /* [in] */ IDataObject __RPC_FAR *pdo,
            /* [in] */ VARIANT __RPC_FAR *arg,
            /* [in] */ VARIANT __RPC_FAR *param);
            
            virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE EnumTasks( 
            /* [in] */ IDataObject __RPC_FAR *pdo,
            /* [string][in] */ LPOLESTR szTaskGroup,
            /* [out] */ IEnumTASK __RPC_FAR *__RPC_FAR *ppEnumTASK);
            
            virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE GetTitle( 
            /* [string][in] */ LPOLESTR pszGroup,
            /* [string][out] */ LPOLESTR __RPC_FAR *pszTitle);
            
            virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE GetDescriptiveText( 
            /* [string][in] */ LPOLESTR pszGroup,
            /* [string][out] */ LPOLESTR __RPC_FAR *pszDescriptiveText);
            
            virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE GetBackground( 
            /* [string][in] */ LPOLESTR pszGroup,
            /* [out] */ MMC_TASK_DISPLAY_OBJECT __RPC_FAR *pTDO);
            
            virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE GetListPadInfo( 
            /* [string][in] */ LPOLESTR pszGroup,
            /* [out] */ MMC_LISTPAD_INFO __RPC_FAR *lpListPadInfo);
            
		
		LONG_PTR  GetScopeCookie()  { return m_pScopeCookie; }
		// multiselection
		HRESULT GetCurrentSelections(CDataObject *pMultiSelectDataObject);
	private:
		LONG_PTR m_pScopeCookie;
};

CComponent* MfxGetComponent(void);

#endif _SAMPCOMP_H_
