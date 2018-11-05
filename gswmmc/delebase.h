//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _BRANCHES_H
#define _BRANCHES_H

#include <mmc.h>
#include <crtdbg.h>
#include "globals.h"
#include "resource.h"
#include "LocalRes.h"
#include "Comp.h"
#include "storage.h"
//#include "CompData.h"

class CDelegationBase {
public:
    CDelegationBase();
    virtual ~CDelegationBase();
    
    virtual const _TCHAR *GetDisplayName(int nCol = 0) = 0;
    virtual const GUID & getNodeType() { _ASSERT(FALSE); return IID_NULL; }
    
    virtual const LPARAM GetCookie() { return reinterpret_cast<LPARAM>(this); }
    virtual const int GetBitmapIndex() = 0;
	virtual CDelegationBase *GetChildPtr(int index) 
	{ 
		return NULL; 
	}
    virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions) { return S_FALSE; }

    // virtual functions go here (for MMCN_*)
    virtual HRESULT OnInitialExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, LPDATAOBJECT pDataObject) { return S_FALSE; }
    virtual HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent) { return S_FALSE; }
    virtual HRESULT OnShow(IConsole *pConsole, BOOL bShow, HSCOPEITEM scopeitem) { return S_FALSE; }
	virtual HRESULT OnViewChange(IConsole *pConsole, LPDATAOBJECT ipDataObject, LPARAM nArg, LPARAM nParam, LONG_PTR pComponent) { return S_FALSE; }
    virtual HRESULT OnAddImages(IImageList *pImageList, HSCOPEITEM hsi);
    virtual HRESULT OnRename(LPOLESTR pszNewName) { return S_FALSE; }
    virtual HRESULT OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect) { return S_FALSE; }
    //virtual HRESULT OnSelect(IConsole *pConsole, BOOL bScope, BOOL bSelect,LPDATAOBJECT pDataObject) { return S_FALSE; }
   // virtual HRESULT OnDoubleClick(IConsole *pConsole, LPDATAOBJECT pDataObject) { return S_FALSE; }
	virtual HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed) { return S_FALSE; }
    virtual HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT pDataObject, CComponentData *pComponentData) { return S_FALSE; }
	virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { _ASSERT(FALSE); }
    virtual HSCOPEITEM GetParentScopeItem() { _ASSERT(FALSE); return 0;}
	virtual HRESULT OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype) { return S_FALSE; }
    virtual HRESULT OnRefresh(IConsole *pConsole) { return S_FALSE; }
   
	// cut / copy / paste implementation
	virtual HRESULT OnPaste(IConsole *pConsole, CComponentData *pComponentData, CDelegationBase *pPasted) { return S_FALSE; }
	virtual HRESULT OnQueryPaste(CDelegationBase *pPasted) { return S_FALSE; }
	//virtual HRESULT OnDelete(IConsole *pConsole) { return S_FALSE; }
	virtual HRESULT OnDelete(CComponentData * pCompData, IConsole *pConsole){ return S_FALSE; }

	virtual HRESULT OnDeleteScopeItem(IConsoleNameSpace *pConsoleNameSpace) { _ASSERT(FALSE); return S_FALSE; }
	
	virtual HRESULT OnListpad(IConsole *pConsole, BOOL bAttaching) { return S_FALSE; }
	// taskpad support
    virtual HRESULT TaskNotify(IConsole *pConsole, VARIANT *v1, VARIANT *v2) { return S_FALSE; }
    virtual MMC_TASK *GetTaskList(LPOLESTR szTaskGroup, LONG *nCount) { return NULL; }
	virtual HRESULT GetTaskpadTitle(LPOLESTR *pszTitle) { return S_FALSE; }
	virtual HRESULT GetTaskpadDescription(LPOLESTR *pszDescription) { return S_FALSE; }
	virtual HRESULT GetTaskpadBackground(MMC_TASK_DISPLAY_OBJECT *pTDO) { return S_FALSE; }
	virtual HRESULT GetListpadInfo(MMC_LISTPAD_INFO *lpListPadInfo) { return S_FALSE; }

	virtual HRESULT GetApplicationItem(Storage::PtrToApplicationItem *p) { return 0;}
    virtual HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider,
        LONG_PTR handle) { return S_FALSE; }
    virtual HRESULT HasPropertySheets() { return S_FALSE; }
    virtual HRESULT GetWatermarks(HBITMAP *lphWatermark,
        HBITMAP *lphHeader,
        HPALETTE *lphPalette,
        BOOL *bStretch) { return S_FALSE; } 
    
    //virtual HRESULT OnPropertyChange(IConsole *pConsole) { return S_OK; }
    virtual HRESULT OnPropertyChange(IConsole *pConsole, CComponent *pComponent) { return S_OK; }

public:
    static HBITMAP m_pBMapSm;
    static HBITMAP m_pBMapLg;
    BOOL bEmpty;

	bool InitCom(void);
	INT_PTR ComDialogProc(WNDPROC WndProc, HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	DWORD MainThreadId;

protected:
    static void LoadBitmaps() {
        m_pBMapSm = LoadBitmap(g_hinst, MAKEINTRESOURCE(IDR_SMICONS));
        m_pBMapLg = LoadBitmap(g_hinst, MAKEINTRESOURCE(IDR_LGICONS));
    }
    
    BOOL bExpanded;
	IConsoleNameSpace * m_ipConsoleNameSpace;
    
private:
     
// {E591A0EC-41D0-43ff-A306-8E9522B7067B}
	static const GUID thisGuid;
	
	HWND ComWnd;
	static LRESULT CALLBACK ComProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

	enum {
		ComDialogProcMessage = WM_USER
	};

	struct ComDialogProcParams {
		WNDPROC WndProc;
		HWND hwndDlg;
		UINT uMsg;
		WPARAM wParam;
		LPARAM lParam;
		INT_PTR rc;
	};
};

#endif // _BRANCHES_H
