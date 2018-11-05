//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _RESOURCE_H
#define _RESOURCE_H

#include <list>
#include "stdafx.h"
#include "DeleBase.h"
#include "CompData.h"
#include "StatNode.h"
#include "rootfolder.h"
#include "storage.h"

class CResourceScope;
	

class CResourceResult : public CDelegationBase 
{
public:
    CResourceResult(Storage::PtrToResourceItem ri, CResourceScope *scope, CStaticNode *StaticNode);
    virtual ~CResourceResult();

    const _TCHAR *GetDisplayName(int nCol = 0);
    const GUID & getNodeType() { return thisGuid; }
    const int GetBitmapIndex() { return INDEX_RESOURCES; }
    
    // virtual functions go here (for MMCN_*)
    //virtual HRESULT OnSelect(IConsole *pConsole, BOOL bScope, BOOL bSelect,LPDATAOBJECT pDataObject);
    //virtual HRESULT OnDoubleClick(IConsole *pConsole, LPDATAOBJECT pDataObject); 
	virtual HRESULT OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect);
	virtual HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle);
    virtual HRESULT HasPropertySheets();
    virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
    virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }
	virtual HRESULT OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype);
    virtual HRESULT OnRefresh(IConsole *pConsole);      
    virtual HRESULT OnDelete(CComponentData * pCompData, IConsole *pConsoleComp);
	
	bool getDeletedStatus() { return isDeleted == TRUE; }
	void SetDeleted() { isDeleted = TRUE; }
	CResourceScope * GetScopeParent() { return m_pParent; }
		
	HRESULT GetResultViewType(/* [out] */ LPOLESTR __RPC_FAR *ppViewType,
                                   /* [out] */ long __RPC_FAR *pViewOptions);
	
	virtual HRESULT GetWatermarks(HBITMAP *lphWatermark,
        HBITMAP *lphHeader,
        HPALETTE *lphPalette,
        BOOL *bStretch);
    
    virtual HRESULT OnPropertyChange(IConsole *pConsole, CComponent *pComponent);

	//CRootFolder * m_RootNode;
    CComponent * m_Component;
	Storage::PtrToResourceItem m_Resource;
	int    nId;

private:
   // {23ECE3D8-0704-48fe-8EC6-465163EF5CAA} 
     static const GUID thisGuid;
	 BOOL isDeleted;
	 CResourceScope * m_pParent;
	 LONG_PTR m_ppHandle;
	 HSCOPEITEM m_hParentHScopeItem;
	 CStaticNode * m_StaticNode;
    
    static INT_PTR CALLBACK DialogProc(
        HWND hwndDlg,  // handle to dialog box
        UINT uMsg,     // message
        WPARAM wParam, // first message parameter
        LPARAM lParam  // second message parameter
        );
    
};

typedef std::list <CResourceResult *> RESLIST;

class CResourceScope : public CDelegationBase {
public:
    CResourceScope(CStaticNode *root);
    
    ~CResourceScope();
  
	HRESULT InvokeAddResource(IConsole *pConsole, IDataObject* piDataObject, CComponentData *pComponentData);
	HRESULT AddResource(const Storage::ResourceItem &RI);

    const _TCHAR *GetDisplayName(int nCol = 0) { return _T("Resources"); }
    const GUID & getNodeType() { return thisGuid; }
    const int GetBitmapIndex() { return INDEX_RESOURCES; }
   
	// virtual functions go here (for MMCN_*)
    HRESULT OnShow(IConsole *pConsole, BOOL bShow, HSCOPEITEM scopeitem);
	HRESULT OnViewChange(IConsole *pConsole, LPDATAOBJECT ipDataObject, LPARAM nArg, LPARAM nParam, LONG_PTR pComponent);
    HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle);
    HRESULT HasPropertySheets();
	HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);
	HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID,LPDATAOBJECT piDataObject, CComponentData *pComponentData);
	//virtual HRESULT OnDoubleClick(IConsole *pConsole, LPDATAOBJECT pDataObject); 
	void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
    HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }
	
	HRESULT GetWatermarks(HBITMAP *lphWatermark,
        HBITMAP *lphHeader,
        HPALETTE *lphPalette,
        BOOL *bStretch);

	static INT_PTR CALLBACK DialogProc(
        HWND hwndDlg,  // handle to dialog box
        UINT uMsg,     // message
        WPARAM wParam, // first message parameter
        LPARAM lParam  // second message parameter
        );
	HRESULT EnumerateResultItems(LPRESULTDATA pResultData);
	
    HRESULT GetResultViewType(/* [out] */ LPOLESTR __RPC_FAR *ppViewType,
                                   /* [out] */ long __RPC_FAR *pViewOptions);
	CStaticNode * m_StaticNode;
	RESLIST m_children;
	IPropertySheetProvider *PSProvider;
	IConsole * m_ipConsole;
	CComponentData *m_CompData;
	LPDATAOBJECT m_ipDataObject;
private:

	Storage::ResourceItemList ResourceList;
	Storage::PtrToResourceItem m_Resource;
	CResourceResult *RC;
	LPDATAOBJECT pDataObject;

    enum { IDM_NEW_SPACE = 4 };
    
    // {5580E218-08B7-4f07-AFFE-A4200D92ADF3}
	static const GUID thisGuid;
    
private:
   
   		HSCOPEITEM m_hParentHScopeItem;
		LONG_PTR m_ppHandle;
		IConsole * m_pConsole;
   
};

#endif // _RESOURCE_H

