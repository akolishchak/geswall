//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _APP_H_
#define _APP_H_
#include <list>
#include "stdafx.h"
#include "DeleBase.h"
#include "CompData.h"
#include "StatNode.h"
#include "rootfolder.h"
#include "storage.h"

class CApplicationRule;
typedef std::list<CDelegationBase *> BASELIST;
typedef std::list<CApplicationRule *> RULELIST;


class CApplicationFolder : public CDelegationBase {
	friend class CApplicationItem;
	friend class CGroupFolder;

public:
    CApplicationFolder(CStaticNode *StaticNode);
    virtual HRESULT OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect);
	virtual HRESULT OnPaste(IConsole *pConsole, CComponentData *pComponentData, CDelegationBase *pPasted);
	virtual HRESULT OnQueryPaste(CDelegationBase *pPasted);
	virtual HRESULT OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype);
	virtual HRESULT OnDeleteScopeItem(IConsoleNameSpace *pConsoleNameSpace);
	
    virtual ~CApplicationFolder();
    
    const _TCHAR *GetDisplayName(int nCol = 0) { return _T("Applications"); }
    const GUID & getNodeType() { return thisGuid; }
    const int GetBitmapIndex() { return INDEX_APPLICATIONS; }
    void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }    HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }	HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);
	HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle);    HRESULT HasPropertySheets();	HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);	HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID,LPDATAOBJECT piDataObject, CComponentData *pComponentData);	HRESULT GetWatermarks(HBITMAP *lphWatermark,HBITMAP *lphHeader,HPALETTE *lphPalette,BOOL *bStretch);
	HRESULT InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page);
	HRESULT CreateGroup(Storage::ApplicationItem &appItem);
	HRESULT CreateApplication(Storage::ApplicationItem &appItem);

	
	static INT_PTR CALLBACK GroupDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );
	
	static INT_PTR CALLBACK ApplicationDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );
public:
	BASELIST m_children;
	
private:
   
   // {6DE8BA0D-31CA-411c-B7B8-D6C462C1A23B}
	static const GUID thisGuid;
     HRESULT Expand(IConsoleNameSpace *pConsoleNameSpace);

	IPropertySheetProvider *PSProvider;
	Storage::ApplicationItemList ApplicationList;
	Storage::ApplicationItem newApp;
    Storage::ApplicationItem newGroup;
	HSCOPEITEM m_hParentHScopeItem;
	CStaticNode * m_StaticNode;
    LONG_PTR m_ppHandle;
	LPDATAOBJECT m_ipDataObject;
	IConsole * m_ipConsole;
	IConsoleNameSpace * m_ipConsoleNameSpace;
	int ActivePage;
	static bool ActiveDialog;
};

class CGroupFolder : public CDelegationBase {
friend class CApplicationItem;
friend class CApplicationFolder;

public:
	CGroupFolder(Storage::PtrToApplicationItem appItem, CDelegationBase * parent, CStaticNode *StaticNode);
	virtual ~CGroupFolder(){};
    
    virtual HRESULT OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect);
	virtual HRESULT OnPaste(IConsole *pConsole, CComponentData *pComponentData, CDelegationBase *pPasted);
	virtual HRESULT OnQueryPaste(CDelegationBase *pPasted);
	virtual HRESULT OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype);
	virtual HRESULT OnDeleteScopeItem(IConsoleNameSpace *pConsoleNameSpace);
	virtual HRESULT OnDelete(CComponentData * pCompData, IConsole *pConsole);

	virtual const _TCHAR *GetDisplayName(int nCol = 0) { return ApplicationItem->Params.Description; }
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_CLOSEDFOLDER; }
    virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }    virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }    virtual HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);
	virtual HRESULT GetApplicationItem(Storage::PtrToApplicationItem *p)
	{ *p = ApplicationItem; return S_OK;}
	HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle);    HRESULT HasPropertySheets();	HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);	HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID,LPDATAOBJECT piDataObject, CComponentData *pComponentData);	HRESULT GetWatermarks(HBITMAP *lphWatermark,HBITMAP *lphHeader,HPALETTE *lphPalette,BOOL *bStretch);	HRESULT OnPropertyChange(IConsole *pConsole, CComponent *pComponent);
	
	HRESULT InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page);
	HRESULT CreateGroup(Storage::ApplicationItem &appItem);
	HRESULT CreateApplication(Storage::ApplicationItem &appItem);
	
	static INT_PTR CALLBACK GroupDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );
	static INT_PTR CALLBACK GroupPropDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );
	static INT_PTR CALLBACK ApplicationDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );

public:
	BASELIST m_children;		
	BASELIST m_ParentList;		
	CDelegationBase * m_parent;
	
	
private:
   
   // {6DE8BA0D-31CA-411c-B7B8-D6C462C1A23B}
	static const GUID thisGuid;
    HRESULT Expand(IConsoleNameSpace *pConsoleNameSpace);

	
	IPropertySheetProvider *PSProvider;
	Storage::PtrToApplicationItem ApplicationItem;
	Storage::ApplicationItemList ApplicationList;
	Storage::ApplicationItem newApp;
    Storage::ApplicationItem newGroup;
    HSCOPEITEM m_hParentHScopeItem;
	CStaticNode *m_StaticNode;
	LONG_PTR m_ppHandle;
	LPDATAOBJECT m_ipDataObject;
	IConsole * m_ipConsole;
	int ActivePage;
	static bool ActiveDialog;
	 

};

class CApplicationItem : public CDelegationBase {
	friend class CGroupFolder;
	friend class CApplicationFolder;

public:
	CApplicationItem(Storage::PtrToApplicationItem appItem, CDelegationBase * parent, CStaticNode *StaticNode);
	virtual ~CApplicationItem(){};
    bool CApplicationItem::CreateApplicationRule(Storage::ResourceItem &Res);

    virtual HRESULT OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect);
	virtual HRESULT OnPaste(IConsole *pConsole, CComponentData *pComponentData, CDelegationBase *pPasted){ return S_FALSE;};
	virtual HRESULT OnQueryPaste(CDelegationBase *pPasted){ return S_FALSE;};
	virtual HRESULT OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype){ return S_FALSE;};
	virtual HRESULT OnDeleteScopeItem(IConsoleNameSpace *pConsoleNameSpace);
	virtual HRESULT OnDelete(CComponentData * pCompData, IConsole *pConsole);

	virtual const _TCHAR *GetDisplayName(int nCol = 0) { return ApplicationItem->Params.Description;  }
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_APPLICATIONS; }
    virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }    virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }	//virtual HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);
	HRESULT OnShow(IConsole *pConsole, BOOL bShow, HSCOPEITEM scopeitem);
	HRESULT OnViewChange(IConsole *pConsole, LPDATAOBJECT ipDataObject, LPARAM nArg, LPARAM nParam, LONG_PTR pComponent);
    HRESULT EnumerateResultItems(LPRESULTDATA pResultData);
	virtual HRESULT GetApplicationItem(Storage::PtrToApplicationItem *p)
	{ *p = ApplicationItem; return S_OK;}
	HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle);    HRESULT HasPropertySheets();	HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);	HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID,LPDATAOBJECT piDataObject, CComponentData *pComponentData);	HRESULT GetWatermarks(HBITMAP *lphWatermark,HBITMAP *lphHeader,HPALETTE *lphPalette,BOOL *bStretch);	HRESULT OnPropertyChange(IConsole *pConsole, CComponent *pComponent);
	HRESULT InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page);
	static INT_PTR CALLBACK RuleDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );
	static INT_PTR CALLBACK ApplicationDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );

public:

	CDelegationBase * m_parent;
	RULELIST m_children;
  
private:
    
   // {6DE8BA0D-31CA-411c-B7B8-D6C462C1A23B}
	static const GUID thisGuid;
    
	
	IPropertySheetProvider *PSProvider;
	Storage::PtrToApplicationItem ApplicationItem;
	HSCOPEITEM m_hParentHScopeItem;
	CStaticNode *m_StaticNode;
	//CDelegationBase * m_pParent;
	LONG_PTR m_ppHandle;
   	Storage::ResourceItemList ResourceList;
	Storage::ResourceItem newRule;
	int ActivePage;
	static bool ActiveDialog;

	LPDATAOBJECT m_ipDataObject;
	IConsole * m_ipConsole;
	CComponentData *m_CompData;
		
};


class CApplicationRule : public CDelegationBase {
public:
CApplicationRule::CApplicationRule(Storage::PtrToResourceItem ri,CApplicationItem *parent, CStaticNode *StaticNode);

	virtual ~CApplicationRule(){};
    
    virtual const _TCHAR *GetDisplayName(int nCol = 0); 
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_RULES; }
    virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }    virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }	//virtual HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);
	HRESULT CApplicationRule::OnSelect(CComponent *pComponent, IConsole *pConsole, BOOL bScope, BOOL bSelect);
	bool getDeletedStatus() { return isDeleted == TRUE; }
	void SetDeleted() { isDeleted = TRUE; }
	HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle);    HRESULT HasPropertySheets();	HRESULT GetWatermarks(HBITMAP *lphWatermark,HBITMAP *lphHeader,HPALETTE *lphPalette,BOOL *bStretch);	virtual HRESULT OnPropertyChange(IConsole *pConsole, CComponent *pComponent);
	virtual HRESULT OnUpdateItem(IConsole *pConsole, long item, ITEM_TYPE itemtype);
    virtual HRESULT OnDelete(CComponentData * pCompData, IConsole *pConsoleComp);
	virtual HRESULT OnRefresh(IConsole *pConsole);

	static INT_PTR CALLBACK RuleDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );

private:
    
   // {6DE8BA0D-31CA-411c-B7B8-D6C462C1A23B}
	static const GUID thisGuid;
    
	
	Storage::PtrToResourceItem m_Resource;
	HSCOPEITEM m_hParentHScopeItem;
	CStaticNode *m_StaticNode;
	CRootFolder * m_RootNode;
	CApplicationItem * m_pParent;
	LONG_PTR m_ppHandle;
	BOOL isDeleted;
	
};
#endif //_APP_H_
