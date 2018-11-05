//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _PROCLIST_H
#define _PROCLIST_H
#include <commctrl.h>
#include "DeleBase.h"
#include "commonlib/gswdrv.h"

class CProcList : public CDelegationBase {

	struct TaskItem {
		DWORD ProcessID;
		DWORD ModuleID;
		DWORD ParentProcessID;
		std::wstring TaskPath;
		std::wstring TaskName;
		std::wstring Caption;
		bool operator < (const TaskItem &r) { return TaskName < r.TaskName; };
	};

	std::vector<TaskItem> TaskArray;

public:
    CProcList();
    virtual ~CProcList();

    virtual const _TCHAR *GetDisplayName(int nCol = 0) { return _T("Isolated Applications"); }
    virtual const GUID & getNodeType() { return thisGuid; }
	virtual const int GetBitmapIndex() { return INDEX_PROCLIST; }
	virtual LPOLESTR CreateWWWPath(LPOLESTR szResource);

   virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions);
	  // taskpad support
   virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
   virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }
   LPOLESTR CreateResourcePath
					( 
						HINSTANCE hInst,         //[in] Global instance handle
						LPOLESTR szResource      //[in] Path to stored resource
					); 

//	virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions);
	  // taskpad support
    virtual HRESULT TaskNotify(IConsole *pConsole, VARIANT *v1, VARIANT *v2);
    virtual MMC_TASK *GetTaskList(LPOLESTR szTaskGroup, LONG *nCount);
	virtual HRESULT GetTaskpadTitle(LPOLESTR *pszTitle);
	virtual HRESULT GetTaskpadDescription(LPOLESTR *pszDescription);
	virtual HRESULT GetTaskpadBackground(MMC_TASK_DISPLAY_OBJECT *pTDO);
	virtual HRESULT GetListpadInfo(MMC_LISTPAD_INFO *lpListPadInfo);
    virtual HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);
    virtual HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID, LPDATAOBJECT piDataObject, CComponentData *pComData);

	bool GetVersionInfoString(const wchar_t* fname, Storage::ApplicationItem &Item);
	bool AddToString(std::wstring &fullstr, const wchar_t* name1, const wchar_t* name2);
	bool CheckPath(std::wstring &chkstr);
	bool CheckIsolated(DWORD procid);

private:
    int KillTask(TaskItem Taskem);
	bool GetAllTasks();
	void TerminateAll(void);
	IConsoleNameSpace * m_ipConsoleNameSpace;
	IConsole * m_ipConsole;

// {B2598F87-0A91-451c-9B62-41EB0FA739CF}
    static const GUID thisGuid;
	HSCOPEITEM m_hParentHScopeItem;
	std::wstring InstallDir; 
	CGswDrv Drv;

    //  {5D210590-D77D-4cbd-8354-9D30B4B3A165}
//	CStaticNode * m_parent;
	IPropertySheetProvider *PSProvider;

	bool cycflag;
	static BOOL CALLBACK etw(HWND wnd, LPARAM lParam);
	static DWORD CurrentPID;
	static std::wstring CurrentWnd;

};

#endif // _PROCLIST_H