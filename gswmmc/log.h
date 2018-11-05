//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _LOG_H
#define _LOG_H
#include <commctrl.h>
#include "DeleBase.h"
#include "Comp.h"
#include "CompData.h"
#include "rootfolder.h"

class CLog : public CDelegationBase {
public:
    CLog();
    virtual ~CLog();

    virtual const _TCHAR *GetDisplayName(int nCol = 0) { return _T("Logs"); }
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_LOG; }

	HRESULT CreatePropertyPages(IPropertySheetCallback *lpProvider, LONG_PTR handle);    HRESULT HasPropertySheets();	HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);	HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID,LPDATAOBJECT piDataObject, CComponentData *pComponentData);	HRESULT GetWatermarks(HBITMAP *lphWatermark,HBITMAP *lphHeader,HPALETTE *lphPalette,BOOL *bStretch);	HRESULT InvokePage(IConsole *pConsole,IDataObject* piDataObject, CComponentData *pComponentData, int page);
	static INT_PTR CALLBACK LogDialogProc(
                                  HWND hwndDlg,  // handle to dialog box
                                  UINT uMsg,     // message
                                  WPARAM wParam, // first message parameter
                                  LPARAM lParam  // second message parameter
                                  );
   virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions);
   virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
   virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }
   virtual HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);
   virtual HRESULT OnPropertyChange(IConsole *pConsole, CComponent *pComponent);

	LONG_PTR m_ppHandle;


    
	IPropertySheetProvider *PSProvider;
	IConsoleNameSpace * m_ipConsoleNameSpace;
	IConsole * m_ipConsole;
	LPDATAOBJECT m_ipDataObject;
	static bool ActiveDialog;
	SYSTEMTIME SysTimeFrom, SysTimeTo;
private:
    // {57002918-514B-478a-897B-3AF807CA8363}
    static const GUID thisGuid;
	HSCOPEITEM m_hParentHScopeItem;
	
	
	
    
};

#endif // _LOG_H

