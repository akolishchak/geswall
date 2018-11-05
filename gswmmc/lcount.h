//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _LCOUNT_H
#define _LCOUNT_H
#include <commctrl.h>
#include "DeleBase.h"

class CLcount : public CDelegationBase {
public:
    CLcount();
    virtual ~CLcount();

    virtual const _TCHAR *GetDisplayName(int nCol = 0) { return _T("Summary"); }
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_LCOUNT; }
	virtual LPOLESTR CreateWWWPath(LPOLESTR szResource);
	void CreateHtml(std::wstring SummaryPage);

   virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions);
	  // taskpad support
   virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
   virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }

	
private:
    
	IConsoleNameSpace * m_ipConsoleNameSpace;
	IConsole * m_ipConsole;

// {B2598F87-0A91-451c-9B62-41EB0FA739CF}
    static const GUID thisGuid;
	HSCOPEITEM m_hParentHScopeItem;
	std::wstring InstallDir;    
};

#endif // _LCOUNT_H