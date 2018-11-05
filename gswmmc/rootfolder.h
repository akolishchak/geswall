//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _ROOTFOLDER_H
#define _ROOTFOLDER_H

#include "DeleBase.h"
#include "StatNode.h"

#include "storage.h"
#include "gesruledef.h"

class CRootFolder : public CDelegationBase {
public:
    CRootFolder(CStaticNode *);
    virtual ~CRootFolder();
	
    virtual const _TCHAR *GetDisplayName(int nCol = 0) { return _T("GeSWall"); }
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_SNAPIN; }

    virtual HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);
	virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions);
	  // taskpad support
    virtual HRESULT TaskNotify(IConsole *pConsole, VARIANT *v1, VARIANT *v2);
    virtual MMC_TASK *GetTaskList(LPOLESTR szTaskGroup, LONG *nCount);
	virtual HRESULT GetTaskpadTitle(LPOLESTR *pszTitle);
	virtual HRESULT GetTaskpadDescription(LPOLESTR *pszDescription);
	virtual HRESULT GetTaskpadBackground(MMC_TASK_DISPLAY_OBJECT *pTDO);
	virtual HRESULT GetListpadInfo(MMC_LISTPAD_INFO *lpListPadInfo);
    virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
    virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }

	
private:
    
	//GesRule::SecurityLevel SecuriyLevel;  
	IConsoleNameSpace * m_ipConsoleNameSpace;
	IConsole * m_ipConsole;

    //  {5D210590-D77D-4cbd-8354-9D30B4B3A165}
    static const GUID thisGuid;
	CStaticNode * m_parent;
    HSCOPEITEM m_hParentHScopeItem;
	IPropertySheetProvider *PSProvider;
    enum { NUMBER_OF_CHILDREN = 7 };
    CDelegationBase *children[NUMBER_OF_CHILDREN];
};

#endif // _ROOTFOLDER_H

