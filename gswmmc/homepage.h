//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _HOMEPAGE_H
#define _HOMEPAGE_H

#include "DeleBase.h"
#include "StatNode.h"
#include "storage.h"
#include "rootfolder.h"

class CHomePage : public CDelegationBase {
public:
    CHomePage();
    virtual ~CHomePage();

    virtual const _TCHAR *GetDisplayName(int nCol = 0) { return _T("Help"); }
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_HOMEPAGE; }

   virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions);
	  // taskpad support
   virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
    virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }

	
private:
    
	IConsoleNameSpace * m_ipConsoleNameSpace;
	IConsole * m_ipConsole;

    //  {36EF9F80-1597-46af-A77A-4123145CB020}
    static const GUID thisGuid;
	HSCOPEITEM m_hParentHScopeItem;
	std::wstring InstallDir;    
};

#endif // _HOMEPAGE_H

