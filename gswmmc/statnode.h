//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SNAPINBASE_H
#define _SNAPINBASE_H

#include "DeleBase.h"
#include "BaseSnap.h"
#include "storage.h"
#include <mmc.h>
#include <gpedit.h>
#include "license/licensemanager.h"
#include "gesruledef.h"

class CStaticNode : public CDelegationBase {
public:
    CStaticNode();
    
    virtual ~CStaticNode();
    
    virtual const _TCHAR *GetDisplayName(int nCol = 0) { 
        static _TCHAR szDisplayName[256];
        LoadString(g_hinst, IDS_SNAPINNAME, szDisplayName, (sizeof szDisplayName)/(sizeof szDisplayName[0]));
        return szDisplayName; 
    }
    virtual const GUID & getNodeType() { return thisGuid; }
    virtual const int GetBitmapIndex() { return INDEX_SNAPIN; }
    // virtual functions go here (for MMCN_*)
    virtual void SetScopeItemValue(HSCOPEITEM hscopeitem) { m_hParentHScopeItem = hscopeitem; }
    virtual HSCOPEITEM GetParentScopeItem() { return m_hParentHScopeItem; }
    virtual HRESULT OnInitialExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, LPDATAOBJECT pDataObject);
    virtual HRESULT OnExpand(IConsoleNameSpace *pConsoleNameSpace, IConsole *pConsole, HSCOPEITEM parent);
    virtual HRESULT GetResultViewType(LPOLESTR *ppViewType, long *pViewOptions);
      // taskpad support
    virtual HRESULT TaskNotify(IConsole *pConsole, VARIANT *v1, VARIANT *v2);
    virtual MMC_TASK *GetTaskList(LPOLESTR szTaskGroup, LONG *nCount);
    virtual HRESULT GetTaskpadTitle(LPOLESTR *pszTitle);
    virtual HRESULT GetTaskpadDescription(LPOLESTR *pszDescription);
    virtual HRESULT GetTaskpadBackground(MMC_TASK_DISPLAY_OBJECT *pTDO);
    virtual HRESULT GetListpadInfo(MMC_LISTPAD_INFO *lpListPadInfo);

    HRESULT OnAddMenuItems(IContextMenuCallback *pContextMenuCallback, long *pInsertionsAllowed);
    HRESULT OnMenuCommand(IConsole *pConsole, long lCommandID,LPDATAOBJECT piDataObject, CComponentData *pComponentData);
    bool PolicyChanged(void);
    bool LevelChange(void);
    GesRule::SecurityLevel PosToSecurityLevel(int Pos);

public:
    Storage::SECMAP SecureTypeMap;
    int SecuriyLevel;
    SnapinMode Mode;
    license::ProductType Product;
    OSVERSIONINFO VerInfo;
    IConsoleNameSpace * m_ipConsoleNameSpace;
    IConsole *m_ipConsole;
    IGPEInformation *m_pGPTInformation;
private:
    enum { MAX_NUMBER_OF_CHILDREN = 7 };
    int NUMBER_OF_CHILDREN;
    CDelegationBase *children[MAX_NUMBER_OF_CHILDREN];
    static bool ActiveRefresh;
 
    HSCOPEITEM m_hParentHScopeItem;
    // {D5AE7C65-7022-493d-B54A-AF5144E8D215}
    static const GUID thisGuid;
};





#endif // _SNAPINBASE_H
