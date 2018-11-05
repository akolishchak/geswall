//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "Resources.h"
//#include "SelectUsersOrGroups.h"
//#include "SelectUsersOrGroupsDlg.h"

//#include "objsel.h"

#include "seluser.h"

// the headers don't have a definition for the the compiler provided smart pointers,
// so we use the macro to roll our own.  I like using smart pointers, because they clean
// up the code considerably, compared to standard COM calls.
_COM_SMARTPTR_TYPEDEF(IDsObjectPicker, IID_IDsObjectPicker);


void OnSelusers(HWND DialogHWND) 
{
	IDsObjectPickerPtr		ptrObjPick (CLSID_DsObjectPicker);		// semi-smart pointer to object
	IDataObjectPtr			pDataObject;							// result data object
	DSOP_INIT_INFO			InitInfo;								// Init Info
	DSOP_SCOPE_INIT_INFO	aScopeInit[1];							// Scope Init Info
	HRESULT					hr;										// standard hresult

	// init the DSOP_SCOPE_INIT_INFO
	ZeroMemory(aScopeInit, sizeof(aScopeInit));
	aScopeInit[0].cbSize = sizeof(DSOP_SCOPE_INIT_INFO);

	// all the relevant settings are assigned directly from the dialogs
	aScopeInit[0].flType	=0x0000037f;
	aScopeInit[0].flScope=	0x000000c3;
	aScopeInit[0].FilterFlags.Uplevel.flBothModes=	0x00000042;
	aScopeInit[0].FilterFlags.Uplevel.flMixedModeOnly=	0x00000000;
	aScopeInit[0].FilterFlags.Uplevel.flNativeModeOnly=	0x00000000;
	aScopeInit[0].FilterFlags.flDownlevel=	0x80000005;


	// init the struct
	ZeroMemory(&InitInfo, sizeof(DSOP_INIT_INFO));
	InitInfo.cbSize = sizeof(DSOP_INIT_INFO);
	InitInfo.pwzTargetComputer = NULL;
	InitInfo.cDsScopeInfos = sizeof(aScopeInit) / sizeof(DSOP_SCOPE_INIT_INFO);
	InitInfo.aDsScopeInfos = aScopeInit;

	// pick up the optional settings
	InitInfo.flOptions = 0x00000003;
	
	// bail out if we could not do anything
	if (ptrObjPick == NULL)
	{	
//		AfxMessageBox(_T("Could not create the required COM object in objsel.dll.  Are you running Win2K or XP?"), MB_OK);
		return;
	}
	
	// make the call to tell the system what kind of dialog it should display
	hr = ptrObjPick->Initialize(&InitInfo);
	if (!SUCCEEDED(hr))
	{
	//	AfxMessageBox(_T("Something went wrong trying in the call to Initialze(), bailing out..."), MB_OK);
		return;
	}
	
	// make the call to show the dialog that we want
	hr = ptrObjPick->InvokeDialog(DialogHWND, (IDataObject**)&pDataObject);
	if (!SUCCEEDED(hr))
	{
	//	AfxMessageBox(_T("InvokeDialog returned with a failure,  bailing out..."), MB_OK);
		return;
	}
	
	// decode the results from the dialog
	hr = ProcessResults(DialogHWND,pDataObject);
	if (!SUCCEEDED(hr))
	{
	//	AfxMessageBox(_T("Problem processing the results,  bailing out..."), MB_OK);
		return;
	}
				
}



/*
	Name:				CSelectUsersOrGroupsDlg::ProcessResults
	Type:				Protected
	Override:			No
	@mfunc
	Description:
		Processes the results from the call
	@parm 				IDataObjectPtr&	 | ptrDataObj	 | Semi smart pointer to the data object
	@rdesc				HRESULT - Standard HRESULT
*/
HRESULT ProcessResults(HWND DialogHWND,IDataObjectPtr& ptrDataObj)
{
	HRESULT					hr;					// standard hresult
	STGMEDIUM				stm;				// the storage medium
	FORMATETC				fe;					// formatetc specifier
	PDS_SELECTION_LIST		pDsSelList;			// pointer to our results
	//LV_ITEM				    lvitem;				// the item

	// Init
	pDsSelList = NULL;

	// Sanity check
	if (ptrDataObj == NULL)
		return E_INVALIDARG;

	// Get the global memory block that contain the user's selections.
    fe.cfFormat = (CLIPFORMAT)RegisterClipboardFormat(CFSTR_DSOP_DS_SELECTION_LIST);
    fe.ptd = NULL;
    fe.dwAspect = DVASPECT_CONTENT;
    fe.lindex = -1;
    fe.tymed = TYMED_HGLOBAL;

	// grab the data object
    hr = ptrDataObj->GetData(&fe, &stm);
    if(!SUCCEEDED(hr))
		return hr;

    // Retrieve a pointer to DS_SELECTION_LIST structure.
    pDsSelList = (PDS_SELECTION_LIST)GlobalLock(stm.hGlobal);
    if(NULL != pDsSelList)
    {
        // Loop through DS_SELECTION array of selected objects.
        if(pDsSelList->cItems) 
        {
			SetDlgItemText(DialogHWND, IDC_NAME_E, pDsSelList->aDsSelection[0].pwzName);
		/*	lvitem.mask = LVIF_TEXT;
			lvitem.iItem = i;
			lvitem.iSubItem = 0;
			lvitem.pszText = _T("");
			lvitem.iImage = NULL;
			m_list.InsertItem(&lvitem); // insert new item

			m_list.SetItemText(i, 0, pDsSelList->aDsSelection[i].pwzName);
			m_list.SetItemText(i, 1, pDsSelList->aDsSelection[i].pwzClass);
			m_list.SetItemText(i, 2, pDsSelList->aDsSelection[i].pwzADsPath);
			m_list.SetItemText(i, 3, pDsSelList->aDsSelection[i].pwzUPN);
		*/
        }
        GlobalUnlock(stm.hGlobal);
    }
    else
    {
        hr = E_POINTER;
    }

    ReleaseStgMedium(&stm);

    return hr;
}