//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "GeSWallIcon.h"


// CGeSWallIcon
STDMETHODIMP CGeSWallIcon::GetOverlayInfo(
             LPWSTR pwszIconFile,
             int cchMax,
             int* pIndex,
             DWORD* pdwFlags)
{
  // Get our module's full path
  GetModuleFileNameW(_AtlBaseModule.GetModuleInstance(), pwszIconFile, cchMax);

  // Use first icon in the resource
  *pIndex=0; 

  *pdwFlags = ISIOI_ICONFILE | ISIOI_ICONINDEX | GIL_SIMULATEDOC;
  return S_OK;
}

// IShellIconOverlayIdentifier::GetPriority
// returns the priority of this overlay 0 being the highest. 
STDMETHODIMP CGeSWallIcon::GetPriority(int* pPriority)
{
  // we want highest priority 
  *pPriority=0;
  return S_OK;
}

// IShellIconOverlayIdentifier::IsMemberOf
// Returns whether the object should have this overlay or not 
STDMETHODIMP CGeSWallIcon::IsMemberOf(LPCWSTR pwszPath, DWORD dwAttrib)
{
  wchar_t *s = _wcsdup(pwszPath);
  HRESULT r = S_FALSE;
  
  _wcslwr(s);

//----------------- Criteria------------------     
  if (wcsstr(s, L"isolated") != 0)
  r = S_OK;
//--------------------------------------------
/*HANDLE hObject = CreateFile(pwszPath, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
OPEN_EXISTING, 0, NULL);
if ( hObject ==  INVALID_HANDLE_VALUE ) return false;

EntityAttributes Attr;
if ( Aci.GetAttr(hObject, Attr, "GSWL") ) {
//      printf("%S: [%x, %x, %x, %x, %x, %x]\n", Name, Attr.Param[0], Attr.Param[1], Attr.Param[2],
//Attr.Param[3], Attr.Param[4], Attr.Param[5]);
      // if file is untrusted
      if ( Attr.Param[3] <=2 ) {
         // file is untrusted, mark it
		r = S_OK;
      }
}
*/
//--------------------------------------------
  free(s);

  return r;
}