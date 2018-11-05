//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _MMC_GLOBALS_H
#define _MMC_GLOBALS_H

#include <tchar.h>

#ifndef STRINGS_ONLY

	enum UPDATE_VIEWS_HINT {UPDATE_SCOPEITEM = 1000, DELETE_SCOPEITEM, UPDATE_RESULTITEM, DELETE_RESULTITEM}; 
		enum ITEM_TYPE {SCOPE = 10, RESULT}; 

        #define IDM_BUTTON1    0x100
        #define IDM_BUTTON2    0x101

        extern HINSTANCE g_hinst;
        extern ULONG g_uObjects;

        #define OBJECT_CREATED InterlockedIncrement((long *)&g_uObjects);
        #define OBJECT_DESTROYED InterlockedDecrement((long *)&g_uObjects);

        // uncomment the following #define to enable message cracking
        // #define MMC_CRACK_MESSAGES
        void MMCN_Crack(BOOL bComponentData,
                                        IDataObject *pDataObject,
                                        IComponentData *pCompData,
                                        IComponent *pComp,
                                        MMC_NOTIFY_TYPE event,
                                        LPARAM arg,
                                        LPARAM param);
#endif

//=--------------------------------------------------------------------------=
// allocates a temporary buffer that will disappear when it goes out of scope
// NOTE: be careful of that -- make sure you use the string in the same or
// nested scope in which you created this buffer. people should not use this
// class directly.  use the macro(s) below.
//
class TempBuffer {
  public:
    TempBuffer(ULONG cBytes) {
        m_pBuf = (cBytes <= 120) ? &m_szTmpBuf : HeapAlloc(GetProcessHeap(), 0, cBytes);
        m_fHeapAlloc = (cBytes > 120);
    }
    ~TempBuffer() {
        if (m_pBuf && m_fHeapAlloc) HeapFree(GetProcessHeap(), 0, m_pBuf);
    }
    void *GetBuffer() {
        return m_pBuf;
    }

  private:
    void *m_pBuf;
    // we'll use this temp buffer for small cases.
    //
    char  m_szTmpBuf[120];
    unsigned m_fHeapAlloc:1;
};

//=--------------------------------------------------------------------------=
// string helpers.
//
// given a _TCHAR, copy it into a wide buffer.
// be careful about scoping when using this macro!
//
// how to use the below two macros:
//
//  ...
//  LPTSTR pszT;
//  pszT = MyGetTStringRoutine();
//  MAKE_WIDEPTR_FROMSTR(pwsz, pszT);
//  MyUseWideStringRoutine(pwsz);
//  ...
#ifdef UNICODE
#define MAKE_WIDEPTR_FROMTSTR(ptrname, tstr) \
    long __l##ptrname = (lstrlenW(tstr) + 1) * sizeof(WCHAR); \
    TempBuffer __TempBuffer##ptrname(__l##ptrname); \
    lstrcpyW((LPWSTR)__TempBuffer##ptrname.GetBuffer(), tstr); \
    LPWSTR ptrname = (LPWSTR)__TempBuffer##ptrname.GetBuffer()
#else // ANSI
#define MAKE_WIDEPTR_FROMTSTR(ptrname, tstr) \
    long __cch##ptrname = (lstrlenA(tstr) + 1);\
    long __l##ptrname = (lstrlenA(tstr) + 1) * sizeof(WCHAR); \
    TempBuffer __TempBuffer##ptrname(__l##ptrname); \
    MultiByteToWideChar(CP_ACP, 0, tstr, -1, (LPWSTR)__TempBuffer##ptrname.GetBuffer(), __cch##ptrname); \
    LPWSTR ptrname = (LPWSTR)__TempBuffer##ptrname.GetBuffer()
#endif

#ifdef UNICODE
#define MAKE_WIDEPTR_FROMTSTR_ALLOC(ptrname, tstr) \
    long __l##ptrname = (lstrlenW(tstr) + 1) * sizeof(WCHAR); \
    LPWSTR ptrname = (LPWSTR)CoTaskMemAlloc(__l##ptrname); \
    lstrcpyW((LPWSTR)ptrname, tstr)
#else // ANSI
#define MAKE_WIDEPTR_FROMTSTR_ALLOC(ptrname, tstr) \
    long __cch##ptrname = (lstrlenA(tstr) + 1);\
    long __l##ptrname = (lstrlenA(tstr) + 1) * sizeof(WCHAR); \
    LPWSTR ptrname = (LPWSTR)CoTaskMemAlloc(__l##ptrname); \
    MultiByteToWideChar(CP_ACP, 0, tstr, -1, ptrname, __cch##ptrname)
#endif

//
// similarily for MAKE_TSTRPTR_FROMWIDE.  note that the first param does not
// have to be declared, and no clean up must be done.
//
// * 2 for DBCS handling in below length computation
//
#ifdef UNICODE
#define MAKE_TSTRPTR_FROMWIDE(ptrname, widestr) \
    size_t __l##ptrname = (wcslen(widestr) + 1) * 2 * sizeof(TCHAR); \
    TempBuffer __TempBuffer##ptrname((ULONG)__l##ptrname); \
    lstrcpyW((LPTSTR)__TempBuffer##ptrname.GetBuffer(), widestr); \
    LPTSTR ptrname = (LPTSTR)__TempBuffer##ptrname.GetBuffer()
#else // ANSI
#define MAKE_TSTRPTR_FROMWIDE(ptrname, widestr) \
    size_t __l##ptrname = (wcslen(widestr) + 1) * 2 * sizeof(TCHAR); \
    TempBuffer __TempBuffer##ptrname((ULONG)__l##ptrname); \
    WideCharToMultiByte(CP_ACP, 0, widestr, -1, (LPSTR)__TempBuffer##ptrname.GetBuffer(), __l##ptrname, NULL, NULL); \
    LPTSTR ptrname = (LPTSTR)__TempBuffer##ptrname.GetBuffer()
#endif


	template<int T=0>
			class ResourceString
		{
public:
	TCHAR string[512];
public:
	explicit ResourceString(int id=T)
	{
		LoadString(id);
	}
	int LoadString(int id)
	{
		ZeroMemory(string, sizeof(string));
		/*
		LCID lang = ::GetThreadLocale();
		WORD plang = PRIMARYLANGID(lang);
		WORD slang = SUBLANGID(lang);
		*/
		if(id > 0)
		{
/* 
#ifdef _DEBUG
			// LoadString without annoying warning from the Debug kernel if the
			//  segment containing the string is not present
			if (::FindResourceEx(_Module.m_hInstResource, MAKEINTRESOURCE((id >> 4) + 1), RT_STRING, MAKELANGID(plang, slang)) == NULL)
			//if (::FindResource(_Module.m_hInstResource, MAKEINTRESOURCE((id >> 4) + 1), RT_STRING) == NULL)
			{
				return 0; // not found
			}
#endif //_DEBUG
*/
			return ::LoadString(g_hinst, id, string, 512);
		}
		return 0;
	}
	operator LPCTSTR() const { return &string[0]; }		//lint -e1930
};

#endif // _MMC_GLOBALS_H
