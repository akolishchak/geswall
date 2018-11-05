

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 6.00.0366 */
/* at Sat Sep 23 01:52:13 2006
 */
/* Compiler settings for .\GIcon.idl:
    Oicf, W1, Zp8, env=Win32 (32b run)
    protocol : dce , ms_ext, c_ext
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
//@@MIDL_FILE_HEADING(  )

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 440
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __GIcon_h__
#define __GIcon_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IGeSWallIcon_FWD_DEFINED__
#define __IGeSWallIcon_FWD_DEFINED__
typedef interface IGeSWallIcon IGeSWallIcon;
#endif 	/* __IGeSWallIcon_FWD_DEFINED__ */


#ifndef __GeSWallIcon_FWD_DEFINED__
#define __GeSWallIcon_FWD_DEFINED__

#ifdef __cplusplus
typedef class GeSWallIcon GeSWallIcon;
#else
typedef struct GeSWallIcon GeSWallIcon;
#endif /* __cplusplus */

#endif 	/* __GeSWallIcon_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 

void * __RPC_USER MIDL_user_allocate(size_t);
void __RPC_USER MIDL_user_free( void * ); 

#ifndef __IGeSWallIcon_INTERFACE_DEFINED__
#define __IGeSWallIcon_INTERFACE_DEFINED__

/* interface IGeSWallIcon */
/* [unique][helpstring][uuid][object] */ 


EXTERN_C const IID IID_IGeSWallIcon;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("14E986D7-1C9B-4EF0-B5DE-449F6B7176BA")
    IGeSWallIcon : public IUnknown
    {
    public:
    };
    
#else 	/* C style interface */

    typedef struct IGeSWallIconVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IGeSWallIcon * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IGeSWallIcon * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IGeSWallIcon * This);
        
        END_INTERFACE
    } IGeSWallIconVtbl;

    interface IGeSWallIcon
    {
        CONST_VTBL struct IGeSWallIconVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IGeSWallIcon_QueryInterface(This,riid,ppvObject)	\
    (This)->lpVtbl -> QueryInterface(This,riid,ppvObject)

#define IGeSWallIcon_AddRef(This)	\
    (This)->lpVtbl -> AddRef(This)

#define IGeSWallIcon_Release(This)	\
    (This)->lpVtbl -> Release(This)


#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IGeSWallIcon_INTERFACE_DEFINED__ */



#ifndef __GIconLib_LIBRARY_DEFINED__
#define __GIconLib_LIBRARY_DEFINED__

/* library GIconLib */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_GIconLib;

EXTERN_C const CLSID CLSID_GeSWallIcon;

#ifdef __cplusplus

class DECLSPEC_UUID("64553E13-4BBB-4930-A3D0-4447DDC1B04A")
GeSWallIcon;
#endif
#endif /* __GIconLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


