

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0555 */
/* at Fri Jul 01 02:21:52 2011
 */
/* Compiler settings for cerpshim.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 7.00.0555 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__


#ifndef __cerpshim_h__
#define __cerpshim_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __CCertPolicyShim_FWD_DEFINED__
#define __CCertPolicyShim_FWD_DEFINED__

#ifdef __cplusplus
typedef class CCertPolicyShim CCertPolicyShim;
#else
typedef struct CCertPolicyShim CCertPolicyShim;
#endif /* __cplusplus */

#endif 	/* __CCertPolicyShim_FWD_DEFINED__ */


#ifndef __CCertManagePolicyModuleShim_FWD_DEFINED__
#define __CCertManagePolicyModuleShim_FWD_DEFINED__

#ifdef __cplusplus
typedef class CCertManagePolicyModuleShim CCertManagePolicyModuleShim;
#else
typedef struct CCertManagePolicyModuleShim CCertManagePolicyModuleShim;
#endif /* __cplusplus */

#endif 	/* __CCertManagePolicyModuleShim_FWD_DEFINED__ */


/* header files for imported files */
#include "wtypes.h"
#include "certpol.h"

#ifdef __cplusplus
extern "C"{
#endif 



#ifndef __CERTPOLICYSHIMLib_LIBRARY_DEFINED__
#define __CERTPOLICYSHIMLib_LIBRARY_DEFINED__

/* library CERTPOLICYSHIMLib */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_CERTPOLICYSHIMLib;

EXTERN_C const CLSID CLSID_CCertPolicyShim;

#ifdef __cplusplus

class DECLSPEC_UUID("022A7141-C73F-4AE3-BB05-344E227CDFBF")
CCertPolicyShim;
#endif

EXTERN_C const CLSID CLSID_CCertManagePolicyModuleShim;

#ifdef __cplusplus

class DECLSPEC_UUID("022A7142-C73F-4AE3-BB05-344E227CDFBF")
CCertManagePolicyModuleShim;
#endif
#endif /* __CERTPOLICYSHIMLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


