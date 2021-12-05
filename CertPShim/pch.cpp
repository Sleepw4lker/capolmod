#include <windows.h>

#pragma warning (disable:4068) // disable warning for unknown pragma for SDK

#include <atlbase.h>

//You may derive a class from CComModule and use it if you want to override
//something, but do not change the name of _Module
extern CComModule _Module;

#include <atlcom.h>
#include <certsrv.h>
#include <strsafe.h>

#define wszCLASS_CERTPOLICYSHIMPREFIX TEXT("CertAuthority_Shim") 
#define wszCLASS_CERTPOLICYSHIM wszCLASS_CERTPOLICYSHIMPREFIX  wszCERTPOLICYMODULE_POSTFIX
#define wszCLASS_CERTMANAGEPOLICYMODULESHIM wszCLASS_CERTPOLICYSHIMPREFIX wszCERTMANAGEPOLICY_POSTFIX

#define wszCLASS_CERTPOLICYWINDOWSPREFIX TEXT("CertificateAuthority_MicrosoftDefault") 
#define wszCLASS_CERTPOLICYWINDOWS wszCLASS_CERTPOLICYWINDOWSPREFIX  wszCERTPOLICYMODULE_POSTFIX

#define wsz_SHIM_NAME           L"Shim Policy Module"
#define wsz_SHIM_DESCRIPTION    L"Shim Policy Module"
#define wsz_SHIM_COPYRIGHT      L"(c)2011 JW Secure, Inc."
#define wsz_SHIM_FILEVER        L"v 1.0"
#define wsz_SHIM_PRODUCTVER     L"v 1.00"


//
// Action configuration definitions.
//
#define SHIM_FILTER_TEMPLATE_NAME           0x1000
#define SHIM_REQUIRE_REQUEST_ATTRIBUTES     0x2000
#define SHIM_REQUIRE_RA_ISSUANCE_OID        0x4000

#define SHIM_ACTION_MASK                    0xFF00

#define wszSHIM_ACTION_FLAGS_REG_VALUE			        L"ActionFlags" 

// Required filter parameters.
#define wszSHIM_TEMPLATE_OID_REG_VALUE					L"ShimTemplateOid" // SHIM_FILTER_TEMPLATE_NAME
#define wszSHIM_REQUEST_ATTRIBUTE_OID_REG_VALUE			L"ShimRequestAttributeOid" // SHIM_REQUIRE_REQUEST_ATTRIBUTES
#define wszSHIM_REQUEST_ATTRIBUTE_VALUE_REG_VALUE    	L"ShimRequestAttributeValue" // SHIM_REQUIRE_REQUEST_ATTRIBUTES
#define wszSHIM_RA_ISSUANCE_OID_REG_VALUE				L"ShimRAIssuanceOid" // SHIM_REQUIRE_RA_ISSUANCE_OID



#pragma hdrstop

