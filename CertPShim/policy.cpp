#include "pch.cpp"
#pragma hdrstop

#include <assert.h>
#include <winhttp.h>
#include "celib.h"
#pragma warning(push)
#pragma warning(disable : 4996) // to disable SDK warning from using deprecated APIs with ATL 7.0 and greater
#include "policy.h"
#include "internal.h"
#include "module.h"
#pragma warning(pop)
#include "messages.h"

BOOL fDebug = DBG_CERTSRV;

#ifndef DBG_CERTSRV
#error -- DBG_CERTSRV not defined!
#endif

static GUID CLSID_WindowsDefaultPolicyModule = {
	0x3B6654D0, 0xC2C8, 0x11D2, 0xB3, 0x13, 0x00, 0xC0, 0x4F, 0x79, 0xDC, 0x72
};

HRESULT LogShimPolModEvent(
	__in					WORD wType,
	__in					WORD wCategory,
	__in					DWORD dwEventID,
	__in					WORD wNumStrings,
	__in					DWORD dwDataSize,
	__in					LPWSTR *lpStrings,
	__in					LPVOID lpRawData);


// worker
HRESULT
polGetServerCallbackInterface(
    OUT ICertServerPolicy **ppServer,
    IN LONG Context)
{
    HRESULT hr;

    if (NULL == ppServer)
    {
        hr = E_POINTER;
	_JumpError(hr, error, "Policy:polGetServerCallbackInterface");
    }

    hr = CoCreateInstance(
                    CLSID_CCertServerPolicy,
                    NULL,               // pUnkOuter
                    CLSCTX_INPROC_SERVER,
                    IID_ICertServerPolicy,
                    (VOID **) ppServer);
    _JumpIfError(hr, error, "Policy:CoCreateInstance");

    if (NULL == *ppServer)
    {
        hr = E_UNEXPECTED;
	_JumpError(hr, error, "Policy:CoCreateInstance");
    }

    // only set context if nonzero
    if (0 != Context)
    {
        hr = (*ppServer)->SetContext(Context);
        _JumpIfError(hr, error, "Policy:SetContext");
    }

error:
    return hr;
}


HRESULT
polGetProperty(
    IN ICertServerPolicy *pServer,
    IN BOOL fRequest,
    IN WCHAR const *pwszPropertyName,
    IN DWORD PropType,
    OUT VARIANT *pvarOut)
{
    HRESULT hr;
    BSTR strName = NULL;

    VariantInit(pvarOut);
    strName = SysAllocString(pwszPropertyName);
    if (IsNullBStr(strName))
    {
	    hr = E_OUTOFMEMORY;
	    _JumpError(hr, error, "Policy:SysAllocString");
    }

    if (fRequest)
    {
	    hr = pServer->GetRequestProperty(strName, PropType, pvarOut);
	    _JumpIfErrorStr2(
		        hr,
		        error,
		        "Policy:GetRequestProperty",
		        pwszPropertyName,
		        CERTSRV_E_PROPERTY_EMPTY);
    }
    else
    {
	    hr = pServer->GetCertificateProperty(strName, PropType, pvarOut);
	    _JumpIfErrorStr2(
		        hr,
		        error,
		        "Policy:GetCertificateProperty",
		        pwszPropertyName,
		        CERTSRV_E_PROPERTY_EMPTY);
    }

error:
    SysFreeString(strName);
    return(hr);
}


HRESULT
polGetRequestBinaryProperty(
    IN ICertServerPolicy *pServer,    
    IN WCHAR const *pwszPropertyName,
    OUT BSTR *pstrOut)
{
    HRESULT hr;
    VARIANT var;

    VariantInit(&var);
    SysFreeString(*pstrOut);
    *pstrOut = NULL;

    hr = polGetProperty(
		    pServer,
		    TRUE,
		    pwszPropertyName,
		    PROPTYPE_BINARY,
		    &var);
    _JumpIfError2(
	    hr,
	    error,
	    "Policy:polGetProperty",
	    CERTSRV_E_PROPERTY_EMPTY);

    if (VT_BSTR != var.vt || IsNullOrEmptyBStr(var.bstrVal))
    {
	    hr = CERTSRV_E_PROPERTY_EMPTY;
	    _JumpError(hr, error, "Policy:polGetProperty");
    }
    *pstrOut = var.bstrVal;
    var.vt = VT_EMPTY;
    hr = S_OK;

error:
    VariantClear(&var);
    return(hr);
}




HRESULT
polGetStringProperty(
    IN ICertServerPolicy *pServer,
    IN BOOL fRequest,
    IN WCHAR const *pwszPropertyName,
    OUT BSTR *pstrOut)
{
    HRESULT hr;
    VARIANT var;

    VariantInit(&var);
    SysFreeString(*pstrOut);
    *pstrOut = NULL;

    hr = polGetProperty(
		    pServer,
		    fRequest,
		    pwszPropertyName,
		    PROPTYPE_STRING,
		    &var);
    _JumpIfError2(
	    hr,
	    error,
	    "Policy:polGetProperty",
	    CERTSRV_E_PROPERTY_EMPTY);

    if (VT_BSTR != var.vt || IsNullOrEmptyBStr(var.bstrVal))
    {
	hr = CERTSRV_E_PROPERTY_EMPTY;
	_JumpError(hr, error, "Policy:polGetProperty");
    }
    *pstrOut = var.bstrVal;
    var.vt = VT_EMPTY;
    hr = S_OK;

error:
    VariantClear(&var);
    return(hr);
}


HRESULT
polGetLongProperty(
    IN ICertServerPolicy *pServer,
    IN BOOL fRequest,
    IN WCHAR const *pwszPropertyName,
    OUT LONG *plOut)
{
    HRESULT hr;
    VARIANT var;

    VariantInit(&var);
    hr = polGetProperty(
		    pServer,
		    fRequest,
		    pwszPropertyName,
		    PROPTYPE_LONG,
		    &var);
    _JumpIfError2(hr, error, "Policy:polGetProperty", CERTSRV_E_PROPERTY_EMPTY);

    if (VT_I4 != var.vt)
    {
	hr = CERTSRV_E_PROPERTY_EMPTY;
	_JumpError(hr, error, "Policy:polGetProperty");
    }
    *plOut = var.lVal;
    hr = S_OK;

error:
    VariantClear(&var);
    return(hr);
}


HRESULT
polGetRequestStringProperty(
    IN ICertServerPolicy *pServer,
    IN WCHAR const *pwszPropertyName,
    OUT BSTR *pstrOut)
{
    HRESULT hr;

    hr = polGetStringProperty(pServer, TRUE, pwszPropertyName, pstrOut);
    _JumpIfError2(hr, error, "polGetStringProperty", CERTSRV_E_PROPERTY_EMPTY);

error:
    return(hr);
}


HRESULT
polGetCertificateStringProperty(
    IN ICertServerPolicy *pServer,
    IN WCHAR const *pwszPropertyName,
    OUT BSTR *pstrOut)
{
    HRESULT hr;

    hr = polGetStringProperty(pServer, FALSE, pwszPropertyName, pstrOut);
    _JumpIfError2(hr, error, "polGetStringProperty", CERTSRV_E_PROPERTY_EMPTY);

error:
    return(hr);
}


HRESULT
polGetRequestLongProperty(
    IN ICertServerPolicy *pServer,
    IN WCHAR const *pwszPropertyName,
    OUT LONG *plOut)
{
    HRESULT hr;

    hr = polGetLongProperty(pServer, TRUE, pwszPropertyName, plOut);
    _JumpIfError2(hr, error, "polGetLongProperty", CERTSRV_E_PROPERTY_EMPTY);

error:
    return(hr);
}


HRESULT
polGetCertificateLongProperty(
    IN ICertServerPolicy *pServer,
    IN WCHAR const *pwszPropertyName,
    OUT LONG *plOut)
{
    HRESULT hr;

    hr = polGetLongProperty(pServer, FALSE, pwszPropertyName, plOut);
    _JumpIfError2(hr, error, "polGetLongProperty", CERTSRV_E_PROPERTY_EMPTY);

error:
    return(hr);
}


HRESULT
polGetRequestAttribute(
    IN ICertServerPolicy *pServer,
    IN WCHAR const *pwszAttributeName,
    OUT BSTR *pstrOut)
{
    HRESULT hr;
    BSTR strName = NULL;

    strName = SysAllocString(pwszAttributeName);
    if (IsNullBStr(strName))
    {
	hr = E_OUTOFMEMORY;
	_JumpError(hr, error, "Policy:SysAllocString");
    }
    hr = pServer->GetRequestAttribute(strName, pstrOut);
    _JumpIfErrorStr2(
		hr,
		error,
		"Policy:GetRequestAttribute",
		pwszAttributeName,
		CERTSRV_E_PROPERTY_EMPTY);

error:
    SysFreeString(strName);
    return(hr);
}


HRESULT
polGetCertificateExtension(
    IN ICertServerPolicy *pServer,
    IN WCHAR const *pwszExtensionName,
    IN DWORD dwPropType,
    IN OUT VARIANT *pvarOut)
{
    HRESULT hr;
    BSTR strName = NULL;

    strName = SysAllocString(pwszExtensionName);
    if (IsNullBStr(strName))
    {
	    hr = E_OUTOFMEMORY;
	    _JumpError(hr, error, "Policy:SysAllocString");
    }
    hr = pServer->GetCertificateExtension(strName, dwPropType, pvarOut);
    _JumpIfErrorStr2(
		hr,
		error,
		"Policy:GetCertificateExtension",
		pwszExtensionName,
		CERTSRV_E_PROPERTY_EMPTY);

error:
    SysFreeString(strName);
    return(hr);
}

//+--------------------------------------------------------------------------
// CCertPolicyShim::~CCertPolicyShim -- destructor
//
// free memory associated with this instance
//+--------------------------------------------------------------------------

CCertPolicyShim::~CCertPolicyShim()
{
    _Cleanup();

}


VOID
CCertPolicyShim::_FreeStringArray(
    __inout DWORD *pcString,
    __inout LPWSTR **papwsz)
{
    LPWSTR *apwsz = *papwsz;
    DWORD i;

    if (NULL != apwsz)
    {
        for (i = *pcString; i-- > 0; )
        {
            if (NULL != apwsz[i])
            {
                DBGPRINT((fDebug, "_FreeStringArray[%u]: '%ws'\n", i, apwsz[i]));
                LocalFree(apwsz[i]);
            }
        }
        LocalFree(apwsz);
        *papwsz = NULL;
    }
    *pcString = 0;
}

VOID
CCertPolicyShim::_FreeStringArray(
    __inout DWORD *pcString,
    __inout LPSTR **papsz)
{
    LPSTR *apsz = *papsz;
    DWORD i;

    if (NULL != apsz)
    {
        for (i = *pcString; i-- > 0; )
        {
            if (NULL != apsz[i])
            {
                DBGPRINT((fDebug, "_FreeStringArray[%u]: '%s'\n", i, apsz[i]));
                LocalFree(apsz[i]);
            }
        }
        LocalFree(apsz);
        *papsz = NULL;
    }
    *pcString = 0;
}




//+--------------------------------------------------------------------------
// CCertPolicyShim::_Cleanup -- free memory associated with this instance
//
// free memory associated with this instance
//+--------------------------------------------------------------------------

VOID
CCertPolicyShim::_Cleanup()
{

    SysFreeString(m_strDescription);
    m_strDescription = NULL;

    // RevocationExtension variables:

    if (NULL != m_wszASPRevocationURL)
    {
        LocalFree(m_wszASPRevocationURL);
    	m_wszASPRevocationURL = NULL;
    }


    _FreeStringArray(&m_cEnableRequestExtensions, &m_apwszEnableRequestExtensions);
    _FreeStringArray(&m_cEnableEnrolleeRequestExtensions, &m_apwszEnableEnrolleeRequestExtensions);
    _FreeStringArray(&m_cDisableExtensions, &m_apwszDisableExtensions);
    _FreeStringArray(&m_cEKUOIDsForVolatileRequests, &m_apszEKUOIDsForVolatileRequests);


    SysFreeString(m_strCAName);
    m_strCAName = NULL;

    SysFreeString(m_strCASanitizedName);
    m_strCASanitizedName = NULL;

    SysFreeString(m_strCASanitizedDSName);
    m_strCASanitizedDSName = NULL;

    SysFreeString(m_strRegStorageLoc);
    m_strRegStorageLoc = NULL;
    if (NULL != m_pCert)
    {
        CertFreeCertificateContext(m_pCert);
        m_pCert = NULL;
    }
    SysFreeString(m_strMachineDNSName);
    m_strMachineDNSName=NULL;

	if (NULL != m_pWinDefCertPol2)
	{
		m_pWinDefCertPol2->Release();
		m_pWinDefCertPol2 = NULL;
	}
}


#if DBG_CERTSRV

VOID
CCertPolicyShim::_DumpStringArray(
    __in PCSTR pszType,
    __in DWORD count,
    __in_ecount(count) LPWSTR const *apwsz)
{
    DWORD i;
    WCHAR const *pwszName;

    for (i = 0; i < count; i++)
    {
	pwszName = L"";
	if (iswdigit(apwsz[i][0]))
	{
	    pwszName = ceGetOIDName(
                                     apwsz[i]); // Static: do not free!
	}
	DBGPRINT((
		fDebug,
		"%hs[%u]: %ws%hs%ws\n",
		pszType,
		i,
		apwsz[i],
		L'\0' != *pwszName? " -- " : "",
		pwszName));
    }
}
#endif // DBG_CERTSRV

//+--------------------------------------------------------------------------
// CCertPolicyShim::Initialize
//
// Returns S_OK on success.
//+--------------------------------------------------------------------------

STDMETHODIMP
CCertPolicyShim::Initialize(
    /* [in] */ BSTR const strConfig)
{
    HRESULT hr = S_OK;

    DBGPRINT((fDebug, "Policy:Initialize:\n"));

	_Cleanup();

	//
	// Load the default policy module
	//

	hr = CoCreateInstance(
		CLSID_WindowsDefaultPolicyModule,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ICertPolicy2,
		(LPVOID *) &m_pWinDefCertPol2);
	_LeaveIfError(hr, error, "CoCreateInstance:CLSID_WindowsDefaultPolicyModule");
	hr = m_pWinDefCertPol2->Initialize(strConfig);
	_LeaveIfError(hr, error, "m_pWinDefCertPol2->Initialize(strConfig)");


    

error:
    return hr;	
}

HRESULT
GetRequestId(
    IN ICertServerPolicy *pServer,
    OUT LONG *plRequestId)
{
    HRESULT hr;

    hr = polGetRequestLongProperty(pServer, wszPROPREQUESTREQUESTID, plRequestId);
    _JumpIfError(hr, error, "Policy:polGetRequestLongProperty");

    DBGPRINT((
	fDebug,
	"Policy:GetRequestId(%ws = %u)\n",
	wszPROPREQUESTREQUESTID,
	*plRequestId));

error:
    return(hr);
}

#pragma warning(push)
#pragma warning(disable: 4509) // nonstandard extension used: uses SEH and has destructor

BOOL 
_CheckForShimIssuanceOid(
	__in					BSTR strRaOidsInRequest,
	__in					BSTR strShimRequiredOid)
{
	COLE2T wszShimRequiredOid(strShimRequiredOid);
	COLE2T wszRaOidsInRequest(strRaOidsInRequest);
	LPWSTR wszTok = NULL, wszTokCtx = NULL;

	do
	{
		wszTok = wcstok_s(
			NULL != wszTokCtx ? NULL : (LPWSTR)(wszRaOidsInRequest), 
			L",", 
			&wszTokCtx);
	}
	while (NULL != wszTok && 0 != _wcsicmp(wszTok, wszShimRequiredOid));

	if (NULL == wszTok)
		return FALSE;

	return TRUE;
}

HRESULT
CCertPolicyShim::AddV1TemplateNameExtension(
    IN ICertServerPolicy *pServer,
    OPTIONAL IN WCHAR const *pwszTemplateName)
{
    HRESULT hr;
    BSTR strName = NULL;
    LONG ExtFlags = 0;
    VARIANT varExtension;
    CERT_NAME_VALUE *pName = NULL;
    CERT_NAME_VALUE NameValue;
    DWORD cbEncoded;
    BYTE *pbEncoded = NULL;
    BOOL fUpdate = TRUE;

    VariantInit(&varExtension);

    strName = SysAllocString(TEXT(szOID_ENROLL_CERTTYPE_EXTENSION));
    if (IsNullBStr(strName))
    {
	hr = E_OUTOFMEMORY;
	_JumpError(hr, error, "Policy:SysAllocString");
    }

    hr = pServer->GetCertificateExtension(
				    strName,
				    PROPTYPE_BINARY,
				    &varExtension);
    _PrintIfError2(hr, "Policy:GetCertificateExtension", hr);
    if (CERTSRV_E_PROPERTY_EMPTY == hr)
    {
	if (NULL == pwszTemplateName)
	{
	    hr = S_OK;
	    goto error;
	}
    }
    else
    {
	_JumpIfError(hr, error, "Policy:GetCertificateExtension");

	hr = pServer->GetCertificateExtensionFlags(&ExtFlags);
	_JumpIfError(hr, error, "Policy:GetCertificateExtensionFlags");

	if (VT_BSTR == varExtension.vt &&
	    0 == (EXTENSION_DISABLE_FLAG & ExtFlags) &&
	    NULL != pwszTemplateName)
	{
	    if (!ceDecodeObject(
			X509_ASN_ENCODING,
			X509_UNICODE_ANY_STRING,
			(BYTE *) varExtension.bstrVal,
			SysStringByteLen(varExtension.bstrVal),
			FALSE,
			(VOID **) &pName,
			&cbEncoded))
	    {
		hr = ceHLastError();
		_JumpError(hr, error, "Policy:ceDecodeObject");
	    }

	    // case sensitive compare -- be sure to match case of template

	    if (0 == lstrcmp(
			(WCHAR const *) pName->Value.pbData,
			pwszTemplateName))
	    {
		fUpdate = FALSE;
	    }
	}
    }
    if (fUpdate)
    {
	if (NULL == pwszTemplateName)
	{
	    ExtFlags |= EXTENSION_DISABLE_FLAG;
	}
	else
	{
	    VariantClear(&varExtension);
	    varExtension.bstrVal = NULL;

	    NameValue.dwValueType = CERT_RDN_UNICODE_STRING;
	    NameValue.Value.pbData = (BYTE *) pwszTemplateName;
	    NameValue.Value.cbData = 0;

	    if (!ceEncodeObject(
			    X509_ASN_ENCODING,
			    X509_UNICODE_ANY_STRING,
			    &NameValue,
			    0,
			    FALSE,
			    &pbEncoded,
			    &cbEncoded))
	    {
		hr = ceHLastError();
		_JumpError(hr, error, "Policy:ceEncodeObject");
	    }
	    if (!ceConvertWszToBstr(
				&varExtension.bstrVal,
				(WCHAR const *) pbEncoded,
				cbEncoded))
	    {
		hr = E_OUTOFMEMORY;
		_JumpError(hr, error, "Policy:ceConvertWszToBstr");
	    }
	    varExtension.vt = VT_BSTR;
	    ExtFlags &= ~EXTENSION_DISABLE_FLAG;
	}
	hr = pServer->SetCertificateExtension(
				strName,
				PROPTYPE_BINARY,
				ExtFlags,
				&varExtension);
	_JumpIfError(hr, error, "Policy:SetCertificateExtension");
    }
    hr = S_OK;

error:
    VariantClear(&varExtension);
    SysFreeString(strName);
    if (NULL != pName)
    {
	LocalFree(pName);
    }
    if (NULL != pbEncoded)
    {
	LocalFree(pbEncoded);
    }
    return(hr);
}

HRESULT _LogDeniedRequest(
	__in				ICertServerPolicy *pServer, 
	__in				LPWSTR wszRequestRaOids)
{
    HRESULT hr = S_OK;
	LPWSTR rgwszEvt [3];
	LONG lRequestId = 0;
	WCHAR rgwszRequestId [32];
	RPC_BINDING_HANDLE hRpcServer = NULL;
	RPC_WSTR wstrRpcServer = NULL;
	RPC_WSTR wstrClientAddr = NULL;

	hr = (HRESULT) RpcBindingServerFromClient(NULL, &hRpcServer);
	_JumpIfError(hr, leave, "RpcBindingServerFromClient");

	hr = (HRESULT) RpcBindingToStringBinding(hRpcServer, &wstrRpcServer);
	_JumpIfError(hr, leave, "RpcBindingToStringBinding");

	hr = (HRESULT) RpcStringBindingParse(
		wstrRpcServer, 
		NULL, 
		NULL,
		&wstrClientAddr,
		NULL,
		NULL);
	_JumpIfError(hr, leave, "RpcStringBindingParse");

	hr = GetRequestId(pServer, &lRequestId);
	_JumpIfError(hr, leave, "GetRequestId");

	StringCbPrintfW(
		rgwszRequestId,
		sizeof(rgwszRequestId),
		L"%d",
		lRequestId);
	
	rgwszEvt [0] = rgwszRequestId;
	rgwszEvt [1] = wszRequestRaOids;
	rgwszEvt [2] = (LPWSTR) wstrClientAddr;
	LogShimPolModEvent(
		EVENTLOG_INFORMATION_TYPE,
		0,
		EVNT_CERPSHIM_REQUEST_DENIED,
		sizeof(rgwszEvt) / sizeof(rgwszEvt [0]),
		0,
		rgwszEvt,
		NULL);

leave:
	RpcStringFree(&wstrClientAddr);
	RpcStringFree(&wstrRpcServer);
	RpcBindingFree(&hRpcServer);
	return hr;
}

STDMETHODIMP
CCertPolicyShim::VerifyRequest(
    /* [in] */ BSTR const strConfig,
    /* [in] */ LONG context,
    /* [in] */ LONG bNewRequest,
    /* [in] */ LONG Flags,
    /* [out, retval] */ LONG __RPC_FAR *pDisposition)
{
    HRESULT hr = S_OK;
    ICertServerPolicy *pServer = NULL;
    CRequestInstance requestInstance;
    CFilter filter;
	
    BOOL fEnableEnrolleeExtensions;
	ICertManageModule *pManageModule = NULL;
	VARIANT var;
    ULONG actionFlags = 0;

	VariantInit(&var);
    //lRequestId = 0;
    	
 


	//
	// Check default policy module result
	//
	hr = m_pWinDefCertPol2->VerifyRequest(
		strConfig, context, bNewRequest, Flags, pDisposition);
	_LeaveIfError(hr, leave_block, "m_pWinDefCertPol2->VerifyRequest");

	//
	// If the default module didn't accept the request, stop
	//
	if (VR_INSTANT_OK != *pDisposition)
		goto leave_block;

       //
	// Get the CA callback interface
	//
	hr = polGetServerCallbackInterface(&pServer, context);
	_LeaveIfError(hr, leave_block, "Policy:polGetServerCallbackInterface");

	//
	// Get the manage module
	//
	hr = GetManageModule(&pManageModule);
	_LeaveIfError(hr, leave_block, "GetManageModule");
    
    // 
    // Is filtering enabled?
    //     
    VariantInit(&var);
	hr = pManageModule->GetProperty(
		strConfig, 
		NULL, 
		CComBSTR(wszSHIM_ACTION_FLAGS_REG_VALUE), 
		0, 
		&var);

    if (hr == ERROR_FILE_NOT_FOUND)
    {
        hr = S_OK;
        goto leave_block;
    }

    actionFlags = var.uintVal;      
    
    if ((actionFlags & SHIM_ACTION_MASK) == 0)
    {     
        hr = S_OK;
        goto leave_block;
    }
    //
    // Build a request and filter instance.
    //
    hr = requestInstance.Initialize(
        this,
        pServer,
        &fEnableEnrolleeExtensions);

    _LeaveIfError(hr, leave_block, "Policy:VerifyRequest:requestInstance.Initialize");

    hr = filter.Initialize(
        pServer,            
        pManageModule,
        context,
        strConfig);

    _LeaveIfError(hr, leave_block, "Policy:VerifyRequest:filter.Initialize");

    // 
    // Only check particular templates...
    //
    if (actionFlags & SHIM_FILTER_TEMPLATE_NAME)
    {
        BOOL match = FALSE;
        hr = filter.FilterTemplateName(&requestInstance, &match);
        _LeaveIfError(hr, leave_block, "Policy:VerifyRequest:FilterTemplateName");

        //
        // if this isn't a match, let it go with success.
        //
        if (!match)
        {
            hr = S_OK;
            goto leave_block;
        }
    }

    if (actionFlags & SHIM_REQUIRE_REQUEST_ATTRIBUTES)
    {
        BOOL match = FALSE;
        hr = filter.FilterRequestAttribute(&requestInstance, &match);
        _LeaveIfError(hr, leave_block, "Policy:VerifyRequest:FilterRequestAttributes");

        //
        // if this isn't a match, deny the request.
        //
        if (!match)
        {
            hr = CERTSRV_E_ENROLL_DENIED;
            goto leave_block;
        }
    }

    if (actionFlags & SHIM_REQUIRE_RA_ISSUANCE_OID)
    {
        BOOL match = FALSE;
        hr = filter.FilterRAIssuanceOid(&requestInstance, &match);
        _LeaveIfError(hr, leave_block, "Policy:VerifyRequest:FilterRAIssuanceOid");

        //
        // if this isn't a match, deny the request.
        //
        if (!match)
        {
            hr = CERTSRV_E_ENROLL_DENIED;
            goto leave_block;
        }
    }
    	
leave_block:
     
    if (CERTSRV_E_ENROLL_DENIED == hr)
	{
		*pDisposition = VR_INSTANT_BAD;
		//_LogDeniedRequest(pServer, strSignerAppPols);
	}
    
	VariantClear(&var);
	
    if (NULL != pServer)
        pServer->Release();
	if (NULL != pManageModule)
		pManageModule->Release();

    return(hr);
}
#pragma warning(pop)


//+--------------------------------------------------------------------------
// CCertPolicyShim::GetDescription
//
// Returns S_OK on success.
//+--------------------------------------------------------------------------

STDMETHODIMP
CCertPolicyShim::GetDescription(
    /* [out, retval] */ BSTR __RPC_FAR *pstrDescription)
{
    HRESULT hr = S_OK;

    SysFreeString(*pstrDescription);
    *pstrDescription = SysAllocString(L"Shim Policy Module");
    if (IsNullBStr(*pstrDescription))
    {
        hr = E_OUTOFMEMORY;
    }
    return(hr);
}


//+--------------------------------------------------------------------------
// CCertPolicyShim::ShutDown
//
// Returns S_OK on success.
//+--------------------------------------------------------------------------

STDMETHODIMP
CCertPolicyShim::ShutDown(VOID)
{
    // called once, as Server unloading policy dll
	if (NULL != m_pWinDefCertPol2)
		m_pWinDefCertPol2->ShutDown();
    _Cleanup();
    return(S_OK);
}


//+--------------------------------------------------------------------------
// CCertPolicyShim::GetManageModule
//
// Returns S_OK on success.
//+--------------------------------------------------------------------------

STDMETHODIMP
CCertPolicyShim::GetManageModule(
    /* [out, retval] */ ICertManageModule **ppManageModule)
{
    HRESULT hr;

    *ppManageModule = NULL;
    hr = CoCreateInstance(
		CLSID_CCertManagePolicyModuleShim,
        NULL,               // pUnkOuter
        CLSCTX_INPROC_SERVER,
		IID_ICertManageModule,
        (VOID **) ppManageModule);
    _JumpIfError(hr, error, "CoCreateInstance");

error:
    return(hr);
}

STDMETHODIMP
CCertPolicyShim::InterfaceSupportsErrorInfo(
    IN REFIID riid)
{
    static const IID *arr[] =
    {
        &IID_ICertPolicy,
    };

    for (int i = 0; i < sizeof(arr)/sizeof(arr[0]); i++)
    {
        if (IsEqualGUID(*arr[i], riid))
        {
            return(S_OK);
        }
    }
    return(S_FALSE);
}

