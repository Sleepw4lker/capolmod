#include "pch.cpp"
#pragma hdrstop
#include "celib.h"
#pragma warning(push)
#pragma warning(disable : 4996) // to disable SDK warning from using deprecated APIs with ATL 7.0 and greater
#include "policy.h"
#pragma warning(pop)
#include "internal.h"
#include <assert.h>



CFilter::CFilter()
{
    m_pServer = NULL;
    m_configString = NULL;
    m_pManageModule = NULL;
}

CFilter::~CFilter()
{
    // we don't own these interfaces...
    m_pServer = NULL;
    m_configString = NULL;
    m_pManageModule = NULL;
}


HRESULT
CFilter::Initialize(
    __in ICertServerPolicy *pServer,
    __in ICertManageModule *pManageModule,    
    __in LONG context,
    __in BSTR configString)
{
    HRESULT hr = S_OK;
    m_pServer = pServer;
    m_context = context;
        
    hr = m_pServer->SetContext(m_context);
    if (hr != S_OK)    
        _LeaveIfError(hr, leave_block, "Initialize:m_pServer->SetContext");

    m_pManageModule = pManageModule;    
    m_configString = configString;

leave_block:

    return hr;
}


HRESULT
CFilter::FilterTemplateName(
    __in CRequestInstance* request,
    __out BOOL* matched )
{     
    HRESULT hr = S_OK;
    VARIANT var;
    
    *matched = FALSE;
    
    VariantInit(&var);

    // we don't currently filter on V1 / W2000 templates
    if (NULL == request->GetTemplateObjId())
        goto leave_block;

	hr = m_pManageModule->GetProperty(
		m_configString, 
		NULL, 
		CComBSTR(wszSHIM_TEMPLATE_OID_REG_VALUE), 
		0, 
		&var);

	if (hr == ERROR_FILE_NOT_FOUND)
	{
		hr = S_OK;
		goto leave_block;
	}
           	
    //
	// Check if the template OIDs match
	// 
    if (0 == _wcsicmp(var.bstrVal, request->GetTemplateObjId()))	
        *matched = TRUE;		
    
leave_block:

	VariantClear(&var);	
    return(hr);
}


BOOL 
CFilter::CheckForShimIssuanceOid(
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
CFilter::FilterRAIssuanceOid(
    __in CRequestInstance* request,
    __out BOOL* matched )
{     
    HRESULT hr = S_OK;
    VARIANT var;        
    BSTR    issuancePolicies = NULL;
    
    UNREFERENCED_PARAMETER(request);

    *matched = FALSE;        
    
    VariantClear(&var);

	hr = m_pManageModule->GetProperty(
            m_configString, 
            NULL, 
            CComBSTR(wszSHIM_RA_ISSUANCE_OID_REG_VALUE), 
            0, 
            &var);
    
    _LeaveIfError(hr, leave_block, "pManageModule->GetProperty");
    
    hr = polGetRequestStringProperty(
		        m_pServer, 
		        wszPROPSIGNERAPPLICATIONPOLICIES, 
		        &issuancePolicies);	
    
    _LeaveIfError(
		hr, 
		leave_block, 
		"polGetRequestStringProperty:wszPROPSIGNERAPPLICATIONPOLICIES");

	//
	// Check if the required OID is present
	//
    (*matched) = CheckForShimIssuanceOid(issuancePolicies, var.bstrVal);
	
leave_block:

	VariantClear(&var);
	SysFreeString(issuancePolicies);
    
    return(hr);
}

HRESULT
CFilter::RegisterRequestAttributeOid()
{
    HRESULT         hr = S_OK;
    VARIANT         var;    
    CRYPT_OID_INFO  oidInfo = {0};
    char           *pszObjId = NULL;
        	
    // certsrv won't store attribute if it isn't registered.
    hr = m_pManageModule->GetProperty(
            m_configString, 
            NULL,   
            CComBSTR(wszSHIM_REQUEST_ATTRIBUTE_OID_REG_VALUE), 
            0, 
            &var);
    
    _LeaveIfError(hr, leave_block, "pManageModule->GetProperty");
         
    if (!ceConvertWszToSz(&pszObjId, var.bstrVal, -1))
        _JumpError(E_OUTOFMEMORY, leave_block, "RegisterRequestAttributeOid");
        
    oidInfo.cbSize = sizeof(CRYPT_OID_INFO);
    oidInfo.pszOID = pszObjId;        
    oidInfo.pwszName = FILTER_OID_NAME;
    oidInfo.dwGroupId = CRYPT_POLICY_OID_GROUP_ID;
    
    if (!CryptRegisterOIDInfo(&oidInfo, 0))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, leave_block, "CryptRegisterOIDInfo");
    }

leave_block:

    VariantClear(&var);
   
    return(hr);
}

HRESULT
CFilter::FilterRequestAttribute(
    __in CRequestInstance* request,
    __out BOOL* match )
{     
    HRESULT             hr = S_OK;
    VARIANT             var;
    CDecoder            decoder;
    DATA_BLOB           requestBlob = {0};
    BSTR                rawRequest = NULL;    
    PCERT_REQUEST_INFO  certRequest = NULL;
    LPSTR               szOid = NULL;
    
    // @todo - attach decoded request to request...
    UNREFERENCED_PARAMETER(request);

    *match = FALSE;        
    
    VariantInit(&var);

    hr = m_pManageModule->GetProperty(
            m_configString, 
            NULL,   
            CComBSTR(wszSHIM_REQUEST_ATTRIBUTE_OID_REG_VALUE), 
            0, 
            &var);
    
    _LeaveIfError(hr, leave_block, "pManageModule->GetProperty");
          
    hr = polGetRequestBinaryProperty(
		        m_pServer, 
		        wszPROPREQUESTRAWREQUEST, 
		        &rawRequest);	
    
    _LeaveIfError(
		hr, 
		leave_block, 
		"polGetRequestStringProperty:wszPROPREQUESTRAWREQUEST");

    requestBlob.cbData = SysStringByteLen(rawRequest);
    requestBlob.pbData = (PBYTE) rawRequest;
        
    hr = decoder.Initialize(&requestBlob);
    _LeaveIfError(hr, leave_block, "decoder.Initialize");
    
    hr = decoder.GetCertificateRequest(&certRequest);        
    _LeaveIfError(hr, leave_block, "decoder.GetCertificateRequest");
             
    if (!ceConvertWszToSz(&szOid, var.bstrVal, -1))
    {
        _JumpError(E_OUTOFMEMORY, leave_block, "ceConvertWszToSz");
    }
        
    for (DWORD i = 0; i < certRequest->cAttribute; i++)
    {                
        if (0 == _stricmp(szOid, certRequest->rgAttribute[i].pszObjId))	
        {
            //
            // @todo - check on value...
            //

            (*match) = true;
            break;
        }
    }
      
leave_block:

    decoder.FreeDecoderData(certRequest);

    if (szOid)
        LocalFree(szOid);
        
	VariantClear(&var);
	SysFreeString(rawRequest);
    
    return hr;
}
