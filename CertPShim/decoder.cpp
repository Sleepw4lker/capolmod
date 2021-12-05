#include "pch.cpp"
#pragma hdrstop
#include "celib.h"
#pragma warning(push)
#pragma warning(disable : 4996) // to disable SDK warning from using deprecated APIs with ATL 7.0 and greater
#include "policy.h"
#pragma warning(pop)
#include "internal.h"
#include <assert.h>


CDecoder::CDecoder()
{
    

}

CDecoder::~CDecoder()
{
    if (m_hMsg)
        CryptMsgClose(m_hMsg);
}

VOID
CDecoder::FreeDecoderData(
    __in PVOID pbBuffer
    )
{
    if (pbBuffer)
    {
        LocalFree(pbBuffer);
    }
}

VOID
CDecoder::FreeDecoderData(
    __in DATA_BLOB *dataBlob
    )
{
    if (dataBlob->pbData)
    {
        LocalFree(dataBlob->pbData);
        dataBlob->pbData = NULL;
        dataBlob->cbData = 0;
    }
}

PVOID
CDecoder::AllocDecoderData(
    __in ULONG cbBuffer
    )
{
    return LocalAlloc(LPTR, cbBuffer);
}

HRESULT
CDecoder::GetMessageParameter(    
    __in DWORD dwParamType,
    __in DWORD dwIndex,
    __out DATA_BLOB *paramData
    )
{
    HRESULT     hr = S_OK;
    PVOID       pbData = NULL;
    DWORD       cbData = 0;
        
    if(!CryptMsgGetParam(
                    m_hMsg,
                    dwParamType,
                    dwIndex,
                    NULL,
                    &cbData))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        if (hr != ERROR_MORE_DATA)
            _LeaveIfError(hr, cleanup, "GetMessageParameter:CryptMsgGetParam");
    }
            
    pbData = AllocDecoderData(cbData);
    if (!pbData)
    {     
        hr = E_OUTOFMEMORY;
        _LeaveIfError(hr, cleanup, "GetMessageParameter:AllocDecoderData");
    }
        
    if (!CryptMsgGetParam(
                    m_hMsg,
                    dwParamType,
                    dwIndex,
                    pbData,
                    &cbData))     
    {
        hr = HRESULT_FROM_WIN32(GetLastError());                    
        _LeaveIfError(hr, cleanup, "GetMessageParameter:CryptMsgGetParam");
    }

    paramData->pbData = (PBYTE) pbData;
    paramData->cbData = cbData;
    pbData = NULL;    
    
cleanup:        
    
    FreeDecoderData(pbData);    
    return hr;
}

HRESULT
CDecoder::CopyDataBlob(
    __in DATA_BLOB *src,
    __in DATA_BLOB *dest
    )
{ 
    dest->cbData = src->cbData;
    dest->pbData = (PBYTE)AllocDecoderData(src->cbData);
    if (!dest->pbData)
        return E_OUTOFMEMORY;

    RtlCopyMemory(dest->pbData, src->pbData, src->cbData);    
    return S_OK;
}

HRESULT
CDecoder::CopyCryptAttribute(
    __in PCRYPT_ATTRIBUTE src,
    __in PCRYPT_ATTRIBUTE dest
    )
{
    HRESULT hr = S_OK;
	DWORD size = (DWORD) strlen(src->pszObjId) + 1;
    
    // Parameters
	dest->pszObjId = (LPSTR) AllocDecoderData(size);
    if (!dest->pszObjId)
    {
        hr = E_OUTOFMEMORY;
        _LeaveIfError(hr, cleanup, "CopyCryptAttribute:AllocDecoderData");
    }
    
	strcpy_s(dest->pszObjId, size, src->pszObjId);
	dest->cValue = src->cValue;

	dest->rgValue = 
			(PCRYPT_ATTR_BLOB) AllocDecoderData(src->cValue * sizeof(CRYPT_ATTR_BLOB));
     
    if (!dest->pszObjId)
    {
        hr = E_OUTOFMEMORY;
        _LeaveIfError(hr, cleanup, "CopyCryptAttribute:AllocDecoderData");
    }

	for (DWORD i = 0; i < dest->cValue; i++)
	{
		hr = CopyDataBlob(&src->rgValue[i], &dest->rgValue[i]);
        _LeaveIfError(hr, cleanup, "CopyCryptAttribute:CopyDataBlob");
	}

cleanup:

    if (hr != S_OK)
        FreeDecoderData(dest);

    return hr;
}

/*
DWORD
CAPolCopyAlgorithmIdentifier(
    __in PCRYPT_ALGORITHM_IDENTIFIER src,
    __in PCRYPT_ALGORITHM_IDENTIFIER dest
    )
{
    HRESULT hr = S_OK;
	DWORD size = (DWORD) strlen(src->pszObjId) + 1;
    
    __try
    {
		// Parameters
		dest->pszObjId = (LPSTR) AllocDecoderData(size));
		strcpy_s(dest->pszObjId, size, src->pszObjId);
		CHECK_DWORD(CAPolCopyDataBlob(&src->Parameters, &dest->Parameters));
    }
    __finally
    {

    }

    return hr;
}


*/


HRESULT
CDecoder::BlobToB64String(
    __in DATA_BLOB *blob,
    __deref_out LPWSTR* base64String
    )
{
    HRESULT     hr = S_OK;
    LPWSTR      s = NULL;
    DWORD       cch = 0;
    
    if (!CryptBinaryToString(
            blob->pbData,
            blob->cbData,
            CRYPT_STRING_BASE64,
            NULL,
            &cch))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        if (hr != ERROR_MORE_DATA)
            _LeaveIfError(hr, cleanup, "BlobToB64String:CryptBinaryToString");
    }
           
    s = (LPWSTR) AllocDecoderData(cch * sizeof(wchar_t));     
    if (!s)
    {
        hr = E_OUTOFMEMORY;
        _LeaveIfError(hr, cleanup, "BlobToB64String:AllocDecoderData");
    }
    
    if (!CryptBinaryToString(
                blob->pbData,
                blob->cbData,
                CRYPT_STRING_BASE64,
                s,
                &cch))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, cleanup, "BlobToB64String:CryptBinaryToString");
    }
        
    (*base64String) = s;    
    s = NULL;

cleanup:

    FreeDecoderData(s);
    return hr;
}


HRESULT
CDecoder::B64StringToBlob(
    __in LPWSTR base64String,
    __in DATA_BLOB *blob )
{
    HRESULT     hr = S_OK;
    DATA_BLOB   retBlob = {0};  
    
    if (!CryptStringToBinary(
                base64String,
                0,
                CRYPT_STRING_BASE64,
                NULL,
                &retBlob.cbData,
                NULL,
                NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        if (hr != ERROR_MORE_DATA)
        {
            _LeaveIfError(hr, cleanup, "B64StringToBlob:CryptStringToBinary");
        }           
    }
        
    retBlob.pbData = (PBYTE)AllocDecoderData(retBlob.cbData);
    if (!retBlob.pbData)
    {
        hr = E_OUTOFMEMORY;
        _LeaveIfError(hr, cleanup, "B64StringToBlob:AllocDecoderData");
    }

    if (!CryptStringToBinary(
                        base64String,
                        0,
                        CRYPT_STRING_BASE64,
                        retBlob.pbData,
                        &retBlob.cbData,
                        NULL,
                        NULL))
    {          
        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, cleanup, "B64StringToBlob:CryptStringToBinary2");
    }

    (*blob) = retBlob;    
    ZeroMemory(&retBlob, sizeof(DATA_BLOB));

cleanup:
    
    FreeDecoderData(&retBlob);

    return hr;
}

HRESULT
CDecoder::Initialize(
	__in DATA_BLOB* certificateRequest
    )
{
    HRESULT hr = S_OK;
    
    m_hMsg = CryptMsgOpenToDecode(
                MY_ENCODING_TYPE,
                0,
                0,
                NULL,
                NULL,
                NULL);

    if (m_hMsg == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, cleanup, "CryptMsgOpenToDecode");
    }
        
    if (!CryptMsgUpdate(                
            m_hMsg, 
            certificateRequest->pbData, 
            certificateRequest->cbData, 
            TRUE))
    {                
        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, cleanup, "CryptMsgUpdate");
    }
    
cleanup:

	return hr;
}


HRESULT
CDecoder::GetCertificateRequest(    
     __out PCERT_REQUEST_INFO *certRequestOut
    )
{
    HRESULT hr = S_OK;
	DATA_BLOB data = {0};
    PCMC_DATA_INFO cmcData = NULL;
    PCERT_SIGNED_CONTENT_INFO signedContentInfo = NULL;
    PCERT_REQUEST_INFO certRequest = NULL;
    DWORD dataSize = 0;

    //CMSG_SIGNER_AUTH_ATTR_PARAM
    hr = GetMessageParameter(CMSG_CONTENT_PARAM, 0, &data);
    _LeaveIfError(hr, cleanup, "GetRequestAttributes:GetMessageParameter");

   // decode CMC / CMS message
    if (!ceDecodeObject(
        MY_ENCODING_TYPE,
        CMC_DATA,
        data.pbData,
        data.cbData,
        false,
        (void**) &cmcData,
        &dataSize))
    {

        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, cleanup, "GetCertificateRequest:ceDecodeObject");
    }


    // @todo - handle multiple requests, etc...
    if (cmcData->cTaggedRequest != 1)
    {
        hr = CERTSRV_E_TOO_MANY_SIGNATURES;
        _LeaveIfError(hr, cleanup, "GetCertificateRequest:requestCount");
    }

    if (cmcData->rgTaggedRequest[0].dwTaggedRequestChoice != CMC_TAGGED_CERT_REQUEST_CHOICE)
    {                
        hr = CRYPT_E_INVALID_MSG_TYPE;
        _LeaveIfError(hr, cleanup, "GetCertificateRequest:badCMCTag");
    }

    // get signer data...    
    if (!ceDecodeObject(
        MY_ENCODING_TYPE,
        X509_CERT,
        cmcData->rgTaggedRequest[0].pTaggedCertRequest->SignedCertRequest.pbData,
        cmcData->rgTaggedRequest[0].pTaggedCertRequest->SignedCertRequest.cbData,
        false,
        (void**) &signedContentInfo,
        &dataSize))
    {

        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, cleanup, "GetCertificateRequest:ceDecodeObject");
    }

    // get the request.        
    if (!ceDecodeObject(
        MY_ENCODING_TYPE,
        X509_CERT_REQUEST_TO_BE_SIGNED,
        signedContentInfo->ToBeSigned.pbData,
        signedContentInfo->ToBeSigned.cbData,
        false,
        (void**) &certRequest,
        &dataSize))
    {

        hr = HRESULT_FROM_WIN32(GetLastError());
        _LeaveIfError(hr, cleanup, "GetRequestAttributes:ceDecodeObject");
    }
	
    (*certRequestOut) = certRequest;
    certRequest = NULL;

cleanup:

    FreeDecoderData(signedContentInfo);
    FreeDecoderData(cmcData);
    FreeDecoderData(certRequest);

	return hr;
}

