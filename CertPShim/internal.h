
#define MY_ENCODING_TYPE    PKCS_7_ASN_ENCODING | X509_ASN_ENCODING
#define FILTER_OID_NAME     L"FilterOID"


class CFilter
{

public:
    CFilter();
    ~CFilter();

    HRESULT Initialize(
        __in ICertServerPolicy *pServer,
        __in ICertManageModule *pManageModule,    
        __in LONG context,
        __in BSTR configString);

    HRESULT FilterTemplateName(
        __in CRequestInstance* request,
        __out BOOL* matched);

    HRESULT FilterRAIssuanceOid(
        __in CRequestInstance* request,
        __out BOOL* matched);

    HRESULT FilterRequestAttribute(
        __in CRequestInstance* request,
        __out BOOL* matched );

    HRESULT RegisterRequestAttributeOid();

private:			

    BOOL CheckForShimIssuanceOid(
	    __in BSTR strRaOidsInRequest,
	    __in BSTR strShimRequiredOid);


    ICertServerPolicy      *m_pServer;
    ICertManageModule      *m_pManageModule;    
    BSTR                    m_configString;
    LONG                    m_context;
};


class CDecoder
{

public:
    CDecoder();
    ~CDecoder();

    HRESULT Initialize(__in DATA_BLOB* certificateRequest);         
    
    VOID FreeDecoderData(__in PVOID pbBuffer);
    VOID FreeDecoderData(__in DATA_BLOB *dataBlob);

    HRESULT GetMessageParameter(    
        __in DWORD dwParamType,
        __in DWORD dwIndex,
        __out DATA_BLOB *paramData );

    HRESULT CopyCryptAttribute(
        __in PCRYPT_ATTRIBUTE src,
        __in PCRYPT_ATTRIBUTE dest );
    
    HRESULT GetCertificateRequest( __out PCERT_REQUEST_INFO *certRequest );
    
private:			

    PVOID AllocDecoderData(__in ULONG cbBuffer);

    HRESULT B64StringToBlob(
        __in LPWSTR base64String,
        __in DATA_BLOB *blob );

    HRESULT BlobToB64String(
        __in DATA_BLOB *blob,
        __deref_out LPWSTR* base64String );

    HRESULT CopyDataBlob(
        __in DATA_BLOB *src,
        __in DATA_BLOB *dest
        );

    HRESULT CopyCryptAttributes(
        __in PCRYPT_ATTRIBUTE src,
        __in DWORD srcCount,
        __out PCRYPT_ATTRIBUTE *dest,
        __out DWORD *destCount
        );

    HCRYPTMSG      m_hMsg;
};