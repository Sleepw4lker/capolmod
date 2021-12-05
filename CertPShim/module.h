#include "cerpshim.h"
#include "resource.h"       // main symbols

class CCertManagePolicyModuleShim: 
    public CComDualImpl<ICertManageModule, &IID_ICertManageModule, &LIBID_CERTPOLICYSHIMLib>, 
    public CComObjectRoot,
    public CComCoClass<CCertManagePolicyModuleShim, &CLSID_CCertManagePolicyModuleShim>
{
public:
    CCertManagePolicyModuleShim() {}
    ~CCertManagePolicyModuleShim() {}

BEGIN_COM_MAP(CCertManagePolicyModuleShim)
    COM_INTERFACE_ENTRY(IDispatch)
    COM_INTERFACE_ENTRY(ICertManageModule)
END_COM_MAP()

DECLARE_NOT_AGGREGATABLE(CCertManagePolicyModuleShim) 
// Remove the comment from the line above if you don't want your object to 
// support aggregation.  The default is to support it

// UNDONE UNDONE
DECLARE_REGISTRY(
    CCertManagePolicyModuleShim,
    wszCLASS_CERTMANAGEPOLICYMODULESHIM TEXT(".1"),
    wszCLASS_CERTMANAGEPOLICYMODULESHIM,
    IDS_CERTMANAGEPOLICYMODULE_DESC,    
    THREADFLAGS_BOTH)

// ICertManageModule
public:
    STDMETHOD (GetProperty) (
            /* [in] */ const BSTR strConfig,
            /* [in] */ BSTR strStorageLocation,
            /* [in] */ BSTR strPropertyName,
            /* [in] */ LONG dwFlags,
            /* [retval][out] */ VARIANT __RPC_FAR *pvarProperty);
        
    STDMETHOD (SetProperty)(
            /* [in] */ const BSTR strConfig,
            /* [in] */ BSTR strStorageLocation,
            /* [in] */ BSTR strPropertyName,
            /* [in] */ LONG dwFlags,
            /* [in] */ VARIANT const __RPC_FAR *pvarProperty);
        
    STDMETHOD (Configure)( 
            /* [in] */ const BSTR strConfig,
            /* [in] */ BSTR strStorageLocation,
            /* [in] */ LONG dwFlags);
};
