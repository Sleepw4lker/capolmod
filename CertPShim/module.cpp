#include "pch.cpp"
#pragma hdrstop

#include "celib.h"
#pragma warning(push)
#pragma warning(disable : 4996) // to disable SDK warning from using deprecated APIs with ATL 7.0 and greater
#include "policy.h"
#include "module.h"
#pragma warning(pop)

static GUID CLSID_WindowsDefaultManagePolicyModule = {
	0x3BB44360, 0xC2C8, 0x11D2, 0xB3, 0x13, 0x00, 0xC0, 0x4F, 0x79, 0xDC, 0x72
};

HRESULT _GetWindowsDefaultManagePolicyModule(
	__out			ICertManageModule **ppManageModule)
{
	return CoCreateInstance(
		CLSID_WindowsDefaultManagePolicyModule,
        NULL,               
        CLSCTX_INPROC_SERVER,
		IID_ICertManageModule,
        (VOID **) ppManageModule);
}

HRESULT _GetConfigRegistryKeyName(
	__in							BSTR strConfig,
	__in							LPWSTR wszModule,
	__in							DWORD cchKeyName,
	__out_ecount(cchKeyName)		LPWSTR wszKeyName,
	__out_opt						PBOOL pfLocal)
{
	HRESULT hr = S_OK;
	LPWSTR wszCaName = NULL;
	BOOL fLocal = FALSE;

	//
	// Get the CA name
	//

	wszCaName = wcschr(strConfig, '\\');
	if (NULL == wszCaName)
	{
		wszCaName = strConfig;
		fLocal = TRUE;
	}
	else
	{
		//
		// Check for local configuration
		//
		
		hr = ceIsConfigLocal(strConfig, NULL, &fLocal);
		_JumpIfError(hr, leave, "ceIsConfigLocal");

		if (L'\0' == wszCaName [0])
		{
			hr = E_INVALIDARG;
			goto leave;
		}

		wszCaName++;
	}

	if (NULL != pfLocal)
		*pfLocal = fLocal;

	//
	// Build the registry key path
	//

	hr = StringCchPrintfW(
		wszKeyName,
		cchKeyName,
		L"System\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\PolicyModules\\%s",
		wszCaName,
		wszModule);
	_JumpIfError(hr, leave, "StringCbPrintfW");

leave:
	return hr;
}

HRESULT _OpenConfigRegKey(
	__in			BSTR strConfig,
	__in			BSTR strStorageLocation,
	__in			BOOL fWrite,
	__out			HKEY *phKey)
{
	HRESULT hr = S_OK;
	WCHAR rgwszRegKey [MAX_PATH];
	BOOL fIsLocal = FALSE;

	UNREFERENCED_PARAMETER(strStorageLocation);

	//
	// Build the registry key path
	//

	hr = _GetConfigRegistryKeyName(
		strConfig, 
		wszCLASS_CERTPOLICYSHIM, 
		sizeof(rgwszRegKey) / sizeof(rgwszRegKey [0]), 
		rgwszRegKey, 
		&fIsLocal);
	_JumpIfError(hr, leave, "_GetConfigRegistryKeyName");

	if (FALSE == fIsLocal)
	{
		hr = E_NOTIMPL;
		goto leave;
	}

	//
	// Open the key
	//

	hr = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		rgwszRegKey,
		0,
		fWrite ? KEY_WRITE : KEY_READ,
		phKey);
	_JumpIfError(hr, leave, "RegOpenKeyEx");

leave:
	return hr;
}

STDMETHODIMP
CCertManagePolicyModuleShim::GetProperty(
    /* [in] */ const BSTR strConfig,
    /* [in] */ BSTR strStorageLocation,
    /* [in] */ BSTR strPropertyName,
    /* [in] */ LONG Flags,
    /* [retval][out] */ VARIANT __RPC_FAR *pvarProperty)
{
	HRESULT hr = S_OK;
	ICertManageModule *pManageModule = NULL;
	LPWSTR szStr = NULL;
	HKEY hKey = NULL;
	WCHAR rgwszProperty [MAX_PATH];
	DWORD cb = sizeof(rgwszProperty);
	DWORD dwType = REG_SZ;
	WCHAR rgwszWinReg [MAX_PATH];

    if (NULL == pvarProperty)
    {
        hr = E_POINTER;
		goto leave;
    }
    VariantInit(pvarProperty);

    if (IsNullOrEmptyBStr(strPropertyName))
	{
		hr = S_FALSE;
		goto leave;
	}

	//
	// Check for properties handled internally
	//

	if (0 == _wcsicmp(strPropertyName, wszSHIM_ACTION_FLAGS_REG_VALUE) ||
        0 == _wcsicmp(strPropertyName, wszSHIM_TEMPLATE_OID_REG_VALUE) ||
		0 == _wcsicmp(strPropertyName, wszSHIM_REQUEST_ATTRIBUTE_OID_REG_VALUE) ||
        0 == _wcsicmp(strPropertyName, wszSHIM_REQUEST_ATTRIBUTE_VALUE_REG_VALUE) ||
        0 == _wcsicmp(strPropertyName, wszSHIM_RA_ISSUANCE_OID_REG_VALUE))
	{
		hr = _OpenConfigRegKey(strConfig, strStorageLocation, FALSE, &hKey);
		_JumpIfError(hr, leave, "_OpenConfigRegKey");

		hr = RegQueryValueEx(
			hKey,
			strPropertyName,
			NULL,
			&dwType,
			(LPBYTE) rgwszProperty,
			&cb);
		_JumpIfError(hr, leave, "RegQueryValueEx");

        if (dwType == REG_DWORD)
        {
            hr = S_OK;
            pvarProperty->vt = VT_UI4;
            pvarProperty->ulVal = (*(DWORD*)rgwszProperty);
            goto leave;
        }

		szStr = rgwszProperty;
	}
	else
	{
		if (0 == _wcsicmp(strPropertyName, wszCMM_PROP_NAME))
			szStr = wsz_SHIM_NAME;
		else if (0 == _wcsicmp(strPropertyName, wszCMM_PROP_DESCRIPTION))
			szStr = wsz_SHIM_DESCRIPTION;
		else if (0 == _wcsicmp(strPropertyName, wszCMM_PROP_COPYRIGHT))
			szStr = wsz_SHIM_COPYRIGHT;
		else if (0 == _wcsicmp(strPropertyName, wszCMM_PROP_FILEVER))
			szStr = wsz_SHIM_FILEVER;
		else if (0 == _wcsicmp(strPropertyName, wszCMM_PROP_PRODUCTVER))
			szStr = wsz_SHIM_PRODUCTVER;
	}
    
	if (NULL != szStr)
	{
		pvarProperty->bstrVal = SysAllocString(szStr);
		if (NULL == pvarProperty->bstrVal)
		{
			hr = E_OUTOFMEMORY;
			goto leave;
		}
		pvarProperty->vt = VT_BSTR;
		hr = S_OK;
		goto leave;
	}

	//
	// Check for properties handled by the Windows module
	//

	hr = _GetWindowsDefaultManagePolicyModule(&pManageModule);
	_JumpIfError(
		hr, leave, "_GetWindowsDefaultManagePolicyModule");

	hr = _GetConfigRegistryKeyName(
		strConfig, 
		wszCLASS_CERTPOLICYWINDOWS, 
		sizeof(rgwszWinReg) / sizeof(rgwszWinReg [0]), 
		rgwszWinReg, 
		NULL);
	_JumpIfError(hr, leave, "_GetConfigRegistryKeyName");

	hr = pManageModule->GetProperty(
		strConfig,
		CComBSTR(rgwszWinReg),
		strPropertyName,
		Flags,
		pvarProperty);
	_JumpIfError(hr, leave, "pManageModule->GetProperty");

leave:
	if (NULL != pManageModule)
		pManageModule->Release();
	if (NULL != hKey)
		RegCloseKey(hKey);
    return hr;
}
        
STDMETHODIMP 
CCertManagePolicyModuleShim::SetProperty(
    /* [in] */ const BSTR strConfig,
    /* [in] */ BSTR strStorageLocation,
    /* [in] */ BSTR strPropertyName,
    /* [in] */ LONG Flags,
    /* [in] */ VARIANT const __RPC_FAR * pvarProperty)
{
	HRESULT hr = S_OK;
	ICertManageModule *pManageModule = NULL;
	HKEY hKey = NULL;
	WCHAR rgwszWinReg [MAX_PATH];

	//
	// Check for properties handled internally
	//    	
    if (0 == _wcsicmp(strPropertyName, wszSHIM_ACTION_FLAGS_REG_VALUE) ||
        0 == _wcsicmp(strPropertyName, wszSHIM_TEMPLATE_OID_REG_VALUE) ||
		0 == _wcsicmp(strPropertyName, wszSHIM_REQUEST_ATTRIBUTE_OID_REG_VALUE) ||
        0 == _wcsicmp(strPropertyName, wszSHIM_REQUEST_ATTRIBUTE_VALUE_REG_VALUE) ||
        0 == _wcsicmp(strPropertyName, wszSHIM_RA_ISSUANCE_OID_REG_VALUE))
	{
		hr = _OpenConfigRegKey(strConfig, strStorageLocation, TRUE, &hKey);
		_JumpIfError(hr, leave, "_OpenConfigRegKey");

		hr = RegSetValueEx(
			hKey,
			strPropertyName,
			0,
			REG_SZ,
			(LPBYTE) pvarProperty->bstrVal,
			sizeof(WCHAR) * (1 + (DWORD) wcslen(pvarProperty->bstrVal)));
		_JumpIfError(hr, leave, "RegSetValueEx");
		goto leave;
	}

	//
	// Otherwise, call the Windows default manage policy module
	//

	hr = _GetWindowsDefaultManagePolicyModule(&pManageModule);
	_JumpIfError(hr, leave, "_GetWindowsDefaultManagePolicyModule");

	hr = _GetConfigRegistryKeyName(
		strConfig, 
		wszCLASS_CERTPOLICYWINDOWS, 
		sizeof(rgwszWinReg) / sizeof(rgwszWinReg [0]), 
		rgwszWinReg, 
		NULL);
	_JumpIfError(hr, leave, "_GetConfigRegistryKeyName");

	hr = pManageModule->SetProperty(
		strConfig,
		CComBSTR(rgwszWinReg),
		strPropertyName,
		Flags,
		pvarProperty);
	_JumpIfError(hr, leave, "pManageModule->SetProperty");

leave:
	if (NULL != pManageModule)
		pManageModule->Release();
	if (NULL != hKey)
		RegCloseKey(hKey);
    return hr;
}
        
STDMETHODIMP
CCertManagePolicyModuleShim::Configure( 
    /* [in] */ const BSTR strConfig,
    /* [in] */ BSTR strStorageLocation,
    /* [in] */ LONG Flags)
{
	HRESULT hr = S_OK;
	ICertManageModule *pManageModule = NULL;

	hr = _GetWindowsDefaultManagePolicyModule(&pManageModule);
	_JumpIfError(hr, leave, "_GetWindowsDefaultManagePolicyModule");

	hr = pManageModule->Configure(
		strConfig,
		strStorageLocation,
		Flags);
	_JumpIfError(hr, leave, "pManageModule->Configure");

leave:
	if (NULL != pManageModule)
		pManageModule->Release();
    return hr;
}