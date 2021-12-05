// ConTst.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

//
// Flow macros
//

static 
void
WINAPI
_OutputDbgStr(
    __in  DWORD dwLine,
    __in  LPSTR szMsg,
    __in  DWORD dwStatus)
{
    CHAR rgsz [256];
    LPSTR szTag = "INFO";

    if (0 != dwStatus)
        szTag = "ERROR";

    StringCbPrintfA(
        rgsz,
        sizeof(rgsz),
        "%s: %s - 0x%x, line %d\n",
        szTag,
        szMsg,
        dwStatus,
        dwLine);
    printf(rgsz);
}

#define CHECK_DWORD(_X) {                                           \
    if (ERROR_SUCCESS != (status = _X)) {                           \
        _OutputDbgStr(__LINE__, #_X, status);                       \
        throw (DWORD) status;                                       \
    }                                                               \
}

#define CHECK_BOOL(_X) {                                            \
    if (FALSE == (_X)) {                                            \
        status = GetLastError();                                    \
        _OutputDbgStr(__LINE__, #_X, status);                       \
        throw (DWORD) status;                                       \
    }                                                               \
}

#define CHECK_PTR(_X) {                                             \
    if (NULL == (_X)) {                                             \
        status = GetLastError();                                    \
        _OutputDbgStr(__LINE__, #_X, status);                       \
        throw (DWORD) status;                                       \
    }                                                               \
}

#define CHECK_ALLOC(_X) {                                           \
    if (NULL == (_X)) {                                             \
        status = ERROR_NOT_ENOUGH_MEMORY;                           \
        throw (DWORD) status;                                       \
    }                                                               \
}

#define CHECK_COM(_X) {                                             \
    hr = _X;                                                        \
    if (FAILED(hr)) {                                               \
        _OutputDbgStr(__LINE__, #_X, hr);                           \
        _com_issue_error(hr);                                       \
    }                                                               \
}

GUID CLSID_WindowsDefaultPolicyModule = {
	0x3B6654D0, 0xC2C8, 0x11D2, 0xB3, 0x13, 0x00, 0xC0, 0x4F, 0x79, 0xDC, 0x72
};

GUID CLSID_TestPolicyModule = {
	0x4986FFB1, 0xD9AD, 0x4EB6, 0xBB, 0x6A, 0x84, 0x85, 0xFD, 0x83, 0xB0, 0xAE
};

//
// Test entry point
//
int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT hr = S_OK;
	ICertPolicy2 *pCertPol2 = NULL;

	try
	{
		CoInitialize(NULL);

		CHECK_COM(CoCreateInstance(
			CLSID_WindowsDefaultPolicyModule,
			NULL,
			CLSCTX_INPROC_SERVER,
			IID_ICertPolicy2,
			(LPVOID *) &pCertPol2));

		pCertPol2->Release();
		pCertPol2 = NULL;

		CHECK_COM(CoCreateInstance(
			CLSID_TestPolicyModule,
			NULL,
			CLSCTX_INPROC_SERVER,
			IID_ICertPolicy2,
			(LPVOID *) &pCertPol2));
	}
	catch (HRESULT)
	{
	}

	if (NULL != pCertPol2)
		pCertPol2->Release();

	return 0;
}

