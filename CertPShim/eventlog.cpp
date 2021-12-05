#include "pch.cpp"
#pragma hdrstop

#define wszEVENT_SOURCE							L"Shim-PolicyModule-JWSecure"

HRESULT LogShimPolModEvent(
	__in					WORD wType,
	__in					WORD wCategory,
	__in					DWORD dwEventID,
	__in					WORD wNumStrings,
	__in					DWORD dwDataSize,
	__in					LPWSTR *lpStrings,
	__in					LPVOID lpRawData)
{
	HRESULT hr = S_OK;
	HANDLE hLog = NULL;

	if (NULL == (hLog = RegisterEventSource(NULL, wszEVENT_SOURCE)))
	{
		hr = (HRESULT) GetLastError();
		goto leave;
	}

	if (FALSE == ReportEventW(
		hLog, 
		wType,
		wCategory,
		dwEventID,
		NULL,
		wNumStrings,
		dwDataSize,
		(LPCWSTR *) lpStrings,
		lpRawData))
	{
		hr = (HRESULT) GetLastError();
		goto leave;
	}

leave:
	if (NULL != hLog)
		DeregisterEventSource(hLog);
	return hr;
}