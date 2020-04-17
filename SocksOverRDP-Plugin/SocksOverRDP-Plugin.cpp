/*
* MIT License
*
* Copyright(c) 2020 Balazs Bucsay
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files(the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions :
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/


#include "stdafx.h"
#include "resource.h"
#include "SocksOverRDP-Plugin.h"

#pragma comment(lib, "Ws2_32.lib")

#define SocksOverRDP_CHANNEL_NAME "SocksChannel"
#define BUF_SIZE 4096

struct arguments {
	DWORD enabled;
	WCHAR *ip;
	WCHAR *port;
};

// main thread struct for global variables
struct threadargs {
	struct arguments	*running_args;
	SOCKET				sockserver;
	BOOL				run;
	IWTSVirtualChannel	*m_ptrChannel = NULL;
	HANDLE				hThread = NULL;
} ta;

struct threads
{
	DWORD	dwThreadId;
	HANDLE	hThread;
	BOOL	run;
	SOCKET	s;
	struct threads *next;
};

// debug verbose flag
static BOOL bVerbose = FALSE;

static struct threads *ThreadHead = NULL;
char szOverflow[BUF_SIZE * 4];
DWORD dwOverflow = 0;

static HANDLE ghMutex, ghLLMutex;

using namespace ATL;

#define CHECK_QUIT_HR( _x_ )    if(FAILED(hr)) { return hr; }

class ATL_NO_VTABLE SocksOverRDPPlugin :
	public CComObjectRootEx<CComMultiThreadModel>,
	public CComCoClass<SocksOverRDPPlugin, &CLSID_CompReg>,
	public IWTSPlugin,
	public IWTSVirtualChannelCallback,
	public IWTSListenerCallback
{
public:
	CComPtr<IWTSVirtualChannel> m_ptrChannel;

	DECLARE_REGISTRY_RESOURCEID(IDR_SocksOverRDPPLUGIN)

	BEGIN_COM_MAP(SocksOverRDPPlugin)
		COM_INTERFACE_ENTRY(IWTSPlugin)
		COM_INTERFACE_ENTRY(IWTSVirtualChannelCallback)
		COM_INTERFACE_ENTRY(IWTSListenerCallback)
	END_COM_MAP()

	DECLARE_PROTECT_FINAL_CONSTRUCT()


	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

	// IWTSPlugin.
	//
	HRESULT STDMETHODCALLTYPE
		Initialize(IWTSVirtualChannelManager *pChannelMgr);

	HRESULT STDMETHODCALLTYPE Connected();

	HRESULT STDMETHODCALLTYPE Disconnected(DWORD dwDisconnectCode)
	{
		// Prevent C4100 "unreferenced parameter" warnings.
		dwDisconnectCode;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Terminated()
	{
		return S_OK;
	}

	VOID SetChannel(IWTSVirtualChannel *pChannel, struct threadargs *pTa);

	// IWTSVirtualChannelCallbackdwDummyThreadId
	//
	HRESULT STDMETHODCALLTYPE OnDataReceived(ULONG cbSize, __in_bcount(cbSize) BYTE *pBuffer);
	
	HRESULT STDMETHODCALLTYPE OnClose()
	{
		ta.run = FALSE;
		//DebugPrint(0, L"[*] Terminating thread, closing socket and channel0");
		TerminateThreads();

		closesocket(gpta->sockserver);
		
		ta.m_ptrChannel = NULL;
		WSACleanup();
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE
		OnNewChannelConnection(
			__in IWTSVirtualChannel *pChannel,
			__in_opt BSTR data,
			__out BOOL *pbAccept,
			__out IWTSVirtualChannelCallback **ppCallback);

	// non-inherited ones

	struct threadargs *gpta;
	struct arguments running_args;

	static struct threads *SocksOverRDPPlugin::AddThread(DWORD dwThreadId, SOCKET s);
	static VOID SocksOverRDPPlugin::DeleteThread(DWORD dwThreadId);
	static VOID SocksOverRDPPlugin::TerminateThreads();
	static struct threads *SocksOverRDPPlugin::LookupThread(DWORD dwThreadId);
	static VOID SocksOverRDPPlugin::StopThread(DWORD dwThreadId);

	static VOID SocksOverRDPPlugin::DebugPrint(HRESULT hrDbg, __in_z LPWSTR fmt, ...);
	LONG SocksOverRDPPlugin::GetDWORDRegKey(HKEY hKey, WCHAR *strValueName, DWORD *nValue);
	LONG SocksOverRDPPlugin::GetStringRegKey(HKEY hKey, WCHAR *strValueName, WCHAR **strValue);
	BOOL SocksOverRDPPlugin::GetRegistrySettings();
	static DWORD WINAPI SocksOverRDPPlugin::RelayToRDPChannel(PVOID param);
	static DWORD WINAPI SocksOverRDPPlugin::ListenerThread(PVOID param);
};

OBJECT_ENTRY_AUTO(__uuidof(CompReg), SocksOverRDPPlugin)

// Add thread to linked list
struct threads *SocksOverRDPPlugin::AddThread(DWORD dwThreadId, SOCKET s)
{
	struct threads *rolling;
	struct threads *ThreadStruct;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		ThreadStruct = (struct threads *)malloc(sizeof(struct threads));
		ThreadStruct->dwThreadId = dwThreadId;
		ThreadStruct->hThread = GetCurrentThread();
		ThreadStruct->run = TRUE;
		ThreadStruct->s = s;
		ThreadStruct->next = NULL;

		if (ThreadHead == NULL)
		{
			ThreadHead = ThreadStruct;
		}
		else
		{
			rolling = ThreadHead;
			while (rolling->next)
			{
				rolling = rolling->next;
			}
			rolling->next = ThreadStruct;
		}

		if (!ReleaseMutex(ghLLMutex))
		{
			if (bVerbose) DebugPrint(0, L"[*] AddThread Release failed: %08X", dwThreadId);
		}

		return ThreadStruct;
		break;

	case WAIT_ABANDONED:
		if (bVerbose) DebugPrint(0, L"[*] AddThread abandoned: %08X", GetCurrentThreadId());
		return NULL;
	}

	return NULL;
}

// Remove thread from linked list
VOID SocksOverRDPPlugin::DeleteThread(DWORD dwThreadId)
{
	struct threads *rolling;
	struct threads *prev = NULL;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		if (!ThreadHead)
		{
			if (!ReleaseMutex(ghLLMutex))
			{
				if (bVerbose) DebugPrint(0, L"[*] DeleteThread Release failed: %08X", GetCurrentThreadId());
			}
			return;
		}

		rolling = ThreadHead;

		while (rolling->dwThreadId != dwThreadId)
		{
			prev = rolling;
			rolling = rolling->next;
		}

		if (prev)
		{
			if (rolling->next)
			{
				prev->next = rolling->next;
			}
			else
			{
				prev->next = NULL;
			}
		}
		else
		{
			if (ThreadHead->next)
			{
				ThreadHead = ThreadHead->next;
			}
			else
			{
				ThreadHead = NULL;
			}
		}

		rolling->run = FALSE;
		closesocket(rolling->s);
		rolling->dwThreadId = 0xffffffff;
		rolling->next = FALSE;
		rolling->hThread = NULL;
		rolling->s = NULL;
		free(rolling);
		rolling = NULL;

		if (!ReleaseMutex(ghLLMutex))
		{
			if (bVerbose) DebugPrint(0, L"[*] DeleteThread Release failed: %08X", GetCurrentThreadId());
		}
		return;
		break;

	case WAIT_ABANDONED:
		if (bVerbose) DebugPrint(0, L"[*] DeleteThread abandoned: %08X", GetCurrentThreadId());
		return;
	}
}

/*
Terminate all running threads that handle communication
by setting the loop condition to FALSE and closing socket.
*/

VOID SocksOverRDPPlugin::TerminateThreads()
{
	struct threads *rolling;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		rolling = ThreadHead;

		if (rolling == NULL)
		{
			if (bVerbose) DebugPrint(0, L"[*] Nothing to terminate. Threadhead empty. %08X", GetCurrentThreadId());
		}

		while (rolling)
		{
			rolling->run = FALSE;
			closesocket(rolling->s);

			rolling = rolling->next;
		}
	
		if (!ReleaseMutex(ghLLMutex))
		{
			if (bVerbose) DebugPrint(0, L"[*] TerminateThreads Release failed: %08X", GetCurrentThreadId());
		}
		return;
		break;

	case WAIT_ABANDONED:
		if (bVerbose) DebugPrint(0, L"[*] TerminateThreads abandoned: %08X", GetCurrentThreadId());
		return;
	}
}

// Stopping a specific thread gently by setting the loop condition to FALSE
VOID SocksOverRDPPlugin::StopThread(DWORD dwThreadId)
{
	struct threads *rolling;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		rolling = ThreadHead;

		while (rolling)
		{
			if (rolling->dwThreadId == dwThreadId)
			{
				rolling->run = FALSE;
				if (!ReleaseMutex(ghLLMutex))
				{
					if (bVerbose) DebugPrint(0, L"[*] StopThread Release failed0: %08X", GetCurrentThreadId());
				}
				return;
			}
			rolling = rolling->next;
		}

		if (!ReleaseMutex(ghLLMutex))
		{
			if (bVerbose) DebugPrint(0, L"[*] StopThread Release failed1: %08X", GetCurrentThreadId());
		}
		return;
		break;

	case WAIT_ABANDONED:
		if (bVerbose) DebugPrint(0, L"[*] lookupThread abandoned: %08X", GetCurrentThreadId());
		return;
	}

	return;
}

// Look up thread and return a pointer to it by ThreadId
struct threads *SocksOverRDPPlugin::LookupThread(DWORD dwThreadId)
{
	struct threads *rolling;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		rolling = ThreadHead;

		while (rolling)
		{
			if (rolling->dwThreadId == dwThreadId)
			{
				if (!ReleaseMutex(ghLLMutex))
				{
					if (bVerbose) DebugPrint(0, L"[*] lookupThread Release failed0: %08X", GetCurrentThreadId());
				}
				return rolling;
			}
			rolling = rolling->next;
		}

		if (!ReleaseMutex(ghLLMutex))
		{
			if (bVerbose) DebugPrint(0, L"[*] lookupThread Release failed1: %08X", GetCurrentThreadId());
		}
		return NULL;
		break;

	case WAIT_ABANDONED:
		if (bVerbose) DebugPrint(0, L"[*] lookupThread abandoned: %08X", GetCurrentThreadId());
		return NULL;
	}

	return NULL;
}

// Debug/Verbose Print function, message shows up in the debugger.
VOID SocksOverRDPPlugin::DebugPrint(HRESULT hrDbg, __in_z LPWSTR fmt, ...)
{
	HRESULT	hr;
	TCHAR	Buffer[DEBUG_PRINT_BUFFER_SIZE];
	size_t	Len;

	hr = StringCchPrintf(Buffer, DEBUG_PRINT_BUFFER_SIZE, TEXT("[hr=0x%8x]"), hrDbg);
	assert(SUCCEEDED(hr)); // buffer is sure to be big enough

	hr = StringCchLength(Buffer, DEBUG_PRINT_BUFFER_SIZE, &Len);
	assert(SUCCEEDED(hr)); // StringCchPrintf is supposed to always NULL term

	va_list argptr;
	va_start(argptr, fmt);

	hr = StringCchVPrintf(Buffer + Len, DEBUG_PRINT_BUFFER_SIZE - Len,
		fmt, argptr);

	// the above could fail but we don't care since we
	// should get a NULL terminated partial string

	// insert terminating eol (despite failure)
	hr = StringCchLength(Buffer, DEBUG_PRINT_BUFFER_SIZE, &Len);
	assert(SUCCEEDED(hr)); // again there should be a NULL term

	if (Len < DEBUG_PRINT_BUFFER_SIZE - 1)
	{
		Len++;
		Buffer[Len] = TEXT('\0');
	}

	Buffer[Len - 1] = TEXT('\n');

	OutputDebugString(Buffer);
}

LONG SocksOverRDPPlugin::GetDWORDRegKey(HKEY hKey, WCHAR *strValueName, DWORD *nValue)
{
	DWORD	dwBufferSize(sizeof(DWORD));
	DWORD	nResult;
	LONG	nError;

	if ((nError = RegQueryValueEx(hKey, strValueName, 0, NULL, (LPBYTE)&nResult, &dwBufferSize)) == ERROR_SUCCESS)
	{
		*nValue = nResult;
	}
	return nError;
}

LONG SocksOverRDPPlugin::GetStringRegKey(HKEY hKey, WCHAR *strValueName, WCHAR **strValue)
{
	LPVOID	szTemp = NULL;
	DWORD	buflen = 255;
	LONG	nError;

	if ((szTemp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)buflen)) == NULL)
	{
		if (bVerbose) DebugPrint(GetLastError(), L"[-] Error allocating heap for read buffer %ld", GetLastError());
		return -1;
	}

	if ((nError = RegQueryValueExW(hKey, strValueName, 0, NULL, (LPBYTE)szTemp, &buflen)) != ERROR_SUCCESS)
	{
		HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, szTemp);
		szTemp = NULL;
	}
	*strValue = (WCHAR *)szTemp;

	return nError;
}

BOOL SocksOverRDPPlugin::GetRegistrySettings()
{
	HKEY	hKey;
	LONG	lRes;
	WCHAR	*szTemp;

	if ((lRes = RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\SocksOverRDP-Plugin\\", 0, KEY_READ, &hKey)) != ERROR_SUCCESS)
	{
		DebugPrint(lRes, L"[-] Error opening registry hive/key");
		return FALSE;
	}

	GetDWORDRegKey(hKey, L"enabled", &running_args.enabled);
	GetStringRegKey(hKey, L"ip", &szTemp);
	if (szTemp != NULL)
	{
		if (wcslen(szTemp) < 16)
		{
			running_args.ip = szTemp;
		}
		else
		{
			MessageBox(NULL, L"IP too long. Please fix it under the following key:\r\nHKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\SocksOverRDP-Plugin\\", L"Registry value error", MB_OK);
		}
	}
	GetStringRegKey(hKey, L"port", &szTemp);
	if (szTemp != NULL)
	{
		if (wcslen(szTemp) < 6)
		{
			running_args.port = szTemp;
		}
		else
		{
			MessageBox(NULL, L"Port too long. Please fix it under the following key:\r\nHKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\SocksOverRDP-Plugin\\", L"Registry value error", MB_OK);
		}
	}
	
	return TRUE;
}


// IWTSPlugin::Initialize implementation.
HRESULT SocksOverRDPPlugin::Initialize(__in IWTSVirtualChannelManager *pChannelMgr)
{
	HRESULT	hr;
	CComObject<SocksOverRDPPlugin> *pListenerCallback;
	CComPtr<SocksOverRDPPlugin> ptrListenerCallback;
	CComPtr<IWTSListener> ptrListener;
	WCHAR	enabledmsg[256];

	running_args.enabled = 0;
	running_args.port = L"1080";
	running_args.ip = L"127.0.0.1";

	if (!GetRegistrySettings())
	{
		DebugPrint(-1, L"[-] Could not access the registry settings");
	}

	if (!running_args.enabled)
	{
		DebugPrint(0, L"[*] Plugin disabled");
		return -1;
	}

	wnsprintf(enabledmsg, 255, L"The SocksOverRDP plugin is enabled. When the server binary gets executed, it will listen on: %s:%s", running_args.ip, running_args.port);
	MessageBox(NULL, enabledmsg, L"SocksOverRDP plugin is enabled", MB_OK | MB_ICONWARNING);


	// Create an instance of the CSampleListenerCallback object.
	hr = CComObject<SocksOverRDPPlugin>::CreateInstance(&pListenerCallback);
	CHECK_QUIT_HR("SocksOverRDPPlugin::CreateInstance");
	ptrListenerCallback = pListenerCallback;

	// Attach the callback to the endpoint.
	hr = pChannelMgr->CreateListener(
		SocksOverRDP_CHANNEL_NAME,
		0,
		(SocksOverRDPPlugin*)ptrListenerCallback,
		&ptrListener);
	CHECK_QUIT_HR("CreateListener");

	return hr;
}

// MSTSC connected to server over RDP
HRESULT STDMETHODCALLTYPE SocksOverRDPPlugin::Connected()
{
	return S_OK;
}

/*
This thread is started for each and every connection that is made to the socks 
proxy. This part only handles the Client->RDP communication.
Whatever comes from the client will be piped into the RDP channel with prefixed
with: DWORD(threadid)+DWORD(sizeof(following_data))+BYTE(closurebit)
*/
DWORD SocksOverRDPPlugin::RelayToRDPChannel(PVOID param)
{
	SOCKET	c = (SOCKET)param;
	DWORD	dwWaitResult, dwThreadId = GetCurrentThreadId();
	char	buf[BUF_SIZE + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE)];
	int		ret;
	struct threads *pta;

	pta = AddThread(dwThreadId, c);	
	if (!pta)
	{
		if (bVerbose) DebugPrint(0, L"%08X: Adding thread failure.", dwThreadId);
		return -1;
	}

	// running till error or thread stopped
	while (pta->run)
	{
		// reading from client socket
		if ((ret = recv(c, buf + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE), BUF_SIZE, 0)) > 0)
		{
			// might have been blocked for a long time and the thread should be
			// stopped already
			if (!pta->run) break;
			// prefixing with the necessities
			memcpy(buf, &dwThreadId, sizeof(DWORD));
			memcpy(buf + sizeof(DWORD), &ret, sizeof(DWORD));
			buf[sizeof(DWORD) + sizeof(DWORD)] = 0;
		}
		else
		{
			// SOCKET_ERROR or RST was received
			if (!pta->run) 
				break;
			if (ret && bVerbose)
				DebugPrint(0, L"%08X: SOCKS thread(%d) Rsend() failed with errorelayToRDPChannel recv error: %ld %ld", dwThreadId, dwThreadId, ret, WSAGetLastError());
			ret = 0;
			memcpy(buf, &dwThreadId, sizeof(DWORD));
			memcpy(buf + sizeof(DWORD), &ret, sizeof(DWORD));
			buf[sizeof(DWORD) + sizeof(DWORD)] = 1;

			pta->run = FALSE;
		}

		// wait on mutex, when it is acquired, block other threads to write
		dwWaitResult = WaitForSingleObject(ghMutex, INFINITE);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			// write prefixed received data on channel
			if (ta.m_ptrChannel != NULL)
				if (ta.m_ptrChannel->Write(ret + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE), (BYTE *)buf, NULL))
				{
					if (bVerbose) DebugPrint(0, L"Write to channel failed for some reason.");
				}
			if (!ReleaseMutex(ghMutex))
			{
				if (bVerbose) DebugPrint(0, L"Release failed");
			}
			break;

		case WAIT_ABANDONED:
			return FALSE;

		}
	}

	DeleteThread(dwThreadId);
	return 0;
}

DWORD SocksOverRDPPlugin::ListenerThread(PVOID param)
{
	WSADATA		wsaData;
	ADDRINFOW	*result = NULL;
	ADDRINFOW	hints;
	SOCKET		s, c;
	HANDLE		hDummyThread;
	DWORD		dwDummyThreadId;
	int			ret;

	DebugPrint(0, L"[*] Setting up server socket");
	if ((ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		DebugPrint(ret, L"WSAStartup() failed with error: %ld", ret);
		return -1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	if ((ret = GetAddrInfoW(ta.running_args->ip, ta.running_args->port, &hints, &result)) != 0) {
		DebugPrint(ret, L"[-] GetAddrInfoW() failed with error: %ld", ret);
		return -1;
	}

	if ((s = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET) {
		DebugPrint(WSAGetLastError(), L"[-] socket() failed with error: %ld", WSAGetLastError());
		FreeAddrInfoW(result);
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, "1", 1) == SOCKET_ERROR)
	{
		DebugPrint(WSAGetLastError(), L"[-] setsockopt() failed with error: %ld", WSAGetLastError());
	}

	ta.sockserver = s;

	if ((ret = bind(s, result->ai_addr, (int)result->ai_addrlen)) == SOCKET_ERROR) {
		DebugPrint(WSAGetLastError(), L"[-] bind() failed with error: %ld", WSAGetLastError());
		FreeAddrInfoW(result);
		closesocket(s);
		return -1;
	}

	FreeAddrInfoW(result);
	DebugPrint(0, L"[*] Listening on: %s:%s", ta.running_args->ip, ta.running_args->port);

	if ((ret = listen(s, SOMAXCONN)) == SOCKET_ERROR) {
		DebugPrint(0, L"[-] listen() failed with error: %ld", WSAGetLastError());
		closesocket(s);
		return -1;
	}

	// while till the RDP connection wasn't closed and
	// create a new thread for all new connections
	while (ta.run)
	{
		if ((c = accept(s, NULL, NULL)) == INVALID_SOCKET) {
			DebugPrint(0, L"[-] accept() failed with error: %ld", WSAGetLastError());
			return -1;
		}

		hDummyThread = CreateThread(
			NULL,
			0,
			&SocksOverRDPPlugin::RelayToRDPChannel,
			(void *)c,
			0,
			&dwDummyThreadId);
		if (bVerbose) DebugPrint(0, L"[+] New thread created: %08X", dwDummyThreadId);
	}
	
	return 0;
}

// IWTSListenerCallback::OnNewChannelConnection implementation.
HRESULT SocksOverRDPPlugin::OnNewChannelConnection(__in IWTSVirtualChannel *pChannel,
	__in_opt BSTR data, __out BOOL *pbAccept, __out IWTSVirtualChannelCallback **ppCallback)
{
	HRESULT		hr;
	CComObject<SocksOverRDPPlugin> *pCallback;
	CComPtr<SocksOverRDPPlugin> ptrCallback;

	// Prevent C4100 "unreferenced parameter" warnings.
	data;

	*pbAccept = FALSE;

	hr = CComObject<SocksOverRDPPlugin>::CreateInstance(&pCallback);
	CHECK_QUIT_HR("SocksOverRDPPlugin::CreateInstance");
	ptrCallback = pCallback;

	ptrCallback->SetChannel(pChannel, &ta);

	ta.running_args = &running_args;
	ta.m_ptrChannel = pChannel;
	ta.run = TRUE;

	ghMutex = CreateMutex(NULL, FALSE, NULL);
	ghLLMutex = CreateMutex(NULL, FALSE, NULL);

	running_args.enabled = 0;
	running_args.port = L"1080";
	running_args.ip = L"127.0.0.1";
	
	if (!GetRegistrySettings())
	{
		DebugPrint(-1, L"[-] Could not access the registry settings");
	}

	DebugPrint(0, L"[+] Starting Listener thread");

	// Create main thread that will spawn other threads upon new connections
	HANDLE hListenerThread = CreateThread(
		NULL,
		0,
		&SocksOverRDPPlugin::ListenerThread,
		NULL,
		0,
		NULL);

	ta.hThread = hListenerThread;

	*ppCallback = ptrCallback;
	(*ppCallback)->AddRef();

	*pbAccept = TRUE;

	return hr;
}

VOID SocksOverRDPPlugin::SetChannel(IWTSVirtualChannel *pChannel, struct threadargs *pTa)
{
	m_ptrChannel = pChannel;
	gpta	= pTa;
}

// When data is received from the RDP server on the channel, this function is
// getting called with the *data on stack
HRESULT STDMETHODCALLTYPE SocksOverRDPPlugin::OnDataReceived(ULONG cbSize, __in_bcount(cbSize) BYTE *pBuffer)
{
	DWORD			dwThreadId, ret, dwRecvdLen, cbFullSize;
	BOOL			bClose = FALSE, ofused = FALSE;
	char			*buf;
	struct threads  *pta;

	buf = (char*)pBuffer;
	cbFullSize = cbSize;

	// if overflow was present from previous call, it was saved and should be 
	// prepended with the new data
	// ofused if set, signals that szOverflow has the data instead of pBuffer
	if (dwOverflow)
	{
		if (bVerbose) DebugPrint(0, L"Overflow was present from previous call. Stored bytes: %ld. Received bytes: %ld", dwOverflow, cbSize);
		memcpy_s(szOverflow + dwOverflow, BUF_SIZE*4, pBuffer, cbSize);
		buf = szOverflow;
		cbFullSize = cbSize + dwOverflow;
		dwOverflow = 0;
		ofused = TRUE;
	}
	while (cbFullSize)
	{
		// parsing the header, getting threadId from server side, that matches 
		// the local threadID; recvlen which has the appended data length ;
		// bClose bit which shows weather the connection will be/was closed
		// on the server side.
		memcpy(&dwThreadId, buf, sizeof(DWORD));
		memcpy(&dwRecvdLen, buf + sizeof(DWORD), sizeof(DWORD));
		if (buf[sizeof(DWORD) + sizeof(DWORD)] == 0x01) bClose = TRUE;

		// finding thread based on the header. If no thread found, that is a
		// problem, since there is no thread that has the associated info for
		// this received data
		pta = LookupThread(dwThreadId);
		if (pta == NULL)
			return -1;

		if (bVerbose) DebugPrint(0, L"%08X: Read: %ld content length: %ld", dwThreadId, cbFullSize, dwRecvdLen);

		if (dwRecvdLen <= cbFullSize - (sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE)))
		{
			if (bVerbose) DebugPrint(0, L"%08X: Last read, smaller or equal.", dwThreadId);
			if (dwRecvdLen)
			{
				if (pta->s)
				{
					// send recvl bytes from the received data to the 
					// corresponding socket
					if ((ret = send(pta->s, buf + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE), dwRecvdLen, 0)) == SOCKET_ERROR)
					{
						// error happened, stopping thread gently and
						// recalculating pointers to the next packet
						StopThread(dwThreadId);
						if (bVerbose) DebugPrint(0, L"%08X: send() failed with error %ld %ld", dwThreadId, ret, WSAGetLastError());

						cbFullSize -= (dwRecvdLen + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE));
						buf += (dwRecvdLen + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE));
					}
					else
					{
						// recalculating pointers to the next packet
						cbFullSize -= (ret + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE));
						buf += (ret + sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE));
						if (bVerbose) DebugPrint(0, L"%08X: Sent on socket: %ld. cbFullSize: %ld", dwThreadId, ret, cbFullSize);
					}
				}
			}
			// bClose bit was set on the server side. Closing down connection
			if (bClose)
			{
				StopThread(dwThreadId);
				if (pta->s)
					shutdown(pta->s, SD_SEND);

				// only RST was sent from server side
				if (!dwRecvdLen)
				{
					cbFullSize -= sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE);
					buf += sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE);
				}
			}
		}
		else
		{
			// data remained on the buffer, less than specified in the header
			if (bVerbose) DebugPrint(0, L"!!! OVERFLOW HAPPENED %ld > %ld", dwRecvdLen, cbFullSize);
			if (ofused)
			{
				// ofused set, memmove needed
				memmove_s(szOverflow, BUF_SIZE * 4, buf, cbFullSize);
				dwOverflow = cbFullSize;
			}
			else
			{
				memcpy_s(szOverflow, BUF_SIZE * 4, buf, cbFullSize);
				dwOverflow = cbFullSize;
			}

			// not enough data to send, need to get more, stopping loop
			cbFullSize = 0;
		}
	}

	return S_OK;
}