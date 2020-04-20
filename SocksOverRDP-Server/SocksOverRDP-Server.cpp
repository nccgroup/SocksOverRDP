/*
 * MIT License
 *
 * Copyright(c) 2018 Balazs Bucsay
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

 /*
 TODO List:
 - verbose/debug mode +others
 - anti-timeout
 - check socket activity and close after timeout
 */


#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <wtsapi32.h>
#include <pchannel.h>
#include <crtdbg.h>
#include <stdio.h>
#include <strsafe.h>
#include <assert.h>
#include "SocksOverRDP-Server.h"
#include "SocksServer.h"


#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "Ws2_32.lib")

#define SocksOverRDP_CHANNEL_NAME "SocksChannel"
#define DEBUG_PRINT_BUFFER_SIZE 1024
#define BUF_SIZE 4096

extern DWORD WINAPI HandleClient(void *param);

DWORD OpenDynamicChannel(LPCSTR szChannelName, HANDLE *phFile);

struct arguments {
	WCHAR	*ip;
	WCHAR	*port;
	BYTE	priority;
} running_args;

struct threadhandles {
	HANDLE	hRDP = NULL;
	SOCKET	sock = NULL;
	HANDLE	pipe = NULL;
};

struct threads *ThreadHead = NULL;

int		CTRLC = 0;
HANDLE	ghMutex, ghLLMutex;
HANDLE	hChannel;
HANDLE	hWTSHandle = NULL;
BOOL	bVerbose = FALSE, bDebug = FALSE;

VOID usage(WCHAR *cmdname)
{
	wprintf(L"Usage: %s [-v] [-t timeout_val]\n"
		"-h\t\tThis help\n"
		"-v\t\tVerbose Mode\n",
//		"-t n\tTimeout on threads. Kills any thread and corresponding connection after n seconds\n",
		cmdname);

	return;
}

BOOL parse_argv(INT argc, __in_ecount(argc) WCHAR **argv)
{
	int num = 0;

	while (num < argc - 1)
	{
		num++;

		if (wcsncmp(argv[num], L"-", 1))
		{
			wprintf(L"[-] Invalid argument: %s\n", argv[num]);
			usage(argv[0]);
			return FALSE;
		}

		switch (argv[num][1])
		{
		case 'h':
		case '?':
			usage(argv[0]);
			return FALSE;
		case 'v':
			bVerbose = TRUE;
			break;
		case 'd':
			bDebug = TRUE;
			break;
		//case 't':
		//	num++;

			//dwTimeout = atoi(argv[num]);
			//printf("timeout: %ld\n", dwTimeout);
			break;

		default:
			wprintf(L"[-] Invalid argument: %s\n", argv[num]);
			usage(argv[0]);
			return FALSE;
		}
	}
	return TRUE;
}

VOID DebugPrint(HRESULT hrDbg, __in_z LPWSTR fmt, ...)
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
	//OutputDebugString(Buffer);
	wprintf(Buffer);
}

// Add thread to linked list
struct threads *AddThread(DWORD dwThreadId, DWORD dwRemoteThreadId, HANDLE hSlot_r, HANDLE hSlot_w)
{
	struct threads *rolling;
	struct threads *ThreadStruct;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		ThreadStruct = (threads *)malloc(sizeof(struct threads));
		ThreadStruct->dwThreadId = dwThreadId;
		ThreadStruct->dwRemoteThreadId = dwRemoteThreadId;
		ThreadStruct->hThread = NULL;
		ThreadStruct->run = TRUE;
		ThreadStruct->hSlot_r = hSlot_r;
		ThreadStruct->hSlot_w = hSlot_w;
		ThreadStruct->hSlot_event = NULL;
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
			printf("Release failed\n");
		}
		return ThreadStruct;
		break;

	case WAIT_ABANDONED:
		printf("%08X: AddThread lock abandoned\n", dwThreadId);
		return NULL;
	}

	return NULL;
}

// Look up thread and return a pointer to it by local ThreadId
struct threads *LookupThread(DWORD dwThreadId)
{
	struct threads *rolling;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		rolling = ThreadHead;
		if (rolling == NULL)
		{
			if (!ReleaseMutex(ghLLMutex))
			{
				DebugPrint(0, L"[-] LookupThread Release Failed0: %08X", GetCurrentThreadId());
			}
			return NULL;
		}

		while (rolling)
		{
			if (rolling->dwThreadId == dwThreadId)
			{
				if (!ReleaseMutex(ghLLMutex))
				{
					DebugPrint(0, L"[-] LookupThread Release Failed1: %08X", GetCurrentThreadId());
				}
				return rolling;
			}
			rolling = rolling->next;
		}

		if (!ReleaseMutex(ghLLMutex))
		{
			DebugPrint(0, L"[-] LookupThread Release Failed2: %08X", GetCurrentThreadId());
		}
		return NULL;
		break;
	case WAIT_ABANDONED:
		printf("%08X: LookupThread lock abandoned\n", dwThreadId);
		return NULL;
	}

	return NULL;
}

// Look up thread and return a pointer to it by remote threadid
struct threads *LookupThreadRemote(DWORD dwRemoteThreadId)
{
	struct threads *rolling;

	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		rolling = ThreadHead;

		if (rolling == NULL)
		{
			if (!ReleaseMutex(ghLLMutex))
			{
				DebugPrint(0, L"[-] LookupThreadRemote Release Failed0: %08X", GetCurrentThreadId());
			}
			return NULL;
		}

		while (rolling)
		{
			if (rolling->dwRemoteThreadId == dwRemoteThreadId)
			{
				if (!ReleaseMutex(ghLLMutex))
				{
					DebugPrint(0, L"[-] LookupThreadRemote Release Failed1: %08X", GetCurrentThreadId());
				}
				return rolling;
			}
			rolling = rolling->next;
		}

		if (!ReleaseMutex(ghLLMutex))
		{
			DebugPrint(0, L"[-] LookupThreadRemote Release Failed2: %08X", GetCurrentThreadId());
		}
		return NULL;
		break;
	case WAIT_ABANDONED:
		printf("%08X: LookupThreadRemote lock abandoned\n", GetCurrentThreadId());
		return NULL;
	}
	return NULL;
}

// Remove thread from linked list
VOID DeleteThread(DWORD dwThreadId)
{
	struct threads *rolling;
	struct threads *prev = NULL;

	//printf("%08X: DeleteThread lock wait\n", dwThreadId);
	DWORD dwWaitResult = WaitForSingleObject(ghLLMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		if (!ThreadHead)
		{
			if (!ReleaseMutex(ghLLMutex))
			{
				DebugPrint(0, L"[-] Trying to delete an empty list. %ld", GetCurrentThreadId());
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

		rolling->dwThreadId = 0xffffffff;
		rolling->next = NULL;
		rolling->run = FALSE;
		rolling->hSlot_w = NULL;
		rolling->hSlot_r = NULL;
		rolling->hSlot_event = NULL;
		rolling->hSlot_r = NULL;
		free(rolling);
		rolling = NULL;

		if (!ReleaseMutex(ghLLMutex))
		{
			printf("Release failed\n");
		}
		return;
		break;

	case WAIT_ABANDONED:
		printf("%08X: DeleteThread lock abandoned\n", dwThreadId);
		return;
	}
}

// If CTRL+C pressed, all threads should be stopped and safely exit
// Double press: closing channel and leaving the rest to the OS.
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	struct threads *rolling;

	switch (fdwCtrlType)
	{
	case CTRL_C_EVENT:
		if (CTRLC)
		{
			wprintf(L"[*] Forced terminating\n");
			WTSVirtualChannelClose(hWTSHandle);
			exit(0);
		}

		wprintf(L"[*] CTRL+C pressed. Closing down.\n");

		CTRLC = 1;
		if (!ThreadHead)
		{
			WTSVirtualChannelClose(hWTSHandle);
			exit(0);
		}

		rolling = ThreadHead;
		
		do
		{
			rolling->run = FALSE;
			SetEvent(rolling->hSlot_event);
		} while (rolling = rolling->next);

		wprintf(L"[*] All threads are signaled to stop\n");
		rolling = ThreadHead;
		
		wprintf(L"[*] Closing channel\n");

		WTSVirtualChannelClose(hWTSHandle);
		exit(0);
		return TRUE;
	default:
		return FALSE;
	}
}

INT _cdecl wmain(INT argc, __in_ecount(argc) WCHAR **argv)
{
	WSADATA	wsaData;
	BOOL        bSucc, ofused, bClose = FALSE;
	HANDLE      hEvent, hSlot_r, hSlot_w = NULL;
	OVERLAPPED  Overlapped, Overlapped_MailSlot;
	DWORD       dwRecvdLen, dwRead, dwWritten, bufWritelen, dwOverflow = 0;
	DWORD		dwRemoteThreadId, dwThreadId;
	ULONG		cbFullSize;
	BYTE        ReadBuffer[CHANNEL_PDU_LENGTH];
	CHANNEL_PDU_HEADER *pHdr = (CHANNEL_PDU_HEADER *)ReadBuffer;
	char		*buf, *bufWrite, szOverflow[BUF_SIZE * 4], szMailSlotName[32];
	int			ret;
	struct threadhandles threadhandle;
	struct threads *pta;

	running_args.port = L"1080";
	running_args.priority = 4;
	running_args.ip = L"127.0.0.1";

	wprintf(L"Socks Over RDP by Balazs Bucsay [[@xoreipeip]]\n\n");

	if (argc > 1)
		if (!parse_argv(argc, argv))
			return -1;
	
	if ((ret = OpenDynamicChannel(SocksOverRDP_CHANNEL_NAME, &hChannel)) != ERROR_SUCCESS)
	{
		if (ret == 31)
			wprintf(L"[-] Could not open Dynamic Virtual Channel, plugin was not loaded on the client side: %ld\n", ret);
		else
			wprintf(L"[-] Could not open Dynamic Virtual Channel: %ld  %08X\n", ret, ret);
		return -1;
	}

	wprintf(L"[*] Channel opened over RDP\n");

	ghMutex = CreateMutex(NULL, FALSE, NULL);
	ghLLMutex = CreateMutex(NULL, FALSE, NULL);

	Overlapped_MailSlot = { 0 };
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	Overlapped = { 0 };
	Overlapped.hEvent = hEvent;

	if ((ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		wprintf(L"[-] WSAStartup() failed with error: %ld\n", ret);
		return -1;
	}

	// set handler for Ctrl+C
	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	// whatever arrives to the channel, it needs to be parsed and written to
	// the corresponding mailslot
	while (TRUE)
	{
		bSucc = ReadFile(hChannel, ReadBuffer, sizeof(ReadBuffer), &dwRead, &Overlapped);
		if (!bSucc)
		{
			if (GetLastError() == ERROR_IO_PENDING)
			{
				WaitForSingleObject(Overlapped.hEvent, INFINITE);
				bSucc = GetOverlappedResult(hChannel, &Overlapped, &dwRead, FALSE);
			}
		}
		if (!bSucc)
		{
			wprintf(L"[-] ReadFile()/WaitForSingleObject() error: %ld\n", GetLastError());
			return -1;
		}

		// no need to pass the header.
		bufWrite = (char *)(pHdr + 1);
		bufWritelen = dwRead - sizeof(CHANNEL_PDU_HEADER);

		buf = (char*)bufWrite;
		cbFullSize = bufWritelen;
		ofused = FALSE;

		// if overflow was present from previous call, we append it to the 
		// saved bytes
		if (dwOverflow)
		{
			if (bDebug) printf("[*] Overflow was present from previous call. Stored bytes: %ld. Received bytes: %ld == %ld \n", dwOverflow, bufWritelen, dwOverflow+bufWritelen);
			memcpy_s(szOverflow + dwOverflow, BUF_SIZE * 4, bufWrite, bufWritelen);
			buf = szOverflow;
			cbFullSize = bufWritelen + dwOverflow;
			dwOverflow = 0;
			ofused = TRUE;
		}

		// run while anything left in buffer
		while (cbFullSize)
		{
			// edge case, less than necesary data in buffer
			if (cbFullSize < 9)
			{
				if (ofused)
				{
					// overflow was used and still not enough data
					if (bDebug) printf("[*] Not enough data, ofused: %ld\n", cbFullSize);
					dwOverflow = cbFullSize;
				}
				else
				{
					// no overflow was used, saving the data to overflow
					if (bDebug) printf("[*] Not enough data, no ofused: %ld\n", cbFullSize);
					memcpy_s(szOverflow, BUF_SIZE * 4, buf, cbFullSize);
					dwOverflow = cbFullSize;
				}

				// exit loop since not enough data
				cbFullSize = 0;
				break;
			}

			// parsing header
			memcpy(&dwRemoteThreadId, buf, sizeof(DWORD));
			memcpy(&dwRecvdLen, buf + sizeof(DWORD), sizeof(DWORD));

			// corresponding thread lookup
			if ((pta = LookupThreadRemote(dwRemoteThreadId)) == NULL)
			{
				// failed to find existing thread, creating one
				memset(szMailSlotName, 0, 32);
				snprintf(szMailSlotName, 32, "\\\\.\\mailslot\\RDPSocks_%08X", dwRemoteThreadId);

				hSlot_r = CreateMailslotA(szMailSlotName, 0, MAILSLOT_WAIT_FOREVER, (LPSECURITY_ATTRIBUTES)NULL);
				if (hSlot_r == INVALID_HANDLE_VALUE)
				{
					printf("CreateMailslot_r failed with %d\n", GetLastError());
					break;
				}

				hSlot_w = CreateFileA(szMailSlotName, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL,
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

				if (hSlot_w == INVALID_HANDLE_VALUE)
				{
					printf("CreateMailslot_w failed with %d.\n", GetLastError());
					break;
				}

				pta = AddThread(0, dwRemoteThreadId, hSlot_r, hSlot_w);

				HANDLE hDummyThread = CreateThread(
					NULL,
					0,
					&HandleClient,
					(void *)pta,
					0,
					&dwThreadId);

				pta->dwThreadId = dwThreadId;
				pta->hThread = hDummyThread;
				if (bDebug) printf("[*] %08X: Thread not found, Mailslot created\n", dwRemoteThreadId);
			}
			else
			{
				if (bDebug) printf("[*] %08X: Thread found, Mailslot found\n", dwRemoteThreadId);
				hSlot_w = pta->hSlot_w;
			}

			// Is data in buffer bigger than expected data + header?
			if (dwRecvdLen <= cbFullSize - (sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE)))
			{
				bSucc = WriteFile(hSlot_w, buf + sizeof(DWORD) + sizeof(DWORD), dwRecvdLen + 1, &dwWritten, &Overlapped_MailSlot);
				if (!bSucc)
				{
					if (GetLastError() == ERROR_IO_PENDING)
					{
						WaitForSingleObject(Overlapped_MailSlot.hEvent, INFINITE);
						bSucc = GetOverlappedResult(hChannel, &Overlapped_MailSlot, &dwWritten, TRUE);
					}
				}
				if (!bSucc)
				{
					if (bDebug) printf("[-] %08X: WriteChannel error: %ld\n", dwRemoteThreadId, GetLastError());
					cbFullSize = 0;
				}
				else
				{
					if (bDebug) printf("[+] %08X: no error, written: %ld, should have written: %ld | cbFullSize: %ld\n", dwRemoteThreadId, dwWritten, dwRecvdLen + 1, cbFullSize);
					cbFullSize -= (dwWritten + sizeof(DWORD) + sizeof(DWORD));
					buf += (dwWritten + sizeof(DWORD) + sizeof(DWORD));
				}
			}
			else
			{
				// less data then expected, saving to szOverflow
				if (bDebug) printf("[*] !!! OVERFLOW HAPPENED %ld < %ld -9\n", dwRecvdLen, cbFullSize);
				if (ofused)
				{
					if (bDebug) printf("[*] Data left in buffer, ofused: %ld\n", cbFullSize);
					memmove_s(szOverflow, BUF_SIZE * 4, buf, cbFullSize);
					dwOverflow = cbFullSize;
				}
				else
				{
					if (bDebug) printf("[*] Data left in buffer, not ofused: %ld\n", cbFullSize);
					memcpy_s(szOverflow, BUF_SIZE * 4, buf, cbFullSize);
					dwOverflow = cbFullSize;
				}
				cbFullSize = 0;
			}
		}
	}

	CloseHandle(ghMutex);
	CloseHandle(hChannel);

	return 0;
}

/*
*  Open a dynamic channel with the name given in szChannelName.
*  The output file handle can be used in ReadFile/WriteFile calls.
*/
DWORD OpenDynamicChannel(LPCSTR szChannelName, HANDLE *phFile)
{
	HANDLE	hWTSFileHandle;
	PVOID	vcFileHandlePtr = NULL;
	DWORD	len;
	DWORD	rc = ERROR_SUCCESS;
	BOOL	fSucc;


	hWTSHandle = WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, (LPSTR)szChannelName,
		WTS_CHANNEL_OPTION_DYNAMIC | running_args.priority);
	if (NULL == hWTSHandle)
	{
		rc = GetLastError();
		goto exitpt;
	}

	fSucc = WTSVirtualChannelQuery(hWTSHandle, WTSVirtualFileHandle,
		&vcFileHandlePtr, &len);
	if (!fSucc)
	{
		rc = GetLastError();
		goto exitpt;
	}
	if (len != sizeof(HANDLE))
	{
		rc = ERROR_INVALID_PARAMETER;
		goto exitpt;
	}

	hWTSFileHandle = *(HANDLE *)vcFileHandlePtr;
	fSucc = DuplicateHandle(GetCurrentProcess(), hWTSFileHandle, 
		GetCurrentProcess(), phFile, 0, FALSE, DUPLICATE_SAME_ACCESS);

	if (!fSucc)
	{
		rc = GetLastError();
		goto exitpt;
	}

	rc = ERROR_SUCCESS;

exitpt:
	if (vcFileHandlePtr)
	{
		WTSFreeMemory(vcFileHandlePtr);
	}
	if (hWTSHandle)
	{
		WTSVirtualChannelClose(hWTSHandle);
	}

	return rc;
}