/*
TODO: check closing flag at negotiation phases - two functions.
TODO: slotevent hslot passed from socksoverrdp-server.cpp
*/


#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "SocksServer.h"
#include "SocksOverRDP-Server.h"

#pragma comment(lib, "Ws2_32.lib")

#define METHOD_NUMBER 1
#define BUF_SIZE 4096

// hardcoded inactive creds, use proper creds check if you want this
#define PREDEF_USERNAME "hello"
#define PREDEF_PASSWORD "bello"

extern threads *LookupThread(DWORD dwThreadId);
extern VOID DeleteThread(DWORD dwThreadId);

extern HANDLE ghMutex;
extern HANDLE hChannel;
extern BOOL bVerbose, bDebug;

int method_no_auth_required(HANDLE c, int count, char *rv);

typedef int(*fn)(HANDLE, int, char*);
static fn method_functions[METHOD_NUMBER] =
{
	method_no_auth_required,
	//	method_username_password, // disabled for security purposes
};
static char method_numbers[METHOD_NUMBER] =
{
	0,
	//	2,
};

int method_no_auth_required(HANDLE c, int count, char *rv)
{
	return TRUE;
}

// dedicated function to handle writes on the virtual channel
BOOL WriteChannel(char *Buffer, DWORD nBytesToWrite, DWORD *nBytesWrittes, DWORD dwRemoteThreadId, BOOL bClose)
{
	HANDLE		hEvent;
	OVERLAPPED	Overlapped;
	DWORD		i, dwLimit, dwToWrite, dwLocalSent, dwWaitResult;
	DWORD		dwHeaderSize = sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE);
	BOOL		bSucc = FALSE;

	dwToWrite = BUF_SIZE;
	dwLocalSent = 0;

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	Overlapped = { 0 };
	Overlapped.hEvent = hEvent;

	// number of writes
	dwLimit = (unsigned int)ceil(nBytesToWrite / (double)BUF_SIZE);
	// no content but close connection request.
	if (!dwLimit && bClose)
		dwLimit = 1;	

	// mandatory header with 
	memcpy_s(Buffer - dwHeaderSize, 4, &dwRemoteThreadId, sizeof(DWORD));
	memcpy_s(Buffer + sizeof(DWORD) - dwHeaderSize, 4, &dwToWrite, sizeof(DWORD));
	Buffer[sizeof(DWORD) + sizeof(DWORD) - dwHeaderSize] = 0;

	dwWaitResult = WaitForSingleObject(ghMutex, INFINITE);
	switch (dwWaitResult)
	{
		case WAIT_OBJECT_0:
			for (i = 0; i < dwLimit; i++)
			{
				if (i == dwLimit - 1)
				{
					dwToWrite = nBytesToWrite % (BUF_SIZE + 1);
					memcpy_s(Buffer + sizeof(DWORD) - 9, 4, &dwToWrite, sizeof(DWORD));
					if (bClose) Buffer[sizeof(DWORD) + sizeof(DWORD) - 9] = 0x01;
				}
				//printf("%08X: CHANNEL Sent: %ld content length: %ld\n", dwRemoteThreadId, dwToWrite + 9, dwToWrite);

				bSucc = WriteFile(hChannel, Buffer - 9, dwToWrite + 9, &dwLocalSent, &Overlapped);
				if (!bSucc)
				{
					if (GetLastError() == ERROR_IO_PENDING)
					{
						WaitForSingleObject(Overlapped.hEvent, INFINITE);
						bSucc = GetOverlappedResult(hChannel, &Overlapped, &dwLocalSent, TRUE);
					}
				}
				if (!bSucc)
				{
					if (bVerbose) printf("[-] hChannel thread(%08X) WriteChannel: %ld\n", GetCurrentThreadId(), GetLastError());
					if (!ReleaseMutex(ghMutex))
					{
						printf("Release failed1\n");
					}
					return FALSE;
				}
				*nBytesWrittes += dwLocalSent;
			}
		
			if (!ReleaseMutex(ghMutex))
			{
				printf("Release failed2\n");
			}
			return bSucc;
			break;

		case WAIT_ABANDONED:
			return FALSE;
	}

	return bSucc;
}

int CheckAuthentication(char *buf_full, int ret)
{
	DWORD	i, j, dwWritten = 2;
	char	*answer, *buf, answer_tosend[2 + sizeof(DWORD) + sizeof(DWORD) + 1];
	struct threads *pta;
	
	buf = buf_full + 1;
	answer = answer_tosend + sizeof(DWORD) + sizeof(DWORD) + 1;

	pta = LookupThread(GetCurrentThreadId());

	answer[0] = 5;

	for (i = 0; i < METHOD_NUMBER; i++)
		for (j = 0; j < (unsigned char)buf[1]; j++)
			if (buf[j + 2] == method_numbers[i])
			{
				answer[1] = method_numbers[i];
				WriteChannel(answer, 2, &dwWritten, pta->dwRemoteThreadId, FALSE);
				return i;
			}

	answer[1] = (unsigned)0xFF;

	WriteChannel(answer, 2, &dwWritten, pta->dwRemoteThreadId, FALSE);

	return -1;
}

void sendReplyv4(char replyField)
{
	char	answer[8];
	DWORD   dwWritten;

	struct threads *pta;

	memset(answer, 0, 8);

	pta = LookupThread(GetCurrentThreadId());

	answer[0] = 0x00;
	answer[1] = replyField;

	if (replyField == 0x5A)
		WriteChannel(answer, 8, &dwWritten, pta->dwRemoteThreadId, FALSE);
	else
		WriteChannel(answer, 8, &dwWritten, pta->dwRemoteThreadId, TRUE);
}


void sendReply(char replyField, char addressType, char *addr, char *port)
{
	char	null[20], *answer, answer2[300 + sizeof(DWORD) + sizeof(DWORD) + 1];
	DWORD   dwWritten, ret;

	struct threads *pta;

	answer = answer2 + sizeof(DWORD) + sizeof(DWORD) + 1;
	memset(answer2, 0, 300 + sizeof(DWORD) + sizeof(DWORD) + 1);
	memset(null, 0, 20);

	pta = LookupThread(GetCurrentThreadId());

	// if addr or port set to NULL, we will send nulls instead of the address
	// it isn't RFC compliant but I do not support info leak either.
	if (addr == NULL) addr = null;
	if (port == NULL) port = null;

	answer[0] = 5;

	answer[1] = replyField;
	answer[3] = addressType;

	switch (addressType)
	{
	case 3:
		memcpy_s(answer + 4, 296, (void *)(addr + 1), (unsigned char)(addr[0]));
		memcpy_s(answer + 4 + (unsigned char)(addr[0]), 396 - (unsigned char)(addr[0]), port, 2);
		ret = (unsigned char)(addr[0]) + 2;
		break;
	case 4:
		memcpy_s(answer + 4, 296, addr, 16);
		memcpy_s(answer + 20, 280, port, 2);
		ret = 22;
		break;
	default:
		memcpy_s(answer + 4, 296, addr, 4);
		memcpy_s(answer + 8, 292, port, 2);
		ret = 10;
		break;
	}

	if (replyField == 0x00)
		WriteChannel(answer, ret, &dwWritten, pta->dwRemoteThreadId, FALSE);
	else
		WriteChannel(answer, ret, &dwWritten, pta->dwRemoteThreadId, TRUE);
}

int getAddressInfo(sockaddr_in *sockaddrin, sockaddr_in6 *sockaddrin6, char *buf, int ret)
{
	ADDRINFOA hints;
	ADDRINFOA *result = NULL;

	char domain[256];

	if (buf[0] == 4)
	{
		sockaddrin->sin_family = AF_INET;
		memcpy_s(&(sockaddrin->sin_addr), 4, buf + 4, 4);

		// Socks4a
		if ((buf[4] == 0x00) && (buf[5] == 0x00) && (buf[6] == 0x00) && (buf[7] != 0x00))
		{
			if (bDebug) printf("%08X: SOCKS HandleClient Socks4a request\n", 0);

			if (ret < 9)
			{
				if (bVerbose) printf("[-] SOCKS thread(%08Xd) getAddressInfo DNSv4a selected, length mismatch: %ld\n", GetCurrentThreadId(), ret);
				return -1;
			}

			int i = 8;
			int nulls = 0;
			char *domainname = NULL;
			BOOL solid = FALSE;
			while (i < ret)
			{ 
				// looking for nulls. First after userid, second at end of domain name
				if (buf[i++] == 0x00)
					nulls++;

				// first null byte found
				if ((nulls == 1) && !domainname)
					domainname = buf + i;

				// second null byte found in boundaries
				if (nulls == 2)
				{
					solid = TRUE;
					break;
				}
			}
			if (!solid)
			{
				if (bVerbose) printf("[-] SOCKS thread(%08Xd) getAddressInfo DNSv4a selected, corrup request: %ld\n", GetCurrentThreadId(), ret);
				return -1;
			}

			ZeroMemory(&hints, sizeof(hints));

			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			hints.ai_flags = AI_PASSIVE;

			if ((ret = GetAddrInfoA(domainname, "1", &hints, &result)) != 0) {
				if (bVerbose) printf("[-] SOCKS thread(%08X) getAddressInfo GetAddrInfoA v4a failed with error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
				return -1;
			}
			memcpy_s(sockaddrin, sizeof(sockaddr_in), result->ai_addr, sizeof(sockaddr_in));
			memcpy_s(&(sockaddrin->sin_port), 2, buf + 2, 2);

			char *s = (char *)malloc(INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(sockaddrin->sin_addr), s, INET_ADDRSTRLEN);
			if (bVerbose) printf("[+] SOCKS thread(%08X) getAddressInfo CONNECT DNSv4a: %s(%s):%hd\n", GetCurrentThreadId(), domainname, s, htons(sockaddrin->sin_port));
			free(s);
		}
		else
		{
			memcpy_s(&(sockaddrin->sin_port), 2, buf + 2, 2);

			char *s = (char *)malloc(INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(sockaddrin->sin_addr), s, INET_ADDRSTRLEN);
			if (bVerbose) printf("[+] SOCKS thread(%08X) getAddressInfo CONNECT IPv4: %s:%hd\n", GetCurrentThreadId(), s, htons(sockaddrin->sin_port));
			free(s);
		}
	}

	if (buf[0] == 5)
	{
		//IPv4
		if (buf[3] == 1)
		{
			if (ret != 10)
			{
				if (bVerbose) printf("[-] SOCKS thread(%08Xd) getAddressInfo IPv4 selected, length mismatch: %ld\n", GetCurrentThreadId(), ret);
				return -1;
			}
			sockaddrin->sin_family = AF_INET;
			memcpy_s(&(sockaddrin->sin_port), 2, buf + 8, 2);
			memcpy_s(&(sockaddrin->sin_addr), 4, buf + 4, 4);

			char *s = (char *)malloc(INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(sockaddrin->sin_addr), s, INET_ADDRSTRLEN);
			if (bVerbose) printf("[+] SOCKS thread(%08X) getAddressInfo CONNECT IPv4: %s:%hd\n", GetCurrentThreadId(), s, htons(sockaddrin->sin_port));
			free(s);
		}
		//DNS
		if (buf[3] == 3)
		{
			if ((7 + (unsigned char)buf[4]) != ret)
			{
				if (bVerbose) printf("[-] SOCKS thread(%08X) getAddressInfo DNS selected, length mismatch: %ld\n", GetCurrentThreadId(), ret);
				return -1;
			}
			ZeroMemory(&hints, sizeof(hints));
			ZeroMemory(domain, 256);

			// change for IPv6?
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			hints.ai_flags = AI_PASSIVE;

			memcpy_s(domain, 256, (void *)(buf + 5), (unsigned char)(buf[4]));

			if ((ret = GetAddrInfoA(domain, "1", &hints, &result)) != 0) {
				if (bVerbose) printf("[-] SOCKS thread(%08X) getAddressInfo GetAddrInfoA failed with error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
				return -1;
			}
			memcpy_s(sockaddrin, sizeof(sockaddr_in), result->ai_addr, sizeof(sockaddr_in));
			memcpy_s(&(sockaddrin->sin_port), 2, buf + ((unsigned char)buf[4]) + 5, 2);

			char *s = (char *)malloc(INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(sockaddrin->sin_addr), s, INET_ADDRSTRLEN);
			if (bVerbose) printf("[+] SOCKS thread(%08X) getAddressInfo CONNECT DNS: %s(%s):%hd\n", GetCurrentThreadId(), domain, s, htons(sockaddrin->sin_port));
			free(s);
		}
		//IPv6
		if (buf[3] == 4)
		{
			if (ret != 22)
			{
				if (bVerbose) printf("[-] SOCKS thread(%08X) getAddressInfo IPv6 selected, length mismatch: %ld\n", GetCurrentThreadId(), ret);
				return -1;
			}
			sockaddrin6->sin6_family = AF_INET6;
			memcpy_s(&(sockaddrin6->sin6_port), 2, buf + 20, 2);
			memcpy_s(&(sockaddrin6->sin6_addr), 30, buf + 4, 16);

			char *s = (char *)malloc(INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(sockaddrin6->sin6_addr), s, INET6_ADDRSTRLEN);
			if (bVerbose) printf("[+] SOCKS thread(%08X) getAddressInfo CONNECT IPv6: %s:%hd\n", GetCurrentThreadId(), s, htons(sockaddrin6->sin6_port));
			free(s);
		}
	}

	return 0;
}

SOCKET DoConnection(char *buf, int ret)
{
	SOCKET			sock;
	sockaddr_in		sockaddrin;
	sockaddr_in6	sockaddrin6;

	if (buf[0] == 5)
	{
		if (getAddressInfo(&sockaddrin, &sockaddrin6, buf, ret) < 0) {
			if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection could not create socket structs\n", GetCurrentThreadId());
			// this isnt "general SOCKS server failure", but there no better error code
			sendReply(0x01, 0x01, NULL, NULL);
			return NULL;
		}

		// CONNECT
		if (buf[1] == 1)
		{
			if (buf[3] == 4)
			{
				if ((sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
					if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection socket6() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(0x01, 0x04, NULL, NULL);
					return NULL;
				}

				if ((ret = connect(sock, (SOCKADDR *)&sockaddrin6, sizeof(sockaddrin6))) == SOCKET_ERROR) {
					if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection connect6() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(0x05, 0x04, NULL, NULL);
					return NULL;
				}
			}
			else
			{
				if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
					if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection socket() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(0x01, 0x01, NULL, NULL);
					return NULL;
				}

				if ((ret = connect(sock, (SOCKADDR *)&sockaddrin, sizeof(sockaddrin))) == SOCKET_ERROR) {
					if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection connect() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(0x05, 0x01, NULL, NULL);
					return NULL;
				}
			}

			sendReply(0x00, 0x01, NULL, NULL);

			return sock;
		}
		// BIND
		if (buf[1] == 2)
		{
			if (bVerbose) printf("[+] SOCKS DoConnection BIND\n");
		}
		// UDP ASSOCIATE
		if (buf[1] == 3)
		{
			//SOCK_DGRAM
			if (bVerbose) printf("[+] SOCKS DoConnection UDP ASSOCIATE\n");
		}
	}
	else if (buf[0] == 4)
	{
		if (getAddressInfo(&sockaddrin, &sockaddrin6, buf, ret) < 0) {
			if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection v4 could not create socket structs\n", GetCurrentThreadId());
			// this isnt "general SOCKS server failure", but there no better error code
			sendReplyv4(0x5B);
			return NULL;
		}

		// CONNECT
		if (buf[1] == 1)
		{
			if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
				if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection v4 socket() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
				sendReplyv4(0x5B);
				return NULL;
			}

			if ((ret = connect(sock, (SOCKADDR *)&sockaddrin, sizeof(sockaddrin))) == SOCKET_ERROR) {
				if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection v4 connect() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
				sendReplyv4(0x5B);
				return NULL;
			}

			sendReplyv4(0x5A);
			return sock;
		}
		// BIND
		if (buf[1] == 2)
		{
			if (bVerbose) printf("[+] SOCKS DoConnection v4 BIND\n");
		}
	}
	else
	{
		if (bVerbose) printf("[-] SOCKS thread(%08X) DoConnection unknown SOCKS version\n", GetCurrentThreadId());
		return NULL;
	}

	return NULL;
}

// Thread's main function that handles all communication of the corresponding
// connection. It's remote ThreadID attribute matches the server's threadID
// which will be used to track the connections.
DWORD WINAPI HandleClient(void *param)
{
	struct threads *pta = (struct threads *)param;
	WSANETWORKEVENTS NetworkEvents;
	WSAOVERLAPPED SendOverlapped;
	OVERLAPPED  Overlapped_MailSlot;
	HANDLE		hEvents[2], hMailSlot = pta->hSlot_r;
	DWORD		dwRet, dwRecvN, dwSentN, dwSentPointer, Flags;
	SOCKET		sRelayConnection;
	BOOL		bClose = FALSE;
	WSABUF		DataBuf;
	char		buf[BUF_SIZE + 1];
	int			rc, iSrecvN, iAuthNum = -1;

	Overlapped_MailSlot = { 0 };

	// socks basics
	if (ReadFile(hMailSlot, buf, BUF_SIZE + 1, &dwRet, NULL))
	{
		if (buf[0] == 0x01)
			goto exitthread;

		if (buf[1] == 4)
		{
			//socks4
			if (bDebug) printf("%08X: SOCKS HandleClient Socks4 request\n", pta->dwRemoteThreadId);
			if (dwRet > 6)
			{
				if ((sRelayConnection = DoConnection(buf + 1, dwRet - 1)) == NULL)
				{
					if (bDebug) printf("%08X: SOCKS HandleClient v4 no socket created\n", pta->dwRemoteThreadId);
					goto exitthread;
				}
			}
			else
			{
				if (bDebug) printf("%08X: SOCKS HandleClient v4 connection request less than 6 error: %ld %ld\n", pta->dwRemoteThreadId, dwRet, WSAGetLastError());
				goto exitthread;
			}

		}
		else
			if (buf[1] == 5)
			{
				// socks5
				if (dwRet - 3 != buf[2])
				{
					if (bDebug) printf("%08X: SOCKS HandleClient wrong list length: %ld\n", pta->dwRemoteThreadId, dwRet);
					goto exitthread;
				}

				if ((iAuthNum = CheckAuthentication(buf, dwRet)) < 0)
				{
					if (bDebug) printf("%08X: SOCKS HandleClient auth failed: %ld\n", pta->dwRemoteThreadId, iAuthNum);
					goto exitthread;
				}


				if (iAuthNum == -1)
				{
					if (bDebug) printf("%08X: SOCKS HandleClient wrong authnum: %ld\n", pta->dwRemoteThreadId, iAuthNum);
					goto exitthread;
				}

				// socks authentication
				if (iAuthNum > 0)
				{
					if (bDebug) printf("%08X: SOCKS HandleClient authentication invoked: %ld\n", pta->dwRemoteThreadId, iAuthNum);

					if (ReadFile(hMailSlot, buf, BUF_SIZE, &dwRet, NULL))
					{
						if (dwRet > 2)
						{
							if (!method_functions[iAuthNum](hMailSlot, dwRet, buf))
							{
								if (bDebug) printf("%08X: SOCKS HandleClient authentication failed: %ld\n", pta->dwRemoteThreadId, iAuthNum);
								goto exitthread;
							}
						}
						else
						{
							if (bDebug) printf("%08X: SOCKS HandleClient less than 2 recv error: %ld %ld\n", pta->dwRemoteThreadId, dwRet, WSAGetLastError());
							goto exitthread;
						}
					}
					else
					{
						if (bDebug) printf("%08X: SOCKS HandleClient authentication recv error: %ld %ld\n", pta->dwRemoteThreadId, dwRet, WSAGetLastError());
						goto exitthread;
					}
				}

				// socks connection phase
				if (ReadFile(hMailSlot, buf, BUF_SIZE, &dwRet, NULL))
				{
					if (dwRet > 0)
						if (buf[0] == 0x01)
							goto exitthread;
					if (dwRet > 6)
					{
						if ((sRelayConnection = DoConnection(buf + 1, dwRet - 1)) == NULL)
						{
							if (bDebug) printf("%08X: SOCKS HandleClient no socket created\n", pta->dwRemoteThreadId);
							goto exitthread;
						}
					}
					else
					{
						if (bDebug) printf("%08X: SOCKS HandleClient connection request less than 6 error: %ld %ld\n", pta->dwRemoteThreadId, dwRet, WSAGetLastError());
						goto exitthread;
					}
				}
				else
				{
					if (bDebug) printf("%08X: SOCKS HandleClient connection request recv error: %ld %ld\n", pta->dwRemoteThreadId, dwRet, WSAGetLastError());
					goto exitthread;
				}

			}
			else
			{
				if (bDebug)
				{
					printf("%08X: SOCKS HandleClient unknown Socks version number\n", pta->dwRemoteThreadId);
					printf("%08X: Readfile ret: %ld\n", pta->dwRemoteThreadId, dwRet);
					for (DWORD i = 0; i < dwRet; i++)
						printf("%02X ", (unsigned char)buf[i]);
					printf("\n");
				}
				goto exitthread;
			}
	}
	else
	{
		if (bDebug) printf("%08X: SOCKS HandleClient while ReadFile error: %ld\n", pta->dwRemoteThreadId, GetLastError());
		goto exitthread;
	}

	hEvents[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
	hEvents[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
	pta->hSlot_event = hEvents[0];

	Overlapped_MailSlot.hEvent = hEvents[0];

	SecureZeroMemory((PVOID)& SendOverlapped, sizeof(WSAOVERLAPPED));
	SendOverlapped.hEvent = WSACreateEvent();
	if (SendOverlapped.hEvent == NULL) {
		printf("Mailslot thread(%08X) WSACreateEvent failed with error: %d\n", pta->dwRemoteThreadId, WSAGetLastError());
		goto exitthread;
	}

	if ((hEvents[0] == NULL) || ((hEvents[1] == NULL)))
	{
		printf("[-] Mailslot thread(%08X) CreateEvent failed with %ld\n", pta->dwRemoteThreadId, GetLastError());
		goto exitthread;
	}

	WSAEventSelect(sRelayConnection, hEvents[1], FD_READ | FD_CLOSE);

	BOOL read = true;

	while (pta->run)
	{
		if (read)
		{
			if (ReadFile(hMailSlot, buf, BUF_SIZE + 1, &dwRecvN, &Overlapped_MailSlot) == FALSE)
			{
				if (GetLastError() != ERROR_IO_PENDING)
				{
					printf("[-] Mailslot thread(%08X) ReadFile error %ld\n", pta->dwRemoteThreadId, GetLastError());
					pta->run = FALSE;
					break;
				}
			}
			read = FALSE;
		}

		dwRet = WaitForMultipleObjects(2, hEvents, FALSE, INFINITE);
		if ((dwRet - WAIT_OBJECT_0) < 0 || (dwRet - WAIT_OBJECT_0) > (2 - 1))
		{
			printf("[-] Mailslot thread(%08X) WaitForMultipleObjects index out of range %ld\n", pta->dwRemoteThreadId, dwRet);
			pta->run = FALSE;
			break;
		}
		if (pta->run == FALSE)
		{
			break;
		}

		switch (dwRet - WAIT_OBJECT_0)
		{
		case 0:
			if (bDebug) printf("%08X: READ recvn: %ld - internalhigh: %ld - internal: %ld\n", pta->dwRemoteThreadId, dwRecvN, Overlapped_MailSlot.InternalHigh, Overlapped_MailSlot.Internal);
			dwRecvN = Overlapped_MailSlot.InternalHigh;
			if (buf[0] == 0x01)
			{
				pta->run = FALSE;
			}
				
			dwSentPointer = 1;
			while (dwSentPointer < dwRecvN)
			{
				if (!pta->run)
				{
					//printf("%08X: was set to exit1\n", pta->dwRemoteThreadId);
					break;
				}

				DataBuf.len = dwRecvN - dwSentPointer;
				DataBuf.buf = buf + dwSentPointer;

				rc = WSASend(sRelayConnection, &DataBuf, 1, &dwSentN, NULL, &SendOverlapped, NULL);
				if ((rc == SOCKET_ERROR) && (WSA_IO_PENDING != WSAGetLastError()))
				{
					printf("[-] Mailslot thread(%08X) WSASend failed with error: %d\n", pta->dwRemoteThreadId, WSAGetLastError());
					pta->run = FALSE;
					break;
				}
				rc = WSAWaitForMultipleEvents(1, &SendOverlapped.hEvent, TRUE, INFINITE, TRUE);
				if (rc == WSA_WAIT_FAILED)
				{
					printf("[-] Mailslot thread(%08X) WSAWaitForMultipleEvents failed with error: %d\n", pta->dwRemoteThreadId, WSAGetLastError());
					pta->run = FALSE;
					break;
				}
				rc = WSAGetOverlappedResult(sRelayConnection, &SendOverlapped, &dwSentN, FALSE, &Flags);
				if (rc == FALSE) 
				{
					printf("[-] Mailslot thread(%08X) WSASend failed with error: %d\n", pta->dwRemoteThreadId, WSAGetLastError());
					pta->run = FALSE;
					break;
				}
				WSAResetEvent(SendOverlapped.hEvent);

				dwSentPointer += dwSentN;
			}
			read = TRUE;

			break;
		case 1:
			if (WSAEnumNetworkEvents(sRelayConnection, hEvents[1], &NetworkEvents) == SOCKET_ERROR) {
				printf("[-] SOCKS thread(%08X) HandleClient WSAEnumNetworkEvents error: %ld\n", pta->dwRemoteThreadId, GetLastError());
			}
			else
			{
				if (NetworkEvents.lNetworkEvents & FD_CLOSE)
				{
					if (bDebug) printf("%08X: bClose FD_CLOSE was set\n", pta->dwRemoteThreadId);
					bClose = TRUE;
				}
			}
			do
			{
				if ((iSrecvN = recv(sRelayConnection, buf + sizeof(DWORD) + sizeof(DWORD) + 1, BUF_SIZE, 0)) > 0)
				{
					if (bDebug) printf("%08X: RECV recvn: %ld\n", pta->dwRemoteThreadId, iSrecvN);
					dwSentPointer = 0;
					if (!WriteChannel(buf + sizeof(DWORD) + sizeof(DWORD) + 1, iSrecvN, &dwSentPointer, pta->dwRemoteThreadId, FALSE))
					{
						pta->run = FALSE;
					}
				}
				else
				{
					bClose = TRUE;
				}

				// run again the loop only if there is more data and the last data packet was set to FIN
			} while (bClose && (iSrecvN > 0));
			if (bClose)
			{
				if (bDebug) printf("%08X: CLOSE\n", pta->dwRemoteThreadId);

				if (!WriteChannel(buf + sizeof(DWORD) + sizeof(DWORD) + 1, 0, &dwSentPointer, pta->dwRemoteThreadId, TRUE))
					printf("[-] Mailslot thread(%08X) HandleClient select1 WriteChannel error: %ld %ld\n", pta->dwRemoteThreadId, dwSentN, GetLastError());

				// FIN recv'd
				if (iSrecvN == SOCKET_ERROR)
				{
					if (bVerbose) printf("[-] SOCKS thread(%08X) HandleClient select1 recv error: %ld %ld\n", pta->dwRemoteThreadId, iSrecvN, WSAGetLastError());
				}
				pta->run = FALSE;
			}
			break;
		default:
			break;
		}
	}
	WSACloseEvent(SendOverlapped.hEvent);
exitthread:
	// closing down the thread
	shutdown(sRelayConnection, SD_SEND);
	CloseHandle(pta->hSlot_r);
	CloseHandle(pta->hSlot_w);
	CloseHandle(hEvents[0]);
	CloseHandle(hEvents[1]);
	DeleteThread(GetCurrentThreadId());

	return 0;
}
