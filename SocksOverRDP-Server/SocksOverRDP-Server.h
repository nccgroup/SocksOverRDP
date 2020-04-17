#pragma once

struct threads
{
	DWORD dwThreadId;
	DWORD dwRemoteThreadId;
	HANDLE hThread;
	BOOL run;
	HANDLE hSlot_r;
	HANDLE hSlot_w;
	HANDLE hSlot_event;
	struct threads *next;
};

struct threads *AddThread(DWORD dwThreadId, DWORD dwRemoteThreadId, HANDLE hSlot_r, HANDLE hSlot_w, HANDLE hChannel);
threads *LookupThread(DWORD dwThreadId);
threads *LookupThreadRemote(DWORD dwRemoteThreadId);
VOID DeleteThread(DWORD dwThreadId);