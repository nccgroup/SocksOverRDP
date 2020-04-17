// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once

#ifndef STRICT
#define STRICT
#endif

#include "targetver.h"

#define _ATL_APARTMENT_THREADED
#define _ATL_NO_AUTOMATIC_NAMESPACE

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// some CString constructors will be explicit
#define _ATL_REGISTER_PER_USER  // This setting must be consistent with the project's RGS file


#include "resource.h"
//#include <afx.h>
#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

using namespace ATL;

// adtn'l includes
#include <ShlObj.h>
#include <TsVirtualChannels.h>
#include <IntSafe.h>

#include <fstream>
#include <vector>

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>

typedef std::basic_ofstream<BYTE> ByteFile;
typedef std::basic_string<WCHAR> WString;
typedef std::vector<WString> WStringVector;
