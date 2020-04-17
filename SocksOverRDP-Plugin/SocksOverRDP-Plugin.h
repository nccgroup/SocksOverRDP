// TsClientPlgn.h : Declaration of the CTsClientPlgn

#pragma once
#include "stdafx.h"
#include "resource.h"       // main symbols

#include "SocksOverRDPPlugin_i.h"

// debug
#include <StrSafe.h>
#include <assert.h>


#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
#endif


// CTsClientPlgn
class ATL_NO_VTABLE CTsClientPlgn :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CTsClientPlgn, &CLSID_CompReg>,
	public IDispatchImpl<IComponentRegistrar, &IID_IComponentRegistrar, &LIBID_SocksOverRDPPluginLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
    public IWTSPlugin,
    public IWTSListenerCallback,
    public IWTSVirtualChannelCallback
{
public:
    CTsClientPlgn(): _hCurrentFile(INVALID_HANDLE_VALUE)
	{
	}

DECLARE_REGISTRY_RESOURCEID(IDR_SocksOverRDPCLIENTPLUGIN)


BEGIN_COM_MAP(CTsClientPlgn)
	COM_INTERFACE_ENTRY(IComponentRegistrar)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY(IWTSPlugin)
	COM_INTERFACE_ENTRY(IWTSListenerCallback)
	COM_INTERFACE_ENTRY(IWTSVirtualChannelCallback)
END_COM_MAP()

	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

    // IWTSPlugin
public:
    /*
     *  Called immediately after instantiating the COM class
     */
    STDMETHOD(Initialize)(
        IWTSVirtualChannelManager *pChannelMgr
        );

    /*
     *  Called when the TS client is connected to the TS server
     */
    STDMETHOD(Connected)();

    /*
     *  Called when the TS client is disconnected to the TS server
     *  Might be followed by another Connected() call
     */
    STDMETHOD(Disconnected)(
        DWORD dwDisconnectCode
        );

    /*
     *  The last method called by the TS client before 
     *  terminating the object
     */
    STDMETHOD(Terminated)();

    // IWTSListenerCallback
public:
	VOID CTsClientPlgn::SetChannel(IWTSVirtualChannel *pChannel);
public:
    /*
     *  Called whenever a request for new channel connection
     *  from the server is received.
     */
    STDMETHOD(OnNewChannelConnection)(
        IWTSVirtualChannel *pChannel,
        BSTR data,           // optional data passed as part of the connect method
        BOOL *pbAccept,      // the callee should return TRUE if connection is accepted
        IWTSVirtualChannelCallback **ppCallback // connection related events
        );
    
    // IWTSVirtualChannelCallback
public:

    /*
     *  Called whenever a full message from the server is received
     *  The message is fully reassembled and has the exact size
     *  as the Write() call on the server
     */
    STDMETHOD(OnDataReceived)(
        ULONG cbSize,            // size of data in bytes
        BYTE *pBuffer            // data buffer
        );

    /*
     *  The channel is disconnected, all Write() calls will fail
     *  no more incomming data is expected. 
     */
    STDMETHOD(OnClose)();

private:

    HRESULT CleanState();


    HRESULT StartFile(
        __in_z LPWSTR szFileName,
        BOOL bDir);

    HRESULT WriteData(
        __in_bcount(usLen) PBYTE pData,
        USHORT usLen);

    HRESULT EndFile(BOOL bDir);

    CComPtr<IWTSListener> _spListener;
    CComPtr<IWTSVirtualChannel> _spChannel;

    HANDLE _hCurrentFile;

    WStringVector _vDirList;
};

//OBJECT_ENTRY_AUTO(__uuidof(CompReg), CTsClientPlgn)


// DEBUG:
#define DEBUG_PRINT_BUFFER_SIZE 1024
