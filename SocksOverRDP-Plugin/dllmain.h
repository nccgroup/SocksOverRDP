// dllmain.h : Declaration of module class.

class CSocksOverRDPPluginModule : public ATL::CAtlDllModuleT< CSocksOverRDPPluginModule >
{
public :
	DECLARE_LIBID(LIBID_SocksOverRDPPluginLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_SocksOverRDPPLUGIN, "{B8DC075B-7F8D-4B06-8733-7EB586CA06F0}")
};

extern class CSocksOverRDPPluginModule _AtlModule;
