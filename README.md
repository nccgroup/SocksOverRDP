# Socks Over RDP / Socks Over Citrix #
This tool adds the capability of a SOCKS proxy to Terminal Services (or Remote Desktop Services) and Citrix (XenApp/XenDesktop). 
It uses Dynamic Virtual Channel that enables us to communicate over an open RDP/Citrix connection without the need to open a new socket, connection or a port on a firewall. 

<img src="https://github.com/nccgroup/SocksOverRDP/blob/master/misc/SocksOverRDP.png" data-canonical-src="https://github.com/nccgroup/SocksOverRDP/blob/master/misc/SocksOverRDP.png" width="30%" height="30%" />

### How can I use it? ###
You need to install a plugin (*.dll*) on your client computer that you use to connect to the RDP/Citrix server. On the RDP/Citrix server you need to use the other half of the project the *.exe*, which creates the channel between the plugin and the server executable. 
More details can be found below. If you want to use it with Citrix/XenApp/XenDesktop please scroll to Citrix section.

### How does this work? ###
If the DLL is properly registered, it will be loaded by the mstsc.exe (Remote Desktop Client) or Citrix Receiver every time it is started. When the server executable runs on the server side, it connects back to the DLL on a dynamic virtual channel, which is a feature of the Remote Desktop Protocol. After the channel is set up, a SOCKS Proxy will spin up on the client computer, by default on 127.0.0.1:1080. This service can be used as a SOCKS5 Proxy from any browser or tool.

### Compatibility ###
Dynamic Virtual Channels were introduced in **Window Server 2008 & Windows Vista SP1**. **These** and anything **newer** than these should be good to go.  
Right now the client works with mstsc.exe (Remote Desktop Client). In case you want to use it from Unix, give FreeRDP a try, it has released a similar module in about the same time as this tool was released.  
Citrix supports the same underlying API as Microsoft, although not sure when it was introduced, it was before 2013 so the plugin should work with most Citrix solutions.


### Installation ###
You can grab the whole project and compile it by yourself or just use the compiled binaries from the [Releases section](https://github.com/nccgroup/SocksOverRDP/releases). It is important that the correct binary is used in all cases, please select the correct one for the corresponding architecture (if your client is 32bit but the server is 64bit then grab the 32bit dll and 64bit exe).
The *.dll* needs to be placed on the client computer in any directory (for long-term use, it is recommended to copy it into the %SYSROOT%\\system32\\ or %SYSROOT%\\SysWoW64\\) and install it with the following command as an elevated user (a.k.a Administrator): 

`regsvr32.exe SocksOverRDP-Plugin.dll`

If your user is not an administrator, you need to import the registry settings under your user too. Please use the *SocksOverRDP-Plugin.reg* file for that.

If you wish to remove it: 

`regsvr32.exe /u SocksOverRDP-Plugin.dll`

**Every time you connect to an RDP server from now on, this plugin will be loaded and will configure itself as it was specified in the registry (see below).**

The *.exe* needs to be copied to the server and executed by any user.

### Citrix / XenApp / XenDesktop ###
The tool works with Citrix Receiver that is used to connect to the Citrix server. Either an app or a full desktop can be provided to the user, the tool works in both cases if the plugin was correctly installed and the *.exe* server component was copied to and executed on the Citrix server.  
**Citrix seems to have 32-bit Citrix Receiver only.** This means that if your operating system is 64-bit, and you have already registered the corresponding *.dll*, you need to unregister the *.dll* and use the 32-bit version. In case you use a 32-bit OS, you just register the *.dll* as mentioned above.  
Please note that 64-bit windows has two *regsvr32.exe*, one in *%WINDIR%\system32\* (x64) and the one in *%WINDIR%\SysWOW64\* (x32), use the latter to register the 32-bit *.dll*, which will be automatically loaded by the Citrix Receiver upon execution. Everything else should be the same, please make sure you have followed the readme before opening issues on Github.

### Options/Configuration ###
The server component (*.exe*) does not need any configuration or requires any arguments. Although there is one for verbosity:
```
PS C:\Users\SocksOverRDP\> .\SocksOverRDP-Server.exe -h
Socks Over RDP by Balazs Bucsay [[@xoreipeip]]

Usage: SocksOverRDP-Server.exe [-v]
-h              This help
-v              Verbose Mode
```

The client component (*.dll*) comes with preset settings, which is installed by the .dll itself when it is registered, or needs to be imported from the *SocksOverRDP-Plugin.reg*.
* **enabled**: *0* disabled, *1* enabled (plugin only). By default it is enabled and will tell you in a messagebox every time you initiate a connection.
* **ip**: which IP to connect to or bind to
* **port**: which port to connect to or bind to

The client *.dll*  reads all the options from the registry, the values can be found under the following key:
`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Terminal Server Client\Default\AddIns\SocksOverRDP-Plugin`
  
Every time the module is enabled and before the connection is made a reminder warning is showed. Just like this:
![warning](https://github.com/nccgroup/SocksOverRDP/blob/master/misc/warning.png?raw=true)

This warning ensures that the user knows about the plugin is loaded and with what settings.


### Issues
In case the plugin does not load or the executable does not run because it is missing some DLLs for example the VCRUNTIME140.DLL, you might want to install the [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145) package.

Tested on Windows 11 ARM64: [Redistributable](https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170#visual-studio-2015-2017-2019-and-2022)

#### 0x8002801c
On Windows 11 ARM64 (Macbook Pro M1) the following error message is shown at installation:
`The module SocksOverRDP-Plugin.dll was located bt the call to DllRegisterServer failed with error code 0x8002801c`

Although this error is shown, the module is properly installed and can be used.

### Security concerns ###
The server component (*.exe*) can be executed with any user, it will work with low privileged users as well, there are no security risks associated with this component at all.

The client component (*.dll*) by default is configured to listen only on localhost, if that is changed to for example 0.0.0.0 and there is no firewall or it is misconfigured, then it could result in a security issue, since other computers on the network can access the SOCKS Proxy and communicate over the RDP server. 

**Please note that the SOCKS Server is only up, when the RDP/Citrix connection is alive and the executable is running on the server.**

### Defence ###
To prevent users to use this tool the only known way is to disable Virtual Channels in the Remote Desktop Server configuration. Although this blocks the usage of this tool indeed, it also disables copy&paste, which might be a show stopper or a big annoyance for the users.

Although it is possible to disable the dynamic virtual channels in RDP, the following solution to do the same is ineffective for Citrix: [https://support.citrix.com/article/CTX202153](https://support.citrix.com/article/CTX202153)
