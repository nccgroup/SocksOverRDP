# Socks Over RDP #
This tool was created to extend the offered capabilities of Terminal Services (or Remote Desktop Services). While it was not possible to create a SOCKS proxy that tunnels data over the RDP channel with this two-pieces tool it is, just like SSH does with the "-D" argument.
It uses Dynamic Virtual Channel that enables us to communicate over an open RDP connection without the need to open a new socket, connection or a port on a firewall. 

![logo](https://github.com/earthquake/SocksOverRDP/blob/master/misc/SocksOverRDP.png?raw=true)

### How can I use it? ###
You need to install a plugin (*.dll*) on your client computer that you use to connect to the RDP server. On the RDP server you need to use the other half of the project the *.exe*, which creates the channel between the plugin and the server executable. 
More details can be found below.

### How does this work? ###
If the DLL is properly registered, it will be loaded by the mstsc.exe (Remote Desktop Client) every time it is started. When the server executable runs on the server side, it connects back to the DLL on a dynamic virtual channel, which is a feature of the Remote Desktop Protocol. After the channel is set up, a SOCKS Proxy will spin up on the client computer, by default on 127.0.0.1:1080. This service can be used as a SOCKS5 Proxy from any browser or tool.

### Compatibility ###
Dynamic Virtual Channels were introduced in **Window Server 2008 & Windows Vista SP1**. **These** and anything **newer** than these should be good to go.  
Right now the client works with mstsc.exe (Remote Desktop Client), but there is a possibility that it will be ported to Unices to use it with FreeRDP.

### Installation ###
You can grab the whole project and compile it by yourself or just use the compiled binaries from the [Releases section](https://github.com/earthquake/SocksOverRDP/releases). It is important that the correct binary is used in all cases, please select the correct one for the corresponding architecture (if your client is 32bit but the server is 64bit then grab the 32bit dll and 64bit exe).
The *.dll* needs to be placed on the client computer in any directory (for long-term use, it is recommended to copy it into the %SYSROOT%\\system32\\ or %SYSROOT%\\SysWoW64\\) and install it with the following command as an elevated user (a.k.a Administrator): 

`regsvr32.exe UDVC-Plugin.dll`

If your user is not an administrator, you need to import the registry settings under your user too. Please use the *SocksOverRDP-Plugin.reg* file for that.

If you wish to remove it: 

`regsvr32.exe /u UDVC-Plugin.dll`

**Every time you connect to an RDP server from now on, this plugin will be loaded and will configure itself as it was specified in the registry (see below).**

The *.exe* needs to be copied to the server and executed by any user.


### Options/Configuration ###
The server component (*.exe*) does not need any configuration or requires any arguments. Although there is a few for extra functionality:
```
PS C:\Users\SocksOverRDP\> .\SocksOverRDP-Server.exe -h
TODO
```

The client component (*.dll*) comes with preset settings, which is installed by the .dll itself when it is registered, or needs to be imported from the *SocksOverRDP-Plugin.reg*.
* **enabled**: *0* disabled, *1* enabled (plugin only). By default it is enabled and will tell you in a messagebox every time you initiate a connection.
* **ip**: which IP to connect to or bind to
* **port**: which port to connect to or bind to

The client *.dll*  reads all the options from the registry, the values can be found under the following key:
`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Terminal Server Client\Default\AddIns\SocksOverRDP-Plugin`
  
Every time the module is enabled and before the connection is made a reminder warning is showed. Just like this:
![warning](https://github.com/earthquake/SocksOverRDP/blob/master/misc/warning.png?raw=true)

This warning ensures that the user knows about the plugin is loaded and with what settings.


### Issues
In case the plugin does not load or the executable does not run because it is missing some DLLs for example the VCRUNTIME140.DLL, you might want to install the [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145) package.

### Security concerns ###
The server component (*.exe*) can be executed with any user, it will work with low privileged users as well, there are no security risks associated with this component at all.

The client component (*.dll*) by default is configured to listen only on localhost, if that is changed to for example 0.0.0.0 and there is no firewall or it is misconfigured, then it could result in a security issue, since other computers on the network can access the SOCKS Proxy and communicate over the RDP server. 

**Please note that the SOCKS Server is only up, when the RDP connection is alive and the executable is running on the server.**
