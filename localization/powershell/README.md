These scripts are to be used to extract the equivalent non-English names for the default counters with which the Microsoft Windows ZenPack ships.  Run get-localcounters.ps1 on a machine with the desired language installed and in use.

They are sorted by Monitoring Template

* Device
* File System
* Hard Disk
* Network Interface
* Network Adapter

The counter indexes for Active Directory, IIS, and Exchange server are inconsistent across different installations.  These can be translated manually or by running get-counter-indexes.ps1 on a machine with one of the desired server roles or software installed.  English must be the default language of the server.
