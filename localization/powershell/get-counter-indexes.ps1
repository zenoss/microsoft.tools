########################################################################################################
#
# Copyright 2017 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script queries the registry. Use with caution!
#
# This script will load counter names from the registry key:
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage
# It assumes English language to convert from the names into their associated indexes.
# These indexes will then be used in get-localcounters.ps1 to pull out non-English counter names.
#
# These are the default counters that the MS Windows ZenPack queries out of the box.
# Any other counters required can be extracted by creating an array of counter names in the 
# standard \PerfObject\Counter format and running each of them through the get_ctr_indexes function.
# Do not include instance information.
#
# Counter indexes for Active Directory, IIS, Exchange server are inconsistent across
# different installations.
#
########################################################################################################


<#
    .SYNOPSIS
    Query english language counters to determine counter indexes.
    .DESCRIPTION
    This script builds a hash table of counter names to pull out indexes which will then be used
    as input for a script to extract foreign language counter names.
    .EXAMPLE
    .\counter_indexes.ps1
#>

# Default counters

$device_counter_names = @("\Memory\Available bytes",
                   "\Memory\Committed Bytes",
                   "\Memory\Pages Input/sec",
                   "\Memory\Pages Output/sec",
                   "\Paging File\% Usage",
                   "\Processor\% Privileged Time",
                   "\Processor\% Processor Time",
                   "\Processor\% User Time",
                   "\System\System Up Time"
)

$File_Systems_counters = @(
    "\LogicalDisk\Disk Read Bytes/sec",
    "\LogicalDisk\% Disk Read Time",
    "\LogicalDisk\Disk Write Bytes/sec",
    "\LogicalDisk\% Disk Write Time",
    "\LogicalDisk\Free Megabytes"
)

$Hard_Disks_counters = @(
    "\PhysicalDisk\Disk Read Bytes/sec",
    "\PhysicalDisk\% Disk Read Time",
    "\PhysicalDisk\Disk Write Bytes/sec",
    "\PhysicalDisk\% Disk Write Time"
)

$Interfaces_counters = @(
    "\Network Interface\Bytes Received/sec",
    "\Network Interface\Bytes Sent/sec",
    "\Network Interface\Packets Received Errors",
    "\Network Interface\Packets Received/sec",
    "\Network Interface\Packets Outbound Errors",
    "\Network Interface\Packets Sent/sec"
)

$Adapters_counters = @(
    "\Network Adapter\Bytes Received/sec",
    "\Network Adapter\Bytes Sent/sec",
    "\Network Adapter\Packets Received Errors",
    "\Network Adapter\Packets Received/sec",
    "\Network Adapter\Packets Outbound Errors",
    "\Network Adapter\Packets Sent/sec"
)

$Active_Directory_counters = @(
    "\NTDS\DS Client Binds/sec",
    "\NTDS\DS Directory Reads/sec",
    "\NTDS\DS Directory Searches/sec",
    "\NTDS\DS Directory Writes/sec",
    "\NTDS\DS Name Cache hit rate",
    "\NTDS\DS Notify Queue Size",
    "\NTDS\DS Search sub-operations/sec",
    "\NTDS\DS Server Binds/sec",
    "\NTDS\DS Server Name Translations/sec",
    "\NTDS\DS Threads in Use",
    "\NTDS\KDC AS Requests",
    "\NTDS\KDC TGS Requests",
    "\NTDS\Kerberos Authentications",
    "\NTDS\LDAP Active Threads",
    "\NTDS\LDAP Bind Time",
    "\NTDS\LDAP Client Sessions",
    "\NTDS\LDAP Closed Connections/sec",
    "\NTDS\LDAP New Connections/sec",
    "\NTDS\LDAP New SSL Connections/sec",
    "\NTDS\LDAP Searches/sec",
    "\NTDS\LDAP Successful Binds/sec",
    "\NTDS\LDAP UDP operations/sec",
    "\NTDS\LDAP Writes/sec",
    "\NTDS\NTLM Authentications"
)

$Exchange_2007_2010 = @(
    "\MSExchangeIS Mailbox\Folder opens/sec",
    "\MSExchangeIS Mailbox\Local delivery rate",
    "\MSExchangeIS Mailbox\Message Opens/sec",
    "\MSExchangeIS\RPC Averaged Latency",
    "\MSExchangeIS\RPC Operations/sec",
    "\MSExchangeIS\RPC Requests",
    "\MSExchangeTransport Queues\Active Mailbox Delivery Queue Length",
    "\MSExchangeTransport SmtpSend\Messages Sent/sec"
)

$Exchange_2013 = @(
    "\MSExchangeIS Store\Folders opened/sec",
    "\MSExchangeIS Store\Messages Delivered/sec",
    "\MSExchangeIS Store\Messages opened/sec",
    "\MSExchange Store Interface\RPC Latency average (msec)",
    "\MSExchange Store Interface\RPC Requests sent/sec",
    "\MSExchange Store Interface\RPC Requests sent",
    "\MSExchangeTransport Queues\Active Mailbox Delivery Queue Length",
    "\MSExchange Delivery SmtpSend\Messages Sent/sec"
)

$IIS = @(
    "\Web Service\Bytes Received/sec",
    "\Web Service\Bytes Sent/sec",
    "\Web Service\CGI Requests/sec",
    "\Web Service\Connection Attempts/sec",
    "\Web Service\Copy Requests/sec",
    "\Web Service\Current Connections",
    "\Web Service\Delete Requests/sec",
    "\Web Service\Files Received/sec",
    "\Web Service\Files Sent/sec",
    "\Web Service\Get Requests/sec",
    "\Web Service\Head Requests/sec",
    "\Web Service\ISAPI Extension Requests/sec",
    "\Web Service\Lock Requests/sec",
    "\Web Service\Mkcol Requests/sec",
    "\Web Service\Move Requests/sec",
    "\Web Service\Options Requests/sec",
    "\Web Service\Other Request Methods/sec",
    "\Web Service\Post Requests/sec",
    "\Web Service\Propfind Requests/sec",
    "\Web Service\Proppatch Requests/sec",
    "\Web Service\Put Requests/sec",
    "\Web Service\Search Requests/sec",
    "\Web Service\Trace Requests/sec",
    "\Web Service\Unlock Requests/sec"
)

function get_perf_hash()
{
    $perfHash = @{}

    $key = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage'
    $counters = (Get-ItemProperty -Path $key -Name Counter).Counter
    $all = $counters.Count
        
    for($i = 0; $i -lt $all; $i+=2)
    {
        if ($counters[$i+1] -and $perfHash.$($counters[$i+1])){continue}
        $perfHash.$($counters[$i+1]) = $counters[$i]
    }
    return $perfHash
}

function get_ctr_indexes($counter, $perfHash)
{
    $names = $counter.Split('\')
    $indexes = ($names | % {$perfHash.$_})
    if ($indexes[1] -and $indexes[2])
    {
        $x = '@("{0}",{1},{2}),' -f $counter,$indexes[1],$indexes[2]
        Write-Host $x
    }
}

if ($perf_hash -eq $null){
    $perf_hash = get_perf_hash
}

write-host '$Device = @('
foreach ($counter in $device_counter_names)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

write-host '$FileSystems = @('
foreach ($counter in $File_Systems_counters)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

write-host '$HardDisks = @('
foreach ($counter in $Hard_Disks_counters)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

write-host '$Interfaces = @('
foreach ($counter in $Interfaces_counters)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

#####################################################################
# Some 2012 systems need to use the "\Network Adapter" Perf Object. #
#####################################################################
write-host '$Adapters = @('
foreach ($counter in $Adapters_counters)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

write-host '$ActiveDirectory = @('
foreach ($counter in $Active_Directory_counters)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

write-host '$Exchange_2007_2010 = @('
foreach ($counter in $Exchange_2007_2010)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

write-host '$Exchange_2013 = @('
foreach ($counter in $Exchange_2013)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'

write-host '$IIS = @('
foreach ($counter in $IIS)
{
    get_ctr_indexes $counter $perf_hash
}
write-host '$null)'
