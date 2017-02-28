#############################################################################################
#
# Copyright 2017 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script queries the registry. Use with caution!
#
# This script extracts the counter name according to the locale being used by the 
# current user.  It looks up the counter by index.  These are the default counters used
# by the Windows ZenPack.
# 
# To manually find the index numbers, search the Counter value in the registry key
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage
#
# To get the counter indexes for Active Directory, Exchange, and IIS, run the
# get-counter-indexes.ps1 script on a machine with English as the current language and
# with AD, IIS, or Exchange installed.  The indexes for perfobjects and counter names are
# inconsistent across different installations.
#
#############################################################################################

<#
    .SYNOPSIS
    Given counter indeces, display local counter names, grouped by monitoring template
    .DESCRIPTION
    This script uses PdhLookupPerfNameByIndex from pdh.dll to look up counter names by index.
    It displays by monitoring template with the datasource name at the start of each line.
    .EXAMPLE
    .\get-localcounters.ps1
#>

# Default counter indeces

$Device = @(
    @('MemoryAvailableBytes',4,24),
    @('MemoryCommittedBytes',4,26),
    @('MemoryPagesInputSec',4,822),
    @('MemoryPagesOutputSec',4,48),
    @('PagingFileTotalUsage',700,702),
    @('ProcessorTotalPrivilegedTime',238,144, '_Total'),
    @('ProcessorTotalProcessorTime',238,6, '_Total'),
    @('ProcessorTotalUserTime',238,142, '_Total'),
    @('sysUpTime',2,674)
)

$Hard_Disks = @(
    @('DiskReadBytesSec',234,220, '${here/instance_name}'),
    @('DiskReadTime',234,202, '${here/instance_name}'),
    @('DiskWriteBytesSec',234,222, '${here/instance_name}'),
    @('DiskWriteTime',234,204, '${here/instance_name}')
)

$File_Systems = @(
    @('DiskReadBytesSec',236,220, '${here/instance_name}'),
    @('DiskReadTime',236,202, '${here/instance_name}'),
    @('DiskWriteBytesSec',236,222, '${here/instance_name}'),
    @('DiskWriteTime',236,204, '${here/instance_name}'),
    @('FreeMegabytes',236,410, '${here/instance_name}')
)

$Interfaces = @(
    @('bytesReceivedSec',510,264, '${here/instance_name}'),
    @('bytesSentSec',510,506, '${here/instance_name}'),
    @('packetsReceivedErrors',510,530, '${here/instance_name}'),
    @('packetsReceivedSec',510,266, '${here/instance_name}'),
    @('packetsSentErrors',510,542, '${here/instance_name}'),
    @('packetsSentSec',510,452, '${here/instance_name}')
)

$Adapters = @(
    @('bytesReceivedSec',1820,264, '${here/instance_name}'),
    @('bytesSentSec',1820,506, '${here/instance_name}'),
    @('packetsReceivedErrors',1820,530, '${here/instance_name}'),
    @('packetsReceivedSec',1820,266, '${here/instance_name}'),
    @('packetsSentErrors',1820,542, '${here/instance_name}'),
    @('packetsSentSec',1820,452, '${here/instance_name}')
)


# import PdhLookupPerfNameByIndex from pdh.dll

$code = '[DllImport("pdh.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern UInt32 PdhLookupPerfNameByIndex(string szMachineName, uint dwNameIndex, System.Text.StringBuilder szNameBuffer, ref uint pcchNameBufferSize);'
$t = Add-Type -MemberDefinition $code -PassThru -Name PerfCounter -Namespace Utility
 
Function Get-PerformanceCounterLocalName($ID)
{
  $Buffer = New-Object System.Text.StringBuilder(1024)
  [UInt32]$BufferSize = $Buffer.Capacity
 
  $rv = $t::PdhLookupPerfNameByIndex($env:COMPUTERNAME, $id, $Buffer, [Ref]$BufferSize)
 
  if ($rv -eq 0 -and $Buffer.ToString().Length -gt 0)
  {
    $Buffer.ToString().Substring(0, $BufferSize-1)
  }
}

function get_local_counters($ids)
{
    <#
        Each item in the array must use this format:
        @(datasourcename, perfobject, counter, instance) where:
            datasourcename is a string denoting the datasource name
            perfobject is the object type name
            counter is the counter name
            instance is the instance to use

    #>
    foreach ($i in $ids)
    {
        if ($i -eq $null) { break }
        $a = Get-PerformanceCounterLocalName $i[1]
        $b = Get-PerformanceCounterLocalName $i[2]

        if ($a -eq $null -or $b -eq $null)
        {
            continue
        }
        else {
            if ($i[3])
            {
                $c = $i[3]
                $x = "\{0}({2})\{1}" -f $a,$b,$c
            }
            else
            {
                $x = "\{0}\{1}" -f $a,$b
            }
            write-host $i[0]": "$x
        }
    }
}


###########
# Execute #
###########

write-host "`nDevice`n"
get_local_counters $Device

write-host "`nFileSystem`n"
get_local_counters $File_Systems

write-host "`nHardDisk`n"
get_local_counters $Hard_Disks

write-host "`nethernetCsmacd`n"
get_local_counters $Interfaces

#####################################################################
# Some 2012 systems need to use the "\Network Adapter" Perf Object. #
#####################################################################
write-host "`nethernetCsmacd - 2012`n"
get_local_counters $Adapters

<# Remove this line and last comment line to execute this part of the script
write-host "`nActive Directory`n"
get_local_counters $ActiveDirectory

write-host "`nExchange 2007 & 2010`n"
get_local_counters $Exchange_2007_2010

write-host "`nExchange 2013`n"
get_local_counters $Exchange_2013

write-host "`nIIS`n"
get_local_counters $IIS
#>