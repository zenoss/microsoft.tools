<##############################################################################
# Copyright 2017 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This is a script that could be run periodically using task scheduler or
# some other mechanism to save off windows remote management analytic logs.
# These logs are useful as they show what is happening on the Windows server
# during modeling/monitoring
#
##############################################################################>


# create c:\temp or other directory if it doesn't exist
if ($(Test-Path c:\temp) -eq $False){
  New-item -type directory -path c:\temp
}

# determine current file name based off of index
if ($(Test-Path C:\temp\winrm-analytic*.evtx) -eq $false) {
  $event_file = c:\temp\winrm-analytic1.evtx
}
else {
  $files = Get-ChildItem c:\temp\*.evtx
  $index = 0
  foreach ($f in $files) {
    $mtch = [regex]::Match($f.Name, 'winrm-analytic(\d+).evtx')
    if ($mtch -ne $null) {
      $i = [convert]::ToInt32($mtch.Groups[1].Value)
      if ($i -gt $index) {
        $index = $i
      }
    }
  }
  $index += 1
  $event_file = 'c:\temp\winrm-analytic{0}.evtx' -f $index
}
# export log
wevtutil epl Microsoft-Windows-WinRM/Analytic $event_file
# disable log
wevtutil set-log Microsoft-Windows-WinRM/Analytic /e:false /q:true
# clear log
wevtutil clear-log Microsoft-Windows-WinRM/Analytic
# enable log
wevtutil set-log Microsoft-Windows-WinRM/Analytic /e:true /q:true