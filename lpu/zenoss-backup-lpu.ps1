#
# Copyright 2015 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# Example of backing up permissions changed by the lpu script
#
# This script queries the registry and several system access permissions. Use with caution!
#
# This script does not backup any settings.  It will display the sddls for the following which can be
# captured in a text file and reapplied if the LPU is removed.
#
#    * WinRM Access
#    * DCOM Permissions
#    * Registry Permissions
#    * Folder/File Permissions
#    * Service Permissions
#
# It does not determine WMI Namespace or Local Group information.
#
# Example usage:  PS > .\zenoss-backup-lpu.ps1 > backup.txt


function backup_winrm_access(){
    $sddlkey = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
    $rootsddlkey = get-itemproperty $sddlkey -Name “rootSDDL”
    $output = "winrm:  {0}" -f $rootsddlkey.rootSDDL
    Write-Output $output
}

function backup_registry_sddl($regkey){
    $regaclitem = get-item $regkey -ea silentlycontinue
    if ($regaclitem -ne $null) {
        $sddl = $regaclitem.getaccesscontrol("Access").sddl
        $output = "{0}:  {1}" -f $regkey,$sddl
        Write-Output $output
    }
}

function backup_dcom_permissions($regkey, $property) {
    $objSDHelper = New-Object System.Management.ManagementClass Win32_SecurityDescriptorHelper
    $objRegProperty = Get-ItemProperty $regkey -Name $property -ea SilentlyContinue
    if ($objRegProperty -ne $null) {
        $sddl = [string]($objSDHelper.BinarySDToSDDL($objRegProperty.$property)).SDDL
        $output = "{0}:{1}:  {2}" -f $regkey,$property,$sddl
        Write-Output $output
    }
}

function backup_folderfile($folderfile) {
    $sddl = (get-item $folderfile).getaccesscontrol("Access").Sddl
    $output = "{0}:  {1}" -f $folderfile,$sddl
    Write-Output $output
}

function backup_service_sddl($service) {
    $servicesddl = [string](CMD /C "sc sdshow `"$service`"")
    $output = "{0}:  {1}" -f $service,$servicesddl
    Write-Output $output
}

###################################################
# The least privileged user needs winrm access
# Write out the current access
###################################################
Write-Output "==== WinRM Access ===="

backup_winrm_access

####################################################
# The lpu needs registry key access
# Write out the current access to the necessary keys
####################################################
Write-Output "`n`n==== Registry Keys Permissions ===="

$registrykeys = @(
	"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib",
	"HKLM:\system\currentcontrolset\control\securepipeservers\winreg",
	"HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}",
	"HKLM:\SYSTEM\CurrentControlSet\Services\Blfp\Parameters\Adapters",
	"HKLM:\Software\Wow6432Node\Microsoft\Microsoft SQL Server",
	"HKLM:\Software\Microsoft\Microsoft SQL Server"
	)
foreach ($registrykey in $registrykeys) {
    backup_registry_sddl $registrykey
}

###################################################
# The least privileged user needs DCOM access
# Write out the current access for each registry value
# DefaultAccessPermission may not exist, which is OK
###################################################
Write-Output "`n`n==== DCOM Permissions ===="

$registryvaluekeys = @{
	"MachineAccessRestriction" = "HKLM:\software\microsoft\ole";
	"MachineLaunchRestriction" = "HKLM:\software\microsoft\ole";
    "DefaultAccessPermission" = "HKLM:\software\microsoft\ole"
}

foreach ($registryvaluekey in $registryvaluekeys.GetEnumerator()){
    backup_dcom_permissions $registryvaluekey.Value $registryvaluekey.Name
}

###################################################
# The least privileged user needs folder access
# Write out the current access for each folder
###################################################
Write-Output "`n`n==== Folder Permissions ===="

$folderfiles = @(
	"C:\Windows\system32\inetsrv\config"
	)
foreach($folderfile in $folderfiles){
	backup_folderfile $folderfile 
}


###################################################
# The least privileged user needs query access to services
# Write out the current access for each service
###################################################
Write-Output "`n`n==== Service Permissions ===="

$services = get-wmiobject -query "Select * from Win32_Service"
foreach ($service in $services){
	backup_service_sddl $service.name
}

