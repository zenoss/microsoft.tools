# BACKUP YOUR SETTINGS BEFORE EXECUTING!
#
# Copyright 2019 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script modifies the registry and several system access permissions. Use with caution!
#    BACKUP YOUR SETTINGS BEFORE EXECUTING!
#
# Example usage:  PS > .\zenoss-lpu-revert.ps1 -f backup.txt


########################################
#  ------------------------------------
#  ----------- Arguments  -------------
#  ------------------------------------
########################################

param (
    [Parameter(HelpMessage="Backup file for revert configurations")]
    [Alias('file', 'f')]
    [string]
    $filepath
)

########################################
#  ------------------------------------
#  ----------- Initialization  --------
#  ------------------------------------
########################################


#Text that parsed from backup file
$backupText

if(Test-Path $filepath) {
    $backupText = Get-Content $filepath | Out-String
} else {
    Write-Host "File not found"
    exit
}


$arrtext = $backupText -split "====.+====" | Where { $_.Length -gt 0 } | Foreach { $_.trim() }

#WinRM security descriptor
$winrmSddl = $arrtext[0].Split(":")[1].trim()

#Array of registry keys and their security descriptors
$arrRegKeyPerm = $arrtext[1].Split("`n")

#Array of folders and their security descriptors
$arrFolderPerm = $arrtext[2].Split("`n")

#Array of services and their security descriptors
$arrServicePerm = $arrtext[3].Split("`n")

########################################
#  ------------------------------------
#  -----------  Functions -------------
#  ------------------------------------
########################################

function revert_winrm_access($sddl) {
    $defaultkey = "O:NSG:BAD:P(A;;GA;;;BA)S:P(AU;FA;GA;;;WD)(AU;SA;GWGX;;;WD)"
    $sddlkey = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"

    if ($sddl.Length -eq 0){
        $sddl = $defaultkey
    }

    Set-ItemProperty $sddlkey -name "rootSDDL" -Value $sddl
}

function revert_registry($regkey, $sddl) {
    if(Test-Path $regkey) {
        $secDesriptor = Get-Acl -Path $regkey
        $secDesriptor.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -Path $regkey -AclObject $secDesriptor
        Write-Host "Registry key reverted: $regkey"
    } else {
        Write-Host "Registry key does not exists: $regkey"
    }
}

function revert_folder($folderpath, $sddl) {
    if (Test-Path $folderpath) {
         $secDesriptor = Get-Acl -Path $folderpath
         $secDesriptor.SetSecurityDescriptorSddlForm($sddl)
         Set-Acl -Path $folderpath -AclObject $secDesriptor
         Write-Host "Folder / File reverted: $folderfile"
    } else {
        Write-Host "Folder not found: $folderpath"
    }
}

function revert_service($service, $sddl) {
    $result = CMD /C "sc sdset $service $sddl"

    if ($result[0] -match '.FAILED.') {
        $reason = $result[2]
        $message = "Revert service $service failed.`n`tReason:  $reason"
    } else {
        $message = "Revert service $service successful."
    }

    Write-Host $message
}

########################################
#  ------------------------------------
#  -------- Execution Center ----------
#  ------------------------------------
########################################

revert_winrm_access $winrmSddl

foreach($registryLine in $arrRegKeyPerm) {
    $arrdata = $registryLine -split ":\s\s"
    $regkey = $arrdata[0]
    $sddl = $arrdata[1]
    revert_registry $regkey $sddl
}

foreach($folder in $arrFolderPerm) {
    $arrdata = $folder -split ":\s\s"
    $folderPath = $arrdata[0]
    $sddl = $arrdata[1]
    revert_folder $folderPath $sddl
}

foreach($serviceLine in $arrServicePerm) {
    $arrdata = $serviceLine -split ":\s\s"
    $service = $arrdata[0]
    $sddl = $arrdata[1]
    revert_service $service $sddl
}

write-host 'Restarting winmgmt and winrm services...'
get-service winmgmt | restart-service -force
get-service winrm | restart-service -force
