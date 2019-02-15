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

<#
    .SYNOPSIS
    Rollback system permissions from backup file
    .DESCRIPTION
    This script rollbacks system permissions for WinRM/WinRS access, registry keys,
    service querying and specific folder/file permissions.
    .INPUT
    -f or -file to specify the backup file path.
    .EXAMPLE
    .\zenoss-lpu-revert.ps1 -f backup.txt
    .EXAMPLE
    If the "zenoss-system-services.ps1" script was used then you need to run this script
    as the system account.
    CAUTION: To run this as the system account, use the psexec.exe program
    to start a cmd shell. PSExec can be found as part of Windows Sysinternals
    here: https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx
    > psexec.exe -s cmd
    > powershell -file zenoss-lpu-revert.ps1 -f backup.txt
#>

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
$winrmLine = $arrtext[0] -split ":\s\s"
$winrmSddl = $winrmLine[1]

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
    $sddlkey = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"

    if ($sddl -ne $null -and $sddl.Length -ne 0){
        #validation of the descriptor
        try {
            $emptyACL = New-Object System.Security.AccessControl.DirectorySecurity
            $emptyACL.SetSecurityDescriptorSddlForm($sddl)
        } catch {
            $message = "Revert WinRM access failed.`n`tReason: The SDDL form is invalid"
            Write-Host $message
            continue
        }

        Set-ItemProperty $sddlkey -name "rootSDDL" -Value $sddl
    }
    else
    {
        #If sddl is empty then we delete 'rootSDDL' property
        if((get-itemproperty $sddlkey).rootSDDL -ne $null) {
            Remove-ItemProperty -Path $sddlkey -Name "rootSDDL"
        }
    }

    Write-Host "WinRM access reverted: $sddlkey"
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

    trap {
        $message = "Revert registry key '$regkey' failed.`n`tReason: $_"
        Write-Host $message
        continue
    }
}

function revert_folder($folderpath, $sddl) {
    if (Test-Path $folderpath) {
         $secDesriptor = Get-Acl -Path $folderpath
         $secDesriptor.SetSecurityDescriptorSddlForm($sddl)
         Set-Acl -Path $folderpath -AclObject $secDesriptor
         Write-Host "Folder/File reverted: $folderpath"
    } else {
        Write-Host "Revert folder/file '$folderpath' failed.`n`tReason: folder/file not found: $folderpath"
    }

    trap {
        $message = "Revert folder '$folderpath' failed.`n`tReason: $_"
        Write-Host $message
        continue
    }
}

function revert_service($service, $sddl) {
    $currentsddl = ([string](CMD /C "sc sdshow `"$service`"")).Trim()
    $sddl = $sddl.Trim()

    if ($currentsddl -ne $sddl) {
        $result = CMD /C "sc sdset $service $sddl"

        if ($result[0] -match '.FAILED.') {
            $reason = $result[2]
            $message = "Revert service $service failed.`n`tReason:  $reason"
        } else {
            $message = "Revert service $service successful."
        }

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
    $folderPath = $arrdata[0].TrimEnd(':')
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
