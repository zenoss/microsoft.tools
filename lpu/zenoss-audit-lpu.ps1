#
# Copyright 2014, 2017 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script queries the registry and several system access permissions. Use with caution!
#
# This script will query WMI namespace security, remote winrm/winrs access, registry permissions,
# group membership, folder/file permissions, and service permissions.  The point is to determine
# if a given user will be able to access information needed to model/monitor a Windows server.
# This script does not make any changes to the system.  It will issue events.  But, as with any script,
# read thoroughly and use with caution.
#


<#
	.SYNOPSIS
	Query local system permissions to support least privilege user access for Zenoss Resource Manager monitoring.
	.DESCRIPTION
	This script queries system permissions to determine if a user has access to WMI namespaces, service querying,
    WinRM/WinRS access, registry keys, local groups, and specific folder/file permissions.
    .INPUT
    -u or -user to specify the user name.  Enter just the user name for a local user and user@domain.com for a domain user.
	.EXAMPLE
	Domain account
	zenoss-audit-lpu.ps1 -u zenny@zenoss.com
	.EXAMPLE
	Local account
	zenoss-audit-lpu.ps1 -u benny
#>

########################################
#  ------------------------------------
#  ----------- Arguments  -------------
#  ------------------------------------
########################################

param(
	[Parameter(HelpMessage="User account to query Zenoss permissions")]
	[Alias('user', 'u')]
	[string]
	$login = 'benny',
	[Alias('debug_switch','d')]
	[switch]
	$_debug = $false
	)

########################################
#  ------------------------------------
#  ----------- Initialization  --------
#  ------------------------------------
########################################


#$login = 'zenny@zenoss.com'					# Domain Account
#$login = 'benny'                               # Local Account

# The following values will be set at runtime. They are place holders here.
$usersid

# Default settings
$inherit = $True      # Set to false (not recommended) if you do not want WMI Acl inheritance

$OBJECT_INHERIT_ACE_FLAG = 0x1
$CONTAINER_INHERIT_ACE_FLAG = 0x2

$objSDHelper = New-Object System.Management.ManagementClass Win32_SecurityDescriptorHelper

# Set account information

if($login.contains("@")){
	$arrlogin = $login.split("@")
	$arrdomain = $arrlogin[1].split(".")
	$domain = $arrdomain[0]
    if ($arrdomain.Count -gt 2){
        for ($i = 1; $i -lt $arrdomain.Count-1; $i++) {
            $domain += "."+$arrdomain[$i]
        }
    }
	$username = $arrlogin[0]
	$userfqdn = $login
    $domainuser = "{1}\{0}" -f $username, $domain.ToUpper()
}
else{
	$domain = $env:COMPUTERNAME
	$username = $login
	$userfqdn = "{1}\{0}" -f $username, $domain
    $domainuser = $userfqdn
}

# Prep event Log
if (![System.Diagnostics.EventLog]::SourceExists('Zenoss-Audit-LPU')){
	New-EventLog -LogName Application -Source "Zenoss-Audit-LPU"
}

########################################
#  ------------------------------------
#  -----------  Functions -------------
#  ------------------------------------
########################################

function get_user_sid($getuser=$userfqdn) {
	$objUser = New-Object System.Security.Principal.NTAccount($getuser)
	$objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
	return $objSID.Value

	trap{
		$message = "User does not exists: $getuser"
		write-host $message
		send_event $message 'Error'
		continue
	}
}

function is_user_in_group($groupname) {
	$objADSI = [ADSI]"WinNT://./$groupname,group"
	$objADSIUser = [ADSI]"WinNT://$domain/$username"
	$objMembers = @($objADSI.psbase.Invoke("Members"))
	if($objMembers.Count -gt 0){
		foreach ($objMember in $objMembers){
			$membername = $objMember.GetType().InvokeMember("Name", 'GetProperty', $null, $objMember, $null)
            $membersid = get_user_sid $membername
            if ($membersid -eq $usersid){
				return $True
			}
		}
	}
	else {
		return $false
	}

	trap{
        $message = "Group does not exist: $groupname"
	 	write-host $message
	 	send_event $error[0] 'Error'
	 	continue
 	}
    return $false
}

function is_user_in_service($service){
    $testuserperms = @('CC','LC','RP','LO','RC')
	$servicesddlstart = [string](CMD /C "sc sdshow `"$service`"")
    $intersection = @('place','holder')
    [regex]$re = '\w;;(\w+);.*'
    foreach ($sddlkey in $servicesddlstart.split('('))  {
        if ($sddlkey -match $usersid) {
            $match = $re.match($sddlkey)
            if ($match.success -eq $true) {
                $perms = $match.Groups[1].value
                $sddlperms = $perms -split '(.{2})' | ? {$_}
                $intersection = $testuserperms | ?{$sddlperms -notcontains $_}
            }
        }
    }
	return $intersection -eq $null
}

function test_folderfile($folderfile){
	if(Test-Path $folderfile){
		$folderfileacl = (get-item $folderfile).getaccesscontrol("Access")
        $folderfileaclstring = $folderfileacl.AccessToString
        $testuser = "{0}\s+Allow\s+ReadFolder" -f $domainuser.replace('\', '\\')
        if ($_debug) {
            Write-Host "debug: `$testuser = $testuser"
            Write-Host "debug: `$folderfileacl = $folderfileacl"
        }
        return $folderfileaclstring -match $testuser
	}

	trap{
		$message = "Folder / File path does not exists: $folderfile"
		write-host $message
		send_event $message 'Error'
		continue
	}
}

function test_registry_security($regkey){
	if(Test-Path $regkey){
        $testuser = "{0}\s+Allow\s+ReadKey" -f $domainuser.replace('\', '\\')
        if ($_debug) {
            Write-Host "debug: `$testuser = $testuser"
        }
		$regacl = (get-item $regkey).getaccesscontrol("Access")
        $regaclstring = $regacl.AccessToString
        if ($_debug) {
            Write-Host "debug:  `$regaclstring = $regaclstring"
        }
        return $regaclstring -match $testuser
	}

	trap{

		$message ="Registry key does not exist: $regkey"
		write-host $message
		send_event $message 'Error'
		continue
	}
}

function test_registry_sd_value($regkey, $property, $usersid, $accessMask){
	$objRegProperty = Get-ItemProperty $regkey -Name $property
	$sddlstart = [string]($objSDHelper.BinarySDToSDDL($objRegProperty.$property)).SDDL
    $usersddl = "(A;;LCRP;;;{0})" -f $usersid
	return $sddlstart.contains($usersddl)

	trap{
		$message = "Registry Security Descriptor failed for $regkey"
		write-host $message
		send_event $message 'Error'
        continue
    }
}

function test_access_to_winrm($usersid) {
	$sddlkey = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
	if($usersid.Length -gt 5){
		if ((get-itemproperty $sddlkey).rootSDDL -eq $null) {
            Write-Host "Registry RootSDDL doesn't exist for WSMAN service."
            return $false
        }
		else{
			$rootsddlkey = get-itemproperty $sddlkey -Name "rootSDDL"
			$sddlstart = $rootsddlkey.rootSDDL
			send_event "Current RootSDDL $sddlstart" "Information"
    	}
    }
    else {
        return $false
    }
    if ($sddlstart.Length -eq 0) {
        Write-Host "RootSDDL was not found!"
        return $false
    }

    $usersddl = [string]::Format("(A;;GXGR;;;{0})",$usersid)
    if ($_debug){
        Write-Host "debug: test_access_to_winrm:  sddlstart: $sddlstart"
        Write-Host "debug: test_access_to_winrm:  Looking in rootSDDL for $usersddl"
    }
	if ($sddlstart.Contains($usersddl)){
        return $True
    }
    return $false
}

function get_accessmask_value($permission) {
	$permTable = @{
		"enable" 				= 1;
		"methodexecute" 		= 2;
		"fullwrite"				= 4;
		"partialwrite"			= 8;
		"providerwrite"			= 0x10;
		"remoteaccess"			= 0x20;
		"readsecurity"			= 0x20000;
		"readfolder"			= 0x20089;
		"deleteperm"			= 0x10000;
		"writesecurity"			= 0x40000;
		"genericall"			= 0x10000000;
		"genericexecute"		= 0x20000000;
		"genericwrite"			= 0x40000000;
		"genericread"			= 0x80000000;
		"listcontents"			= 0x00000004;
		"readallprop"			= 0x00000010;
		"keyallaccess"			= 0xF003F;
		"keyread"				= 0x20019;
		"keywrite"				= 0x20006;
		"keyexecute"			= 0x20019;
		"keyenumeratesubkeys"	= 0x0004;
		"keyqueryvalue"			= 0x0001;
		"keysetvalue"			= 0x0002;
		"servicequeryconfig"	= 0x0001;
		"servicequeryservice"	= 0x0004;
		"servicestart"			= 0x0010;
		"servicestop"			= 0x0020;
		"serviceinterrogate"    = 0x0080
	}
    $perm = $permission.ToLower()
    if ($permTable.ContainsKey($perm)) {
        return $permTable[$perm]
    }
}
function get_accesslist($permissions){
	<#
	$permissions = @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
	#>


	$accessList = @()
	foreach ($perm in $permissions) {
		$perm = $perm.ToLower()
        $accessmask = get_accessmask_value($perm)
		if($accessmask -ne $null){
			$accessList += $accessmask
		}
		else {
		    throw "Unknown permission: $perm"
		}
	}
	return $accessList
}

function get_accessmask($permissions){
	<#
	$permissions = @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
	#>


	$accessMask = 0
	foreach ($perm in $permissions) {
		$perm = $perm.ToLower()
        $accessmask_value = get_accessmask_value($perm)
		if($accessmask_value -ne $null){
			$accessMask += $accessmask_value
		}
		else {
		    throw "Unknown permission: $perm"
		}
	}
	return $accessMask
}

function test_namespace_access($accessList, $namespaceParams){
	$currentSecurityDescriptor = Invoke-WmiMethod @namespaceParams -Name GetSecurityDescriptor -ErrorAction 'silentlycontinue'
    if ($? -eq $false){
        Write-Host "GetSecurityDescriptor is not valid for this operating system.  Check user in namespaces manually."
        Return $false
    }
	if($currentSecurityDescriptor.ReturnValue -ne 0){
        throw "Failed to get security descriptor for namespace: $namespace"
    }
    $accessMask = 0
    $userMask = 0
	$objACL = $currentSecurityDescriptor.Descriptor
    if ($_debug) {
        Write-Host "debug: checking access for $userfqdn, $usersid"
    }
    foreach ($acl in $objACL.DACL) {
        if ($acl.Trustee.SIDString -eq $usersid) {
            foreach ($mask in $accessList) {
                $masknum = get_accessmask $mask
                if ($_debug) {
                    Write-Host "debug: $mask = $masknum"
                }
                $accessMask += $masknum
                if ($acl.AccessMask -band $masknum){
                    if ($_debug) {
                        Write-Host "debug: acl.AccessMask($acl.AccessMask) -band `$masknum($masknum) = `$true"
                    }
                    $userMask += $masknum
                }
            }
        }
    }
    if ($accessMask -eq $userMask -and $accessMask -gt 0) {
        return $True
    }
    return $false
}

function send_event($message, $errortype){
	Write-EventLog -LogName Application -Source "Zenoss-Audit-LPU" -EntryType $errortype -EventId 1 -Message $message
}

########################################
#  ------------------------------------
#  -------- Execution Center ----------
#  ------------------------------------
########################################

# Initialize user information
$usersid = get_user_sid

##############################
# Validate Namespace Security
##############################
# Root/CIMv2/Security/MicrosoftTpm  -->  OperatingSystem modeler - Win32_OperatingSystem
# Root/RSOP/Computer  -->  OperatingSystem modeler - Win32_ComputerSystem

$namespaces = @(
	"Root", 
	"Root/CIMv2", 
	"Root/DEFAULT", 
	"Root/RSOP", 
	"Root/RSOP/Computer",
	"Root/WMI", 
	"Root/CIMv2/Security/MicrosoftTpm"
	)
$namespaceaccesslist = @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
$namespaceString = $namespaces -join ","
Write-Host "`nTesting $userfqdn rights for WMI namespaces"
foreach ($namespace in $namespaces) {
	$namespaceParams = @{Namespace=$namespace;Path="__systemsecurity=@"}
	$ret = test_namespace_access $namespaceaccesslist $namespaceParams
    if ($ret -eq $false){
        Write-Host "`tUser $userfqdn needs Enable, MethodExecute, ReadSecurity, and RemoteAccess rights to" $namespace
    }
    else {
        Write-Host "`tUser $userfqdn has sufficient rights to access namespace" $namespace
    }
}

##############################
# Validate remote WinRM/WinRS access
##############################
Write-Host "`nTesting $userfqdn for access to winrm"
$winrm_ret = test_access_to_winrm $usersid 
if ($winrm_ret -eq $false) {
    Write-Host "`tUser $userfqdn needs `"genericexecute`" and `"genericread`" access to winrm"
}
else{
    Write-Host "`tUser $userfqdn has access to winrm"
}

##############################
# Validate Registry permissions
##############################
$registrykeys = @(
	"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib",
	"HKLM:\system\currentcontrolset\control\securepipeservers\winreg",
	"HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}",
	"HKLM:\SYSTEM\CurrentControlSet\Services\Blfp\Parameters\Adapters",
	"HKLM:\Software\Wow6432Node\Microsoft\Microsoft SQL Server",
	"HKLM:\Software\Microsoft\Microsoft SQL Server"
	)
Write-Host "`nTesting $userfqdn for registry read access"
foreach ($registrykey in $registrykeys) {
	$reg_ret = test_registry_security $registrykey
    if ($reg_ret -eq $True) {
        Write-Host "`tUser $userfqdn has correct access to registry key $registrykey"
    }
    elseif ($reg_ret -eq $false) {
        Write-Host "`tUser $userfqdn needs ReadKey access to registry key $registrykey"
    }
    else {
        Write-Host "`tRegistry key $registrykey does not exist on this system"
    }
}

##############################
# Validate local group permissions
##############################
$localgroups = @(
	"S-1-5-32-558",
	"S-1-5-32-559",
	"S-1-5-32-573",
	"S-1-5-32-562",
	"WinRMRemoteWMIUsers__"
	)

Write-Host "`nTesting $userfqdn for group membership"
foreach ($localgroup in $localgroups) {
    if ($localgroup.StartsWith('S-1-5-32-')) {
        $GrObj = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $localgroup;
        $localgroup = $GrObj.Translate([System.Security.Principal.NTAccount]).Value.split('\')[1]
    }
	$grp_ret = is_user_in_group $localgroup
    if ($grp_ret -eq $True) {
        Write-Host "`tUser $userfqdn is a member of the $localgroup group"
    }
    elseif ($grp_ret -eq $false) {
        Write-Host "`tUser $userfqdn is not a member of the $localgroup group"
    }
    else {
        Write-Host "`tThe $localgroup group does not exist."
    }
}

##############################
# Validate Folder/File permissions
##############################

$folderfiles = @(
	"C:\Windows\system32\inetsrv\config"
	)

$folderfileaccessmap = get_accessmask @(
	"readfolder"
	)

Write-Host "`nTesting $userfqdn for folder read access"
foreach($folderfile in $folderfiles){
	$folder_ret = test_folderfile $folderfile 
    if ($folder_ret -eq $True) {
        Write-Host "`tUser $userfqdn has read access to folder/file $folderfile"
    }
    elseif ($folder_ret -eq $false) {
        Write-Host "`tUser $userfqdn does not have read access to folder/file $folderfile"
    }
    else {
        Write-Host "`tThe folder/file $folderfile does not exist on this system.  This is not a critical error."
    }
}


##############################
# Validate Services Permissions
##############################

$services = get-wmiobject -query "Select * from Win32_Service"
$serviceaccessmap = get_accessmask @("servicequeryconfig","servicequeryservice","readallprop","readsecurity","serviceinterrogate")
Write-Host "`nTesting $userfqdn for access to services.  Some services are controlled by the system and permissions cannot be changed. `nFor example, the EFS service."
foreach ($service in $services){
	$svc_ret = is_user_in_service $service.name
    if ($svc_ret -eq $True) {
        Write-Host "`tUser $userfqdn has correct access to service $($service.name)"
    }
    else {
        Write-Host "`tUser $userfqdn must have servicequeryconfig,servicequeryservice,readallprop,readsecurity,serviceinterrogate access to service $($service.name)"
    }
}

##############################
# Message Center
##############################

$message = "Zenoss Resource Manager security permissions have been tested for $userfqdn"
write-output $message
send_event $message 'Information'
