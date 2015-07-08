#
# Copyright 2014 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script modifies several system service access permissions. Use with caution!
#
# This script is not intended for Clusters.  Monitoring a cluster requires local administrator access
#
# This script must be run as the system account.  There are a handful of services that are owned
# by the system account and permissions cannot be altered by the Administrator.  We default to these
# services:  'DPS','EFS','gpsvc','idsvc','WdiServiceHost','WdiSystemHost'.  If you discover more
# services whose permissions cannot be changed, add them to the @services array in the 
# Execution Center at the end of this script.
#
# To run this as the system account, use the psexec.exe program to start a cmd shell, e.g. > psexec.exe -s cmd
# PSExec can be found as part of Windows Sysinternals here: https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx
#
#########################################################################################
#                                                                                       #
#  WARNINGS:                                                                            #
#  DO NOT DELETE USER WITHOUT BACKING OUT CHANGES MADE BY LPU SCRIPT!                   #
#  DO NOT RUN THIS SCRIPT ON A WINDOWS SERVER WITH A HYPER-V ROLE.  IT WILL RENDER THE  #
#       SERVER INACCESSIBLE                                                             #
#                                                                                       #
#########################################################################################

<#
	.SYNOPSIS
	Configure local service permissions to support least privilege user access for Zenoss Resource Manager monitoring.
	.DESCRIPTION
	This script configures system permissions to allow a least privileged user access to services that are
    owned by the local SYSTEM account.  It must be run as the system user.  Use psexec.exe to start a cmd shell as the
    SYSTEM account, then execute the files through powershell.
    .INPUT
    -u or -user to specify the user name.  Enter just the user name for a local user and user@domain.com for a domain user.
    -f or -force to force an update to the service properties for the user.
    .EXAMPLE
	Domain account
	powershell -file "zenoss-lpu.ps1 -u zenny@zenoss.com"
	.EXAMPLE
	Local account
	powershell -file "zenoss-lpu.ps1 -u benny"
    .EXAMPLE
    Update service permissions for domain account
    powershell -file "zenoss-lpu.ps1 -u zenny@zenoss.com -force"
#>

########################################
#  ------------------------------------
#  ----------- Arguments  -------------
#  ------------------------------------
########################################

param(
	[Parameter(HelpMessage="User account to provide Zenoss permissions")]
	[Alias('user', 'u')]
	[string]
	$login = 'benny',
	[Alias('force','f')]
	[switch]
	$force_update = $false
	)

########################################
#  ------------------------------------
#  ----------- Initialization  --------
#  ------------------------------------
########################################


#$login = 'zenny@zenoss.com'					# Domain Account
#$login = 'benny'                               # Local Account


if($login.contains("@")){
	$arrlogin = $login.split("@")
	$arrdomain = $arrlogin[1].split(".")
    $domain = $arrdomain[0]
	$username = $arrlogin[0]
	$userfqdn = $login
}
else{
	$domain = $env:COMPUTERNAME
	$username = $login
	$userfqdn = "{1}\{0}" -f $username, $domain
}

# Prep event Log
if (![System.Diagnostics.EventLog]::SourceExists('Zenoss-LPU')){
	New-EventLog -LogName Application -Source "Zenoss-LPU"
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
		$message = "User does not exist: $getuser"
		write-host $message
		send_event $message 'Error'
		continue
	}
}

function add_user_to_service($service, $accessMask){
	$servicesddlstart = [string](CMD /C "sc sdshow `"$service`"")
	if(($servicesddlstart.contains($usersid) -eq $False) -or ($force_update -eq $true)){
		$servicesddlnew = update_sddl $servicesddlstart $usersid $accessMask
		$ret = CMD /C "sc sdset $service $servicesddlnew"
        if ($ret[0] -match '.FAILED.') {
            $reason = $ret[2]
            $message = "User: $userfqdn was not added to service $service.`n`tReason:  $reason"
        } else {
            $message = "User: $userfqdn added to service $service."
        }
		send_event $message
	}
	else{
		$message = "Service $service already contains permission for user $userfqdn"
		#write-output $message
		send_event $message
	}
}

function update_sddl($sddlstart, $usersid, $accessMask){
	$securitydescriptor = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList @($false, $false, $sddlstart);
 	$securitydescriptor.DiscretionaryAcl.AddAccess("Allow", $usersid, $accessMask,"None","None")
	return $securitydescriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}

function get_accessmask($permissions){
	<#
	$permissions = @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
	#>

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
        "dcomremoteaccess"      = 0x00000005;
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

	$accessMask = 0
	foreach ($perm in $permissions) {
		$perm = $perm.ToLower()
		if($permTable.ContainsKey($perm)){
			$accessMask += $permTable[$perm]
		}
		else {
		    throw "Unknown permission: $perm"
		}
	}
	return $accessMask
}

function send_event($message, $errortype){
	Write-EventLog -LogName Application -Source "Zenoss-LPU" -EntryType $errortype -EventId 1 -Message $message
}

########################################
#  ------------------------------------
#  -------- Execution Center ----------
#  ------------------------------------
########################################

<# Remove this line along with the last line of this file.

###############################################################################################################################
# Update Services Permissions
# The least privileged user needs "servicequeryconfig","servicequeryservice","readallprop","readsecurity","serviceinterrogate"
# permissions added to all services
###############################################################################################################################
$usersid = get_user_sid

$services = @('DPS','EFS','gpsvc','idsvc','WdiServiceHost','WdiSystemHost')
$serviceaccessmap = get_accessmask @("servicequeryconfig","servicequeryservice","readallprop","readsecurity","serviceinterrogate")
Write-Host 'accessmask='$serviceaccessmap
foreach ($service in $services){
	add_user_to_service $service $serviceaccessmap
}

Remove this line and the line just after the Execution Center section title to enable script. #> 