# BACKUP YOUR SETTINGS BEFORE EXECUTING!
#
# Copyright 2016 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script modifies the registry and several system access permissions. Use with caution!
#    BACKUP YOUR SETTINGS BEFORE EXECUTING!
#
# To make sure you understand this you'll need to uncomment out the section at the bottom of the script before you can use it.
# Each section in the Execution Center at the bottom describes what permissions need to be set
#
# Information:
# This script is not intended for Clusters.  Monitoring a cluster requires local administrator access
#
# Windows Server 2003 is not supported using this script.  You can manually apply the appropriate permissions
# using this script as a guide.
#
# Some service permissions cannot be changed with this script.  The administrator does not have write object access
# to system owned services such as EFS(Encrypted File Service) or gpsvc(Group Policy Client).
#
# This script has been tested on simple Domain Controllers successfully.  The user must be
# manually added to the necessary domain security groups.  The user account will need to
# be logged off to pick up the new settings or have the kerberos ticket granting ticket destroyed.
#
#########################################################################################
#                                                                                       #
#  WARNINGS:                                                                            #
#  DO NOT DELETE USER WITHOUT BACKING OUT CHANGES MADE BY LPU SCRIPT!                   #
#      Run zenoss-audit-lpu.ps1 to see which changes will be made and make a backup     #
#      of your settings.                                                                #
#                                                                                       #
#########################################################################################

<#
	.SYNOPSIS
	Configure local system permissions to support least privilege user access for Zenoss Resource Manager monitoring.
	.DESCRIPTION
	This script configures system permissions to allow a least privileged user access to WMI namespaces, service querying,
    WinRM/WinRS access, registry keys, local groups, and specific folder/file permissions.
    .INPUT
    -u or -user to specify the user name.  Enter just the user name for a local user and user@domain.com for a domain user.
    -f or -force to force an update to the service properties for the user.
    .EXAMPLE
	Domain account
	zenoss-lpu.ps1 -u zenny@zenoss.com
	.EXAMPLE
	Local account
	zenoss-lpu.ps1 -u benny 
    .EXAMPLE
    Update service permissions for domain account
    zenoss-lpu.ps1 -u zenny@zenoss.com -force
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
		$message = "User does not exists: $getuser"
		write-host $message
		send_event $message 'Error'
		continue
	}
}

function add_user_to_group($groupname) {
    try
    {
        $objADSI = [ADSI]"WinNT://./$groupname,group"
        $objADSIUser = [ADSI]"WinNT://$domain/$username"
        [array]$objMembers = $objADSI.psbase.Invoke("Members")
        $objADSI.psbase.Invoke("Add",$objADSIUser.psbase.path)
        $message = "User added to group: $groupname"
        send_event $message 'Information'
    }
    catch
    {
        $message = "[$groupname] $($_.Exception.InnerException.Message)"
        write-host $message send_event $error[0] 'Error'
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
		send_event $message 'Information'
	}
	else{
		$message = "Service $service already contains permission for user $userfqdn"
		write-output $message
		send_event $message 'Information'
	}
}

function update_folderfile($folderfile, $accessMask){
	if(Test-Path $folderfile){
		$folderfileacl = (get-item $folderfile).getaccesscontrol("Access")
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($userfqdn, $accessMask, "ContainerInherit, ObjectInherit", "None", "Allow")
		$folderfileacl.AddAccessRule($rule)
		set-acl -path $folderfile -aclobject $folderfileacl
	}

	$message = "Folder / File updated: $folderfile"
	send_event $message 'Information'
	trap{
		$message = "Folder / File path does not exists: $folderfile"
		write-host $message
		send_event $message 'Error'
		continue
	}
}

function get_db_instances(){
	#32/64 bit 2008
	$regkey2008 = 'HKLM:\Software\Wow6432Node\Microsoft\Microsoft SQL Server\'
	# 2003
	$regkey2003 = 'HKLM:\Software\Microsoft\Microsoft SQL Server\'
	if(Test-Path $regkey2008){
		$objsqlreg = Get-ItemProperty $regkey2008
		return $objsqlreg.InstalledInstances 
	}

	if(Test-Path $regkey2003){
		$objsqlreg = Get-ItemProperty $regkey2003
		return $objsqlreg.InstalledInstances
	}
}

function update_sql_perms($dbinstance, $permission){

	$useraccount = "{0}\{1}" -f $domain, $username
	write-host "Setting permissions on DB Instance: $dbinstance"

	if($dbinstnace -eq "MSSQLSERVER"){
		$dbinstancename = $domain		
	}
	else{
		$dbinstancename = '{0}\{1}' -f $domain, $dbinstance
	}

	$connection = New-Object("Microsoft.SqlServer.Management.Common.ServerConnection") $dbinstancename
	$connection.LoginSecure = $True
	$connection.connect()


	$server = New-Object ("Microsoft.SqlServer.Management.Smo.Server") $connection
	$perm = New-Object ("Microsoft.SqlServer.Management.Smo.ObjectPermissionSet")

	$perm.$($permission.ToString()) = $True
	$server.Grant($perm, $username)

}

function set_registry_security($regkey, $userfqdn, $accessmap){
	#accessmap = "ReadPermissions, ReadKey, EnumerateSubKeys, QueryValues"
	if(Test-Path $regkey){
		$regacl = (get-item $regkey).getaccesscontrol("Access")
		$rule = New-Object System.Security.AccessControl.RegistryAccessRule($userfqdn,$accessmap,"ContainerInherit", "InheritOnly", "Allow")
		$regacl.SetAccessRule($rule)
		$regacl | set-acl -path $regkey
		$message = "Registry key updated: $regkey"
	}

	trap{

		$message ="Registry key does not exists: $regkey"
		write-host $message
		send_event $message 'Error'
		continue
	}
}

function load_sql_assembly(){
	add-type -AssemblyName 'Microsoft.SqlServer.ConnectionInfo'
	add-type -AssemblyName 'Microsoft.SqlServer.Smo'
}


function set_registry_sd_value($regkey, $property, $usersid, $accessMask){
	$objRegProperty = Get-ItemProperty $regkey -Name $property -ErrorAction silentlycontinue
    if ($objRegProperty -ne $null) {
        $sddlstart = [string]($objSDHelper.BinarySDToSDDL($objRegProperty.$property)).SDDL
        if($sddlstart.contains($usersid) -eq $False){
            $newsddl = update_sddl $sddlstart $usersid $accessMask
            $binarySDDL = $objSDHelper.SDDLToBinarySD($newsddl)
            Set-ItemProperty $regkey -Name $property -Value $binarySDDL.BinarySD
            $message = "Registry security updated: $regkey"
            send_event $message "Information"
        }
        else{
            $message = "Value already contains permission for user $userfqdn"
            write-output $message
            send_event $message 'Information'
        }
    }
    else {
        $message = "Property $property does not exist in registry key $regkey.  Nothing to update."
        write-host $message
    }

	trap{
		$message = "Registry Security Descriptor failed for $regkey"
		write-host $message
		send_event $message 'Error'
        continue
    }
}


function allow_access_to_winrm($usersid) {
	
	$defaultkey = "O:NSG:BAD:P(A;;GA;;;BA)S:P(AU;FA;GA;;;WD)(AU;SA;GWGX;;;WD)"
	$sddlkey = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
	if($usersid.Length -gt 5){
		if ((get-itemproperty $sddlkey).rootSDDL -eq $null) {
			$sddlstart = $defaultkey
			send_event "Registry RootSDDL doesn't exists. Will use default settings." "Information"
			}
		else{
			$rootsddlkey = get-itemproperty $sddlkey -Name "rootSDDL"
			$sddlstart = $rootsddlkey.rootSDDL
			send_event "Current RootSDDL $sddlstart" "Information"
			}
	}
	else
	{
		send_event "Problem getting sddl key from registry" "Error"
		exit
	}

	if ($sddlstart.Length -eq 0){
		$sddlstart = $defaultkey
		send_event "Using default RootSDDL of $sddlstart" "Information"
	}

	if ($sddlstart.contains($usersid) -eq $False){
		$permissions = @("genericexecute","genericread")
		$accessMask = get_accessmask $permissions
		$newsddl = [string](update_sddl $sddlstart $usersid $accessMask)
		set-itemproperty $sddlkey -name "rootSDDL" -Value $newsddl
		send_event "RootSDDL has updated" "Information"
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

function add_ace_to_namespace($accessMask, $namespaceParams){
	$currentSecurityDescriptor = Invoke-WmiMethod @namespaceParams -Name GetSecurityDescriptor -ErrorAction 'silentlycontinue'
    if ($? -eq $false){
        Write-Host "GetSecurityDescriptor is not valid for this operating system.  Add user to namespaces manually."
        Return $false
    }
	if($currentSecurityDescriptor.ReturnValue -ne 0){
        throw "Failed to get security descriptor for namespace: $namespace"
    }
	$objACL = $currentSecurityDescriptor.Descriptor
    # check if user has permissions already
    foreach ($acl in $objACL.DACL) {
        if ($acl.Trustee.SIDString -eq $usersid) {
            return $true
        }
    }

	$objACE = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
	$objACE.AccessMask = $accessMask
	if ($inherit){
		$objACE.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
	}
	else {
	    $objACE.AceFlags = 0
	}
	$objTrust = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
	$objTrust.SidString = $usersid
	$objACE.Trustee = $objTrust
	$objACE.AceType = 0x0
	$objACL.DACL += $objACE.psobject.immediateBaseObject
	$daclparams = @{
		Name="SetSecurityDescriptor";
		ArgumentList=$objACL.psobject.immediateBaseObject
	} + $namespaceParams
	$setresults = Invoke-WmiMethod @daclparams
	if ($setresults.ReturnValue -ne 0) {
		throw "Set Security Descriptor FAILED: $($setresults.ReturnValue)"
		}
    return $true
}

function send_event($message, $errortype){
	Write-EventLog -LogName Application -Source "Zenoss-LPU" -EntryType $errortype -EventId 1 -Message $message
}

########################################
#  ------------------------------------
#  -------- Execution Center ----------
#  BACKUP YOUR SETTINGS BEFORE EXECUTING!
#  ------------------------------------
########################################

<# By removing this line and the last line of the file you understand the risks associated with script execution.
# Initialize user information
$usersid = get_user_sid

###########################################################################################
# Configure Namespace Security
# The least privileged user requires "Enable","MethodExecute","ReadSecurity","RemoteAccess"
# permissions to the WMI namespaces listed below
###########################################################################################
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
$ns = Get-WMIObject -class __Namespace -namespace root -Filter "name='WebAdministration'"
if ($ns -ne $null){
    $namespaces += "Root/Webadministration"
}
$ns = Get-WMIObject -class __Namespace -namespace root -Filter "name='microsoftiisv2'"
if ($ns -ne $null){
    $namespaces += "Root/microsoftiisv2"
}

$namespaceaccessmap = get_accessmask @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
foreach ($namespace in $namespaces) {
	$namespaceParams = @{Namespace=$namespace;Path="__systemsecurity=@"}
	$ret = add_ace_to_namespace $namespaceaccessmap $namespaceParams
    if ($ret -eq $false){
        break
    }
}

###################################################
# Configure RootSDDL for remote WinRM/WinRS access
# The least privileged user needs winrm access
###################################################
allow_access_to_winrm $usersid

##########################################################################################
# Set Registry permissions
# The least privileged user needs ReadPermissions, ReadKey, EnumerateSubKeys, QueryValues
# permissions to the registry keys listed below
##########################################################################################
$registrykeys = @(
	"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib",
	"HKLM:\system\currentcontrolset\control\securepipeservers\winreg",
    "HKLM:\System\CurrentControlSet\Services\eventlog\Security",
	"HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}",
	"HKLM:\SYSTEM\CurrentControlSet\Services\Blfp\Parameters\Adapters",
	"HKLM:\Software\Wow6432Node\Microsoft\Microsoft SQL Server",
	"HKLM:\Software\Microsoft\Microsoft SQL Server"
	)

# NOTE: Registry keys security values are handled differently with set-acl
# We do not have to convert
$registrykeyaccessmap = "ReadPermissions, ReadKey, EnumerateSubKeys, QueryValues"
foreach ($registrykey in $registrykeys) {
	set_registry_security $registrykey $userfqdn $registrykeyaccessmap
}

########################################################################
# Update local group permissions
# The least privileged user needs to be members of the following groups
# For a domain controller, manually add the user to the domain groups
#    "Performance Monitor Users",
#    "Performance Log Users",
#    "Event Log Readers",
#    "Distributed COM Users",
#    "WinRMRemoteWMIUsers__",
#    "Remote Management Users"
########################################################################
$localgroups = @(
	"S-1-5-32-558",
	"S-1-5-32-559",
	"S-1-5-32-573",
	"S-1-5-32-562",
	"WinRMRemoteWMIUsers__",
	"Remote Management Users"
	)

foreach ($localgroup in $localgroups) {
    if ($localgroup.StartsWith('S-1-5-32-')) {
        $GrObj = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $localgroup;
        $localgroup = $GrObj.Translate([System.Security.Principal.NTAccount]).Value.split('\')[1]
    }
	add_user_to_group $localgroup
}

#############################################################################
# Modify Folder/File permissions
# The least privileged user needs readfolder access to the following folders
#############################################################################

$folderfiles = @(
	"C:\Windows\system32\inetsrv\config"
	)

$folderfileaccessmap = get_accessmask @(
	"readfolder"
	)

foreach($folderfile in $folderfiles){
	update_folderfile $folderfile $folderfileaccessmap
}


###############################################################################################################################
# Update Services Permissions
# The least privileged user needs "servicequeryconfig","servicequeryservice","readallprop","readsecurity","serviceinterrogate"
# permissions added to all services
###############################################################################################################################

$services = get-wmiobject -query "Select * from Win32_Service"
$serviceaccessmap = get_accessmask @("servicequeryconfig","servicequeryservice","readallprop","readsecurity","serviceinterrogate")
add_user_to_service 'SCMANAGER' $serviceaccessmap
foreach ($service in $services){
	add_user_to_service $service.name $serviceaccessmap
}

#############################################################################
# Restart winrm/winmgmt services
# Permissions are not usually picked up until a restart is performed
#############################################################################

write-host 'Restarting winmgmt and winrm services...'
get-service winmgmt | restart-service -force
get-service winrm | restart-service -force

##############################
# Message Center
##############################

$message = "Zenoss Resource Manager security permissions have been set for $userfqdn"
write-output $message
send_event $message 'Information'
By removing this line and the line before Execution Center you understand the risks associated with script execution. #>
