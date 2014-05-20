#
# Copyright 2014 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script modifies the registry and several system access permissions. Use with caution!
#
# To make sure you understand this you'll need to uncomment out the section at the bottom of the script before you can use it.




<#
	.SYNOPSIS
	Configure local system permissions to support least privilege user access for Zenoss Resource Manager monitoring.
	.DESCRIPTION
	Need to add some more info here 
	.EXAMPLE
	Domain account
	zenoss-lpu.ps1 -u zenny@zenoss.com
	.EXAMPLE
	Local account
	zenoss-lpu.ps1 -u benny 

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
	$login = 'benny'
	)

########################################
#  ------------------------------------
#  ----------- Initialization  --------
#  ------------------------------------
########################################


#$username = 'zenny'					# Username alone
#$domaintype = 'domain'		# local or domain

#$username = 'benny'
#$domaintype = 'local'

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
New-EventLog -LogName Application -Source "Zenoss-LPU"

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
	$objADSI = [ADSI]"WinNT://localhost/$groupname,group"
	$objADSIUser = [ADSI]"WinNT://$domain/$username"
	$objMembers = @($objADSI.psbase.Invoke("Members"))
	if($objMembers.Count -gt 0){
		foreach ($objMember in $objMembers){
			$membername = $objMember.GetType().InvokeMember("Name", 'GetProperty', $null, $objMember, $null)
			if ($membername -ne $username){
				$objADSI.psbase.Invoke("Add",$objADSIUser.psbase.path)
			}
		}
	}
	else {
		$objADSI.psbase.Invoke("Add",$objADSIUser.psbase.path)
	}
	$message = "User added to group: $groupname"
	send_event $message 'Information'

	trap{
	 	$message = "Group does not exists: $groupname"
	 	write-host $message
	 	send_event $error[0] 'Error'
	 	continue
 	}
}

function add_user_to_service($service, $accessMask){
	$servicesddlstart = [string](CMD /C "sc sdshow $service")
	if($servicesddlstart.contains($usersid) -eq $False){
		$servicesddlnew = update_sddl $servicesddlstart $usersid $accessMask
		$ret = CMD /C "sc sdset $service $servicesddlnew"
		$message = "User: $userfqdn added to service"
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
	$objRegProperty = Get-ItemProperty $regkey -Name $property
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

	trap{
		$message = "Registry Security Descriptor failed for $regkey"
		write-host $message
		send_event $message 'Error'
	}
}

function allow_access_to_winrm($usersid) {
	if($usersid.Length -gt 5) {
		$sddlstart = [string](Get-Item WSMan:\localhost\Service\RootSDDL).Value
	} 
	else {
		throw "Error getting WinRM SDDL"
		break
	}
	if ($sddlstart.contains($usersid) -eq $False){
		$permissions = @("genericexecute","genericread")
		$accessMask = get_accessmask $permissions
		$newsddl = [string](update_sddl $sddlstart $usersid $accessMask)
		Set-Item WSMan:\localhost\Service\RootSDDL -value $newsddl -Force
		$message = "WinRM Perms setup correctly"
		send_event $message "Information"
	}
	else {
		$message ="User already has permissions set"
		write-output $message
		send_event $message 'Information'
	}

	trap{
		$message = "Problem setting RootSDDL permissions"
		write-output $message
		send_event $message 'Error'
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
		"servicestop"			= 0x0020
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
	$currentSecurityDescriptor = Invoke-WmiMethod @namespaceParams -Name GetSecurityDescriptor
	if($currentSecurityDescriptor.ReturnValue -ne 0){
		throw "Failed to get security descriptor for namespace: $namespace"
	}
	$objACL = $currentSecurityDescriptor.Descriptor

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
# Initialize user information
$usersid = get_user_sid

##############################
# Configure Namespace Security
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
$namespaceaccessmap = get_accessmask @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
foreach ($namespace in $namespaces) {
	$namespaceParams = @{Namespace=$namespace;Path="__systemsecurity=@"}
	add_ace_to_namespace $namespaceaccessmap $namespaceParams
}

##############################
# Configure RootSDDL for remote WinRM/WinRS access
##############################
allow_access_to_winrm $usersid

##############################
# Set Registry permissions
##############################
$registrykeys = @(
	"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib",
	"HKLM:\system\currentcontrolset\control\securepipeservers\winreg",
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

##############################
# Set Registry Security Descriptor Values
##############################
$registryvaluekeys = @{
	"MachineAccessRestriction" = "HKLM:\software\microsoft\ole";
	"MachineLaunchRestriction" = "HKLM:\software\microsoft\ole"
}

$registrykeyvalueaccessmap = get_accessmask @("listcontents", "readallprop")
foreach ($registryvaluekey in $registryvaluekeys.GetEnumerator()){
	set_registry_sd_value $registryvaluekey.Value $registryvaluekey.Name $usersid $registrykeyvalueaccessmap
}

##############################
# Update local group permissions
##############################
$localgroups = @(
	"Performance Monitor Users",
	"Performance Log Users", 
	"Event Log Readers", 
	"Distributed COM Users", 
	"WinRMRemoteWMIUsers__"
	)

foreach ($localgroup in $localgroups) {
	add_user_to_group $localgroup
}

##############################
# Modify Folder/File permissions
##############################

$folderfiles = @(
	"C:\Windows\system32\inetsrv\config"
	)

$folderfileaccessmap = get_accessmask @(
	"readfolder"
	)

foreach($folderfile in $folderfiles){
	update_folderfile $folderfile $folderfileaccessmap
}


##############################
# Update Services Permissions
##############################

$services = get-wmiobject -query "Select * from Win32_Service"
$serviceaccessmap = get_accessmask @("servicequeryconfig","servicequeryservice","readallprop","readsecurity")
add_user_to_service 'SCMANAGER' $serviceaccessmap
foreach ($service in $services){
	add_user_to_service $service.name $serviceaccessmap
}

##############################
# Message Center
##############################

$message = "Zenoss Resource Manager security permissions have been set for $userfqdn"
write-output $message
send_event $message 'Information'
Remove this line and the line just after the Execution Center section title to enable script. #> 