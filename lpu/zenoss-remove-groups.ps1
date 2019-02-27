#
# Copyright 2019 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script removes users from WMI local groups in which users have been added by the
# "zenoss-lpu.ps1" script

<#
    .SYNOPSIS
    Remove users from WMI local groups
    .DESCRIPTION
    This script removes users from WMI local groups in which users have been added by the "zenoss-lpu.ps1" script
    .INPUT
    -u or -user to specify the user name.  Enter just the user name for a local user and user@domain.com for a domain user.
    .EXAMPLE
    Domain account
    zenoss-remove-groups.ps1 -u zenny@zenoss.com
    .EXAMPLE
    Local account
    zenoss-remove-groups.ps1 -u benny
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
	$login
	)

########################################
#  ------------------------------------
#  ----------- Initialization  --------
#  ------------------------------------
########################################

# The following values will be set at runtime. They are place holders here.
$usersid

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

########################################
#  ------------------------------------
#  -----------  Functions -------------
#  ------------------------------------
########################################

function remove_user_from_group($groupname) {
    try
    {
        $objADSI = [ADSI]"WinNT://./$groupname,group"
        $objADSIUser = [ADSI]"WinNT://$domain/$username"
        [array]$objMembers = $objADSI.psbase.Invoke("Members")
        $objADSI.psbase.Invoke("Remove",$objADSIUser.psbase.path)
        $message = "User removed from group: $groupname"
        write-host $message
    }
    catch
    {
        $message = "[$groupname] $($_.Exception.InnerException.Message)"
        write-host $message
        continue
    }
}

$localgroups = @(
	"S-1-5-32-558",
	"S-1-5-32-559",
	"S-1-5-32-573",
	"S-1-5-32-562",
	"WinRMRemoteWMIUsers__"
	)

  foreach ($localgroup in $localgroups) {
      if ($localgroup.StartsWith('S-1-5-32-')) {
          $GrObj = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $localgroup;
          $localgroup = $GrObj.Translate([System.Security.Principal.NTAccount]).Value.split('\')[1]
      }
  	remove_user_from_group $localgroup
  }
