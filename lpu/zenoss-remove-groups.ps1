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
#  -----------  Functions -------------
#  ------------------------------------
########################################

function remove_user_from_group($groupname) {
    try
    {
        Invoke-Command -ComputerName $env:COMPUTERNAME -Command {
            net localgroup $args[0] $args[1] /delete
        } -ArgumentList $groupname, $login -ErrorVariable error -ErrorAction SilentlyContinue

        if($error){
            # $error = $error[1].ToString().Trim()
            Write-Host "[$groupname] User not removed from local group. `n`tReason: $error"
        } else {
            Write-Host "[$groupname] User removed from group"
        }
    }
    catch
    {
        $message = "[$groupname] $($_.Exception.InnerException.Message)"
        write-host $message send_event $error[0] 'Error'
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
