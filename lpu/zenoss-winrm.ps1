#
# Copyright 2015 Zenoss Inc., All rights reserved
#
# DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
#
# This script modifies the winrm configuration, the firewall, and the registry. Use with caution!
#
# To make sure you understand this you'll need to uncomment out the section at the bottom of the script before you can use it.

function Add-FirewallRule {
   param( 
      $name,
      $tcpPorts,
      $appName = $null,
      $serviceName = $null
   )
    $fw = New-Object -ComObject hnetcfg.fwpolicy2 
    $rule = New-Object -ComObject HNetCfg.FWRule
        
    $rule.Name = $name
    if ($appName -ne $null) { $rule.ApplicationName = $appName }
    if ($serviceName -ne $null) { $rule.serviceName = $serviceName }
    $rule.Protocol = 6 #NET_FW_IP_PROTOCOL_TCP
    $rule.LocalPorts = $tcpPorts
    $rule.Enabled = $true
    $rule.Grouping = "@firewallapi.dll,-23255"
    $rule.Profiles = 7 # all
    $rule.Action = 1 # NET_FW_ACTION_ALLOW
    $rule.EdgeTraversal = $false
    
    $fw.Rules.Add($rule)
}

function Enable-FirewallRule {
    param($name)
    $rules=(New-object –comObject HNetCfg.FwPolicy2).rules
    
    if ($name) {
        $rules = $rules | where-object {$_.name -like $name}
        foreach ($rule in $rules) {
            $rule.Enabled = "True"
        }
    }
}

#<# Remove this and the final line of the script to enable execution

# Check to see if we're on domain or local
$onDomain = $False
if ((gwmi win32_computersystem).partofdomain -eq $True) {
    write-host "Server is part of a domain"
    $onDomain = $True
}
else {
    write-host "Server is not on a domain.  Enabling local account policy in registry."
    # Make sure LocalAccountTokenFilterPolicy is set for local server.  Not needed on domain system.
    $rg = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -name LocalAccountTokenFilterPolicy -erroraction silentlycontinue
    if ($rg -eq $null -or $rg.LocalAccountTokenFilterPolicy -eq 0) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -name LocalAccountTokenFilterPolicy -Value 1
    }
}

# Run quickconfig.  This will return $False if there's a problem with winrm and we won't continue
winrm qc -q
if ($? -ne $True) {
    exit
}

# Check for windows 2003
$win2003 = $false
if ([System.Environment]::OSVersion.Version.Major -eq 5) {
    $win2003 = $true
    winrm create winrm/config/listener?Address=*+Transport=HTTP
}

# Most of these settings will be there by default, but we will make sure
write-host "Configuring WinRM for Zenoss access"
if ($win2003 -eq $false) {
    winrm s winrm/config/service '@{IPv4Filter="*";IPv6Filter="*";AllowRemoteAccess="true"}'
}
else {
    winrm s winrm/config/service '@{IPv4Filter="*";IPv6Filter="*"}'
}

# If non-domain system then we need to allow unencrypted communication and basic authentication
if ($onDomain -eq $False) {
    winrm s winrm/config/service '@{AllowUnencrypted="true"}'
    winrm s winrm/config/service/Auth '@{Basic="true"}'
}
else {
    winrm s winrm/config/service/Auth '@{Kerberos="true"}'
}

# Make Winrs changes
winrm s winrm/config/Winrs '@{AllowRemoteShellAccess="true";MaxProcessesPerShell="2000000000";MaxShellsPerUser="2000000000"}'

# Display the configuration
winrm g winrm/config

# Make firewall rules for http, ping
write-host "Adding and enabling firewall rules for HTTP port 5985 and ping"
if ($win2003 -eq $false) {
    Add-FirewallRule "HTTP" "5985"
    Enable-FirewallRule "File and Printer Sharing (Echo Request - ICMPv4-In)"
    Enable-FirewallRule "File and Printer Sharing (Echo Request - ICMPv6-In)"
}
else {
    netsh firewall add portopening TCP 5985 "HTTP"
    netsh firewall set service type = fileandprint mode = enable
}
#Remove this line to execute. #>