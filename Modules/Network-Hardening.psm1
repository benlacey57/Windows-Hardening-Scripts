<#
.SYNOPSIS
    Network Hardening module
.DESCRIPTION
    Contains functions for network-specific security hardening
#>

function Protect-NetworkProtocols {
    <#
    .SYNOPSIS
        Secures network protocols (SMB, LLMNR, NetBIOS)
    .PARAMETER DisableIPv6
        Whether to disable IPv6
    #>
    param(
        [bool]$DisableIPv6 = $false
    )
    
    Write-Banner "Network Protocol Security"
    
    # Disable SMBv1
    Set-AndLogSetting -Description "Disabling SMBv1 Protocol on Server" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
    Invoke-AndLogCommand -Description "Disabling SMBv1 Server Configuration" -Command { 
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
    }
    Set-AndLogWindowsFeature -FeatureName "SMB1Protocol" -Enable $false
    
    # Disable LLMNR
    Set-AndLogSetting -Description "Disabling LLMNR" -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -SkipReadBefore
    
    # Disable NetBIOS
    Invoke-AndLogCommand -Description "Disabling NetBIOS over TCP/IP" -Command {
        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration
        foreach ($adapter in $adapters) {
            if ($adapter.TcpipNetbiosOptions -ne 2) {
                $adapter.SetTcpipNetbios(2)
            }
        }
        return "NetBIOS disabled on all adapters"
    }
    
    # Disable IPv6 if configured
    if ($DisableIPv6) {
        Set-AndLogSetting -Description "Disabling IPv6" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF
    }
}

function Configure-Firewall {
    <#
    .SYNOPSIS
        Configures Windows Firewall with enhanced security
    #>
    Write-Banner "Firewall Configuration"
    
    # Enable Firewall on all profiles
    Invoke-AndLogCommand -Description "Enabling Windows Firewall on all profiles" -Command { 
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True 
    }
    
    # Block all inbound connections by default
    Invoke-AndLogCommand -Description "Setting default inbound action to block" -Command { 
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block 
    }
    
    # Configure logging
    Invoke-AndLogCommand -Description "Configuring firewall logging" -Command {
        $logPath = "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName $logPath -LogMaxSizeKilobytes 32767 -LogAllowed True -LogBlocked True
        return "Firewall logging configured"
    }
}

function Configure-AdvancedNetworkSecurity {
    <#
    .SYNOPSIS
        Applies advanced network security settings
    #>
    Write-Banner "Advanced Network Security"
    
    # Disable weak TLS/SSL ciphers
    Invoke-AndLogCommand -Description "Disabling weak ciphers" -Command {
        # Disable RC4
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0
        
        # Disable DES
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0
        
        # Disable Triple DES
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0
        
        return "Weak ciphers disabled"
    }
    
    # Enable strong ciphers
    Invoke-AndLogCommand -Description "Enabling strong ciphers" -Command {
        # Enable AES 128
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0xffffffff
        
        # Enable AES 256
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0xffffffff
        
        return "Strong ciphers enabled"
    }
    
    # Disable NetBIOS and LLMNR (more thorough approach)
    Invoke-AndLogCommand -Description "Disabling NetBIOS via Group Policy" -Command {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "EnableMulticast" -Value 0
        return "NetBIOS and LLMNR disabled via Group Policy"
    }
}

# Export the functions
Export-ModuleMember -Function Protect-NetworkProtocols, Configure-Firewall, Configure-AdvancedNetworkSecurity