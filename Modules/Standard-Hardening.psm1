<#
.SYNOPSIS
    Standard Windows Hardening module
.DESCRIPTION
    Contains functions for standard Windows security hardening
#>

function Enable-SecurityFeatures {
    <#
    .SYNOPSIS
        Enables and configures security features and protections
    #>
    Write-Banner "Security Features and Protections"
    
    # Enable Windows SmartScreen
    Set-AndLogSetting -Description "Enabling Windows SmartScreen" -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin"
    
    # Enable Windows Defender Exploit Protection
    Invoke-AndLogCommand -Description "Enabling Exploit Protection" -Command { 
        Set-ProcessMitigation -System -Enable DEP,SEHOP,CFG 
    }
    
    # Configure audit policies
    Invoke-AndLogCommand -Description "Configuring audit policies" -Command {
        Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
        Auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
        Auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
        Auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable
        Auditpol /set /subcategory:"System Events" /success:enable /failure:enable
        return "Audit policies configured"
    }
    
    # Restrict Anonymous Access
    Set-AndLogSetting -Description "Restricting Anonymous Access" -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
    
    # Configure Windows Update settings
    Set-AndLogService -ServiceName "wuauserv" -TargetStatus "Running" -TargetStartupType "Automatic"
}

function Enable-BitLockerEncryption {
    <#
    .SYNOPSIS
        Enables BitLocker encryption if available
    #>
    Write-Banner "BitLocker Encryption"
    
    Invoke-AndLogCommand -Description "Checking BitLocker status and enabling if needed" -Command {
        $bitlockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($bitlockerVolume -and $bitlockerVolume.ProtectionStatus -eq "On") {
            return "BitLocker is already enabled on C:"
        }
        else {
            try {
                Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnlyEncryption -RecoveryPasswordProtector
                return "BitLocker enabled successfully"
            }
            catch {
                return "Failed to enable BitLocker: $($_.Exception.Message)"
            }
        }
    }
}

function Disable-UnnecessaryServices {
    <#
    .SYNOPSIS
        Disables unnecessary services
    .PARAMETER Services
        Array of services to disable
    #>
    param(
        [string[]]$Services
    )
    
    Write-Banner "Service Hardening"
    
    foreach ($service in $Services) {
        Set-AndLogService -ServiceName $service -TargetStatus "Stopped" -TargetStartupType "Disabled"
    }
}

function Configure-TLSSettings {
    <#
    .SYNOPSIS
        Configures secure TLS/SSL settings
    #>
    Write-Banner "TLS/SSL Security Configuration"
    
    # Disable TLS 1.0
    Set-AndLogSetting -Description "Disabling TLS 1.0 for Client" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling TLS 1.0 for Server" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -SkipReadBefore
    
    # Disable TLS 1.1
    Set-AndLogSetting -Description "Disabling TLS 1.1 for Client" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling TLS 1.1 for Server" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -SkipReadBefore
    
    # Enable TLS 1.2
    Set-AndLogSetting -Description "Enabling TLS 1.2 for Client" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1 -SkipReadBefore
    Set-AndLogSetting -Description "Enabling TLS 1.2 for Server" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -SkipReadBefore
    
    # Enable TLS 1.3 if available
    Set-AndLogSetting -Description "Enabling TLS 1.3 for Client" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "Enabled" -Value 1 -SkipReadBefore
    Set-AndLogSetting -Description "Enabling TLS 1.3 for Server" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Value 1 -SkipReadBefore
}

function Invoke-StandardHardening {
    <#
    .SYNOPSIS
        Performs standard security hardening
    .PARAMETER Config
        Configuration settings
    #>
    param(
        [hashtable]$Config
    )
    
    # Include basic hardening
    Invoke-BasicHardening -Config $Config
    
    # Enable additional security features
    Enable-SecurityFeatures
    
    # Configure TLS settings
    Configure-TLSSettings
    
    # Disable unnecessary services
    if ($Config.DisableUnnecessarySvcs) {
        Disable-UnnecessaryServices -Services $Config.ServicesToDisable
    }
    
    # Enable BitLocker if configured
    if ($Config.EnableBitLocker) {
        Enable-BitLockerEncryption
    }
    
    Write-LogEntry "Standard hardening completed" -Level "SUCCESS"
}

# Export the functions
Export-ModuleMember -Function Enable-SecurityFeatures, Enable-BitLockerEncryption, 
    Disable-UnnecessaryServices, Configure-TLSSettings, Invoke-StandardHardening