<#
.SYNOPSIS
    Enhanced Windows Hardening module
.DESCRIPTION
    Contains functions for enhanced (maximum) Windows security hardening
#>

function Configure-PrivacySettings {
    <#
    .SYNOPSIS
        Configures privacy-related settings
    #>
    Write-Banner "Privacy Settings"
    
    # Disable Windows Telemetry
    Set-AndLogSetting -Description "Disabling Windows Telemetry" -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -SkipReadBefore
    
    # Disable other data collection features
    Set-AndLogSetting -Description "Disabling Customer Experience Improvement Program" -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling app telemetry" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -SkipReadBefore
    
    # Disable advertising ID
    Set-AndLogSetting -Description "Disabling Advertising ID" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -SkipReadBefore
    
    # Disable app launch tracking
    Set-AndLogSetting -Description "Disabling app launch tracking" -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0
}

function Remove-UnwantedApps {
    <#
    .SYNOPSIS
        Removes unwanted Windows apps
    .PARAMETER AppPatterns
        Array of app name patterns to remove
    #>
    param(
        [string[]]$AppPatterns
    )
    
    Write-Banner "Removing Unwanted Applications"
    
    foreach ($appPattern in $AppPatterns) {
        Invoke-AndLogCommand -Description "Removing apps matching: $appPattern" -Command {
            $removedCount = 0
            $apps = Get-AppxPackage -Name $appPattern -AllUsers -ErrorAction SilentlyContinue
            foreach ($app in $apps) {
                Remove-AppxPackage -Package $app.PackageFullName -ErrorAction SilentlyContinue
                $removedCount++
            }
            return "Removed $removedCount apps matching '$appPattern'"
        }
    }
    
    # Special handling for OneDrive
    Invoke-AndLogCommand -Description "Removing OneDrive" -Command {
        # Stop OneDrive process
        Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
        
        # Uninstall OneDrive
        $oneDrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        if (-not (Test-Path $oneDrivePath)) {
            $oneDrivePath = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
        }
        
        if (Test-Path $oneDrivePath) {
            Start-Process $oneDrivePath -ArgumentList "/uninstall" -Wait
            return "OneDrive uninstallation process completed"
        } else {
            return "OneDrive setup not found"
        }
    }
}

function Protect-ScriptExecution {
    <#
    .SYNOPSIS
        Secures script execution environments
    #>
    Write-Banner "Script and Execution Security"
    
    # Disable Windows Script Host
    Set-AndLogSetting -Description "Disabling Windows Script Host" -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -SkipReadBefore
    
    # Disable JavaScript in Windows Script Host
    Set-AndLogSetting -Description "Disabling JavaScript in Windows Script Host" -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "JScriptEnabled" -Value 0 -SkipReadBefore
    
    # Disable PowerShell V2
    Set-AndLogWindowsFeature -FeatureName "MicrosoftWindowsPowerShellV2Root" -Enable $false
    Set-AndLogWindowsFeature -FeatureName "MicrosoftWindowsPowerShellV2" -Enable $false
    
    # Set PowerShell execution policy to restrict
    Invoke-AndLogCommand -Description "Setting PowerShell execution policy to restricted" -Command {
        Set-ExecutionPolicy Restricted -Force -Scope LocalMachine
        return "PowerShell execution policy set to Restricted"
    }
}

function Disable-RemoteAccess {
    <#
    .SYNOPSIS
        Disables remote access capabilities
    #>
    Write-Banner "Remote Access Security"
    
    # Disable Remote Assistance
    Set-AndLogSetting -Description "Disabling Remote Assistance" -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
    
    # Disable Remote Desktop
    Set-AndLogSetting -Description "Disabling Remote Desktop" -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    
    # Disable Windows Remote Management
    Set-AndLogService -ServiceName "WinRM" -TargetStatus "Stopped" -TargetStartupType "Disabled"
    
    # Disable Remote Registry
    Set-AndLogService -ServiceName "RemoteRegistry" -TargetStatus "Stopped" -TargetStartupType "Disabled"
}

function Configure-EnhancedSecurity {
    <#
    .SYNOPSIS
        Applies additional enhanced security settings
    #>
    Write-Banner "Enhanced Security Settings"
    
    # Disable autorun/autoplay completely
    Set-AndLogSetting -Description "Disabling AutoPlay completely" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
    Set-AndLogSetting -Description "Disabling AutoPlay for all drives" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
    
    # Enable Credential Guard (if hardware supports it)
    Invoke-AndLogCommand -Description "Enabling Credential Guard if supported" -Command {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        if ($deviceGuard.SecurityServicesRunning -notcontains 1) {
            # Try to enable Credential Guard
            $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            if (!(Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $registryPath -Name "EnableVirtualizationBasedSecurity" -Value 1
            Set-ItemProperty -Path $registryPath -Name "RequirePlatformSecurityFeatures" -Value 1
            
            $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Set-ItemProperty -Path $registryPath -Name "LsaCfgFlags" -Value 1
            
            return "Credential Guard settings applied - requires reboot"
        } else {
            return "Credential Guard is already enabled"
        }
    }
    
    # Block untrusted fonts
    Set-AndLogSetting -Description "Blocking untrusted fonts" -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers" -Name "BlockUntrustedFonts" -Value 1 -SkipReadBefore
    
    # Disable Office macros
    Set-AndLogSetting -Description "Disabling all macros in Office" -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Value 4 -SkipReadBefore
}

function Invoke-EnhancedHardening {
    <#
    .SYNOPSIS
        Performs enhanced security hardening
    .PARAMETER Config
        Configuration settings
    #>
    param(
        [hashtable]$Config
    )
    
    # Include standard hardening
    Invoke-StandardHardening -Config $Config
    
    # Apply enhanced privacy settings
    Configure-PrivacySettings
    
    # Remove unwanted apps
    Remove-UnwantedApps -AppPatterns $Config.AppsToRemove
    
    # Protect script execution
    Protect-ScriptExecution
    
    # Disable remote access
    Disable-RemoteAccess
    
    # Configure enhanced security settings
    Configure-EnhancedSecurity
    
    # Disable USB storage if configured
    if ($Config.DisableUSBStorage) {
        Set-AndLogSetting -Description "Disabling USB Storage" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
    }
    
    Write-LogEntry "Enhanced hardening completed" -Level "SUCCESS"
}

# Export the functions
Export-ModuleMember -Function Configure-PrivacySettings, Remove-UnwantedApps, 
    Protect-ScriptExecution, Disable-RemoteAccess, Configure-EnhancedSecurity, 
    Invoke-EnhancedHardening