<#
.SYNOPSIS
    Additional Security Features module
.DESCRIPTION
    Enhances Windows security beyond basic hardening
#>

function Set-BrowserHardening {
    <#
    .SYNOPSIS
        Configures browser security settings for Edge, Chrome, and Firefox
    #>
    Write-Banner "Browser Hardening"
    
    # Microsoft Edge hardening
    Write-Host "Configuring Microsoft Edge security settings..." -ForegroundColor Cyan
    
    $edgePolicies = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (!(Test-Path $edgePolicies)) {
        New-Item -Path $edgePolicies -Force | Out-Null
    }
    
    $edgeSettings = @{
        "SmartScreenEnabled" = 1  # Enable SmartScreen
        "SmartScreenPuaEnabled" = 1  # Block potentially unwanted apps
        "PasswordManagerEnabled" = 0  # Disable password manager
        "AutofillAddressEnabled" = 0  # Disable address autofill
        "AutofillCreditCardEnabled" = 0  # Disable credit card autofill
        "DefaultSearchProviderEnabled" = 1  # Enable default search provider
        "BuiltInDnsClientEnabled" = 0  # Disable DNS over HTTPS
        "SitePerProcess" = 1  # Enable site isolation
        "SSLVersionMin" = "tls1.2"  # Minimum TLS version 1.2
        "AllowCrossOriginAuthPrompt" = 0  # Disable cross-origin auth prompts
        "AllowDeletingBrowserHistory" = 0  # Prevent clearing browser history
    }
    
    foreach ($setting in $edgeSettings.GetEnumerator()) {
        Set-AndLogSetting -Description "Edge: $($setting.Key)" -Path $edgePolicies -Name $setting.Key -Value $setting.Value -SkipReadBefore
    }
    
    # Google Chrome hardening (similar to Edge since both are Chromium-based)
    Write-Host "Configuring Google Chrome security settings..." -ForegroundColor Cyan
    
    $chromePolicies = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (!(Test-Path $chromePolicies)) {
        New-Item -Path $chromePolicies -Force | Out-Null
    }
    
    $chromeSettings = @{
        "IncognitoModeAvailability" = 1  # Disable incognito mode
        "ForceGoogleSafeSearch" = 1  # Force SafeSearch
        "SafeBrowsingProtectionLevel" = 2  # Enhanced protection
        "PasswordManagerEnabled" = 0  # Disable password manager
        "AutofillAddressEnabled" = 0  # Disable address autofill
        "AutofillCreditCardEnabled" = 0  # Disable credit card autofill
        "SitePerProcess" = 1  # Enable site isolation
        "SSLVersionMin" = "tls1.2"  # Minimum TLS version 1.2
        "AllowCrossOriginAuthPrompt" = 0  # Disable cross-origin auth prompts
    }
    
    foreach ($setting in $chromeSettings.GetEnumerator()) {
        Set-AndLogSetting -Description "Chrome: $($setting.Key)" -Path $chromePolicies -Name $setting.Key -Value $setting.Value -SkipReadBefore
    }
    
    # Firefox hardening (if installed)
    $firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
    $firefoxPathx86 = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    
    if ((Test-Path $firefoxPath) -or (Test-Path $firefoxPathx86)) {
        Write-Host "Configuring Mozilla Firefox security settings..." -ForegroundColor Cyan
        
        $firefoxPolicies = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
        if (!(Test-Path $firefoxPolicies)) {
            New-Item -Path $firefoxPolicies -Force | Out-Null
        }
        
        $firefoxSettings = @{
            "DisableFormHistory" = 1  # Disable form history
            "DisableTelemetry" = 1  # Disable telemetry
            "DisablePocket" = 1  # Disable Pocket
            "OfferToSaveLogins" = 0  # Don't offer to save logins
            "OfferToSaveLoginsDefault" = 0  # Don't offer to save logins by default
            "PasswordManagerEnabled" = 0  # Disable password manager
            "SanitizeOnShutdown" = 1  # Clear data on shutdown
        }
        
        foreach ($setting in $firefoxSettings.GetEnumerator()) {
            Set-AndLogSetting -Description "Firefox: $($setting.Key)" -Path $firefoxPolicies -Name $setting.Key -Value $setting.Value -SkipReadBefore
        }
    }
    
    Write-Host "Browser hardening completed." -ForegroundColor Green
}

function Disable-WiFiSense {
    <#
    .SYNOPSIS
        Disables WiFi Sense features
    #>
    Write-Banner "Disabling WiFi Sense"
    
    # Disable automatic connection to WiFi hotspots
    Set-AndLogSetting -Description "Disabling WiFi Sense shared hotspot connections" -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0
    
    # Disable sharing of WiFi networks
    Set-AndLogSetting -Description "Disabling WiFi network sharing" -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared" -Value 0
    
    # Disable automatic connection to open hotspots
    Set-AndLogSetting -Description "Disabling automatic connections to open hotspots" -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseOpen" -Value 0
    
    # Disable WiFi Sense via Group Policy
    Set-AndLogSetting -Description "Disabling WiFi Sense via Group Policy" -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling WiFi Sense via Group Policy" -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0 -SkipReadBefore
    
    Write-Host "WiFi Sense features have been disabled." -ForegroundColor Green
}

function Optimize-TPMSecurity {
    <#
    .SYNOPSIS
        Configures TPM for maximum security
    #>
    Write-Banner "TPM Security Enhancement"
    
    # Check if TPM is present and enabled
    try {
        $tpm = Get-Tpm
        
        if ($tpm) {
            Write-Host "TPM Information:" -ForegroundColor Cyan
            Write-Host "  TPM Present: $($tpm.TpmPresent)" -ForegroundColor Cyan
            Write-Host "  TPM Ready: $($tpm.TpmReady)" -ForegroundColor Cyan
            Write-Host "  TPM Enabled: $($tpm.TpmEnabled)" -ForegroundColor Cyan
            Write-Host "  TPM Activated: $($tpm.TpmActivated)" -ForegroundColor Cyan
            Write-Host "  TPM Owner Authorization: $($tpm.OwnerAuth.ToString() -ne '')" -ForegroundColor Cyan
            
            if ($tpm.TpmPresent -and $tpm.TpmReady) {
                # Get TPM version
                $tpmVersion = "Unknown"
                try {
                    $tpmWmi = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class "Win32_Tpm" -ErrorAction SilentlyContinue
                    if ($tpmWmi) {
                        $tpmVersion = $tpmWmi.SpecVersion
                    }
                } catch {
                    Write-LogEntry "Error getting TPM version: $($_.Exception.Message)" -Level "WARNING"
                }
                
                Write-Host "  TPM Version: $tpmVersion" -ForegroundColor Cyan
                
                # Configure TPM security settings if it's TPM 2.0
                if ($tpmVersion -like "*2.0*") {
                    Write-Host "`nConfiguring TPM 2.0 for enhanced security..." -ForegroundColor Yellow
                    
                    # Enable Platform Configuration Register (PCR) protection
                    Invoke-AndLogCommand -Description "Enabling PCR protection for TPM" -Command {
                        # This is best done through Group Policy - here's a registry approach
                        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
                        if (!(Test-Path $path)) {
                            New-Item -Path $path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $path -Name "EnableVirtualizationBasedSecurity" -Value 1
                        Set-ItemProperty -Path $path -Name "RequirePlatformSecurityFeatures" -Value 1
                        
                        return "TPM PCR protection configured"
                    }
                    
                    # Clear TPM if requested (CAUTION)
                    Write-Host "`nWARNING: Clearing the TPM will remove all keys and data protected by the TPM." -ForegroundColor Red
                    Write-Host "This is generally NOT recommended unless you're reconfiguring from scratch." -ForegroundColor Red
                    Write-Host "Do you want to clear the TPM? (Y/N)" -ForegroundColor Red
                    $clearResponse = Read-Host
                    
                    if ($clearResponse -eq "Y" -or $clearResponse -eq "y") {
                        Invoke-AndLogCommand -Description "Clearing TPM" -Command {
                            Clear-Tpm
                            return "TPM cleared - system may require a restart"
                        }
                    }
                } else {
                    Write-Host "`nTPM 1.2 detected. Limited security configuration options available." -ForegroundColor Yellow
                }
            } else {
                Write-Host "`nTPM is either not present or not ready. Unable to configure TPM security." -ForegroundColor Red
                Write-Host "Please enable TPM in your system BIOS/UEFI settings first." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Unable to detect TPM on this system." -ForegroundColor Red
        }
    } catch {
        Write-LogEntry "Error configuring TPM: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Error accessing TPM information: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Configure-WindowsSandbox {
    <#
    .SYNOPSIS
        Sets up and hardens Windows Sandbox environment
    #>
    Write-Banner "Windows Sandbox Configuration"
    
    # Check if Windows Sandbox is supported
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [Version]$osInfo.Version
    
    if ($osVersion -lt [Version]"10.0.18305") {
        Write-Host "Windows Sandbox is only supported on Windows 10 version 1903 or newer." -ForegroundColor Red
        Write-LogEntry "Windows Sandbox not supported on this Windows version" -Level "WARNING"
        return
    }
    
    # Check if virtualization is enabled
    $processorInfo = Get-WmiObject -Class Win32_Processor
    if ($processorInfo.VirtualizationFirmwareEnabled -ne $true) {
        Write-Host "Hardware virtualization is not enabled. Windows Sandbox requires this feature." -ForegroundColor Red
        Write-Host "Please enable virtualization in your system BIOS/UEFI settings." -ForegroundColor Yellow
        Write-LogEntry "Virtualization not enabled for Windows Sandbox" -Level "WARNING"
        return
    }
    
    # Check if Windows Sandbox feature is installed
    $sandboxFeature = Get-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online
    
    if ($sandboxFeature.State -ne "Enabled") {
        Write-Host "Windows Sandbox is not installed. Would you like to install it now? (Y/N)" -ForegroundColor Yellow
        $installResponse = Read-Host
        
        if ($installResponse -eq "Y" -or $installResponse -eq "y") {
            Invoke-AndLogCommand -Description "Installing Windows Sandbox" -Command {
                Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online -NoRestart
                return "Windows Sandbox feature installation requested"
            }
            
            Write-Host "Windows Sandbox feature installation requested. A system restart is required to complete installation." -ForegroundColor Yellow
            return
        } else {
            Write-Host "Windows Sandbox installation canceled." -ForegroundColor Yellow
            return
        }
    }
    
    # Create a sandbox configuration file
    $sandboxConfigDir = "$env:USERPROFILE\Documents\WindowsSandbox"
    $sandboxConfigFile = "$sandboxConfigDir\SecureConfig.wsb"
    
    if (!(Test-Path $sandboxConfigDir)) {
        New-Item -Path $sandboxConfigDir -ItemType Directory -Force | Out-Null
    }
    
    $sandboxConfig = @"
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MemoryInMB>4096</MemoryInMB>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
</Configuration>
"@
    
    $sandboxConfig | Out-File -FilePath $sandboxConfigFile -Encoding utf8 -Force
    
    Write-Host "Windows Sandbox secure configuration has been created at:" -ForegroundColor Green
    Write-Host $sandboxConfigFile -ForegroundColor Cyan
    Write-Host "`nTo use the secure sandbox, double-click the .wsb file or right-click and select 'Open With > Windows Sandbox'" -ForegroundColor Yellow
    
    # Offer to create a desktop shortcut
    Write-Host "`nWould you like to create a desktop shortcut to the secure sandbox? (Y/N)" -ForegroundColor Yellow
    $shortcutResponse = Read-Host
    
    if ($shortcutResponse -eq "Y" -or $shortcutResponse -eq "y") {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcutFile = "$desktopPath\Secure Windows Sandbox.lnk"
        
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutFile)
        $Shortcut.TargetPath = $sandboxConfigFile
        $Shortcut.Save()
        
        Write-Host "Desktop shortcut created." -ForegroundColor Green
    }
    
    Write-LogEntry "Windows Sandbox configured with enhanced security settings" -Level "SUCCESS"
}

function Verify-SecureBoot {
    <#
    .SYNOPSIS
        Checks and enforces Secure Boot status
    #>
    Write-Banner "Secure Boot Verification"
    
    # Check if Secure Boot is enabled
    try {
        $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        
        if ($secureBootStatus -eq $true) {
            Write-Host "Secure Boot is enabled on this system." -ForegroundColor Green
            Write-LogEntry "Secure Boot is enabled" -Level "SUCCESS"
        } else {
            Write-Host "Secure Boot is NOT enabled on this system." -ForegroundColor Red
            Write-Host "This is a security risk that could allow unauthorized boot code to execute." -ForegroundColor Red
            Write-Host "`nTo enable Secure Boot:" -ForegroundColor Yellow
            Write-Host "1. Restart your computer and enter BIOS/UEFI settings (typically by pressing F2, Delete, or F10 during startup)" -ForegroundColor Yellow
            Write-Host "2. Navigate to the Boot or Security section" -ForegroundColor Yellow
            Write-Host "3. Enable Secure Boot" -ForegroundColor Yellow
            Write-Host "4. Save changes and exit" -ForegroundColor Yellow
            
            Write-LogEntry "Secure Boot is not enabled - user notified of security risk" -Level "WARNING"
        }
    } catch {
        if ($_.Exception.Message -like "*Cmdlet not supported on this platform*") {
            Write-Host "This system does not support Secure Boot (likely using legacy BIOS instead of UEFI)." -ForegroundColor Red
            Write-Host "For maximum security, consider upgrading to a UEFI-compatible system with Secure Boot support." -ForegroundColor Yellow
            
            Write-LogEntry "System does not support Secure Boot (non-UEFI system)" -Level "WARNING"
        } else {
            Write-Host "Error checking Secure Boot status: $($_.Exception.Message)" -ForegroundColor Red
            Write-LogEntry "Error checking Secure Boot status: $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    # Check BitLocker and Secure Boot dependencies
    $bitlockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bitlockerVolume -and $bitlockerVolume.ProtectionStatus -eq "On") {
        Write-Host "`nBitLocker is enabled on the system drive." -ForegroundColor Cyan
        
        $bitlockerInfo = Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty KeyProtector
        $hasTPMProtector = $bitlockerInfo | Where-Object { $_.KeyProtectorType -eq "Tpm" }
        
        if ($hasTPMProtector -and $secureBootStatus -ne $true) {
            Write-Host "WARNING: BitLocker is using TPM protection, but Secure Boot is disabled." -ForegroundColor Red
            Write-Host "This reduces the security effectiveness of BitLocker as the boot chain is not validated." -ForegroundColor Red
            Write-Host "Enabling Secure Boot is strongly recommended for maximum security." -ForegroundColor Yellow
            
            Write-LogEntry "Security issue: BitLocker using TPM but Secure Boot disabled" -Level "WARNING"
        }
    }
}

function Invoke-AdditionalSecurity {
    <#
    .SYNOPSIS
        Implements additional security features
    #>
    param(
        [hashtable]$Config
    )
    
    Write-Banner "Additional Security Features"
    
    # Show menu for additional security options
    Write-Host "Additional Security Options:" -ForegroundColor Cyan
    Write-Host "1. Browser Hardening (Edge, Chrome, Firefox)" -ForegroundColor White
    Write-Host "2. Disable WiFi Sense" -ForegroundColor White
    Write-Host "3. TPM Security Enhancement" -ForegroundColor White
    Write-Host "4. Windows Sandbox Configuration" -ForegroundColor White
    Write-Host "5. Secure Boot Verification" -ForegroundColor White
    Write-Host "6. Apply All Additional Security Features" -ForegroundColor White
    Write-Host "7. Return to Main Menu" -ForegroundColor White
    Write-Host ""
    
    $securityChoice = Read-Host "Enter your choice (1-7)"
    
    switch ($securityChoice) {
        "1" {
            Set-BrowserHardening
        }
        "2" {
            Disable-WiFiSense
        }
        "3" {
            Optimize-TPMSecurity
        }
        "4" {
            Configure-WindowsSandbox
        }
        "5" {
            Verify-SecureBoot
        }
        "6" {
            Set-BrowserHardening
            Disable-WiFiSense
            Optimize-TPMSecurity
            Configure-WindowsSandbox
            Verify-SecureBoot
        }
        "7" {
            return
        }
        default {
            Write-Host "Invalid choice. No changes were made." -ForegroundColor Red
            return
        }
    }
    
    Write-LogEntry "Additional security features configuration completed" -Level "SUCCESS"
}

# Export the functions
Export-ModuleMember -Function Set-BrowserHardening, Disable-WiFiSense, 
    Optimize-TPMSecurity, Configure-WindowsSandbox, Verify-SecureBoot, 
    Invoke-AdditionalSecurity