<#
.SYNOPSIS
    Privacy Protection module
.DESCRIPTION
    Advanced privacy controls for Windows
#>

function Show-PrivacyDashboard {
    <#
    .SYNOPSIS
        Creates a visual dashboard showing privacy settings status
    #>
    Write-Banner "Windows Privacy Dashboard"
    
    $privacySettings = @(
        @{Category="Telemetry"; Setting="AllowTelemetry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Desired=0; Description="Windows Telemetry"}
        @{Category="Telemetry"; Setting="AITEnable"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Desired=0; Description="App Telemetry"}
        @{Category="Advertising"; Setting="Enabled"; Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Desired=0; Description="Advertising ID"}
        @{Category="Error Reporting"; Setting="Disabled"; Path="HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Desired=1; Description="Error Reporting"}
        @{Category="Diagnostics"; Setting="AllowDiagnostics"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Desired=0; Description="Diagnostic Data"}
        @{Category="Location"; Setting="DisableLocation"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Desired=1; Description="Location Services"}
        @{Category="Speech"; Setting="AllowInputPersonalization"; Path="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Desired=0; Description="Speech Recognition"}
        @{Category="Timeline"; Setting="EnableActivityFeed"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Desired=0; Description="Activity History"}
        @{Category="Services"; Setting="Start"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack"; Desired=4; Description="Connected User Experiences"}
        @{Category="Cortana"; Setting="AllowCortana"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Desired=0; Description="Cortana"}
    )
    
    $results = @()
    
    foreach ($setting in $privacySettings) {
        $currentValue = $null
        $status = "Unknown"
        
        try {
            if (Test-Path $setting.Path) {
                $regValue = Get-ItemProperty -Path $setting.Path -Name $setting.Setting -ErrorAction SilentlyContinue
                if ($regValue -ne $null) {
                    $currentValue = $regValue.($setting.Setting)
                    
                    if ($currentValue -eq $setting.Desired) {
                        $status = "Optimal"
                    } else {
                        $status = "Privacy Risk"
                    }
                }
            }
        } catch {
            $status = "Error"
        }
        
        $results += [PSCustomObject]@{
            Category = $setting.Category
            Description = $setting.Description
            Status = $status
            CurrentValue = $currentValue
            RecommendedValue = $setting.Desired
        }
    }
    
    # Display dashboard
    Write-Host "Windows Privacy Status:" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    $categoryGroups = $results | Group-Object -Property Category
    
    foreach ($group in $categoryGroups) {
        Write-Host "$($group.Name) Settings:" -ForegroundColor Yellow
        
        foreach ($item in $group.Group) {
            $statusColor = switch ($item.Status) {
                "Optimal" { "Green" }
                "Privacy Risk" { "Red" }
                "Unknown" { "Gray" }
                "Error" { "Red" }
                default { "White" }
            }
            
            Write-Host "  $($item.Description): " -NoNewline
            Write-Host "$($item.Status)" -ForegroundColor $statusColor
        }
        Write-Host ""
    }
    
    # Count issues
    $privacyIssues = $results | Where-Object { $_.Status -eq "Privacy Risk" }
    if ($privacyIssues.Count -gt 0) {
        Write-Host "Found $($privacyIssues.Count) privacy issues that could be improved." -ForegroundColor Yellow
        Write-Host "Use the Privacy Protection options to resolve these issues." -ForegroundColor Yellow
    } else {
        Write-Host "Your system has optimal privacy settings!" -ForegroundColor Green
    }
    
    Write-LogEntry "Privacy dashboard displayed with $($privacyIssues.Count) issues found" -Level "INFO"
    return $results
}

function Block-TelemetryEndpoints {
    <#
    .SYNOPSIS
        Blocks Microsoft telemetry endpoints in hosts file
    #>
    Write-Banner "Blocking Microsoft Telemetry Endpoints"
    
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $telemetryDomains = @(
        "vortex.data.microsoft.com",
        "vortex-win.data.microsoft.com",
        "telecommand.telemetry.microsoft.com",
        "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com",
        "oca.telemetry.microsoft.com.nsatc.net",
        "sqm.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com.nsatc.net",
        "watson.telemetry.microsoft.com",
        "watson.telemetry.microsoft.com.nsatc.net",
        "redir.metaservices.microsoft.com",
        "choice.microsoft.com",
        "choice.microsoft.com.nsatc.net",
        "df.telemetry.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com",
        "services.wes.df.telemetry.microsoft.com",
        "sqm.df.telemetry.microsoft.com",
        "telemetry.microsoft.com",
        "watson.ppe.telemetry.microsoft.com",
        "telemetry.appex.bing.net",
        "telemetry.urs.microsoft.com",
        "telemetry.appex.bing.net:443",
        "settings-sandbox.data.microsoft.com",
        "vortex-sandbox.data.microsoft.com",
        "survey.watson.microsoft.com",
        "watson.live.com",
        "statsfe2.ws.microsoft.com",
        "corpext.msitadfs.glbdns2.microsoft.com",
        "compatexchange.cloudapp.net",
        "cs1.wpc.v0cdn.net",
        "a-0001.a-msedge.net",
        "statsfe2.update.microsoft.com.akadns.net",
        "sls.update.microsoft.com.akadns.net",
        "fe2.update.microsoft.com.akadns.net",
        "diagnostics.support.microsoft.com",
        "corp.sts.microsoft.com",
        "statsfe1.ws.microsoft.com",
        "pre.footprintpredict.com",
        "i1.services.social.microsoft.com",
        "i1.services.social.microsoft.com.nsatc.net",
        "feedback.windows.com",
        "feedback.microsoft-hohm.com",
        "feedback.search.microsoft.com"
    )
    
    # Create backup of hosts file
    $backupFile = "$env:SystemRoot\System32\drivers\etc\hosts.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -Path $hostsFile -Destination $backupFile -Force
    Write-LogEntry "Created backup of hosts file at $backupFile" -Level "INFO"
    
    # Read current hosts file
    $currentHosts = Get-Content -Path $hostsFile
    
    # Create new hosts content
    $newHosts = $currentHosts.Clone()
    $telemetryBlockComment = "# Added by Windows Hardening Script to block telemetry"
    
    # Check if telemetry block comment already exists
    if ($currentHosts -notcontains $telemetryBlockComment) {
        $newHosts += ""
        $newHosts += $telemetryBlockComment
        
        foreach ($domain in $telemetryDomains) {
            $entry = "0.0.0.0 $domain"
            if ($currentHosts -notcontains $entry) {
                $newHosts += $entry
            }
        }
    }
    
    try {
        # Save new hosts file
        $newHosts | Set-Content -Path $hostsFile -Force
        Write-LogEntry "Successfully updated hosts file with telemetry blocking" -Level "SUCCESS"
        Write-Host "Successfully blocked $($telemetryDomains.Count) telemetry endpoints" -ForegroundColor Green
        Write-Host "Hosts file backup created at: $backupFile" -ForegroundColor Cyan
    } catch {
        Write-LogEntry "Failed to update hosts file: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Failed to update hosts file. Make sure you're running as administrator." -ForegroundColor Red
    }
}

function Disable-ErrorReporting {
    <#
    .SYNOPSIS
        Disables Windows Error Reporting
    #>
    Write-Banner "Disabling Windows Error Reporting"
    
    # Disable Windows Error Reporting Service
    Set-AndLogService -ServiceName "WerSvc" -TargetStatus "Stopped" -TargetStartupType "Disabled"
    
    # Disable Windows Error Reporting via registry
    Set-AndLogSetting -Description "Disabling Windows Error Reporting" -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
    Set-AndLogSetting -Description "Disabling WER logs" -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Value 1
    
    # Disable report sending
    Set-AndLogSetting -Description "Disabling automatic report sending" -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Value 1
    Set-AndLogSetting -Description "Disabling report sending" -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Value 0
    
    # Disable Error Reporting via Group Policy
    Set-AndLogSetting -Description "Disabling Error Reporting via Group Policy" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -SkipReadBefore
    
    Write-Host "Windows Error Reporting has been disabled." -ForegroundColor Green
}

function Disable-SpeechRecognition {
    <#
    .SYNOPSIS
        Disables speech recognition data collection
    #>
    Write-Banner "Disabling Speech Recognition Data Collection"
    
    # Disable speech recognition
    Set-AndLogSetting -Description "Disabling speech service" -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -SkipReadBefore
    
    # Disable speech model updates
    Set-AndLogSetting -Description "Disabling automatic updates to speech data" -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Value 0 -SkipReadBefore
    
    # Disable "Getting to know you" features
    Set-AndLogSetting -Description "Disabling 'Getting to know you' features" -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
    Set-AndLogSetting -Description "Disabling 'Getting to know you' features" -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
    
    # Disable online speech recognition
    Set-AndLogSetting -Description "Disabling online speech recognition" -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0
    
    Write-Host "Speech recognition data collection has been disabled." -ForegroundColor Green
}

function Set-AppPermissions {
    <#
    .SYNOPSIS
        Manages app permissions for privacy-sensitive features
    #>
    Write-Banner "App Permission Manager"
    
    $permissions = @(
        @{Name="Location"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"; Description="access your location"}
        @{Name="Microphone"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"; Description="use your microphone"}
        @{Name="Camera"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Description="use your camera"}
        @{Name="Contacts"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"; Description="access your contacts"}
        @{Name="Calendar"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"; Description="access your calendar"}
        @{Name="Call History"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"; Description="access your call history"}
        @{Name="Email"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"; Description="access your email"}
        @{Name="Notifications"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"; Description="access your notifications"}
        @{Name="Account Info"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"; Description="access your account information"}
        @{Name="Background Apps"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"; Description="run in the background"}
    )
    
    Write-Host "Current App Permissions:" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($permission in $permissions) {
        Write-Host "$($permission.Name): " -ForegroundColor Yellow -NoNewline
        
        if (Test-Path "$($permission.Path)\NonPackaged") {
            $status = Get-ItemProperty -Path "$($permission.Path)" -Name "Value" -ErrorAction SilentlyContinue
            if ($status -and $status.Value -eq "Deny") {
                Write-Host "Blocked" -ForegroundColor Green
            } else {
                Write-Host "Allowed" -ForegroundColor Red
            }
        } else {
            Write-Host "Not Configured" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nWould you like to change app permissions? (Y/N)" -ForegroundColor Yellow
    $response = Read-Host
    
    if ($response -eq "Y" -or $response -eq "y") {
        Write-Host "`nChoose an option:" -ForegroundColor Cyan
        Write-Host "1. Block all app permissions (most private)" -ForegroundColor White
        Write-Host "2. Allow only essential permissions" -ForegroundColor White
        Write-Host "3. Configure permissions individually" -ForegroundColor White
        Write-Host "4. Cancel" -ForegroundColor White
        
        $choice = Read-Host "`nEnter your choice (1-4)"
        
        switch ($choice) {
            "1" {
                # Block all permissions
                foreach ($permission in $permissions) {
                    Set-AndLogSetting -Description "Blocking $($permission.Name) permission" -Path $permission.Path -Name "Value" -Value "Deny"
                    
                    # Also block for NonPackaged apps
                    if (!(Test-Path "$($permission.Path)\NonPackaged")) {
                        New-Item -Path "$($permission.Path)\NonPackaged" -Force | Out-Null
                    }
                    Set-AndLogSetting -Description "Blocking $($permission.Name) permission for desktop apps" -Path "$($permission.Path)\NonPackaged" -Name "Value" -Value "Deny"
                }
                Write-Host "All app permissions have been blocked." -ForegroundColor Green
            }
            "2" {
                # Allow only essential (based on typical needs)
                foreach ($permission in $permissions) {
                    if ($permission.Name -in @("Microphone", "Camera")) {
                        # Allow essential permissions
                        Set-AndLogSetting -Description "Allowing $($permission.Name) permission" -Path $permission.Path -Name "Value" -Value "Allow"
                        
                        # Allow for NonPackaged apps
                        if (!(Test-Path "$($permission.Path)\NonPackaged")) {
                            New-Item -Path "$($permission.Path)\NonPackaged" -Force | Out-Null
                        }
                        Set-AndLogSetting -Description "Allowing $($permission.Name) permission for desktop apps" -Path "$($permission.Path)\NonPackaged" -Name "Value" -Value "Allow"
                    } else {
                        # Block non-essential permissions
                        Set-AndLogSetting -Description "Blocking $($permission.Name) permission" -Path $permission.Path -Name "Value" -Value "Deny"
                        
                        # Block for NonPackaged apps
                        if (!(Test-Path "$($permission.Path)\NonPackaged")) {
                            New-Item -Path "$($permission.Path)\NonPackaged" -Force | Out-Null
                        }
                        Set-AndLogSetting -Description "Blocking $($permission.Name) permission for desktop apps" -Path "$($permission.Path)\NonPackaged" -Name "Value" -Value "Deny"
                    }
                }
                Write-Host "Essential app permissions have been configured." -ForegroundColor Green
            }
            "3" {
                # Configure individually
                foreach ($permission in $permissions) {
                    Write-Host "`nShould apps be allowed to $($permission.Description)? (Y/N)" -ForegroundColor Yellow
                    $permResponse = Read-Host
                    
                    if ($permResponse -eq "N" -or $permResponse -eq "n") {
                        Set-AndLogSetting -Description "Blocking $($permission.Name) permission" -Path $permission.Path -Name "Value" -Value "Deny"
                        
                        # Block for NonPackaged apps
                        if (!(Test-Path "$($permission.Path)\NonPackaged")) {
                            New-Item -Path "$($permission.Path)\NonPackaged" -Force | Out-Null
                        }
                        Set-AndLogSetting -Description "Blocking $($permission.Name) permission for desktop apps" -Path "$($permission.Path)\NonPackaged" -Name "Value" -Value "Deny"
                    } else {
                        Set-AndLogSetting -Description "Allowing $($permission.Name) permission" -Path $permission.Path -Name "Value" -Value "Allow"
                        
                        # Allow for NonPackaged apps
                        if (!(Test-Path "$($permission.Path)\NonPackaged")) {
                            New-Item -Path "$($permission.Path)\NonPackaged" -Force | Out-Null
                        }
                        Set-AndLogSetting -Description "Allowing $($permission.Name) permission for desktop apps" -Path "$($permission.Path)\NonPackaged" -Name "Value" -Value "Allow"
                    }
                }
                Write-Host "App permissions have been configured according to your preferences." -ForegroundColor Green
            }
            "4" {
                Write-Host "Operation canceled. No changes were made." -ForegroundColor Yellow
            }
            default {
                Write-Host "Invalid choice. No changes were made." -ForegroundColor Red
            }
        }
    }
}

function Invoke-PrivacyProtection {
    <#
    .SYNOPSIS
        Implements privacy protection enhancements
    #>
    param(
        [hashtable]$Config
    )
    
    Write-Banner "Privacy Protection Configuration"
    
    # Show menu for privacy protection options
    Write-Host "Privacy Protection Options:" -ForegroundColor Cyan
    Write-Host "1. View Privacy Dashboard" -ForegroundColor White
    Write-Host "2. Block Microsoft Telemetry Endpoints" -ForegroundColor White
    Write-Host "3. Disable Windows Error Reporting" -ForegroundColor White
    Write-Host "4. Disable Speech Recognition Data Collection" -ForegroundColor White
    Write-Host "5. Manage App Permissions" -ForegroundColor White
    Write-Host "6. Apply All Privacy Protections" -ForegroundColor White
    Write-Host "7. Return to Main Menu" -ForegroundColor White
    Write-Host ""
    
    $privacyChoice = Read-Host "Enter your choice (1-7)"
    
    switch ($privacyChoice) {
        "1" {
            Show-PrivacyDashboard
        }
        "2" {
            Block-TelemetryEndpoints
        }
        "3" {
            Disable-ErrorReporting
        }
        "4" {
            Disable-SpeechRecognition
        }
        "5" {
            Set-AppPermissions
        }
        "6" {
            Show-PrivacyDashboard
            Block-TelemetryEndpoints
            Disable-ErrorReporting
            Disable-SpeechRecognition
            Set-AppPermissions
        }
        "7" {
            return
        }
        default {
            Write-Host "Invalid choice. No changes were made." -ForegroundColor Red
            return
        }
    }
    
    Write-LogEntry "Privacy protection configuration completed" -Level "SUCCESS"
}

# Export the functions
Export-ModuleMember -Function Show-PrivacyDashboard, Block-TelemetryEndpoints, 
    Disable-ErrorReporting, Disable-SpeechRecognition, Set-AppPermissions, 
    Invoke-PrivacyProtection