<#
.SYNOPSIS
    Windows Debloat module
.DESCRIPTION
    Remove unnecessary Windows components, disable telemetry, and optimize performance
#>

function Remove-BloatwareApps {
    <#
    .SYNOPSIS
        Removes pre-installed Windows bloatware apps
    #>
    Write-Banner "Removing Bloatware Apps"
    
    # List of bloatware apps to remove
    $bloatwareApps = @(
        # Common bloatware
        "*Microsoft.3DBuilder*"
        "*Microsoft.WindowsAlarms*"
        "*Microsoft.WindowsFeedbackHub*"
        "*Microsoft.WindowsMaps*"
        "*Microsoft.BingWeather*"
        "*Microsoft.BingNews*"
        "*Microsoft.GetHelp*"
        "*Microsoft.Getstarted*"
        "*Microsoft.Messaging*"
        "*Microsoft.Microsoft3DViewer*"
        "*Microsoft.MicrosoftOfficeHub*"
        "*Microsoft.MicrosoftSolitaireCollection*"
        "*Microsoft.MicrosoftStickyNotes*"
        "*Microsoft.MixedReality.Portal*"
        "*Microsoft.OneConnect*"
        "*Microsoft.People*"
        "*Microsoft.Print3D*"
        "*Microsoft.SkypeApp*"
        "*Microsoft.Wallet*"
        "*Microsoft.WindowsSoundRecorder*"
        "*Microsoft.ZuneMusic*"
        "*Microsoft.ZuneVideo*"
        "*microsoft.windowscommunicationsapps*"
        "*Microsoft.YourPhone*"
        "*Microsoft.XboxApp*"
        "*Microsoft.XboxGameOverlay*"
        "*Microsoft.XboxGamingOverlay*"
        "*Microsoft.XboxIdentityProvider*"
        "*Microsoft.XboxSpeechToTextOverlay*"
        # Games
        "*Microsoft.MinecraftUWP*"
        "*Microsoft.MicrosoftMahjong*"
        "*Microsoft.MicrosoftSudoku*"
        # Partner bloatware
        "*HPJumpStarts*"
        "*HPPCHardwareDiagnosticsWindows*"
        "*HPPowerManager*"
        "*HPPrivacySettings*"
        "*HPSupportAssistant*"
        "*HPSureShieldAI*"
        "*HPWorkWell*"
        "*DellInc.DellSupportAssistforPCs*"
        "*DellInc.DellDigitalDelivery*"
        "*DellInc.DellPowerManager*"
        "*DellInc.DellCommandUpdate*"
        "*LenovoCompanion*"
        "*LenovoSettings*"
        "*LenovoUtility*"
        # Advertising apps
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Disney*"
    )
    
    foreach ($app in $bloatwareApps) {
        Invoke-AndLogCommand -Description "Removing app package: $app" -Command {
            $removedCount = 0
            
            # Remove for current user
            Get-AppxPackage -Name $app -AllUsers | ForEach-Object {
                Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
                $removedCount++
            }
            
            # Remove provisioned packages (pre-installed for new users)
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | ForEach-Object {
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
                $removedCount++
            }
            
            return "Removed $removedCount instances of $app"
        }
    }
}

function Disable-WindowsTelemetry {
    <#
    .SYNOPSIS
        Disables Windows telemetry and data collection
    #>
    Write-Banner "Disabling Windows Telemetry"
    
    # Disable telemetry
    Set-AndLogSetting -Description "Disabling telemetry" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -SkipReadBefore
    
    # Disable Customer Experience Improvement Program
    Set-AndLogSetting -Description "Disabling CEIP" -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -SkipReadBefore
    
    # Disable application telemetry
    Set-AndLogSetting -Description "Disabling app telemetry" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling app telemetry" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -SkipReadBefore
    
    # Disable advertising ID
    Set-AndLogSetting -Description "Disabling advertising ID" -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    Set-AndLogSetting -Description "Disabling advertising ID" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -SkipReadBefore
    
    # Disable feedback requests
    Set-AndLogSetting -Description "Disabling feedback requests" -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling feedback requests" -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -SkipReadBefore
    
    # Disable diagnostic tracking service
    Set-AndLogService -ServiceName "DiagTrack" -TargetStatus "Stopped" -TargetStartupType "Disabled"
    Set-AndLogService -ServiceName "dmwappushservice" -TargetStatus "Stopped" -TargetStartupType "Disabled"
}

function Optimize-WindowsPerformance {
    <#
    .SYNOPSIS
        Optimizes Windows for better performance
    #>
    Write-Banner "Optimizing Windows Performance"
    
    # Disable visual effects for performance
    Invoke-AndLogCommand -Description "Optimizing visual effects for performance" -Command {
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name "VisualFXSetting" -Value 2 # 2 = Custom
        
        $path = "HKCU:\Control Panel\Desktop"
        Set-ItemProperty -Path $path -Name "DragFullWindows" -Value 0
        Set-ItemProperty -Path $path -Name "UserPreferencesMask" -Value ([byte[]](0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00))
        
        $path = "HKCU:\Control Panel\Desktop\WindowMetrics"
        Set-ItemProperty -Path $path -Name "MinAnimate" -Value 0
        
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $path -Name "ListviewAlphaSelect" -Value 0
        Set-ItemProperty -Path $path -Name "ListviewShadow" -Value 0
        Set-ItemProperty -Path $path -Name "TaskbarAnimations" -Value 0
        
        $path = "HKCU:\Software\Microsoft\Windows\DWM"
        Set-ItemProperty -Path $path -Name "EnableAeroPeek" -Value 0
        
        return "Visual effects optimized for performance"
    }
    
    # Disable search indexing for better performance
    Set-AndLogService -ServiceName "WSearch" -TargetStatus "Stopped" -TargetStartupType "Disabled"
    
    # Disable superfetch/prefetch for SSDs
    Set-AndLogService -ServiceName "SysMain" -TargetStatus "Stopped" -TargetStartupType "Disabled"
    
    # Disable Windows Tips
    Set-AndLogSetting -Description "Disabling Windows Tips" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -SkipReadBefore
    
    # Disable lock screen spotlight and consumer features
    Set-AndLogSetting -Description "Disabling lock screen spotlight" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling consumer features" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -SkipReadBefore
    
    # Optimize power settings for performance
    Invoke-AndLogCommand -Description "Optimizing power settings for performance" -Command {
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c # High performance power plan
        return "Set high performance power plan"
    }
}

function Disable-UnnecessaryServices {
    <#
    .SYNOPSIS
        Disables unnecessary Windows services
    #>
    Write-Banner "Disabling Unnecessary Services"
    
    # List of services to disable
    $servicesToDisable = @(
        # Telemetry and data collection
        "DiagTrack"               # Connected User Experiences and Telemetry
        "dmwappushservice"        # WAP Push Message Routing Service
        
        # Xbox and gaming-related
        "XblAuthManager"          # Xbox Live Auth Manager
        "XblGameSave"             # Xbox Live Game Save
        "XboxNetApiSvc"           # Xbox Live Networking Service
        
        # Mobile and unused features
        "PhoneSvc"                # Phone Service
        "TabletInputService"      # Touch Keyboard and Handwriting Panel Service
        "RetailDemo"              # Retail Demo Service
        
        # Rarely used features
        "PrintNotify"             # Printer Extensions and Notifications (if not using printers)
        "WalletService"           # Payment service (rarely used)
        "SensorService"           # Sensor Service (for tablets/mobile devices)
        "SensrSvc"                # Sensor Monitoring Service
        "SensorDataService"       # Sensor Data Service
        
        # Other optional services
        "MapsBroker"              # Downloaded Maps Manager
        "lfsvc"                   # Geolocation Service
        "SharedAccess"            # Internet Connection Sharing
        "WbioSrvc"                # Windows Biometric Service (if not using fingerprint/face)
        "icssvc"                  # Windows Mobile Hotspot Service
    )
    
    foreach ($service in $servicesToDisable) {
        Set-AndLogService -ServiceName $service -TargetStatus "Stopped" -TargetStartupType "Disabled"
    }
}

function Disable-OneDrive {
    <#
    .SYNOPSIS
        Disables and uninstalls OneDrive
    #>
    Write-Banner "Disabling OneDrive"
    
    Invoke-AndLogCommand -Description "Disabling and uninstalling OneDrive" -Command {
        # Stop OneDrive process
        Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
        
        # Disable OneDrive via Group Policy
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name "DisableFileSyncNGSC" -Value 1
        
        # Uninstall OneDrive
        $oneDrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        if (!(Test-Path $oneDrivePath)) {
            $oneDrivePath = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
        }
        
        if (Test-Path $oneDrivePath) {
            Start-Process $oneDrivePath -ArgumentList "/uninstall" -Wait
        }
        
        # Remove OneDrive from Explorer sidebar
        $path = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "System.IsPinnedToNameSpaceTree" -Value 0
        }
        $path = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "System.IsPinnedToNameSpaceTree" -Value 0
        }
        
        return "OneDrive disabled and uninstalled"
    }
}

function Disable-Cortana {
    <#
    .SYNOPSIS
        Disables Cortana and related features
    #>
    Write-Banner "Disabling Cortana"
    
    Set-AndLogSetting -Description "Disabling Cortana" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling Cortana above lock screen" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling Cortana web search" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -SkipReadBefore
    Set-AndLogSetting -Description "Disabling Cortana search history" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -SkipReadBefore
}

function Invoke-WindowsDebloat {
    <#
    .SYNOPSIS
        Performs Windows debloating operations
    .PARAMETER Config
        Configuration settings
    #>
    param(
        [hashtable]$Config
    )
    
    # Show prompt with options
    Write-Host "Windows Debloat Options:" -ForegroundColor Cyan
    Write-Host "1. Remove Bloatware Apps" -ForegroundColor White
    Write-Host "2. Disable Telemetry & Data Collection" -ForegroundColor White
    Write-Host "3. Optimize Windows Performance" -ForegroundColor White
    Write-Host "4. Disable Unnecessary Services" -ForegroundColor White
    Write-Host "5. Disable OneDrive" -ForegroundColor White
    Write-Host "6. Disable Cortana" -ForegroundColor White
    Write-Host "7. All of the above" -ForegroundColor White
    Write-Host "8. Return to main menu" -ForegroundColor White
    Write-Host ""
    
    $debloatChoice = Read-Host "Enter your choice (1-8)"
    
    switch ($debloatChoice) {
        "1" {
            Remove-BloatwareApps
        }
        "2" {
            Disable-WindowsTelemetry
        }
        "3" {
            Optimize-WindowsPerformance
        }
        "4" {
            Disable-UnnecessaryServices
        }
        "5" {
            Disable-OneDrive
        }
        "6" {
            Disable-Cortana
        }
        "7" {
            Remove-BloatwareApps
            Disable-WindowsTelemetry
            Optimize-WindowsPerformance
            Disable-UnnecessaryServices
            Disable-OneDrive
            Disable-Cortana
        }
        "8" {
            return
        }
        default {
            Write-Host "Invalid choice. No changes were made." -ForegroundColor Red
            return
        }
    }
    
    Write-LogEntry "Windows debloat completed" -Level "SUCCESS"
}

# Export the functions
Export-ModuleMember -Function Remove-BloatwareApps, Disable-WindowsTelemetry, 
    Optimize-WindowsPerformance, Disable-UnnecessaryServices, 
    Disable-OneDrive, Disable-Cortana, Invoke-WindowsDebloat