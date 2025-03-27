<#
.SYNOPSIS
    Performance Optimization module
.DESCRIPTION
    Enhances Windows performance and optimizes system resources
#>

function Optimize-Startup {
    <#
    .SYNOPSIS
        Manages and disables unnecessary startup programs
    #>
    Write-Banner "Startup Optimization"
    
    # Get current startup items
    try {
        $startupItems = @()
        
        # Get startup items from registry (Current User)
        $cuStartupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $cuStartupPath) {
            Get-ItemProperty -Path $cuStartupPath | Get-Member -MemberType NoteProperty | 
                Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') } | 
                ForEach-Object {
                    $startupItems += [PSCustomObject]@{
                        Name = $_.Name
                        Command = (Get-ItemProperty -Path $cuStartupPath -Name $_.Name).$($_.Name)
                        Location = "HKCU Run"
                        Type = "Registry"
                    }
                }
        }
        
        # Get startup items from registry (Local Machine)
        $lmStartupPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $lmStartupPath) {
            Get-ItemProperty -Path $lmStartupPath | Get-Member -MemberType NoteProperty | 
                Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') } | 
                ForEach-Object {
                    $startupItems += [PSCustomObject]@{
                        Name = $_.Name
                        Command = (Get-ItemProperty -Path $lmStartupPath -Name $_.Name).$($_.Name)
                        Location = "HKLM Run"
                        Type = "Registry"
                    }
                }
        }
        
        # Get startup items from Task Scheduler
        Get-ScheduledTask | Where-Object { $_.Settings.DisallowStartIfOnBatteries -eq $false -and $_.Settings.StopIfGoingOnBatteries -eq $false -and $_.Triggers.LogonTrigger } | 
            ForEach-Object {
                $startupItems += [PSCustomObject]@{
                    Name = $_.TaskName
                    Command = $_.Actions.Execute
                    Location = "Task Scheduler"
                    Type = "Task"
                }
            }
        
        # Get startup items from Startup folder (Current User)
        $cuStartupFolder = [Environment]::GetFolderPath('Startup')
        if (Test-Path $cuStartupFolder) {
            Get-ChildItem -Path $cuStartupFolder -Filter *.lnk | 
                ForEach-Object {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($_.FullName)
                    
                    $startupItems += [PSCustomObject]@{
                        Name = $_.BaseName
                        Command = $shortcut.TargetPath
                        Location = "Startup Folder (User)"
                        Type = "Shortcut"
                    }
                }
        }
        
        # Get startup items from Startup folder (All Users)
        $allUsersStartupFolder = [Environment]::GetFolderPath('CommonStartup')
        if (Test-Path $allUsersStartupFolder) {
            Get-ChildItem -Path $allUsersStartupFolder -Filter *.lnk | 
                ForEach-Object {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($_.FullName)
                    
                    $startupItems += [PSCustomObject]@{
                        Name = $_.BaseName
                        Command = $shortcut.TargetPath
                        Location = "Startup Folder (All Users)"
                        Type = "Shortcut"
                    }
                }
        }
        
        # Display startup items
        if ($startupItems.Count -gt 0) {
            Write-Host "Current Startup Items:" -ForegroundColor Cyan
            Write-Host "=====================" -ForegroundColor Cyan
            
            $counter = 1
            foreach ($item in $startupItems) {
                Write-Host "`n$counter. $($item.Name)" -ForegroundColor Yellow
                Write-Host "   Command: $($item.Command)" -ForegroundColor White
                Write-Host "   Location: $($item.Location)" -ForegroundColor White
                Write-Host "   Type: $($item.Type)" -ForegroundColor White
                $counter++
            }
            
            # Known safe and unsafe startup items
            $safeStartupItems = @(
                "SecurityHealth",
                "Windows Security notification icon",
                "OneDrive",
                "Dropbox",
                "RealTimeProtection"
            )
            
            $unsafeStartupItems = @(
                "ccleaner",
                "utorrent",
                "bittorrent",
                "anydesk",
                "teamviewer",
                "ammy",
                "steam"
            )
            
            # Suggest optimizations
            Write-Host "`nRecommended Actions:" -ForegroundColor Green
            
            $checkedItems = @()
            foreach ($item in $startupItems) {
                $recommendation = "Unknown"
                
                # Check if it's in our known lists
                $isSafe = $false
                foreach ($safeItem in $safeStartupItems) {
                    if ($item.Name -like "*$safeItem*" -or $item.Command -like "*$safeItem*") {
                        $isSafe = $true
                        break
                    }
                }
                
                $isUnsafe = $false
                foreach ($unsafeItem in $unsafeStartupItems) {
                    if ($item.Name -like "*$unsafeItem*" -or $item.Command -like "*$unsafeItem*") {
                        $isUnsafe = $true
                        break
                    }
                }
                
                if ($isSafe) {
                    $recommendation = "Keep (Security/System)"
                } elseif ($isUnsafe) {
                    $recommendation = "Consider disabling (Performance impact)"
                } else {
                    # Try to detect known programs
                    if ($item.Command -like "*Microsoft*" -or $item.Command -like "*Windows*") {
                        $recommendation = "Keep (Microsoft/Windows component)"
                    } elseif ($item.Name -like "*update*" -or $item.Command -like "*update*") {
                        $recommendation = "Consider disabling (Updates can run manually)"
                    } else {
                        $recommendation = "Review (Unrecognized)"
                    }
                }
                
                $checkedItems += [PSCustomObject]@{
                    Index = $checkedItems.Count + 1
                    Name = $item.Name
                    Recommendation = $recommendation
                    Type = $item.Type
                    Location = $item.Location
                }
            }
            
            # Display recommendations
            Write-Host "`nStartup Item Recommendations:" -ForegroundColor Cyan
            
            foreach ($item in $checkedItems) {
                $recommendationColor = switch ($item.Recommendation) {
                    { $_ -like "Keep*" } { "Green" }
                    { $_ -like "Consider*" } { "Yellow" }
                    default { "White" }
                }
                
                Write-Host "$($item.Index). $($item.Name): " -NoNewline
                Write-Host "$($item.Recommendation)" -ForegroundColor $recommendationColor
            }
            
            # Ask if user wants to disable any items
            Write-Host "`nWould you like to disable any startup items? (Y/N)" -ForegroundColor Yellow
            $disableResponse = Read-Host
            
            if ($disableResponse -eq "Y" -or $disableResponse -eq "y") {
                Write-Host "Enter the numbers of items to disable (comma-separated, e.g., 1,3,5): " -ForegroundColor Yellow
                $disableIndexes = (Read-Host) -split ',' | ForEach-Object { $_.Trim() }
                
                foreach ($index in $disableIndexes) {
                    $indexNum = [int]$index - 1
                    if ($indexNum -ge 0 -and $indexNum -lt $startupItems.Count) {
                        $itemToDisable = $startupItems[$indexNum]
                        
                        try {
                            switch ($itemToDisable.Type) {
                                "Registry" {
                                    if ($itemToDisable.Location -eq "HKCU Run") {
                                        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $itemToDisable.Name -ErrorAction Stop
                                    } elseif ($itemToDisable.Location -eq "HKLM Run") {
                                        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $itemToDisable.Name -ErrorAction Stop
                                    }
                                }
                                "Task" {
                                    Disable-ScheduledTask -TaskName $itemToDisable.Name -ErrorAction Stop
                                }
                                "Shortcut" {
                                    if ($itemToDisable.Location -eq "Startup Folder (User)") {
                                        $startupPath = [Environment]::GetFolderPath('Startup')
                                    } else {
                                        $startupPath = [Environment]::GetFolderPath('CommonStartup')
                                    }
                                    
                                    Remove-Item -Path "$startupPath\$($itemToDisable.Name).lnk" -ErrorAction Stop
                                }
                            }
                            
                            Write-Host "Successfully disabled: $($itemToDisable.Name)" -ForegroundColor Green
                            Write-LogEntry "Disabled startup item: $($itemToDisable.Name)" -Level "SUCCESS"
                        } catch {
                            Write-Host "Failed to disable: $($itemToDisable.Name) - $($_.Exception.Message)" -ForegroundColor Red
                            Write-LogEntry "Failed to disable startup item: $($itemToDisable.Name) - $($_.Exception.Message)" -Level "ERROR"
                        }
                    } else {
                        Write-Host "Invalid item number: $index" -ForegroundColor Red
                    }
                }
            }
        } else {
            Write-Host "No startup items found." -ForegroundColor Yellow
        }
    } catch {
        Write-LogEntry "Error analyzing startup items: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Error analyzing startup items: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Configure-WindowsUpdateDelivery {
    <#
    .SYNOPSIS
        Configures Windows Update Delivery Optimization
    #>
    Write-Banner "Windows Update Delivery Optimization"
    
    # Show current settings
    $doPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    if (Test-Path $doPath) {
        $doConfig = Get-ItemProperty -Path $doPath
        
        Write-Host "Current Delivery Optimization Settings:" -ForegroundColor Cyan
        Write-Host "====================================" -ForegroundColor Cyan
        
        $doMode = if ($doConfig.DODownloadMode -ne $null) { $doConfig.DODownloadMode } else { "Not set" }
        
        $modeDescription = switch ($doMode) {
            0 { "Disabled (HTTP only, no peering)" }
            1 { "PCs on local network only" }
            2 { "Local network and Internet PCs" }
            3 { "Local network, Internet, and Internet PCs from same organization" }
            99 { "Simple download mode (no peering)" }
            100 { "Bypass mode (disable with registry key)" }
            default { "Unknown or not set" }
        }
        
        Write-Host "Download Mode: $doMode - $modeDescription" -ForegroundColor White
        
        if ($doConfig.DODownloadMode -ne 0 -and $doConfig.DODownloadMode -ne 99 -and $doConfig.DODownloadMode -ne 100) {
            # Display bandwidth limits if peering is enabled
            $downloadPercentage = if ($doConfig.DODownloadModeProvider -ne $null) { $doConfig.DODownloadModeProvider } else { "Not set" }
            $monthlyUploadGB = if ($doConfig.DOMonthlyUploadDataCap -ne $null) { $doConfig.DOMonthlyUploadDataCap / 1GB } else { "Not set" }
            
            Write-Host "Background Download Bandwidth Limit: $downloadPercentage%" -ForegroundColor White
            Write-Host "Monthly Upload Limit: $monthlyUploadGB GB" -ForegroundColor White
        }
    } else {
        Write-Host "Delivery Optimization settings registry key not found." -ForegroundColor Yellow
    }
    
    # Configure settings
    Write-Host "`nConfigure Delivery Optimization:" -ForegroundColor Yellow
    Write-Host "1. Disable completely (HTTP only, most private)" -ForegroundColor White
    Write-Host "2. Local network only (balanced)" -ForegroundColor White
    Write-Host "3. Local network and Internet (fastest, least private)" -ForegroundColor White
    Write-Host "4. No change" -ForegroundColor White
    
    $doChoice = Read-Host "`nEnter your choice (1-4)"
    
    switch ($doChoice) {
        "1" {
            Set-AndLogSetting -Description "Disabling Delivery Optimization" -Path $doPath -Name "DODownloadMode" -Value 0
            Write-Host "Delivery Optimization set to HTTP only (no peering)." -ForegroundColor Green
        }
        "2" {
            Set-AndLogSetting -Description "Setting Delivery Optimization to local network" -Path $doPath -Name "DODownloadMode" -Value 1
            
            # Set bandwidth limits
            Set-AndLogSetting -Description "Setting download bandwidth limit" -Path $doPath -Name "DODownloadModeProvider" -Value 60
            Set-AndLogSetting -Description "Setting monthly upload limit" -Path $doPath -Name "DOMonthlyUploadDataCap" -Value (5GB)
            
            Write-Host "Delivery Optimization set to local network only with bandwidth limits." -ForegroundColor Green
        }
        "3" {
            Set-AndLogSetting -Description "Setting Delivery Optimization to LAN and Internet" -Path $doPath -Name "DODownloadMode" -Value 3
            
            # Set bandwidth limits
            Set-AndLogSetting -Description "Setting download bandwidth limit" -Path $doPath -Name "DODownloadModeProvider" -Value 80
            Set-AndLogSetting -Description "Setting monthly upload limit" -Path $doPath -Name "DOMonthlyUploadDataCap" -Value (10GB)
            
            Write-Host "Delivery Optimization set to local network and Internet with bandwidth limits." -ForegroundColor Green
        }
        "4" {
            Write-Host "No changes made to Delivery Optimization settings." -ForegroundColor Yellow
        }
        default {
            Write-Host "Invalid choice. No changes made to Delivery Optimization settings." -ForegroundColor Red
        }
    }
}

function Configure-StorageSense {
    <#
    .SYNOPSIS
        Configures Storage Sense for automated disk cleanup
    #>
    Write-Banner "Storage Sense Configuration"
    
    # Storage Sense base path
    $storageSensePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
    
    # Create the key if it doesn't exist
    if (!(Test-Path $storageSensePath)) {
        New-Item -Path $storageSensePath -Force | Out-Null
    }
    
    # Current settings
    $currentSettings = Get-ItemProperty -Path $storageSensePath -ErrorAction SilentlyContinue
    
    $enabled = if ($currentSettings.01 -ne $null) { $currentSettings.01 } else { 0 }
    $frequency = if ($currentSettings.2048 -ne $null) { $currentSettings.2048 } else { 0 }
    $tempFilesCleanup = if ($currentSettings.04 -ne $null) { $currentSettings.04 } else { 0 }
    $recyclebinCleanup = if ($currentSettings.08 -ne $null) { $currentSettings.08 } else { 0 }
    $downloadsFolderCleanup = if ($currentSettings.32 -ne $null) { $currentSettings.32 } else { 0 }
    $recyclebinDays = if ($currentSettings.256 -ne $null) { $currentSettings.256 } else { 0 }
    $downloadsFolderDays = if ($currentSettings.512 -ne $null) { $currentSettings.512 } else { 0 }
    
    $frequencyText = switch ($frequency) {
        0 { "During low free disk space" }
        1 { "Every day" }
        7 { "Every week" }
        30 { "Every month" }
        default { "Unknown" }
    }
    
    # Display current settings
    Write-Host "Current Storage Sense Settings:" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host "Storage Sense Enabled: $($enabled -eq 1)" -ForegroundColor White
    Write-Host "Run Frequency: $frequencyText" -ForegroundColor White
    Write-Host "Delete Temporary Files: $($tempFilesCleanup -eq 1)" -ForegroundColor White
    Write-Host "Clean Recycle Bin: $($recyclebinCleanup -eq 1)" -ForegroundColor White
    Write-Host "Clean Downloads Folder: $($downloadsFolderCleanup -eq 1)" -ForegroundColor White
    Write-Host "Recycle Bin Cleanup (days): $recyclebinDays" -ForegroundColor White
    Write-Host "Downloads Folder Cleanup (days): $downloadsFolderDays" -ForegroundColor White
    
    # Configure settings
    Write-Host "`nConfigure Storage Sense:" -ForegroundColor Yellow
    Write-Host "1. Enable Storage Sense (recommended)" -ForegroundColor White
    Write-Host "2. Disable Storage Sense" -ForegroundColor White
    Write-Host "3. No change" -ForegroundColor White
    
    $storageChoice = Read-Host "`nEnter your choice (1-3)"
    
    switch ($storageChoice) {
        "1" {
            # Enable Storage Sense
            Set-AndLogSetting -Description "Enabling Storage Sense" -Path $storageSensePath -Name "01" -Value 1
            
            # Ask for frequency
            Write-Host "`nChoose frequency:" -ForegroundColor Yellow
            Write-Host "1. During low free disk space" -ForegroundColor White
            Write-Host "2. Every day" -ForegroundColor White
            Write-Host "3. Every week" -ForegroundColor White
            Write-Host "4. Every month" -ForegroundColor White
            
            $frequencyChoice = Read-Host "`nEnter your choice (1-4)"
            
            $frequencyValue = switch ($frequencyChoice) {
                "1" { 0 }
                "2" { 1 }
                "3" { 7 }
                "4" { 30 }
                default { 7 } # Default to weekly
            }
            
            Set-AndLogSetting -Description "Setting Storage Sense frequency" -Path $storageSensePath -Name "2048" -Value $frequencyValue
            
            # Configure cleanup options
            Set-AndLogSetting -Description "Enabling temporary files cleanup" -Path $storageSensePath -Name "04" -Value 1
            
            # Configure Recycle Bin cleanup
            Write-Host "`nClean files in Recycle Bin if they've been there for over:" -ForegroundColor Yellow
            Write-Host "1. Never" -ForegroundColor White
            Write-Host "2. 1 day" -ForegroundColor White
            Write-Host "3. 14 days" -ForegroundColor White
            Write-Host "4. 30 days" -ForegroundColor White
            Write-Host "5. 60 days" -ForegroundColor White
            
            $recycleChoice = Read-Host "`nEnter your choice (1-5)"
            
            switch ($recycleChoice) {
                "1" {
                    Set-AndLogSetting -Description "Disabling Recycle Bin cleanup" -Path $storageSensePath -Name "08" -Value 0
                }
                "2" {
                    Set-AndLogSetting -Description "Enabling Recycle Bin cleanup" -Path $storageSensePath -Name "08" -Value 1
                    Set-AndLogSetting -Description "Setting Recycle Bin cleanup days" -Path $storageSensePath -Name "256" -Value 1
                }
                "3" {
                    Set-AndLogSetting -Description "Enabling Recycle Bin cleanup" -Path $storageSensePath -Name "08" -Value 1
                    Set-AndLogSetting -Description "Setting Recycle Bin cleanup days" -Path $storageSensePath -Name "256" -Value 14
                }
                "4" {
                    Set-AndLogSetting -Description "Enabling Recycle Bin cleanup" -Path $storageSensePath -Name "08" -Value 1
                    Set-AndLogSetting -Description "Setting Recycle Bin cleanup days" -Path $storageSensePath -Name "256" -Value 30
                }
                "5" {
                    Set-AndLogSetting -Description "Enabling Recycle Bin cleanup" -Path $storageSensePath -Name "08" -Value 1
                    Set-AndLogSetting -Description "Setting Recycle Bin cleanup days" -Path $storageSensePath -Name "256" -Value 60
                }
                default {
                    Set-AndLogSetting -Description "Enabling Recycle Bin cleanup" -Path $storageSensePath -Name "08" -Value 1
                    Set-AndLogSetting -Description "Setting Recycle Bin cleanup days" -Path $storageSensePath -Name "256" -Value 30
                }
            }
            
            # Configure Downloads folder cleanup
            Write-Host "`nClean files in Downloads folder if they've been there for over:" -ForegroundColor Yellow
            Write-Host "1. Never" -ForegroundColor White
            Write-Host "2. 30 days" -ForegroundColor White
            Write-Host "3. 60 days" -ForegroundColor White
            Write-Host "4. 90 days" -ForegroundColor White
            
            $downloadsChoice = Read-Host "`nEnter your choice (1-4)"
            
            switch ($downloadsChoice) {
                "1" {
                    Set-AndLogSetting -Description "Disabling Downloads folder cleanup" -Path $storageSensePath -Name "32" -Value 0
                }
                "2" {
                    Set-AndLogSetting -Description "Enabling Downloads folder cleanup" -Path $storageSensePath -Name "32" -Value 1
                    Set-AndLogSetting -Description "Setting Downloads folder cleanup days" -Path $storageSensePath -Name "512" -Value 30
                }
                "3" {
                    Set-AndLogSetting -Description "Enabling Downloads folder cleanup" -Path $storageSensePath -Name "32" -Value 1
                    Set-AndLogSetting -Description "Setting Downloads folder cleanup days" -Path $storageSensePath -Name "512" -Value 60
                }
                "4" {
                    Set-AndLogSetting -Description "Enabling Downloads folder cleanup" -Path $storageSensePath -Name "32" -Value 1
                    Set-AndLogSetting -Description "Setting Downloads folder cleanup days" -Path $storageSensePath -Name "512" -Value 90
                }
                default {
                    Set-AndLogSetting -Description "Disabling Downloads folder cleanup" -Path $storageSensePath -Name "32" -Value 0
                }
            }
            
            Write-Host "Storage Sense has been configured successfully." -ForegroundColor Green
        }
        "2" {
            # Disable Storage Sense
            Set-AndLogSetting -Description "Disabling Storage Sense" -Path $storageSensePath -Name "01" -Value 0
            Write-Host "Storage Sense has been disabled." -ForegroundColor Yellow
        }
        "3" {
            Write-Host "No changes made to Storage Sense settings." -ForegroundColor Yellow
        }
        default {
            Write-Host "Invalid choice. No changes made to Storage Sense settings." -ForegroundColor Red
        }
    }
}

function Optimize-SSDTrim {
    <#
    .SYNOPSIS
        Ensures TRIM is enabled for SSDs
    #>
    Write-Banner "SSD TRIM Optimization"
    
    # Check if system has an SSD
    $drives = Get-PhysicalDisk | Where-Object { $_.MediaType -eq "SSD" }
    
    if ($drives.Count -eq 0) {
        Write-Host "No SSD drives detected in the system." -ForegroundColor Yellow
        Write-LogEntry "No SSD drives detected, skipping TRIM optimization" -Level "INFO"
        return
    }
    
    # Check TRIM status
    $trimEnabled = $null
    try {
        $trimStatus = fsutil behavior query DisableDeleteNotify
        $trimEnabled = $trimStatus -like "*DisableDeleteNotify = 0*"
        
        Write-Host "SSD Information:" -ForegroundColor Cyan
        Write-Host "===============" -ForegroundColor Cyan
        
        foreach ($drive in $drives) {
            Write-Host "Drive: $($drive.FriendlyName)" -ForegroundColor White
            Write-Host "Size: $([math]::Round($drive.Size / 1GB, 2)) GB" -ForegroundColor White
            Write-Host "Health Status: $($drive.HealthStatus)" -ForegroundColor White
            Write-Host "Operational Status: $($drive.OperationalStatus)" -ForegroundColor White
        }
        
        Write-Host "`nTRIM Status: " -NoNewline
        if ($trimEnabled) {
            Write-Host "Enabled" -ForegroundColor Green
        } else {
            Write-Host "Disabled" -ForegroundColor Red
        }
    }
    catch {
        Write-LogEntry "Error checking TRIM status: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "Error checking TRIM status: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Enable TRIM if disabled
    if ($trimEnabled -eq $false) {
        Write-Host "`nTRIM is currently disabled. Would you like to enable it? (Y/N)" -ForegroundColor Yellow
        $enableTrimResponse = Read-Host
        
        if ($enableTrimResponse -eq "Y" -or $enableTrimResponse -eq "y") {
            try {
                Invoke-AndLogCommand -Description "Enabling TRIM for SSD drives" -Command {
                    fsutil behavior set DisableDeleteNotify 0
                    return "TRIM has been enabled for all SSD drives"
                }
                
                Write-Host "TRIM has been enabled for all SSD drives." -ForegroundColor Green
            }
            catch {
                Write-LogEntry "Error enabling TRIM: $($_.Exception.Message)" -Level "ERROR"
                Write-Host "Error enabling TRIM: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "`nTRIM is already enabled for all SSD drives." -ForegroundColor Green
    }
    
    # Schedule regular TRIM operation
    Write-Host "`nWould you like to schedule a weekly TRIM operation? (Y/N)" -ForegroundColor Yellow
    $scheduleTrimResponse = Read-Host
    
    if ($scheduleTrimResponse -eq "Y" -or $scheduleTrimResponse -eq "y") {
        try {
            $taskName = "WeeklyTRIM"
            $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            
            if ($taskExists) {
                Write-Host "A scheduled TRIM task already exists." -ForegroundColor Yellow
            } else {
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Optimize-Volume -DriveLetter C -ReTrim -Verbose`""
                $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "3:00 AM"
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Weekly TRIM operation for SSD health" -User "SYSTEM" -Force
                
                Write-Host "Weekly TRIM operation scheduled for every Sunday at 3:00 AM." -ForegroundColor Green
                Write-LogEntry "Scheduled weekly TRIM operation" -Level "SUCCESS"
            }
        }
        catch {
            Write-LogEntry "Error scheduling TRIM operation: $($_.Exception.Message)" -Level "ERROR"
            Write-Host "Error scheduling TRIM operation: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Additional SSD optimizations
    Write-Host "`nWould you like to apply additional SSD optimizations? (Y/N)" -ForegroundColor Yellow
    $additionalOptsResponse = Read-Host
    
    if ($additionalOptsResponse -eq "Y" -or $additionalOptsResponse -eq "y") {
        try {
            # Disable Prefetch/Superfetch for SSDs
            Set-AndLogService -ServiceName "SysMain" -TargetStatus "Stopped" -TargetStartupType "Disabled"
            
            # Disable defragmentation for SSDs
            $defragPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout"
            Set-AndLogSetting -Description "Disabling automatic defragmentation for SSDs" -Path $defragPath -Name "EnableAutoLayout" -Value 0
            
            Write-Host "Additional SSD optimizations applied." -ForegroundColor Green
            Write-LogEntry "Applied additional SSD optimizations" -Level "SUCCESS"
        }
        catch {
            Write-LogEntry "Error applying additional SSD optimizations: $($_.Exception.Message)" -Level "ERROR"
            Write-Host "Error applying additional SSD optimizations: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Invoke-PerformanceOptimization {
    <#
    .SYNOPSIS
        Performs performance optimization tasks
    #>
    param(
        [hashtable]$Config
    )
    
    Write-Banner "Performance Optimization"
    
    # Show menu for performance optimization options
    Write-Host "Performance Optimization Options:" -ForegroundColor Cyan
    Write-Host "1. Startup Optimization" -ForegroundColor White
    Write-Host "2. Windows Update Delivery Optimization" -ForegroundColor White
    Write-Host "3. Storage Sense Configuration" -ForegroundColor White
    Write-Host "4. SSD TRIM Optimization" -ForegroundColor White
    Write-Host "5. Apply All Performance Optimizations" -ForegroundColor White
    Write-Host "6. Return to Main Menu" -ForegroundColor White
    Write-Host ""
    
    $optimizationChoice = Read-Host "Enter your choice (1-6)"
    
    switch ($optimizationChoice) {
        "1" {
            Optimize-Startup
        }
        "2" {
            Configure-WindowsUpdateDelivery
        }
        "3" {
            Configure-StorageSense
        }
        "4" {
            Optimize-SSDTrim
        }
        "5" {
            Optimize-Startup
            Configure-WindowsUpdateDelivery
            Configure-StorageSense
            Optimize-SSDTrim
        }
        "6" {
            return
        }
        default {
            Write-Host "Invalid choice. No changes were made." -ForegroundColor Red
            return
        }
    }
    
    Write-LogEntry "Performance optimization completed" -Level "SUCCESS"
}

# Export the functions
Export-ModuleMember -Function Optimize-Startup, Configure-WindowsUpdateDelivery, 
    Configure-StorageSense, Optimize-SSDTrim, Invoke-PerformanceOptimization