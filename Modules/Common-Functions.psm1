<#
.SYNOPSIS
    Common functions for Windows Hardening script
.DESCRIPTION
    Contains helper functions for logging, UI elements, and system operations
#>

# Global variables
$Global:LogFilePath = ""

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging system
    .PARAMETER Path
        Path where log files will be stored
    #>
    param(
        [string]$Path = "$env:USERPROFILE"
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logFileName = "Windows_Hardening_$timestamp.log"
    $Global:LogFilePath = Join-Path -Path $Path -ChildPath $logFileName
    
    # Initialize log file
    "Windows 10/11 Hardening Log - Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $Global:LogFilePath
    Write-Output "Logging initialized. Log file: $Global:LogFilePath"
}

function Write-Banner {
    <#
    .SYNOPSIS
        Creates a visual banner in console and log
    .PARAMETER Text
        The text to display in the banner
    #>
    param([string]$Text)
    
    $line = "=" * 80
    $spacedText = "===  $Text  "
    $spacedText = $spacedText.PadRight(80, "=")
    
    Write-Output $line
    Write-Output $spacedText
    Write-Output $line
    
    Add-Content -Path $Global:LogFilePath -Value $line
    Add-Content -Path $Global:LogFilePath -Value $spacedText
    Add-Content -Path $Global:LogFilePath -Value $line
}

function Write-LogEntry {
    <#
    .SYNOPSIS
        Writes a consistent log entry to the log file
    .PARAMETER Message
        The message to log
    .PARAMETER Level
        The logging level (INFO, WARNING, ERROR)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $Global:LogFilePath -Value $logEntry
    
    # Also write to console with appropriate color
    switch ($Level) {
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry }
    }
}

function Set-AndLogSetting {
    <#
    .SYNOPSIS
        Sets a registry setting and logs before/after values
    .PARAMETER Description
        Description of the setting being changed
    .PARAMETER Path
        Registry path
    .PARAMETER Name
        Registry value name
    .PARAMETER Value
        New value to set
    .PARAMETER SkipReadBefore
        Skip reading the value before changing (if it doesn't exist yet)
    #>
    param(
        [string]$Description,
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [switch]$SkipReadBefore
    )
    
    Write-Output "  - $Description"
    Write-LogEntry "Setting: $Description" -Level "INFO"
    
    if (-not $SkipReadBefore) {
        try {
            $beforeValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | 
                           Select-Object -ExpandProperty $Name
            Write-LogEntry "  Before: $beforeValue" -Level "INFO"
        }
        catch {
            Write-LogEntry "  Before: [Value does not exist]" -Level "INFO"
        }
    } 
    else {
        Write-LogEntry "  Before: [Read skipped]" -Level "INFO"
    }
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-LogEntry "  Created path: $Path" -Level "INFO"
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
        
        $afterValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | 
                     Select-Object -ExpandProperty $Name
        Write-LogEntry "  After: $afterValue" -Level "SUCCESS"
    }
    catch {
        Write-LogEntry "  Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Set-AndLogService {
    <#
    .SYNOPSIS
        Configures a service and logs before/after state
    .PARAMETER ServiceName
        Name of the service to configure
    .PARAMETER TargetStatus
        Target status (Running/Stopped)
    .PARAMETER TargetStartupType
        Target startup type (Automatic/Manual/Disabled)
    #>
    param(
        [string]$ServiceName,
        [string]$TargetStatus,
        [string]$TargetStartupType
    )
    
    Write-Output "  - Configuring service: $ServiceName"
    Write-LogEntry "Configuring service: $ServiceName" -Level "INFO"
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        
        Write-LogEntry "  Before Status: $($service.Status)" -Level "INFO"
        Write-LogEntry "  Before StartType: $($wmiService.StartMode)" -Level "INFO"
        
        if ($TargetStatus -eq "Stopped" -and $service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        elseif ($TargetStatus -eq "Running" -and $service.Status -ne "Running") {
            Start-Service -Name $ServiceName -ErrorAction Stop
        }
        
        Set-Service -Name $ServiceName -StartupType $TargetStartupType -ErrorAction Stop
        
        $updatedService = Get-Service -Name $ServiceName
        $updatedWmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
        
        Write-LogEntry "  After Status: $($updatedService.Status)" -Level "INFO"
        Write-LogEntry "  After StartType: $($updatedWmiService.StartMode)" -Level "SUCCESS"
    }
    catch {
        Write-LogEntry "  Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Set-AndLogWindowsFeature {
    <#
    .SYNOPSIS
        Enables or disables a Windows feature and logs the change
    .PARAMETER FeatureName
        Name of the Windows feature
    .PARAMETER Enable
        Whether to enable or disable the feature
    #>
    param(
        [string]$FeatureName,
        [bool]$Enable
    )
    
    $action = if ($Enable) { "Enabling" } else { "Disabling" }
    Write-Output "  - $action Windows feature: $FeatureName"
    Write-LogEntry "$action Windows feature: $FeatureName" -Level "INFO"
    
    try {
        $beforeStatus = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName | 
                       Select-Object -ExpandProperty State
        Write-LogEntry "  Before: $beforeStatus" -Level "INFO"
        
        if ($Enable) {
            Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart
        } 
        else {
            Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart
        }
        
        $afterStatus = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName | 
                      Select-Object -ExpandProperty State
        Write-LogEntry "  After: $afterStatus" -Level "SUCCESS"
    }
    catch {
        Write-LogEntry "  Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Invoke-AndLogCommand {
    <#
    .SYNOPSIS
        Executes a command and logs the output
    .PARAMETER Description
        Description of the command being executed
    .PARAMETER Command
        ScriptBlock containing the command to execute
    #>
    param(
        [string]$Description,
        [scriptblock]$Command
    )
    
    Write-Output "  - $Description"
    Write-LogEntry "$Description" -Level "INFO"
    
    try {
        $output = & $Command
        if ($output) {
            Write-LogEntry "  Output: $output" -Level "INFO"
        }
        Write-LogEntry "  Command executed successfully" -Level "SUCCESS"
        return $output
    }
    catch {
        Write-LogEntry "  Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function New-SystemRestorePoint {
    <#
    .SYNOPSIS
        Creates a system restore point
    .PARAMETER Description
        Description for the restore point
    #>
    param(
        [string]$Description = "Before Windows Security Hardening"
    )
    
    Write-Output "Creating system restore point..."
    Write-LogEntry "Creating system restore point: $Description" -Level "INFO"
    
    try {
        # Ensure System Restore is enabled on the system drive
        Enable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction SilentlyContinue
        
        # Create the restore point
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS"
        
        Write-LogEntry "System restore point created successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-LogEntry "Failed to create restore point: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Export the functions
Export-ModuleMember -Function Initialize-Logging, Write-Banner, Write-LogEntry, Set-AndLogSetting, 
    Set-AndLogService, Set-AndLogWindowsFeature, Invoke-AndLogCommand, New-SystemRestorePoint