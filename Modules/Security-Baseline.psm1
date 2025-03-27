<#
.SYNOPSIS
    Security Baseline Assessment module
.DESCRIPTION
    Downloads and runs security baseline assessment for Windows 10/11
#>

function Invoke-SecurityBaselineAssessment {
    <#
    .SYNOPSIS
        Performs a security baseline assessment
    .PARAMETER ConfigPath
        Path to configuration files
    #>
    param(
        [string]$ConfigPath
    )
    
    Write-Banner "Security Baseline Assessment"
    
    # Create temporary directory for downloads
    $tempDir = Join-Path -Path $env:TEMP -ChildPath "WindowsSecurityBaseline"
    if (!(Test-Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }
    
    Write-LogEntry "Created temporary directory for baseline assessment at $tempDir" -Level "INFO"
    
    # Download the security baseline script from GitHub
    $baselineUrl = "https://raw.githubusercontent.com/atlantsecurity/windows-hardening-scripts/refs/heads/main/windows-11-hardening-script"
    $baselineScript = Join-Path -Path $tempDir -ChildPath "baseline-assessment.ps1"
    
    Write-LogEntry "Downloading security baseline script from GitHub..." -Level "INFO"
    
    try {
        Invoke-WebRequest -Uri $baselineUrl -OutFile $baselineScript -UseBasicParsing
        Write-LogEntry "Downloaded baseline script successfully" -Level "SUCCESS"
        
        # Generate report directory
        $reportDir = Join-Path -Path $ConfigPath -ChildPath "Reports"
        if (!(Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
        }
        
        $reportPath = Join-Path -Path $reportDir -ChildPath "SecurityBaseline_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        
        # Execute the script in assessment-only mode
        Write-LogEntry "Running security baseline assessment (this may take a few minutes)..." -Level "INFO"
        
        # Execute the downloaded script with assessment-only flag
        & $baselineScript -AssessmentOnly -ReportPath $reportPath
        
        if (Test-Path $reportPath) {
            Write-LogEntry "Security baseline assessment complete" -Level "SUCCESS"
            Write-LogEntry "Report saved to: $reportPath" -Level "SUCCESS"
            
            # Open the report
            Write-Output "Would you like to open the security baseline report? (Y/N)"
            $openReport = Read-Host
            if ($openReport -eq "Y" -or $openReport -eq "y") {
                Start-Process $reportPath
            }
        } else {
            Write-LogEntry "Report not generated. There might have been an issue with the assessment." -Level "WARNING"
        }
    }
    catch {
        Write-LogEntry "Error downloading or running security baseline: $($_.Exception.Message)" -Level "ERROR"
    }
    finally {
        # Clean up temp files
        if (Test-Path $baselineScript) {
            Remove-Item $baselineScript -Force
        }
    }
}

# Export the function
Export-ModuleMember -Function Invoke-SecurityBaselineAssessment