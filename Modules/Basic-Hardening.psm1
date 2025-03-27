<#
.SYNOPSIS
    Basic Windows Hardening module
.DESCRIPTION
    Contains functions for basic Windows security hardening
#>

function Enable-WindowsDefender {
    <#
    .SYNOPSIS
        Enables and configures Windows Defender
    #>
    Write-Banner "Windows Defender Configuration"
    
    # Enable Windows Defender
    Invoke-AndLogCommand -Description "Enabling Windows Defender" -Command {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisablePrivacyMode $false
        return "Windows Defender protections enabled"
    }
    
    # Update Windows Defender definitions
    Invoke-AndLogCommand -Description "Updating Windows Defender signatures" -Command {
        Update-MpSignature
        return "Windows Defender signatures updated"
    }
}

function Set-PasswordPolicies {
    <#
    .SYNOPSIS
        Configures password policies
    .PARAMETER MinLength
        Minimum password length
    #>
    param(
        [int]$MinLength = 12
    )
    
    Write-Banner "Password Policy Configuration"
    
    # Configure password policies
    Invoke-AndLogCommand -Description "Setting password complexity and length requirements" -Command {
        $tempPath = "C:\Windows\Temp\secpol.cfg"
        secedit /export /cfg $tempPath
        $content = Get-Content $tempPath
        $content = $content -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1'
        $content = $content -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = $MinLength"
        $content | Set-Content $tempPath
        secedit /configure /db secedit.sdb /cfg $tempPath /areas SECURITYPOLICY
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        return "Password policies configured successfully"
    }
}

function Protect-UserAccounts {
    <#
    .SYNOPSIS
        Secures user accounts and authentication
    #>
    Write-Banner "User Account Security"
    
    # Disable Guest Account
    Invoke-AndLogCommand -Description "Disabling Guest Account" -Command { 
        Net user Guest /active:no 
    }
    
    # Configure UAC to require credentials
    Set-AndLogSetting -Description "Configuring UAC to require credentials" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 1
    
    # Enforce Account Lockout Policy
    Invoke-AndLogCommand -Description "Enforcing Account Lockout Policy" -Command {
        $tempPath = "$env:TEMP\lockout.inf"
        "[Version]`r`nSignature=`"$CHICAGO$`"`r`n[System Access]`r`nLockoutBadCount = 5`r`nLockoutDuration = 30`r`nResetLockoutCount = 30`r`n" | 
            Out-File -FilePath $tempPath -Encoding ASCII
        secedit /configure /db "$env:windir\security\local.sdb" /cfg $tempPath /areas SECURITYPOLICY
        Remove-Item -Path $tempPath -Force
        return "Account lockout policy applied"
    }
}

function Protect-BasicNetwork {
    <#
    .SYNOPSIS
        Applies basic network security settings
    #>
    Write-Banner "Basic Network Protection"
    
    # Enable Firewall
    Invoke-AndLogCommand -Description "Ensuring Windows Firewall is enabled" -Command { 
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True 
    }
    
    # Disable SMBv1
    Set-AndLogSetting -Description "Disabling SMBv1 Protocol on Server" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
    Invoke-AndLogCommand -Description "Disabling SMBv1 Server Configuration" -Command { 
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
    }
}

function Invoke-BasicHardening {
    <#
    .SYNOPSIS
        Performs basic security hardening
    .PARAMETER Config
        Configuration settings
    #>
    param(
        [hashtable]$Config
    )
    
    # Enable Windows Defender
    Enable-WindowsDefender
    
    # Set password policies
    Set-PasswordPolicies -MinLength $Config.PasswordMinLength
    
    # Protect user accounts
    Protect-UserAccounts
    
    # Enable basic network protection
    Protect-BasicNetwork
    
    Write-LogEntry "Basic hardening completed" -Level "SUCCESS"
}

# Export the functions
Export-ModuleMember -Function Enable-WindowsDefender, Set-PasswordPolicies, 
    Protect-UserAccounts, Protect-BasicNetwork, Invoke-BasicHardening