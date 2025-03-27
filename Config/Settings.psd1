@{
    # Log settings
    LogPath                = "$env:USERPROFILE"
    
    # Hardening options
    DisableRemoteAccess    = $true  # Disable RDP, WinRM, etc.
    DisableUnnecessarySvcs = $true  # Disable non-essential services
    DisableUSBStorage      = $false # Set to $true to disable USB storage
    DisableIPv6            = $false # Set to $true to disable IPv6
    PasswordMinLength      = 12     # Minimum password length
    EnableBitLocker        = $true  # Enable BitLocker encryption
    
    # Apps to consider for removal (comma-separated list)
    AppsToRemove           = @(
        "*bing*", 
        "*Xbox*", 
        "*ZuneMusic*", 
        "*WindowsMaps*"
    )
    
    # Services to disable (can be customized)
    ServicesToDisable      = @(
        "XblGameSave", 
        "XboxNetApiSvc", 
        "WbioSrvc", 
        "SharedAccess", 
        "WpnService"
    )
}