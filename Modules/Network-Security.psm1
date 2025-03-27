<#
.SYNOPSIS
    Network Security module
.DESCRIPTION
    Advanced network security configurations for Windows
#>

function Configure-SecureDNS {
    <#
    .SYNOPSIS
        Configures DNS to use secure providers
    #>
    Write-Banner "Secure DNS Configuration"
    
    # Available secure DNS providers
    $dnsProviders = @(
        @{
            Name = "Cloudflare"
            Description = "Cloudflare 1.1.1.1 (Privacy-focused, fast)"
            Primary = "1.1.1.1"
            Secondary = "1.0.0.1"
            URL = "https://1.1.1.1/"
        },
        @{
            Name = "Cloudflare Family"
            Description = "Cloudflare 1.1.1.1 for Families (Blocks malware and adult content)"
            Primary = "1.1.1.3"
            Secondary = "1.0.0.3"
            URL = "https://1.1.1.1/family/"
        },
        @{
            Name = "Quad9"
            Description = "Quad9 (Security-focused, blocks malicious domains)"
            Primary = "9.9.9.9"
            Secondary = "149.112.112.112"
            URL = "https://quad9.net/"
        },
        @{
            Name = "Google"
            Description = "Google Public DNS (Fast and reliable)"
            Primary = "8.8.8.8"
            Secondary = "8.8.4.4"
            URL = "https://developers.google.com/speed/public-dns"
        },
        @{
            Name = "OpenDNS"
            Description = "OpenDNS (Security and content filtering)"
            Primary = "208.67.222.222"
            Secondary = "208.67.220.220"
            URL = "https://www.opendns.com/"
        },
        @{
            Name = "Comodo Secure"
            Description = "Comodo Secure DNS (Security-focused)"
            Primary = "8.26.56.26"
            Secondary = "8.20.247.20"
            URL = "https://www.comodo.com/secure-dns/"
        }
    )
    
    # Get current DNS configuration
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    Write-Host "Current Network Adapter DNS Configuration:" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    
    foreach ($adapter in $networkAdapters) {
        $dnsSettings = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4
        
        Write-Host "`nAdapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Yellow
        Write-Host "DNS Servers: $($dnsSettings.ServerAddresses -join ', ')" -ForegroundColor White
    }
    
    # Display available DNS providers
    Write-Host "`nAvailable Secure DNS Providers:" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    
    for ($i=0; $i -lt $dnsProviders.Count; $i++) {
        Write-Host "`n$($i+1). $($dnsProviders[$i].Name)" -ForegroundColor Yellow
        Write-Host "   $($dnsProviders[$i].Description)" -ForegroundColor White
        Write-Host "   Primary: $($dnsProviders[$i].Primary)" -ForegroundColor White
        Write-Host "   Secondary: $($dnsProviders[$i].Secondary)" -ForegroundColor White
    }
    
    Write-Host "`n$($dnsProviders.Count + 1). Keep current DNS settings" -ForegroundColor Yellow
    Write-Host "$($dnsProviders.Count + 2). Restore automatic DNS (DHCP)" -ForegroundColor Yellow
    
    # Ask user to select a DNS provider
    $dnsChoice = Read-Host "`nSelect a DNS provider (1-$($dnsProviders.Count+2))"
    
    if ($dnsChoice -match '^\d+$') {
        $choiceNumber = [int]$dnsChoice
        
        if ($choiceNumber -ge 1 -and $choiceNumber -le $dnsProviders.Count) {
            $selectedProvider = $dnsProviders[$choiceNumber - 1]
            
            # Ask which adapters to apply to
            Write-Host "`nSelect which network adapters to apply DNS changes to:" -ForegroundColor Yellow
            Write-Host "1. All active adapters" -ForegroundColor White
            Write-Host "2. Select specific adapters" -ForegroundColor White
            
            $adapterChoice = Read-Host "`nEnter your choice (1-2)"
            
            $adaptersToChange = @()
            
            if ($adapterChoice -eq "1") {
                $adaptersToChange = $networkAdapters
            } 
            elseif ($adapterChoice -eq "2") {
                for ($i=0; $i -lt $networkAdapters.Count; $i++) {
                    Write-Host "$($i+1). $($networkAdapters[$i].Name) ($($networkAdapters[$i].InterfaceDescription))" -ForegroundColor White
                }
                
                $adapterIndexes = Read-Host "`nEnter adapter numbers (comma-separated, e.g., 1,3)"
                $adapterNumbers = $adapterIndexes -split ',' | ForEach-Object { $_.Trim() }
                
                foreach ($num in $adapterNumbers) {
                    if ([int]$num -ge 1 -and [int]$num -le $networkAdapters.Count) {
                        $adaptersToChange += $networkAdapters[[int]$num - 1]
                    }
                }
            }
            
            # Apply DNS changes
            if ($adaptersToChange.Count -gt 0) {
                foreach ($adapter in $adaptersToChange) {
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $selectedProvider.Primary, $selectedProvider.Secondary
                        
                        Write-Host "Applied $($selectedProvider.Name) DNS to adapter: $($adapter.Name)" -ForegroundColor Green
                        Write-LogEntry "Applied $($selectedProvider.Name) DNS to adapter: $($adapter.Name)" -Level "SUCCESS"
                    }
                    catch {
                        Write-Host "Failed to set DNS on adapter $($adapter.Name): $($_.Exception.Message)" -ForegroundColor Red
                        Write-LogEntry "Failed to set DNS on adapter $($adapter.Name): $($_.Exception.Message)" -Level "ERROR"
                    }
                }
                
                Write-Host "`nDNS configuration complete. You are now using $($selectedProvider.Name) DNS servers." -ForegroundColor Green
                Write-Host "For more information, visit: $($selectedProvider.URL)" -ForegroundColor Cyan
            } else {
                Write-Host "No adapters selected. DNS settings unchanged." -ForegroundColor Yellow
            }
        }
        elseif ($choiceNumber -eq $dnsProviders.Count + 1) {
            Write-Host "Keeping current DNS settings." -ForegroundColor Yellow
        }
        elseif ($choiceNumber -eq $dnsProviders.Count + 2) {
            # Restore automatic DNS
            foreach ($adapter in $networkAdapters) {
                try {
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses
                    
                    Write-Host "Reset DNS settings to automatic (DHCP) on adapter: $($adapter.Name)" -ForegroundColor Green
                    Write-LogEntry "Reset DNS settings to automatic (DHCP) on adapter: $($adapter.Name)" -Level "SUCCESS"
                }
                catch {
                    Write-Host "Failed to reset DNS on adapter $($adapter.Name): $($_.Exception.Message)" -ForegroundColor Red
                    Write-LogEntry "Failed to reset DNS on adapter $($adapter.Name): $($_.Exception.Message)" -Level "ERROR"
                }
            }
            
            Write-Host "`nDNS configuration reset to automatic (DHCP)." -ForegroundColor Green
        }
        else {
            Write-Host "Invalid choice. DNS settings unchanged." -ForegroundColor Red
        }
    } else {
        Write-Host "Invalid input. DNS settings unchanged." -ForegroundColor Red
    }
}

function Disable-NICPowerSaving {
    <#
    .SYNOPSIS
        Disables power saving mode on network adapters
    #>
    Write-Banner "NIC Power Saving Disabling"
    
    # Get network adapters
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    if ($networkAdapters.Count -eq 0) {
        Write-Host "No active network adapters found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Active Network Adapters:" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    
    foreach ($adapter in $networkAdapters) {
        Write-Host "`nAdapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Yellow
        
        # Get adapter power settings
        try {
            $devicePath = (Get-PnpDeviceProperty -InstanceId $adapter.DeviceID -KeyName DEVPKEY_Device_LocationPaths).Data[0]
            if ($devicePath) {
                $powerMgmtSupported = $true
                Write-Host "Power Management Supported: Yes" -ForegroundColor White
            } else {
                $powerMgmtSupported = $false
                Write-Host "Power Management Supported: Unknown" -ForegroundColor Gray
            }
        }
        catch {
            $powerMgmtSupported = $false
            Write-Host "Power Management Supported: No" -ForegroundColor Gray
        }
    }
    
    # Confirm disabling power saving
    Write-Host "`nWould you like to disable power saving on all network adapters? (Y/N)" -ForegroundColor Yellow
    $response = Read-Host
    
    if ($response -eq "Y" -or $response -eq "y") {
        Write-Host "`nDisabling power saving features on network adapters..." -ForegroundColor Cyan
        
        foreach ($adapter in $networkAdapters) {
            try {
                # Use DevCon (or PowerShell alternative) to disable power management
                Invoke-AndLogCommand -Description "Disabling power management for adapter $($adapter.Name)" -Command {
                    # This approach uses registry editing since DevCon requires external tools
                    $deviceKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\$($adapter.DeviceID.Split('\')[-1])"
                    if (Test-Path $deviceKey) {
                        Set-ItemProperty -Path $deviceKey -Name "PnPCapabilities" -Value 24 -Type DWord -ErrorAction Stop
                        return "Power management disabled via registry for $($adapter.Name)"
                    } else {
                        # Try alternative method using the device interface index
                        $adapters = Get-WmiObject -Class Win32_NetworkAdapter
                        $nicIndex = ($adapters | Where-Object { $_.NetConnectionID -eq $adapter.Name }).DeviceID
                        
                        if ($nicIndex) {
                            $deviceKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\$('{0:D4}' -f $nicIndex)"
                            if (Test-Path $deviceKey) {
                                Set-ItemProperty -Path $deviceKey -Name "PnPCapabilities" -Value 24 -Type DWord -ErrorAction Stop
                                return "Power management disabled via WMI index for $($adapter.Name)"
                            }
                        }
                        
                        return "Unable to find registry key for adapter $($adapter.Name)"
                    }
                }
            }
            catch {
                Write-Host "Error disabling power management for $($adapter.Name): $($_.Exception.Message)" -ForegroundColor Red
                Write-LogEntry "Error disabling power management for $($adapter.Name): $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        Write-Host "`nPower saving has been disabled on network adapters." -ForegroundColor Green
        Write-Host "Note: You may need to restart your computer for these changes to take effect." -ForegroundColor Yellow
    } else {
        Write-Host "No changes made to network adapter power settings." -ForegroundColor Yellow
    }
}

function Disable-NetworkDiscoveryProtocols {
    <#
    .SYNOPSIS
        Disables NetBIOS, LLMNR, and mDNS
    #>
    Write-Banner "Network Discovery Protocol Hardening"
    
    # Check current status
    Write-Host "Current Protocol Status:" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    
    # Check NetBIOS
    $netbiosStatus = "Unknown"
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
        $netbiosEnabled = $false
        
        foreach ($adapter in $adapters) {
            if ($adapter.TcpipNetbiosOptions -ne 2) {
                $netbiosEnabled = $true
                break
            }
        }
        
        $netbiosStatus = if ($netbiosEnabled) { "Enabled" } else { "Disabled" }
    }
    catch {
        $netbiosStatus = "Error checking"
        Write-LogEntry "Error checking NetBIOS status: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Check LLMNR
    $llmnrStatus = "Unknown"
    try {
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (Test-Path $llmnrPath) {
            $llmnrSetting = Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
            if ($llmnrSetting -and $llmnrSetting.EnableMulticast -eq 0) {
                $llmnrStatus = "Disabled"
            } else {
                $llmnrStatus = "Enabled"
            }
        } else {
            $llmnrStatus = "Enabled (Default)"
        }
    }
    catch {
        $llmnrStatus = "Error checking"
        Write-LogEntry "Error checking LLMNR status: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Check mDNS
    $mdnsStatus = "Unknown"
    try {
        $mdnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if (Test-Path $mdnsPath) {
            $mdnsSetting = Get-ItemProperty -Path $mdnsPath -Name "EnableMDNS" -ErrorAction SilentlyContinue
            if ($mdnsSetting -and $mdnsSetting.EnableMDNS -eq 0) {
                $mdnsStatus = "Disabled"
            } else {
                $mdnsStatus = "Enabled"
            }
        } else {
            $mdnsStatus = "Enabled (Default)"
        }
    }
    catch {
        $mdnsStatus = "Error checking"
        Write-LogEntry "Error checking mDNS status: $($_.Exception.Message)" -Level "ERROR"
    }
    
    Write-Host "NetBIOS over TCP/IP: $netbiosStatus" -ForegroundColor White
    Write-Host "LLMNR (Link-Local Multicast Name Resolution): $llmnrStatus" -ForegroundColor White
    Write-Host "mDNS (Multicast DNS): $mdnsStatus" -ForegroundColor White
    
    # Disable protocols
    Write-Host "`nDisable Network Discovery Protocols:" -ForegroundColor Yellow
    Write-Host "1. Disable all protocols (most secure)" -ForegroundColor White
    Write-Host "2. Disable only NetBIOS" -ForegroundColor White
    Write-Host "3. Disable only LLMNR" -ForegroundColor White
    Write-Host "4. Disable only mDNS" -ForegroundColor White
    Write-Host "5. No changes" -ForegroundColor White
    
    $protocolChoice = Read-Host "`nEnter your choice (1-5)"
    
    switch ($protocolChoice) {
        "1" {
            # Disable all protocols
            Disable-NetBIOS
            Disable-LLMNR
            Disable-MDNS
        }
        "2" {
            # Disable only NetBIOS
            Disable-NetBIOS
        }
        "3" {
            # Disable only LLMNR
            Disable-LLMNR
        }
        "4" {
            # Disable only mDNS
            Disable-MDNS
        }
        "5" {
            Write-Host "No changes made to network discovery protocols." -ForegroundColor Yellow
        }
        default {
            Write-Host "Invalid choice. No changes made." -ForegroundColor Red
        }
    }
}

function Disable-NetBIOS {
    <#
    .SYNOPSIS
        Disables NetBIOS over TCP/IP
    #>
    Write-Host "`nDisabling NetBIOS over TCP/IP..." -ForegroundColor Cyan
    
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
        
        foreach ($adapter in $adapters) {
            $result = $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
            
           if ($result.ReturnValue -eq 0) {
                Write-Host "NetBIOS disabled on adapter: $($adapter.Description)" -ForegroundColor Green
                Write-LogEntry "NetBIOS disabled on adapter: $($adapter.Description)" -Level "SUCCESS"
            } else {
                Write-Host "Failed to disable NetBIOS on adapter: $($adapter.Description) (Code: $($result.ReturnValue))" -ForegroundColor Red
                Write-LogEntry "Failed to disable NetBIOS on adapter: $($adapter.Description) (Code: $($result.ReturnValue))" -Level "ERROR"
            }
        }
        
        # Also disable NetBIOS via registry to ensure it stays disabled
        Set-AndLogSetting -Description "Disabling NetBIOS in registry" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NetbiosOptions" -Value 2 