# Windows 10/11 Hardening Toolkit

A comprehensive PowerShell toolkit for hardening, optimising, and securing Windows 10 and Windows 11 systems. This collection of scripts provides a modular approach to system security, privacy protection, performance optimization, and debloating.

## Features

- **Security Baseline Assessment**: Analyze your system against security best practices
- **Windows Debloating**: Remove unnecessary apps and features
- **Privacy Protection**: Control data collection and enhance privacy
- **Performance Optimization**: Improve system responsiveness and efficiency
- **Network Security**: Enhance network-related security settings
- **Additional Security Features**: Configure browser security, TPM, Secure Boot
- **Tiered Hardening**: Basic, Standard, and Enhanced security profiles

## Requirements

- Windows 10 (version 1903 or newer) or Windows 11
- PowerShell 5.1 or newer
- Administrator privileges
- Internet connectivity for some features

## Installation

1. Clone this repository or download and extract the ZIP file
2. Right-click on `Run-Hardening.ps1` and select "Run with PowerShell"
3. If prompted about execution policy, consider running: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`

## Usage

Run the main script as Administrator:

```powershell
.\Run-Hardening.ps1
```

Navigate the menu by entering the number of your desired option.

## Directory Structure

```
Windows-Hardening/
├── Run-Hardening.ps1           # Main script with menu interface
├── Modules/
│   ├── Common-Functions.psm1    # Shared functions and utilities
│   ├── Security-Baseline.psm1   # Security assessment functions
│   ├── Basic-Hardening.psm1     # Basic security hardening
│   ├── Standard-Hardening.psm1  # Standard security hardening
│   ├── Enhanced-Hardening.psm1  # Enhanced security hardening
│   ├── Network-Hardening.psm1   # Network-specific hardening
│   ├── Windows-Debloat.psm1     # Windows bloatware removal
│   ├── Privacy-Protection.psm1  # Privacy enhancement features
│   ├── Additional-Security.psm1 # Browser, TPM, and other security
│   ├── Performance-Optimization.psm1 # System performance features
│   └── Network-Security.psm1    # Advanced network security
└── Config/
    └── Settings.psd1           # Configuration settings
```

## Configuration Settings

The `Settings.psd1` file contains configurable parameters that control the behavior of various hardening features:

```powershell
@{
    # Log settings
    LogPath                = "$env:USERPROFILE"  # Where logs are stored
    
    # Hardening options
    DisableRemoteAccess    = $true  # Disable RDP, WinRM, etc.
    DisableUnnecessarySvcs = $true  # Disable non-essential services
    DisableUSBStorage      = $false # Disable USB storage devices
    DisableIPv6            = $false # Disable IPv6 networking
    PasswordMinLength      = 12     # Minimum password length requirement
    EnableBitLocker        = $true  # Enable drive encryption
    
    # Apps to remove during debloat
    AppsToRemove           = @(
        "*bing*", 
        "*Xbox*", 
        "*ZuneMusic*", 
        "*WindowsMaps*"
    )
    
    # Services to disable during hardening
    ServicesToDisable      = @(
        "XblGameSave", 
        "XboxNetApiSvc", 
        "WbioSrvc", 
        "SharedAccess", 
        "WpnService"
    )
}
```

## Module Descriptions

### Common-Functions

Provides shared utilities used across other modules:
- Logging system with different severity levels
- Banner generation for visual separation
- Registry setting modification with logging
- Service configuration with before/after state tracking
- Windows feature management
- System restore point creation

### Security-Baseline

Performs security assessment without making changes:
- Downloads baseline assessment scripts
- Generates HTML reports on security status
- Identifies security vulnerabilities
- Makes recommendations for improvements

### Windows-Debloat

Removes unnecessary Windows components and optimizes the system:
- Uninstalls pre-installed bloatware apps
- Disables telemetry and data collection
- Optimizes performance settings
- Disables unnecessary services
- Removes OneDrive and Cortana

### Privacy-Protection

Enhances privacy settings and controls data collection:
- Creates visual dashboard of privacy settings
- Blocks telemetry endpoints via hosts file
- Disables Windows Error Reporting
- Stops speech recognition data collection
- Manages app permissions (camera, microphone, location)

### Performance-Optimization

Improves system performance and resource usage:
- Manages startup programs
- Configures Windows Update delivery optimization
- Sets up Storage Sense for automated disk cleanup
- Optimizes SSD settings including TRIM

### Network-Security

Enhances network-related security settings:
- Configures DNS to use secure providers (Cloudflare/Quad9)
- Disables NIC power saving for reliable connections
- Disables insecure discovery protocols (NetBIOS/LLMNR/mDNS)
- Manages network profile security settings

### Additional-Security

Implements specialized security features:
- Browser hardening for Edge, Chrome, and Firefox
- WiFi Sense disabling to prevent automatic connections
- TPM security enhancement and configuration
- Windows Sandbox hardening
- Secure Boot verification

### Basic-Hardening

Implements essential security measures:
- Enables Windows Defender real-time protection
- Updates malware definitions
- Sets secure password policies
- Protects user accounts
- Applies basic network protection

### Standard-Hardening

Builds upon basic hardening with additional protections:
- Enables advanced security features
- Configures secure TLS settings
- Enables BitLocker encryption
- Disables unnecessary services
- Sets up audit policies

### Enhanced-Hardening

Provides maximum security with potential functionality impact:
- Applies strict privacy settings
- Removes unnecessary applications
- Disables remote access
- Protects against script-based attacks
- Enforces maximum security configurations

## Registry and System Changes

This toolkit modifies numerous registry keys and system settings to enhance security. Key categories of changes include:

### Security Settings
- Windows Defender configuration
- SmartScreen and exploit protection
- User Account Control (UAC) settings
- Script execution policies
- BitLocker encryption

### Privacy Settings
- Telemetry and data collection controls
- Advertising ID and tracking settings
- Diagnostic data uploads
- Feedback and error reporting

### Network Settings
- Firewall configuration
- DNS settings
- Network protocol security
- Remote access capabilities

### Performance Settings
- Visual effects optimization
- Startup program management
- Disk cleanup automation
- Service optimization

## Safety Precautions

The toolkit includes several safety features:
- Creates system restore points before major changes
- Logs all modifications with before/after values
- Confirms significant changes with the user
- Allows selective application of hardening measures

## Disclaimer

Use this toolkit at your own risk. While efforts have been made to ensure safety, comprehensive system hardening can affect functionality and compatibility. Always backup important data before applying security hardening.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

This toolkit incorporates security recommendations and techniques from multiple sources including Microsoft Security Baselines, CIS Benchmarks, and community best practices.