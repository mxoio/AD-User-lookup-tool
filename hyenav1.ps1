# AD Management Tool - Enhanced Version
# Version: 2.0 - Simplified and Fixed
# All functions properly structured with correct syntax

#Requires -Version 5.0
#Requires -Modules ActiveDirectory

# ============================================
# CONFIGURATION & INITIALIZATION
# ============================================

# Configuration variables
$Script:Config = @{
    MaxComputersToScan = 50
    LogPath = "$env:TEMP\ADManagementTool_$(Get-Date -Format 'yyyyMMdd').log"
    ExportPath = "$env:USERPROFILE\Documents\ADExports"
    EnableLogging = $true
    CacheExpiration = 300  # seconds
    DefaultPageSize = 25
}

# Cache for performance
$Script:Cache = @{
    DomainControllers = $null
    LastUpdate = $null
}

# ============================================
# HELPER FUNCTIONS
# ============================================

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    if ($Script:Config.EnableLogging) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logEntry = "$timestamp [$Level] $Message"
        Add-Content -Path $Script:Config.LogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    
    # Display to console with color coding
    switch ($Level) {
        'Info'    { Write-Host $Message -ForegroundColor White }
        'Warning' { Write-Host $Message -ForegroundColor Yellow }
        'Error'   { Write-Host $Message -ForegroundColor Red }
        'Success' { Write-Host $Message -ForegroundColor Green }
    }
}

# Initialize environment
function Initialize-Environment {
    Write-Log "Initializing AD Management Tool..." -Level Info
    
    # Check for AD module
    if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory module not found. Please install RSAT tools." -Level Error
        return $false
    }
    
    # Import module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "ActiveDirectory module loaded successfully" -Level Success
    }
    catch {
        Write-Log "Failed to load ActiveDirectory module: $_" -Level Error
        return $false
    }
    
    # Test AD connectivity
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Log "Connected to domain: $($domain.Name)" -Level Success
        return $true
    }
    catch {
        Write-Log "Cannot connect to Active Directory: $_" -Level Error
        return $false
    }
}

# Validate user exists
function Test-ADUserExists {
    param([string]$Username)
    try {
        $null = Get-ADUser $Username -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# ============================================
# MAIN MENU
# ============================================

function Show-MainMenu {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "    AD Management Tool - Version 2.0" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USER OPERATIONS" -ForegroundColor Yellow
    Write-Host "  1.  Search for User"
    Write-Host "  2.  Check User Login Status"
    Write-Host "  3.  Reset User Password"
    Write-Host "  4.  Unlock User Account"
    Write-Host "  5.  Enable/Disable User"
    Write-Host ""
    Write-Host "REPORTS" -ForegroundColor Yellow
    Write-Host "  6.  Locked Out Accounts"
    Write-Host "  7.  Password Expiry Report"
    Write-Host "  8.  Export User List"
    Write-Host ""
    Write-Host "SYSTEM" -ForegroundColor Yellow
    Write-Host "  9.  Settings"
    Write-Host "  H.  Help"
    Write-Host "  Q.  Quit"
    Write-Host ""
}

# ============================================
# USER FUNCTIONS
# ============================================

# 1. Search for User
function Search-ADUserByName {
    Write-Host "`n=== SEARCH FOR USER ===" -ForegroundColor Cyan
    $searchTerm = Read-Host "Enter username, name, or email"
    
    if ([string]::IsNullOrWhiteSpace($searchTerm)) { return }
    
    try {
        Write-Host "Searching..." -ForegroundColor Yellow
        $users = Get-ADUser -Filter "Name -like '*$searchTerm*' -or SamAccountName -like '*$searchTerm*' -or EmailAddress -like '*$searchTerm*'" -Properties DisplayName, EmailAddress, Department, Enabled
        
        if ($users) {
            Write-Host "`nFound $($users.Count) user(s):" -ForegroundColor Green
            $users | Format-Table SamAccountName, DisplayName, EmailAddress, Department, Enabled -AutoSize
        }
        else {
            Write-Host "No users found matching '$searchTerm'" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error searching for user: $_" -ForegroundColor Red
    }
}

# 2. Check User Login Status
function Get-UserLoginStatus {
    Write-Host "`n=== USER LOGIN STATUS ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    
    if (!(Test-ADUserExists $username)) {
        Write-Host "User not found" -ForegroundColor Red
        return
    }
    
    try {
        $user = Get-ADUser $username -Properties *
        
        Write-Host "`nUser Information:" -ForegroundColor Yellow
        Write-Host "  Username:        $($user.SamAccountName)"
        Write-Host "  Display Name:    $($user.DisplayName)"
        Write-Host "  Email:           $($user.EmailAddress)"
        Write-Host "  Department:      $($user.Department)"
        Write-Host "  Enabled:         $($user.Enabled)"
        Write-Host "  Locked Out:      $($user.LockedOut)"
        Write-Host "  Password Set:    $($user.PasswordLastSet)"
        
        # Get accurate last logon by querying all DCs
        Write-Host "`nChecking last logon across all domain controllers..." -ForegroundColor Gray
        $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
        $lastLogonTime = 0
        $lastLogonDC = ""
        
        foreach ($dc in $dcs) {
            try {
                $dcUser = Get-ADUser $username -Server $dc -Properties LastLogon -ErrorAction Stop
                if ($dcUser.LastLogon -gt $lastLogonTime) {
                    $lastLogonTime = $dcUser.LastLogon
                    $lastLogonDC = $dc
                }
            }
            catch {
                # DC might be unreachable, continue to next
            }
        }
        
        if ($lastLogonTime -ne 0) {
            $lastLogonDateTime = [DateTime]::FromFileTime($lastLogonTime)
            $daysSince = (New-TimeSpan -Start $lastLogonDateTime -End (Get-Date)).Days
            Write-Host "  Last Logon:      $lastLogonDateTime (from DC: $lastLogonDC)" -ForegroundColor Green
            Write-Host "  Days Since:      $daysSince days"
        }
        else {
            Write-Host "  Last Logon:      Never logged on" -ForegroundColor Yellow
        }
        
        # Also show the replicated LastLogonDate for comparison
        if ($user.LastLogonDate) {
            Write-Host "  Replicated Date: $($user.LastLogonDate) (may be up to 14 days old)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Error getting user status: $_" -ForegroundColor Red
    }
}

# 3. Reset User Password
function Reset-UserPassword {
    Write-Host "`n=== RESET USER PASSWORD ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    
    if (!(Test-ADUserExists $username)) {
        Write-Host "User not found" -ForegroundColor Red
        return
    }
    
    try {
        $newPassword = Read-Host "Enter new password" -AsSecureString
        Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset
        Set-ADUser -Identity $username -ChangePasswordAtLogon $true
        Write-Host "Password reset successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Error resetting password: $_" -ForegroundColor Red
    }
}

# 4. Unlock User Account
function Unlock-UserAccount {
    Write-Host "`n=== UNLOCK USER ACCOUNT ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    
    if (!(Test-ADUserExists $username)) {
        Write-Host "User not found" -ForegroundColor Red
        return
    }
    
    try {
        Unlock-ADAccount -Identity $username
        Write-Host "Account unlocked successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Error unlocking account: $_" -ForegroundColor Red
    }
}

# 5. Enable/Disable User
function Toggle-UserAccount {
    Write-Host "`n=== ENABLE/DISABLE USER ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    
    if (!(Test-ADUserExists $username)) {
        Write-Host "User not found" -ForegroundColor Red
        return
    }
    
    try {
        $user = Get-ADUser $username
        $newState = !$user.Enabled
        Set-ADUser -Identity $username -Enabled $newState
        $status = if($newState) { "enabled" } else { "disabled" }
        Write-Host "Account $status successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Error toggling account: $_" -ForegroundColor Red
    }
}

# 6. Get Locked Out Accounts
function Get-LockedOutAccounts {
    Write-Host "`n=== LOCKED OUT ACCOUNTS ===" -ForegroundColor Cyan
    
    try {
        $lockedUsers = Search-ADAccount -LockedOut -UsersOnly
        
        if ($lockedUsers) {
            Write-Host "`nFound $($lockedUsers.Count) locked account(s):" -ForegroundColor Yellow
            $lockedUsers | Format-Table SamAccountName, Name -AutoSize
            
            $unlock = Read-Host "`nUnlock all accounts? (Y/N)"
            if ($unlock -eq 'Y') {
                foreach ($user in $lockedUsers) {
                    Unlock-ADAccount -Identity $user.SamAccountName
                    Write-Host "Unlocked: $($user.SamAccountName)" -ForegroundColor Green
                }
            }
        }
        else {
            Write-Host "No locked accounts found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error checking locked accounts: $_" -ForegroundColor Red
    }
}

# 7. Password Expiry Report
function Get-PasswordExpiryReport {
    Write-Host "`n=== PASSWORD EXPIRY REPORT ===" -ForegroundColor Cyan
    $days = Read-Host "Show passwords expiring in next X days"
    
    try {
        $users = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false} -Properties PasswordLastSet, DisplayName
        $maxAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
        
        $expiringUsers = @()
        foreach ($user in $users) {
            if ($user.PasswordLastSet) {
                $expiryDate = $user.PasswordLastSet.AddDays($maxAge)
                $daysLeft = ($expiryDate - (Get-Date)).Days
                
                if ($daysLeft -le [int]$days -and $daysLeft -ge 0) {
                    $expiringUsers += [PSCustomObject]@{
                        Username = $user.SamAccountName
                        DisplayName = $user.DisplayName
                        ExpiryDate = $expiryDate
                        DaysLeft = $daysLeft
                    }
                }
            }
        }
        
        if ($expiringUsers) {
            $expiringUsers | Sort-Object DaysLeft | Format-Table -AutoSize
        }
        else {
            Write-Host "No passwords expiring in the next $days days" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error generating report: $_" -ForegroundColor Red
    }
}

# 8. Export User List
function Export-UserList {
    Write-Host "`n=== EXPORT USER LIST ===" -ForegroundColor Cyan
    
    try {
        $users = Get-ADUser -Filter * -Properties DisplayName, EmailAddress, Department, Enabled
        $filename = "UserExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $filepath = Join-Path $Script:Config.ExportPath $filename
        
        # Create directory if it doesn't exist
        if (!(Test-Path $Script:Config.ExportPath)) {
            New-Item -ItemType Directory -Path $Script:Config.ExportPath -Force | Out-Null
        }
        
        $users | Select-Object SamAccountName, DisplayName, EmailAddress, Department, Enabled | 
                 Export-Csv -Path $filepath -NoTypeInformation
        
        Write-Host "Exported $($users.Count) users to:" -ForegroundColor Green
        Write-Host "  $filepath" -ForegroundColor Green
    }
    catch {
        Write-Host "Error exporting users: $_" -ForegroundColor Red
    }
}

# 9. Settings
function Show-Settings {
    Write-Host "`n=== SETTINGS ===" -ForegroundColor Cyan
    Write-Host "Current Settings:" -ForegroundColor Yellow
    Write-Host "  Log Path:    $($Script:Config.LogPath)"
    Write-Host "  Export Path: $($Script:Config.ExportPath)"
    Write-Host "  Logging:     $($Script:Config.EnableLogging)"
    Write-Host ""
}

# 10. Help
function Show-Help {
    Write-Host "`n=== HELP ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "AD Management Tool - Version 2.0" -ForegroundColor Gray
    Write-Host ""
    Write-Host "This tool provides Active Directory management capabilities." -ForegroundColor Gray
    Write-Host ""
    Write-Host "KEY FEATURES:" -ForegroundColor Gray
    Write-Host "* User search and management" -ForegroundColor Gray
    Write-Host "* Password reset and account unlock" -ForegroundColor Gray
    Write-Host "* Account status reporting" -ForegroundColor Gray
    Write-Host "* Bulk export capabilities" -ForegroundColor Gray
    Write-Host ""
}

# ============================================
# MAIN PROGRAM EXECUTION
# ============================================

# Initialize
if (!(Initialize-Environment)) {
    Write-Host "`nFailed to initialize. Please ensure you have the necessary permissions and modules." -ForegroundColor Red
    exit 1
}

# Main loop
do {
    Show-MainMenu
    $choice = Read-Host "Select an option"
    
    switch ($choice) {
        "1" { Search-ADUserByName; Read-Host "`nPress Enter to continue" }
        "2" { Get-UserLoginStatus; Read-Host "`nPress Enter to continue" }
        "3" { Reset-UserPassword; Read-Host "`nPress Enter to continue" }
        "4" { Unlock-UserAccount; Read-Host "`nPress Enter to continue" }
        "5" { Toggle-UserAccount; Read-Host "`nPress Enter to continue" }
        "6" { Get-LockedOutAccounts; Read-Host "`nPress Enter to continue" }
        "7" { Get-PasswordExpiryReport; Read-Host "`nPress Enter to continue" }
        "8" { Export-UserList; Read-Host "`nPress Enter to continue" }
        "9" { Show-Settings; Read-Host "`nPress Enter to continue" }
        "H" { Show-Help; Read-Host "`nPress Enter to continue" }
        "h" { Show-Help; Read-Host "`nPress Enter to continue" }
        "Q" { Write-Host "`nExiting..." -ForegroundColor Yellow }
        "q" { Write-Host "`nExiting..." -ForegroundColor Yellow }
        default { 
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($choice -notin @('Q','q'))

Write-Host "Goodbye!" -ForegroundColor Green
