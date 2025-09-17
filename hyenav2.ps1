# AD Management Tool - Hynea-Style Feature Pack
# Version: 2.0 (adds groups, bulk ops, OU moves, HTML/CSV reports, stale computers, dry-run, paging, smarter caching)
#Requires -Version 5.0
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
AD Management Tool – Hynea-Style Feature Pack
.DESCRIPTION
Adds:
- Dry-Run mode for safe previews
- Cached Domain Controller list with expiry
- Group management: list/add/remove membership (handles nested display)
- Move user between OUs (with DN validation)
- Disable & optionally move inactive users (60/120+ days) in bulk
- Stale computer report (LastLogonTimestamp) with disable & move to quarantine OU
- Bulk actions from CSV (reset pw / unlock / enable-disable / move OU / add-remove groups)
- Advanced user search with paging, export, and selected actions
- Password expiry & account expiry combined report
- HTML report export (styled) + CSVs (auto creates ExportPath)
- Basic AD health snapshot (DCs, FSMO, replication failures)
- Settings menu: toggle logging, dry-run, paths; persist settings per session

Note: Some features require appropriate privileges. Replication health uses AD cmdlets when available.
#>

# ============================================
# CONFIGURATION & INITIALIZATION
# ============================================

$Script:Config = @{
    MaxComputersToScan   = 200
    LogPath              = Join-Path $env:TEMP ("ADTool_" + (Get-Date -Format 'yyyyMMdd') + ".log")
    ExportPath           = Join-Path $env:USERPROFILE 'Documents/ADExports'
    EnableLogging        = $true
    CacheExpiration      = 300  # seconds
    DefaultPageSize      = 25
    DryRun               = $false
    QuarantineOU         = ''   # e.g. "OU=Quarantine,DC=contoso,DC=com"
}

$Script:State = @{
    Cache = @{
        DomainControllers = $null
        LastUpdate        = Get-Date '1900-01-01'
    }
}

# ============================================
# HELPER FUNCTIONS
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Debug')] [string]$Level = 'Info'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "$timestamp [$Level] $Message"
    if ($Script:Config.EnableLogging) {
        try { Add-Content -Path $Script:Config.LogPath -Value $logEntry -ErrorAction Stop } catch {}
    }
    switch ($Level) {
        'Info'    { Write-Host $Message -ForegroundColor White }
        'Warning' { Write-Host $Message -ForegroundColor Yellow }
        'Error'   { Write-Host $Message -ForegroundColor Red }
        'Success' { Write-Host $Message -ForegroundColor Green }
        'Debug'   { Write-Host $Message -ForegroundColor DarkGray }
    }
}

function Ensure-ExportPath { if (!(Test-Path $Script:Config.ExportPath)) { New-Item -ItemType Directory -Path $Script:Config.ExportPath -Force | Out-Null } }

function Confirm-YesNo([string]$Prompt, [switch]$DefaultYes){
    $suf = if($DefaultYes){' [Y/n]'} else {' [y/N]'}
    $ans = Read-Host ("$Prompt$suf")
    if([string]::IsNullOrWhiteSpace($ans)){ return $DefaultYes }
    return $ans.Trim().ToLower() -eq 'y'
}

function Invoke-WithDryRun {
    param([scriptblock]$Action,[string]$Description)
    if ($Script:Config.DryRun) {
        Write-Log "DRY-RUN: would do -> $Description" -Level Warning
    } else {
        & $Action
        Write-Log "DONE: $Description" -Level Success
    }
}

function Get-DCsCached {
    $now = Get-Date
    if ($null -ne $Script:State.Cache.DomainControllers -and ($now - $Script:State.Cache.LastUpdate).TotalSeconds -lt $Script:Config.CacheExpiration) {
        return $Script:State.Cache.DomainControllers
    }
    try {
        $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        $Script:State.Cache.DomainControllers = $dcs
        $Script:State.Cache.LastUpdate = $now
        return $dcs
    } catch {
        Write-Log "Failed to get DCs: $_" -Level Error
        return @()
    }
}

function Initialize-Environment {
    Write-Log "Initializing AD Management Tool..." -Level Info
    if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory module not found. Install RSAT (Windows) or AD DS tools." -Level Error
        return $false
    }
    try { Import-Module ActiveDirectory -ErrorAction Stop; Write-Log "ActiveDirectory module loaded" -Level Success }
    catch { Write-Log "Failed to load ActiveDirectory: $_" -Level Error; return $false }
    try { $domain = Get-ADDomain -ErrorAction Stop; Write-Log "Connected to domain: $($domain.Name)" -Level Success; return $true }
    catch { Write-Log "Cannot connect to AD: $_" -Level Error; return $false }
}

function Test-ADUserExists([string]$Username){ try { $null = Get-ADUser $Username -ErrorAction Stop; $true } catch { $false } }

# ============================================
# CORE USER OPS (from v2 with small tweaks)
# ============================================

function Search-ADUserByName {
    Write-Host "`n=== SEARCH FOR USER (paged) ===" -ForegroundColor Cyan
    $searchTerm = Read-Host "Enter username, name, or email"
    if ([string]::IsNullOrWhiteSpace($searchTerm)) { return }
    try {
        $ldap = "(|(name=*$searchTerm*)(samaccountname=*$searchTerm*)(mail=*$searchTerm*)(userprincipalname=*$searchTerm*))"
        $users = @(Get-ADUser -LDAPFilter $ldap -Properties DisplayName,mail,Department,Enabled,UserPrincipalName)
        if (-not $users -or $users.Count -eq 0){ Write-Host "No users found" -ForegroundColor Yellow; return }
        $pageSize = [int]$Script:Config.DefaultPageSize
        for($i=0; $i -lt $users.Count; $i+=$pageSize){
            $chunk = $users | Select-Object -Skip $i -First $pageSize
            $chunk | Select-Object SamAccountName,DisplayName,@{n='Email';e={$_.mail}},Department,Enabled | Format-Table -AutoSize
            if(($i+$pageSize) -lt $users.Count){ $c = Read-Host "Show next page? (Y to continue, any other to stop)"; if($c -ne 'Y'){break} }
        }
        if (Confirm-YesNo "Export results to CSV?" ){
            Ensure-ExportPath
            $fp = Join-Path $Script:Config.ExportPath ("SearchUsers_"+(Get-Date -Format 'yyyyMMdd_HHmmss')+".csv")
            $users | Select-Object SamAccountName,DisplayName,@{n='Email';e={$_.mail}},Department,Enabled,UserPrincipalName | Export-Csv -Path $fp -NoTypeInformation
            Write-Log "Exported to $fp" -Level Success
        }
    } catch { Write-Host "Error searching for user: $_" -ForegroundColor Red }
}

function Get-UserLoginStatus {
    Write-Host "`n=== USER LOGIN STATUS ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try {
        $user = Get-ADUser $username -Properties *
        Write-Host "`nUser Information:" -ForegroundColor Yellow
        "  Username:        {0}\n  Display Name:    {1}\n  Email:           {2}\n  Department:      {3}\n  Enabled:         {4}\n  Locked Out:      {5}\n  Password Set:    {6}" -f $user.SamAccountName,$user.DisplayName,$user.EmailAddress,$user.Department,$user.Enabled,$user.LockedOut,$user.PasswordLastSet | Write-Host
        Write-Host "`nChecking last logon across DCs..." -ForegroundColor Gray
        $dcs = Get-DCsCached
        $lastLogonTime = 0; $lastLogonDC = ""
        foreach ($dc in $dcs) {
            try {
                $dcUser = Get-ADUser $username -Server $dc -Properties LastLogon -ErrorAction Stop
                if ($dcUser.LastLogon -gt $lastLogonTime) { $lastLogonTime = $dcUser.LastLogon; $lastLogonDC = $dc }
            } catch {}
        }
        if ($lastLogonTime -ne 0) {
            $lastLogonDateTime = [DateTime]::FromFileTime($lastLogonTime)
            $daysSince = (New-TimeSpan -Start $lastLogonDateTime -End (Get-Date)).Days
            Write-Host ("  Last Logon:      {0} (from DC: {1})" -f $lastLogonDateTime,$lastLogonDC) -ForegroundColor Green
            Write-Host ("  Days Since:      {0} days" -f $daysSince)
        } else { Write-Host "  Last Logon:      Never logged on" -ForegroundColor Yellow }
        if ($user.LastLogonDate) { Write-Host "  Replicated Date: $($user.LastLogonDate) (may be stale)" -ForegroundColor Gray }
    } catch { Write-Host "Error getting user status: $_" -ForegroundColor Red }
}

function Reset-UserPassword {
    Write-Host "`n=== RESET USER PASSWORD ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try {
        $newPassword = Read-Host "Enter new password" -AsSecureString
        Invoke-WithDryRun -Description "Reset password & force change at logon for $username" -Action {
            Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset
            Set-ADUser -Identity $username -ChangePasswordAtLogon $true
        }
    } catch { Write-Host "Error resetting password: $_" -ForegroundColor Red }
}

function Unlock-UserAccount {
    Write-Host "`n=== UNLOCK USER ACCOUNT ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try { Invoke-WithDryRun -Description "Unlock $username" -Action { Unlock-ADAccount -Identity $username } }
    catch { Write-Host "Error unlocking account: $_" -ForegroundColor Red }
}

function Toggle-UserAccount {
    Write-Host "`n=== ENABLE/DISABLE USER ===" -ForegroundColor Cyan
    $username = Read-Host "Enter username"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try {
        $user = Get-ADUser $username
        $newState = -not $user.Enabled
        Invoke-WithDryRun -Description ("Set {0} -> Enabled={1}" -f $username,$newState) -Action { Set-ADUser -Identity $username -Enabled $newState }
    } catch { Write-Host "Error toggling account: $_" -ForegroundColor Red }
}

# ============================================
# NEW: GROUP MANAGEMENT
# ============================================

function Show-UserGroups {
    $username = Read-Host "Enter username"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try {
        $groups = Get-ADPrincipalGroupMembership -Identity $username | Sort-Object Name
        if($groups){ $groups | Format-Table Name, DistinguishedName -AutoSize } else { Write-Host "No groups found" -ForegroundColor Yellow }
    } catch { Write-Host "Error: $_" -ForegroundColor Red }
}

function Add-UserToGroup {
    $username = Read-Host "Enter username"
    $group = Read-Host "Enter group (samAccountName or DN)"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try { Invoke-WithDryRun -Description "Add $username to $group" -Action { Add-ADGroupMember -Identity $group -Members $username -ErrorAction Stop } }
    catch { Write-Host "Error adding to group: $_" -ForegroundColor Red }
}

function Remove-UserFromGroup {
    $username = Read-Host "Enter username"
    $group = Read-Host "Enter group (samAccountName or DN)"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try { Invoke-WithDryRun -Description "Remove $username from $group" -Action { Remove-ADGroupMember -Identity $group -Members $username -Confirm:$false -ErrorAction Stop } }
    catch { Write-Host "Error removing from group: $_" -ForegroundColor Red }
}

# ============================================
# NEW: MOVE USER TO OU
# ============================================

function Move-UserToOU {
    $username = Read-Host "Enter username"
    $targetOU = Read-Host "Enter target OU DN (e.g., OU=Sales,DC=contoso,DC=com)"
    if (!(Test-ADUserExists $username)) { Write-Host "User not found" -ForegroundColor Red; return }
    try {
        $u = Get-ADUser $username
        # Validate OU exists using -Identity (robust for commas etc.)
        $null = Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop
        Invoke-WithDryRun -Description "Move $username to $targetOU" -Action { Move-ADObject -Identity $u.DistinguishedName -TargetPath $targetOU }
    } catch { Write-Host "Error moving user: $_" -ForegroundColor Red }
}

# ============================================
# REPORTS (existing + enhanced)
# ============================================

function Get-LockedOutAccounts {
    Write-Host "`n=== LOCKED OUT ACCOUNTS ===" -ForegroundColor Cyan
    try {
        $lockedUsers = Search-ADAccount -LockedOut -UsersOnly
        if ($lockedUsers) {
            Write-Host "`nFound $($lockedUsers.Count) locked account(s):" -ForegroundColor Yellow
            $lockedUsers | Format-Table SamAccountName, Name -AutoSize
            if (Confirm-YesNo "Unlock ALL listed accounts now?") {
                foreach ($user in $lockedUsers) { Invoke-WithDryRun -Description ("Unlock {0}" -f $user.SamAccountName) -Action { Unlock-ADAccount -Identity $user.SamAccountName } }
            }
        } else { Write-Host "No locked accounts found" -ForegroundColor Green }
    } catch { Write-Host "Error checking locked accounts: $_" -ForegroundColor Red }
}

function Get-PasswordExpiryReport {
    Write-Host "`n=== PASSWORD & ACCOUNT EXPIRY REPORT ===" -ForegroundColor Cyan
    $days = [int](Read-Host "Show users expiring in next X days")
    try {
        $users = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false} -Properties PasswordLastSet, DisplayName, AccountExpirationDate
        $maxAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
        $expiring = foreach($user in $users){
            if ($user.PasswordLastSet) {
                $pwdExpiry = $user.PasswordLastSet.AddDays($maxAge)
                $pwdLeft = ($pwdExpiry - (Get-Date)).Days
                $accLeft = if($user.AccountExpirationDate){ ($user.AccountExpirationDate - (Get-Date)).Days } else { [int]::MaxValue }
                if (($pwdLeft -le $days -and $pwdLeft -ge 0) -or ($accLeft -le $days -and $accLeft -ge 0)){
                    [pscustomobject]@{ Username=$user.SamAccountName; DisplayName=$user.DisplayName; PasswordExpiry=$pwdExpiry; DaysToPwd=$pwdLeft; AccountExpiry=$user.AccountExpirationDate; DaysToAcct=$accLeft }
                }
            }
        }
        if($expiring){ $expiring | Sort-Object DaysToPwd | Format-Table -AutoSize } else { Write-Host "None within $days days" -ForegroundColor Green }
        if (Confirm-YesNo "Export to CSV & HTML?"){
            Ensure-ExportPath
            $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
            $csv = Join-Path $Script:Config.ExportPath "Expiry_$ts.csv"; $html = Join-Path $Script:Config.ExportPath "Expiry_$ts.html"
            $expiring | Export-Csv -NoTypeInformation -Path $csv
            $style = @"
<style>
body{font-family:Segoe UI,Arial;}
h1{color:#0b6fa4} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} tr:nth-child(even){background:#f9f9f9}
</style>
"@
            $report = ($expiring | ConvertTo-Html -Title "Password/Account Expiry" -PreContent '<h1>Password & Account Expiry</h1>' -PostContent ("<p>Generated: {0}</p>" -f (Get-Date))) -join [Environment]::NewLine
$report = $report.Replace('<head>', '<head>' + $style)
Set-Content -Path $html -Value $report -Encoding UTF8
            Write-Log "Exported CSV: $csv | HTML: $html" -Level Success
        }
    } catch { Write-Host "Error generating report: $_" -ForegroundColor Red }
}

function Get-InactiveUsersReport {
    Write-Host "`n=== INACTIVE USERS REPORT (DC-aware) ===" -ForegroundColor Cyan
    Write-Host "Checking across all DCs; may take time..." -ForegroundColor Gray
    try {
        $dcs = Get-DCsCached
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties DisplayName,Department,Title,EmailAddress
        $inactive60=@(); $inactive120=@(); $never=@(); $i=0
        foreach($user in $users){
            $i++; Write-Progress -Activity "Scanning users" -Status $user.SamAccountName -PercentComplete (($i/$users.Count)*100)
            $ll=0; foreach($dc in $dcs){ try{ $du = Get-ADUser $user.SamAccountName -Server $dc -Properties LastLogon -ErrorAction Stop; if($du.LastLogon -gt $ll){$ll=$du.LastLogon} }catch{} }
            if($ll -eq 0){ $never += [pscustomobject]@{Username=$user.SamAccountName;DisplayName=$user.DisplayName;Department=$user.Department;Title=$user.Title;Email=$user.EmailAddress;LastLogon='Never';DaysInactive='N/A'} }
            else { $dt=[DateTime]::FromFileTime($ll); $d=(New-TimeSpan -Start $dt -End (Get-Date)).Days
                $obj=[pscustomobject]@{Username=$user.SamAccountName;DisplayName=$user.DisplayName;Department=$user.Department;Title=$user.Title;Email=$user.EmailAddress;LastLogon=$dt;DaysInactive=$d}
                if($d -ge 120){$inactive120+=$obj} elseif($d -ge 60){$inactive60+=$obj}
            }
        }
        Write-Progress -Activity "Scanning users" -Completed
        Write-Host ("Never Logged In: {0} | 120+ days: {1} | 60-119 days: {2}" -f $never.Count,$inactive120.Count,$inactive60.Count) -ForegroundColor Cyan
        if (Confirm-YesNo "Export all to CSV & HTML?"){
            Ensure-ExportPath; $ts=Get-Date -Format 'yyyyMMdd_HHmmss'
            $never | Export-Csv (Join-Path $Script:Config.ExportPath "Never_$ts.csv") -NoTypeInformation
            $inactive120 | Export-Csv (Join-Path $Script:Config.ExportPath "Inactive120_$ts.csv") -NoTypeInformation
            $inactive60 | Export-Csv (Join-Path $Script:Config.ExportPath "Inactive60_$ts.csv") -NoTypeInformation
            $all = $never + $inactive120 + $inactive60
            $html = Join-Path $Script:Config.ExportPath "Inactive_$ts.html"
            $style='<style>body{font-family:Segoe UI,Arial} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px}</style>'
            $allSorted = $all | Sort-Object DaysInactive -Descending
$htmlContent = ($allSorted | ConvertTo-Html -Title 'Inactive Users' -PreContent '<h1>Inactive Users</h1>') -join [Environment]::NewLine
$htmlContent = $htmlContent.Replace('<head>', '<head>' + $style)
Set-Content -Path $html -Value $htmlContent -Encoding UTF8
            Write-Log "Exported HTML: $html" -Level Success
        }
        if ((($inactive120 + $inactive60).Count -gt 0) -and (Confirm-YesNo "Disable 120+ day inactive users? (safe; honors Dry-Run)")) {
            foreach($u in $inactive120){ Invoke-WithDryRun -Description ("Disable {0}" -f $u.Username) -Action { Disable-ADAccount -Identity $u.Username } }
        }
        if ((($inactive120 + $inactive60).Count -gt 0) -and (Confirm-YesNo "Move disabled to Quarantine OU? (requires QuarantineOU setting)")) {
            if([string]::IsNullOrWhiteSpace($Script:Config.QuarantineOU)){ Write-Log "QuarantineOU not set." -Level Warning }
            else { foreach($u in $inactive120){ try{ $dn=(Get-ADUser $u.Username).DistinguishedName; Invoke-WithDryRun -Description ("Move {0} to {1}" -f $u.Username,$Script:Config.QuarantineOU) -Action { Move-ADObject -Identity $dn -TargetPath $Script:Config.QuarantineOU } }catch{ Write-Log $_ -Level Error } } }
        }
    } catch { Write-Host "Error generating inactive users report: $_" -ForegroundColor Red }
}

function Export-UserList {
    Write-Host "`n=== EXPORT USER LIST ===" -ForegroundColor Cyan
    try {
        Ensure-ExportPath
        $ou = Read-Host "Limit to OU DN (ENTER for entire domain)"
        $extra = Confirm-YesNo "Include extended admin columns (LastLogonDate, Manager, etc.)?"
        $props = @('DisplayName','mail','Department','Enabled')
        if($extra){ $props += 'Title','Office','City','Company','whenCreated','whenChanged','LastLogonDate','PasswordLastSet','PasswordNeverExpires','AccountExpirationDate','Manager','UserPrincipalName' }
        if([string]::IsNullOrWhiteSpace($ou)){
            $users = @(Get-ADUser -Filter * -Properties $props)
        } else {
            $users = @(Get-ADUser -Filter * -SearchBase $ou -SearchScope Subtree -Properties $props)
        }
        $export = $users | Select-Object SamAccountName,DisplayName,@{n='Email';e={$_.mail}},Department,Enabled,
            Title,Office,City,Company,whenCreated,whenChanged,LastLogonDate,PasswordLastSet,PasswordNeverExpires,AccountExpirationDate,Manager,UserPrincipalName
        $fp = Join-Path $Script:Config.ExportPath ("UserExport_"+(Get-Date -Format 'yyyyMMdd_HHmmss')+".csv")
        $export | Export-Csv -Path $fp -NoTypeInformation
        Write-Host "Exported $($users.Count) users -> $fp" -ForegroundColor Green
    } catch { Write-Host "Error exporting users: $_" -ForegroundColor Red }
}

# ============================================
# NEW: STALE COMPUTERS & BULK OPS
# ============================================

function Report-StaleComputers {
    Write-Host "`n=== STALE COMPUTERS REPORT ===" -ForegroundColor Cyan
    $days = [int](Read-Host "Flag computers inactive for X days (via LastLogonTimestamp)")
    try {
        $comps = Get-ADComputer -Filter {Enabled -eq $true} -Properties Name,LastLogonTimestamp,OperatingSystem
        $stale = foreach($c in $comps){ if($c.LastLogonTimestamp){ $dt=[DateTime]::FromFileTime($c.LastLogonTimestamp); $d=(New-TimeSpan -Start $dt -End (Get-Date)).Days; if($d -ge $days){ [pscustomobject]@{Name=$c.Name;OS=$c.OperatingSystem;LastLogon=$dt;DaysInactive=$d} } } }
        if($stale){ $stale | Sort-Object DaysInactive -Descending | Format-Table -AutoSize } else { Write-Host "No stale computers >= $days days" -ForegroundColor Green }
        if ($stale -and (Confirm-YesNo "Export, disable and optionally move to Quarantine OU?")) {
            Ensure-ExportPath; $ts=Get-Date -Format 'yyyyMMdd_HHmmss'
            $csv=Join-Path $Script:Config.ExportPath "StaleComputers_$ts.csv"; $stale | Export-Csv $csv -NoTypeInformation; Write-Log "Exported to $csv" -Level Success
            if(Confirm-YesNo "Disable all listed computers?"){
                foreach($s in $stale){ Invoke-WithDryRun -Description ("Disable computer {0}" -f $s.Name) -Action { Disable-ADAccount -Identity $s.Name } }
            }
            if (-not [string]::IsNullOrWhiteSpace($Script:Config.QuarantineOU) -and (Confirm-YesNo "Move disabled computers to Quarantine OU?")) {
                foreach($s in $stale){ try{ $dn=(Get-ADComputer $s.Name).DistinguishedName; Invoke-WithDryRun -Description ("Move {0} to {1}" -f $s.Name,$Script:Config.QuarantineOU) -Action { Move-ADObject -Identity $dn -TargetPath $Script:Config.QuarantineOU } }catch{ Write-Log $_ -Level Error } }
            }
        }
    } catch { Write-Host "Error: $_" -ForegroundColor Red }
}

function Search-ComputerByName {
    Write-Host "`n=== SEARCH FOR COMPUTER ===" -ForegroundColor Cyan
    $term = Read-Host "Enter computer name or DNS hostname"
    if([string]::IsNullOrWhiteSpace($term)){ return }
    try {
        $comps = @(Get-ADComputer -Filter "(Name -like '*$term*') -or (DNSHostName -like '*$term*')" -Properties DNSHostName,OperatingSystem,LastLogonTimestamp,Enabled)
        if(-not $comps){ Write-Host "No computers found" -ForegroundColor Yellow; return }
        $comps | Select-Object Name,DNSHostName,OperatingSystem,Enabled,@{n='LastLogonTimestamp';e={ if($_.LastLogonTimestamp){ [DateTime]::FromFileTime($_.LastLogonTimestamp) } }} | Format-Table -AutoSize
    } catch { Write-Host "Error searching computers: $_" -ForegroundColor Red }
}

function Get-ComputerLiveInfo {
    Write-Host "`n=== COMPUTER LIVE INFO ===" -ForegroundColor Cyan
    $name = Read-Host "Enter computer (SAM or DNS)"
    if([string]::IsNullOrWhiteSpace($name)){ return }
    try {
        $ad = Get-ADComputer -Identity $name -Properties DNSHostName,OperatingSystem,LastLogonTimestamp,whenCreated,whenChanged,Enabled
        if(-not $ad){ Write-Host "Computer not found in AD" -ForegroundColor Red; return }
        $dcs = Get-DCsCached; $ll=0; $llDC=""
        foreach($dc in $dcs){ try{ $c = Get-ADComputer $ad.SamAccountName -Server $dc -Properties LastLogon -ErrorAction Stop; if($c.LastLogon -gt $ll){ $ll=$c.LastLogon; $llDC=$dc } } catch{} }
        $llDate = if($ll -gt 0){ [DateTime]::FromFileTime($ll) } else { $null }
        $online=$false; $live=@{}
        $target = if($ad.DNSHostName){$ad.DNSHostName}else{$ad.Name}
        if(Test-Connection -ComputerName $target -Count 1 -Quiet){
            $online=$true
            try {
                $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $target -ErrorAction Stop
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $target -ErrorAction Stop
                $live = [ordered]@{
                    LoggedOnUser = $cs.UserName
                    Manufacturer = $cs.Manufacturer
                    Model        = $cs.Model
                    LastBoot     = $os.LastBootUpTime
                    UptimeDays   = ([int]((Get-Date) - $os.LastBootUpTime).TotalDays)
                }
            } catch { Write-Log "WMI/CIM query failed: $_" -Level Warning }
        }
        Write-Host "`nAD Computer:" -ForegroundColor Yellow
        Write-Host ("  Name: {0}" -f $ad.Name)
        Write-Host ("  DNS:  {0}" -f $ad.DNSHostName)
        Write-Host ("  OS:   {0}" -f $ad.OperatingSystem)
        Write-Host ("  Enabled: {0}" -f $ad.Enabled)
        if($ad.LastLogonTimestamp){ Write-Host ("  LastLogonTimestamp: {0}" -f ([DateTime]::FromFileTime($ad.LastLogonTimestamp))) }
        if($llDate){ Write-Host ("  LastLogon (best DC): {0} (DC: {1})" -f $llDate,$llDC) }
        if($online){
            Write-Host "`nLive (via CIM):" -ForegroundColor Yellow
            $live.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-14}: {1}" -f $_.Key,$_.Value) }
        } else { Write-Host "`nHost not reachable for live info (ICMP)." -ForegroundColor Gray }
    } catch { Write-Host "Error getting computer info: $_" -ForegroundColor Red }
}

function Bulk-FromCSV {
    Write-Host "`n=== BULK ACTIONS FROM CSV ===" -ForegroundColor Cyan
    Write-Host "CSV columns supported (any subset): Username,Action,NewPassword,TargetOU,Group" -ForegroundColor Gray
    $path = Read-Host "Enter path to CSV"
    if(!(Test-Path $path)){ Write-Host "File not found" -ForegroundColor Red; return }
    $rows = Import-Csv -Path $path
    foreach($r in $rows){
        $u=$r.Username; $a=$r.Action
        switch($a){
            'ResetPassword' { $sec=ConvertTo-SecureString $r.NewPassword -AsPlainText -Force; Invoke-WithDryRun -Description ("Reset password for {0}" -f $u) -Action { Set-ADAccountPassword -Identity $u -NewPassword $sec -Reset; Set-ADUser -Identity $u -ChangePasswordAtLogon $true } }
            'Unlock'        { Invoke-WithDryRun -Description ("Unlock {0}" -f $u) -Action { Unlock-ADAccount -Identity $u } }
            'Enable'        { Invoke-WithDryRun -Description ("Enable {0}" -f $u) -Action { Enable-ADAccount -Identity $u } }
            'Disable'       { Invoke-WithDryRun -Description ("Disable {0}" -f $u) -Action { Disable-ADAccount -Identity $u } }
            'MoveOU'        { Invoke-WithDryRun -Description ("Move {0} -> {1}" -f $u,$r.TargetOU) -Action { $dn=(Get-ADUser $u).DistinguishedName; Move-ADObject -Identity $dn -TargetPath $r.TargetOU } }
            'AddGroup'      { Invoke-WithDryRun -Description ("Add {0} -> {1}" -f $u,$r.Group) -Action { Add-ADGroupMember -Identity $r.Group -Members $u } }
            'RemoveGroup'   { Invoke-WithDryRun -Description ("Remove {0} -> {1}" -f $u,$r.Group) -Action { Remove-ADGroupMember -Identity $r.Group -Members $u -Confirm:$false } }
            default         { Write-Log "Unknown action '$a' for $u" -Level Warning }
        }
    }
} {
    Write-Host "`n=== BULK ACTIONS FROM CSV ===" -ForegroundColor Cyan
    Write-Host "CSV columns supported (any subset): Username,Action,NewPassword,TargetOU,Group" -ForegroundColor Gray
    $path = Read-Host "Enter path to CSV"
    if(!(Test-Path $path)){ Write-Host "File not found" -ForegroundColor Red; return }
    $rows = Import-Csv -Path $path
    foreach($r in $rows){
        $u=$r.Username; $a=$r.Action
        switch($a){
            'ResetPassword' { $sec=ConvertTo-SecureString $r.NewPassword -AsPlainText -Force; Invoke-WithDryRun -Description ("Reset password for {0}" -f $u) -Action { Set-ADAccountPassword -Identity $u -NewPassword $sec -Reset; Set-ADUser -Identity $u -ChangePasswordAtLogon $true } }
            'Unlock'        { Invoke-WithDryRun -Description ("Unlock {0}" -f $u) -Action { Unlock-ADAccount -Identity $u } }
            'Enable'        { Invoke-WithDryRun -Description ("Enable {0}" -f $u) -Action { Enable-ADAccount -Identity $u } }
            'Disable'       { Invoke-WithDryRun -Description ("Disable {0}" -f $u) -Action { Disable-ADAccount -Identity $u } }
            'MoveOU'        { Invoke-WithDryRun -Description ("Move {0} -> {1}" -f $u,$r.TargetOU) -Action { $dn=(Get-ADUser $u).DistinguishedName; Move-ADObject -Identity $dn -TargetPath $r.TargetOU } }
            'AddGroup'      { Invoke-WithDryRun -Description ("Add {0} -> {1}" -f $u,$r.Group) -Action { Add-ADGroupMember -Identity $r.Group -Members $u } }
            'RemoveGroup'   { Invoke-WithDryRun -Description ("Remove {0} -> {1}" -f $u,$r.Group) -Action { Remove-ADGroupMember -Identity $r.Group -Members $u -Confirm:$false } }
            default         { Write-Log "Unknown action '$a' for $u" -Level Warning }
        }
    }
}

# ============================================
# NEW: AD HEALTH SNAPSHOT
# ============================================

function Show-ADHealth {
    Write-Host "`n=== AD HEALTH SNAPSHOT ===" -ForegroundColor Cyan
    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        Write-Host ("Domain: {0} | Forest: {1}" -f $domain.DNSRoot,$forest.Name) -ForegroundColor Yellow
        Write-Host ("FSMO Roles: {0}" -f (($forest.SchemaMaster,$forest.NamingMaster,$domain.PDCEmulator,$domain.RIDMaster,$domain.InfrastructureMaster) -join ', '))
        $dcs = Get-DCsCached; Write-Host ("DCs: {0}" -f ($dcs -join ', '))
        try {
            $fail = Get-ADReplicationFailure -Scope Site -ErrorAction Stop | Select-Object Server, FirstFailureTime, Partner
            if($fail){ Write-Host "Replication Failures:" -ForegroundColor Red; $fail | Format-Table -AutoSize } else { Write-Host "No replication failures reported." -ForegroundColor Green }
        } catch { Write-Log "Replication failure query not available: $_" -Level Warning }
    } catch { Write-Host "Error: $_" -ForegroundColor Red }
}

# ============================================
# SETTINGS & HELP
# ============================================

function Show-Settings {
    Write-Host "`n=== SETTINGS ===" -ForegroundColor Cyan
    $Script:Config.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-18}: {1}" -f $_.Key,$_.Value) }
    Write-Host "`n1) Toggle Logging  2) Toggle Dry-Run  3) Set Export Path  4) Set Quarantine OU  5) Set Page Size  ENTER=Back" -ForegroundColor Gray
    $opt = Read-Host "Choose"
    switch($opt){
        '1' { $Script:Config.EnableLogging = -not $Script:Config.EnableLogging; Write-Log ("Logging -> {0}" -f $Script:Config.EnableLogging) }
        '2' { $Script:Config.DryRun = -not $Script:Config.DryRun; Write-Log ("DryRun -> {0}" -f $Script:Config.DryRun) -Level Warning }
        '3' { $p = Read-Host "New export path"; if($p){ $Script:Config.ExportPath=$p; Ensure-ExportPath; Write-Log "ExportPath updated" -Level Success } }
        '4' { $ou = Read-Host "Quarantine OU DN"; if($ou){ $Script:Config.QuarantineOU=$ou; Write-Log "QuarantineOU set" -Level Success } }
        '5' { $n = [int](Read-Host "Page size"); if($n -gt 0){ $Script:Config.DefaultPageSize=$n } }
        default { }
    }
}

function Show-Help {
    Write-Host "`n=== HELP ===" -ForegroundColor Cyan
    Write-Host "This tool provides enhanced AD management with dry-run safety, reports, bulk ops, and group/OU tools." -ForegroundColor Gray
    Write-Host "Tip: Enable Dry-Run in Settings to preview changes before applying." -ForegroundColor Gray
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
    Write-Host "  1.  Search for User (paged/export)"
    Write-Host "  2.  Check User Login Status"
    Write-Host "  3.  Reset User Password"
    Write-Host "  4.  Unlock User Account"
    Write-Host "  5.  Enable/Disable User"
    Write-Host "  6.  Show User Groups"
    Write-Host "  7.  Add User to Group"
    Write-Host "  8.  Remove User from Group"
    Write-Host "  9.  Move User to OU"
    Write-Host ""
    Write-Host "REPORTS" -ForegroundColor Yellow
    Write-Host "  10. Locked Out Accounts"
    Write-Host "  11. Password & Account Expiry Report"
    Write-Host "  12. Inactive Users Report (60/120+, export/disable/move)"
    Write-Host "  13. Export User List (filter by OU, extended columns)"
    Write-Host "  14. Stale Computers Report (disable/move/export)"
    Write-Host ""
    Write-Host "COMPUTERS" -ForegroundColor Yellow
    Write-Host "  18. Search for Computer"
    Write-Host "  19. Computer Live Info (logged-on user, last boot)"
    Write-Host ""
    Write-Host "BULK & HEALTH" -ForegroundColor Yellow
    Write-Host "  15. Bulk Actions From CSV"
    Write-Host "  16. AD Health Snapshot"
    Write-Host ""
    Write-Host "SYSTEM" -ForegroundColor Yellow
    Write-Host "  17. Settings"
    Write-Host "  H.  Help"
    Write-Host "  Q.  Quit"
    Write-Host ""
}

# ============================================
# MAIN PROGRAM EXECUTION
# ============================================

if (!(Initialize-Environment)) {
    Write-Host "`nFailed to initialize. Ensure permissions and modules are present." -ForegroundColor Red
    exit 1
}

# Main loop
do {
    Show-MainMenu
    $choice = Read-Host "Select an option"
    switch ($choice) {
        '1' { Search-ADUserByName; Read-Host "`nEnter to continue" }
        '2' { Get-UserLoginStatus; Read-Host "`nEnter to continue" }
        '3' { Reset-UserPassword; Read-Host "`nEnter to continue" }
        '4' { Unlock-UserAccount; Read-Host "`nEnter to continue" }
        '5' { Toggle-UserAccount; Read-Host "`nEnter to continue" }
        '6' { Show-UserGroups; Read-Host "`nEnter to continue" }
        '7' { Add-UserToGroup; Read-Host "`nEnter to continue" }
        '8' { Remove-UserFromGroup; Read-Host "`nEnter to continue" }
        '9' { Move-UserToOU; Read-Host "`nEnter to continue" }
        '10'{ Get-LockedOutAccounts; Read-Host "`nEnter to continue" }
        '11'{ Get-PasswordExpiryReport; Read-Host "`nEnter to continue" }
        '12'{ Get-InactiveUsersReport; Read-Host "`nEnter to continue" }
        '13'{ Export-UserList; Read-Host "`nEnter to continue" }
        '14'{ Report-StaleComputers; Read-Host "`nEnter to continue" }
        '15'{ Bulk-FromCSV; Read-Host "`nEnter to continue" }
        '16'{ Show-ADHealth; Read-Host "`nEnter to continue" }
        '17'{ Show-Settings; Read-Host "`nEnter to continue" }
        '18'{ Search-ComputerByName; Read-Host "`nEnter to continue" }
        '19'{ Get-ComputerLiveInfo; Read-Host "`nEnter to continue" }
        'H' { Show-Help; Read-Host "`nEnter to continue" }
        'h' { Show-Help; Read-Host "`nEnter to continue" }
        'Q' { Write-Host "`nExiting..." -ForegroundColor Yellow }
        'q' { Write-Host "`nExiting..." -ForegroundColor Yellow }
        default { Write-Host "Invalid selection. Try again." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
} while ($choice -notin @('Q','q')) ($choice -notin @('Q','q'))

Write-Host "Goodbye!" -ForegroundColor Green

