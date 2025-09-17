# AD Management Tool - Section 1 of 8 (Core Functions) - REPLACEMENT
# Save as: ADTool-Section1.ps1

#Requires -Version 5.0
#Requires -Modules ActiveDirectory

# Global configuration
$Script:Config = @{
    LogPath       = Join-Path $env:TEMP "ADTool_$(Get-Date -Format 'yyyyMMdd').log"
    ExportPath    = Join-Path $env:USERPROFILE 'Documents\ADToolExports'
    EnableLogging = $true
}

$Script:Stats = @{
    OperationCount = 0
    ErrorCount     = 0
    StartTime      = Get-Date
}

function Write-ADLog {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')][string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry  = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'Info'    { Write-Host $logEntry -ForegroundColor White }
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        'Error'   { Write-Host $logEntry -ForegroundColor Red }
        'Success' { Write-Host $logEntry -ForegroundColor Green }
    }

    if ($Script:Config.EnableLogging) {
        try   { Add-Content -Path $Script:Config.LogPath -Value $logEntry -ErrorAction Stop }
        catch { Write-Warning "Failed to write to log file" }
    }
}

function Initialize-ADTool {
    Write-ADLog "Initializing AD Management Tool..." -Level Info

    if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-ADLog "ActiveDirectory module not found" -Level Error
        return $false
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        Write-ADLog "Connected to domain: $($domain.Name)" -Level Success

        if (!(Test-Path $Script:Config.ExportPath)) {
            New-Item -ItemType Directory -Path $Script:Config.ExportPath -Force | Out-Null
        }

        return $true
    } catch {
        Write-ADLog "Failed to initialize: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# NEW: Get accurate (non-replicated) lastLogon across all DCs
function Get-ADLastLogonAcrossDCs {
    param(
        [ValidateSet('User','Computer')][string]$ObjectClass,
        [Parameter(Mandatory)][string]$Identity
    )

    $latest  = $null
    $sourceDc = $null

    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    foreach ($dc in $dcs) {
        try {
            $obj = if ($ObjectClass -eq 'User') {
                Get-ADUser -Identity $Identity -Server $dc -Properties lastLogon -ErrorAction Stop
            } else {
                Get-ADComputer -Identity $Identity -Server $dc -Properties lastLogon -ErrorAction Stop
            }

            if ($obj.lastLogon -and $obj.lastLogon -gt 0) {
                $dt = [DateTime]::FromFileTime($obj.lastLogon)
                if (-not $latest -or $dt -gt $latest) {
                    $latest  = $dt
                    $sourceDc = $dc
                }
            }
        } catch {
            # ignore per-DC lookup errors so one bad DC doesn't kill the query
        }
    }

    [PSCustomObject]@{
        Date = $latest
        DC   = $sourceDc
    }
}

function Search-ADUsers {
    param(
        [string]$SearchTerm = '*',
        [switch]$IncludeDisabled,
        [int]$MaxResults = 100,
        [switch]$Accurate
    )

    try {
        $enabledFilter = if ($IncludeDisabled) { "" } else { " -and Enabled -eq `$true" }
        $filter = "(Name -like '*$SearchTerm*' -or SamAccountName -like '*$SearchTerm*')$enabledFilter"

        $raw = Get-ADUser -Filter $filter -Properties DisplayName,mail,Department,Enabled,LastLogonDate |
               Select-Object -First $MaxResults

        if (-not $Accurate) {
            Write-ADLog "Found $(@($raw).Count) users (approx dates)" -Level Success
            return $raw
        }

        $results = foreach ($u in $raw) {
            $acc = Get-ADLastLogonAcrossDCs -ObjectClass User -Identity $u.SamAccountName
            [PSCustomObject]@{
                Username              = $u.SamAccountName
                DisplayName           = $u.DisplayName
                Email                 = $u.mail
                Department            = $u.Department
                Enabled               = $u.Enabled
                LastLogonDate         = $u.LastLogonDate
                LastLogonDateAccurate = $acc.Date
                LastLogonFromDC       = $acc.DC
            }
        }

        Write-ADLog "Found $(@($results).Count) users (accurate dates)" -Level Success
        return $results

    } catch {
        Write-ADLog "User search failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

# UPDATED: includes accurate cross-DC last logon + source DC
function Get-UserDetails {
    param([string]$Username)

    try {
        $user     = Get-ADUser -Identity $Username -Properties *
        $groups   = Get-ADPrincipalGroupMembership -Identity $Username
        $accurate = Get-ADLastLogonAcrossDCs -ObjectClass User -Identity $Username

        return [PSCustomObject]@{
            Username              = $user.SamAccountName
            DisplayName           = $user.DisplayName
            Email                 = $user.mail
            Department            = $user.Department
            Enabled               = $user.Enabled
            LockedOut             = $user.LockedOut
            LastLogonDate         = $user.LastLogonDate                 # replicated/approximate
            LastLogonDateAccurate = $accurate.Date                      # precise, per-DC max
            LastLogonFromDC       = $accurate.DC
            Groups                = ($groups.Name -join ', ')
        }
    } catch {
        Write-ADLog "Failed to get user details: $($_.Exception.Message)" -Level Error
        throw
    }
}

Write-ADLog "Section 1 loaded successfully" -Level Success
# SECTION 2/8 — User Management

function Set-UserEnabled {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Username,
        [bool]$Enabled
    )

    $action = if ($Enabled) { "Enable" } else { "Disable" }

    try {
        if ($PSCmdlet.ShouldProcess($Username, $action)) {
            Set-ADUser -Identity $Username -Enabled $Enabled
            Write-ADLog "$action user: $Username" -Level Success
            $Script:Stats.OperationCount++
        }
    } catch {
        Write-ADLog "Failed to $action user: $($_.Exception.Message)" -Level Error
        $Script:Stats.ErrorCount++
        throw
    }
}

function Unlock-ADUserAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Username)

    try {
        if ($PSCmdlet.ShouldProcess($Username, "Unlock Account")) {
            Unlock-ADAccount -Identity $Username
            Write-ADLog "Unlocked user: $Username" -Level Success
            $Script:Stats.OperationCount++
        }
    } catch {
        Write-ADLog "Failed to unlock user: $($_.Exception.Message)" -Level Error
        $Script:Stats.ErrorCount++
        throw
    }
}

function New-RandomPassword {
    param([int]$Length = 12)

    $lowercase = 'abcdefghijklmnopqrstuvwxyz'
    $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $numbers   = '0123456789'
    $symbols   = '!@#$%^&*'
    $allChars  = $lowercase + $uppercase + $numbers + $symbols

    do {
        $password = -join ((1..$Length) | ForEach-Object { $allChars[(Get-Random -Maximum $allChars.Length)] })
        $hasLower  = $password -cmatch '[a-z]'
        $hasUpper  = $password -cmatch '[A-Z]'
        $hasNumber = $password -match '\d'
        $hasSymbol = $password -match '[!@#$%^&*]'
    } while (!($hasLower -and $hasUpper -and $hasNumber -and $hasSymbol))

    return @{
        Password = $password
        Length   = $Length
        Strength = 'Strong'
    }
}

function Reset-ADUserPassword {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Username,
        [SecureString]$NewPassword,
        [switch]$GeneratePassword,
        [switch]$ForceChangeAtLogon
    )

    try {
        $passwordToUse = if ($GeneratePassword) {
            $generated = New-RandomPassword
            Write-Host "Generated password: $($generated.Password)" -ForegroundColor Yellow
            ConvertTo-SecureString $generated.Password -AsPlainText -Force
        } elseif ($NewPassword) {
            $NewPassword
        } else {
            Read-Host "Enter new password" -AsSecureString
        }

        if ($PSCmdlet.ShouldProcess($Username, "Reset Password")) {
            Set-ADAccountPassword -Identity $Username -NewPassword $passwordToUse -Reset
            if ($ForceChangeAtLogon) { Set-ADUser -Identity $Username -ChangePasswordAtLogon $true }
            Write-ADLog "Reset password for: $Username" -Level Success
            $Script:Stats.OperationCount++
        }
    } catch {
        Write-ADLog "Failed to reset password: $($_.Exception.Message)" -Level Error
        $Script:Stats.ErrorCount++
        throw
    }
}

function Invoke-BulkUserOperation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$Usernames,
        [ValidateSet('Enable','Disable','Unlock','ResetPassword')][string]$Operation,
        [switch]$GeneratePasswords
    )

    Write-ADLog "Starting bulk $Operation for $($Usernames.Count) users" -Level Info

    $results       = @()
    $successCount  = 0
    $failureCount  = 0

    foreach ($username in $Usernames) {
        try {
            switch ($Operation) {
                'Enable' {
                    if ($PSCmdlet.ShouldProcess($username, "Enable User")) {
                        Set-ADUser -Identity $username -Enabled $true
                        $results += [PSCustomObject]@{ Username = $username; Operation = 'Enable';        Status = 'Success' }
                        $successCount++
                    }
                }
                'Disable' {
                    if ($PSCmdlet.ShouldProcess($username, "Disable User")) {
                        Set-ADUser -Identity $username -Enabled $false
                        $results += [PSCustomObject]@{ Username = $username; Operation = 'Disable';       Status = 'Success' }
                        $successCount++
                    }
                }
                'Unlock' {
                    if ($PSCmdlet.ShouldProcess($username, "Unlock User")) {
                        Unlock-ADAccount -Identity $username
                        $results += [PSCustomObject]@{ Username = $username; Operation = 'Unlock';        Status = 'Success' }
                        $successCount++
                    }
                }
                'ResetPassword' {
                    if ($PSCmdlet.ShouldProcess($username, "Reset Password")) {
                        $newPassword = if ($GeneratePasswords) {
                            $generated = New-RandomPassword
                            ConvertTo-SecureString $generated.Password -AsPlainText -Force
                        } else {
                            Read-Host "Password for $username" -AsSecureString
                        }

                        Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset
                        Set-ADUser -Identity $username -ChangePasswordAtLogon $true

                        $results += [PSCustomObject]@{
                            Username    = $username
                            Operation   = 'ResetPassword'
                            Status      = 'Success'
                            NewPassword = if ($GeneratePasswords) { $generated.Password } else { 'Set' }
                        }
                        $successCount++
                    }
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                Username  = $username
                Operation = $Operation
                Status    = 'Failed'
                Error     = $_.Exception.Message
            }
            $failureCount++
        }
    }

    $Script:Stats.OperationCount += $successCount
    $Script:Stats.ErrorCount     += $failureCount

    Write-ADLog "Bulk operation complete: $successCount success, $failureCount failed" -Level Success
    return $results
}

Write-ADLog "Section 2 loaded successfully" -Level Success
# AD Management Tool - Section 3 of 8 (Computer Management) - UPDATED
# Save as: ADTool-Section3.ps1

# Prefer private LAN IPv4s over CGNAT/Tailscale/public when resolving hostnames
function Resolve-PreferPrivateIPv4 {
    param([string]$HostName)
    try {
        $ipv4s = [System.Net.Dns]::GetHostAddresses($HostName) |
                 Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        if (-not $ipv4s) { return $null }

        $ranked = $ipv4s | Sort-Object -Property @{
            Expression = {
                $b = $_.GetAddressBytes()
                if     ($b[0] -eq 192 -and $b[1] -eq 168)                         { 0 }   # 192.168.x.x
                elseif ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31)        { 1 }   # 172.16–31.x.x
                elseif ($b[0] -eq 10)                                             { 2 }   # 10.x.x.x
                elseif ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)       { 10 }  # 100.64/10 (CGNAT/Tailscale)
                else                                                               { 5 }   # anything else
            }
        }
        return $ranked[0].IPAddressToString
    } catch { return $null }
}

function Search-ADComputers {
    param(
        [string]$SearchTerm = '*',
        [switch]$IncludeDisabled,
        [int]$MaxResults = 100,
        [switch]$Accurate
    )

    try {
        $enabledFilter = if ($IncludeDisabled) { "" } else { " -and Enabled -eq `$true" }
        $filter = "(Name -like '*$SearchTerm*' -or DNSHostName -like '*$SearchTerm*')$enabledFilter"

        $raw = Get-ADComputer -Filter $filter -Properties OperatingSystem,LastLogonTimestamp,Enabled,IPv4Address |
               Select-Object -First $MaxResults

        $results = foreach ($c in $raw) {
            $approx = if ($c.LastLogonTimestamp) { [DateTime]::FromFileTime($c.LastLogonTimestamp) } else { $null }
            $acc    = if ($Accurate) { Get-ADLastLogonAcrossDCs -ObjectClass Computer -Identity $c.Name } else { $null }

            [PSCustomObject]@{
                Name                    = $c.Name
                DNSHostName             = $c.DNSHostName
                OperatingSystem         = $c.OperatingSystem
                Enabled                 = $c.Enabled
                IPv4Address             = $c.IPv4Address                        # AD attribute (may be stale)
                ResolvedIPv4            = if ($c.DNSHostName) { Resolve-PreferPrivateIPv4 $c.DNSHostName } else { $null }
                LastLogonDate           = $approx                                # replicated/approx
                AccurateLastLogonDate   = if ($Accurate) { $acc.Date } else { $null }
                AccurateLastLogonFromDC = if ($Accurate) { $acc.DC }   else { $null }
                DaysSinceLogon          = if ($approx) { [int]((Get-Date) - $approx).TotalDays } else { 'Never' }
            }
        }

        Write-ADLog "Found $(@($results).Count) computers$(@{ $true=' (accurate dates)'; $false='' }[$Accurate.IsPresent])" -Level Success
        return $results

    } catch {
        Write-ADLog "Computer search failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-ComputerDetails {
    param([string]$ComputerName)

    try {
        $computer = Get-ADComputer -Identity $ComputerName -Properties *
        $isOnline = $false
        try { $isOnline = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop } catch {}

        # Accurate (non-replicated) last logon across DCs
        $accurate = Get-ADLastLogonAcrossDCs -ObjectClass Computer -Identity $ComputerName

        # Live DNS resolve with LAN preference
        $resolvedIPv4 = if ($computer.DNSHostName) { Resolve-PreferPrivateIPv4 $computer.DNSHostName } else { $null }

        # LiveInfo via CIM with WMI fallback
        $liveInfo = if ($isOnline) {
            $info = $null
            try {
                $cs = Get-CimInstance -ClassName Win32_ComputerSystem  -ComputerName $ComputerName -ErrorAction Stop
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
                $info = @{
                    LoggedOnUser  = $cs.UserName
                    Manufacturer  = $cs.Manufacturer
                    Model         = $cs.Model
                    TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                    LastBootTime  = $os.LastBootUpTime
                    UptimeDays    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
                }
            } catch {
                try {
                    $cs = Get-WmiObject -Class Win32_ComputerSystem  -ComputerName $ComputerName -ErrorAction Stop
                    $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
                    $info = @{
                        LoggedOnUser  = $cs.UserName
                        Manufacturer  = $cs.Manufacturer
                        Model         = $cs.Model
                        TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                        LastBootTime  = $os.LastBootUpTime
                        UptimeDays    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
                    }
                } catch {
                    @{ Error = "Remote management (CIM/WMI) failed" }
                }
            }
            $info
        } else {
            @{ Status = "Computer not reachable" }
        }

        $approx = if ($computer.LastLogonTimestamp) { [DateTime]::FromFileTime($computer.LastLogonTimestamp) } else { $null }

        return [PSCustomObject]@{
            Name                    = $computer.Name
            DNSHostName             = $computer.DNSHostName
            Description             = $computer.Description
            OperatingSystem         = $computer.OperatingSystem
            Enabled                 = $computer.Enabled
            IPv4Address             = $computer.IPv4Address
            ResolvedIPv4            = $resolvedIPv4
            LastLogonTimestampDate  = $approx
            AccurateLastLogonDate   = $accurate.Date
            AccurateLastLogonFromDC = $accurate.DC
            Created                 = $computer.whenCreated
            Modified                = $computer.whenChanged
            Online                  = $isOnline
            LiveInfo                = $liveInfo
        }

    } catch {
        Write-ADLog "Failed to get computer details: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-ComputerConnectivity {
    param(
        [string[]]$ComputerNames,
        [int]$TimeoutSeconds = 5
    )

    Write-ADLog "Testing connectivity for $($ComputerNames.Count) computers" -Level Info

    $supportsTimeout = (Get-Command Test-Connection).Parameters.Keys -contains 'TimeoutSeconds'

    $results = foreach ($computerName in $ComputerNames) {
        try {
            $pingResult = $false
            try {
                if ($supportsTimeout) {
                    $pingResult = Test-Connection -ComputerName $computerName -Count 1 -TimeoutSeconds $TimeoutSeconds -Quiet -ErrorAction Stop
                } else {
                    # PS 5.1: no TimeoutSeconds
                    $pingResult = Test-Connection -ComputerName $computerName -Count 1 -Quiet -ErrorAction Stop
                }
            } catch {}

            if (-not $pingResult) {
                try { $pingResult = Test-NetConnection -ComputerName $computerName -InformationLevel Quiet -WarningAction SilentlyContinue } catch {}
            }

            [PSCustomObject]@{
                ComputerName = $computerName
                Online       = [bool]$pingResult
                Status       = if ($pingResult) { 'Reachable' } else { 'Unreachable' }
                TestTime     = Get-Date
            }
        } catch {
            [PSCustomObject]@{
                ComputerName = $computerName
                Online       = $false
                Status       = 'Error'
                Error        = $_.Exception.Message
                TestTime     = Get-Date
            }
        }
    }

    $onlineCount = ($results | Where-Object Online -eq $true).Count
    Write-ADLog "Connectivity test completed: $onlineCount/$($results.Count) online" -Level Success
    return $results
}

function Get-StaleComputersReport {
    param([int]$InactiveDays = 90)

    try {
        $cutoffDate = (Get-Date).AddDays(-$InactiveDays)
        $computers  = Get-ADComputer -Filter {Enabled -eq $true} -Properties LastLogonTimestamp,OperatingSystem

        $staleComputers = foreach ($computer in $computers) {
            $approx = if ($computer.LastLogonTimestamp) { [DateTime]::FromFileTime($computer.LastLogonTimestamp) } else { $null }
            $days   = if ($approx) { [int]((Get-Date) - $approx).TotalDays } else { $null }

            if (!$approx -or $approx -lt $cutoffDate) {
                [PSCustomObject]@{
                    Name            = $computer.Name
                    OperatingSystem = $computer.OperatingSystem
                    LastLogonDate   = $approx
                    DaysSinceLogon  = if ($days) { $days } else { 'Never' }
                    Status          = if (!$approx) { 'Never Logged On' } else { 'Stale' }
                }
            }
        }

        $results = $staleComputers | Sort-Object @{ Expression = { if ($_.DaysSinceLogon -eq 'Never') { 9999 } else { [int]$_.DaysSinceLogon } } } -Descending
        Write-ADLog "Found $($results.Count) stale computers" -Level Success
        return $results

    } catch {
        Write-ADLog "Failed to generate stale computers report: $($_.Exception.Message)" -Level Error
        throw
    }
}

Write-ADLog "Section 3 loaded successfully" -Level Success

# SECTION 4/8 — Reporting

function Get-LockedOutUsers {
    try {
        $lockedUsers = Search-ADAccount -LockedOut -UsersOnly
        if ($lockedUsers) {
            $results = $lockedUsers | ForEach-Object {
                [PSCustomObject]@{
                    Username    = $_.SamAccountName
                    Name        = $_.Name
                    LockoutTime = $_.AccountLockoutTime
                    BadPwdCount = $_.BadPwdCount
                }
            }
            Write-ADLog "Found $($results.Count) locked out users" -Level Success
            return $results
        } else {
            Write-ADLog "No locked out users found" -Level Success
            return @()
        }
    } catch {
        Write-ADLog "Failed to get locked out users: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-PasswordExpiryReport {
    param([int]$DaysThreshold = 30)

    try {
        $domainPolicy   = Get-ADDefaultDomainPasswordPolicy
        $maxPasswordAge = $domainPolicy.MaxPasswordAge.Days

        if ($maxPasswordAge -eq 0) {
            Write-ADLog "Domain password policy allows unlimited password age" -Level Warning
            return @()
        }

        $users = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false} -Properties PasswordLastSet,DisplayName,mail

        $expiringUsers = foreach ($user in $users) {
            if ($user.PasswordLastSet) {
                $passwordExpiry = $user.PasswordLastSet.AddDays($maxPasswordAge)
                $daysToExpiry   = ($passwordExpiry - (Get-Date)).Days

                if ($daysToExpiry -le $DaysThreshold -and $daysToExpiry -ge 0) {
                    [PSCustomObject]@{
                        Username        = $user.SamAccountName
                        DisplayName     = $user.DisplayName
                        Email           = $user.mail
                        PasswordLastSet = $user.PasswordLastSet
                        PasswordExpiry  = $passwordExpiry
                        DaysToExpiry    = $daysToExpiry
                        Status          = if ($daysToExpiry -le 7) { 'Critical' } elseif ($daysToExpiry -le 14) { 'Warning' } else { 'Notice' }
                    }
                }
            }
        }

        $results = $expiringUsers | Sort-Object DaysToExpiry
        Write-ADLog "Found $($results.Count) users with passwords expiring within $DaysThreshold days" -Level Success
        return $results

    } catch {
        Write-ADLog "Failed to generate password expiry report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-InactiveUsersReport {
    param([int]$InactiveDays = 90)

    try {
        $cutoffDate = (Get-Date).AddDays(-$InactiveDays)
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate,DisplayName,Department,mail

        $inactiveUsers = foreach ($user in $users) {
            $daysSinceLogon = if ($user.LastLogonDate) { [int]((Get-Date) - $user.LastLogonDate).TotalDays } else { $null }
            if (!$user.LastLogonDate -or $user.LastLogonDate -lt $cutoffDate) {
                [PSCustomObject]@{
                    Username       = $user.SamAccountName
                    DisplayName    = $user.DisplayName
                    Email          = $user.mail
                    Department     = $user.Department
                    LastLogonDate  = $user.LastLogonDate
                    DaysSinceLogon = if ($daysSinceLogon) { $daysSinceLogon } else { 'Never' }
                    Status         = if (!$user.LastLogonDate) { 'Never Logged On' } else { 'Inactive' }
                }
            }
        }

        $results = $inactiveUsers | Sort-Object @{ Expression = { if ($_.DaysSinceLogon -eq 'Never') { 9999 } else { [int]$_.DaysSinceLogon } } } -Descending
        Write-ADLog "Found $($results.Count) inactive users" -Level Success
        return $results

    } catch {
        Write-ADLog "Failed to generate inactive users report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-PrivilegedUsersReport {
    param([string[]]$PrivilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Account Operators'))

    try {
        $privilegedUsers = @()

        foreach ($groupName in $PrivilegedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue | Where-Object objectClass -eq 'user'
                foreach ($member in $members) {
                    $user = Get-ADUser -Identity $member -Properties DisplayName,LastLogonDate,Enabled
                    $privilegedUsers += [PSCustomObject]@{
                        Username       = $user.SamAccountName
                        DisplayName    = $user.DisplayName
                        Group          = $groupName
                        Enabled        = $user.Enabled
                        LastLogonDate  = $user.LastLogonDate
                        DaysSinceLogon = if ($user.LastLogonDate) { [int]((Get-Date) - $user.LastLogonDate).TotalDays } else { 'Never' }
                    }
                }
            } catch {
                Write-ADLog "Could not process group $groupName" -Level Warning
            }
        }

        # Collapse duplicates, aggregate group list
        $uniqueUsers = $privilegedUsers | Group-Object Username | ForEach-Object {
            $user = $_.Group[0]
            $allGroups = ($_.Group.Group | Sort-Object -Unique) -join ', '
            $user | Add-Member -NotePropertyName 'Groups' -NotePropertyValue $allGroups -Force -PassThru
        }

        Write-ADLog "Found $($uniqueUsers.Count) privileged users" -Level Success
        return $uniqueUsers

    } catch {
        Write-ADLog "Failed to generate privileged users report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-ADHealthReport {
    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        $dcs    = Get-ADDomainController -Filter *

        $dcStatus = foreach ($dc in $dcs) {
            $online = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet
            [PSCustomObject]@{
                Name            = $dc.Name
                HostName        = $dc.HostName
                Site            = $dc.Site
                OperatingSystem = $dc.OperatingSystem
                Online          = $online
                Status          = if ($online) { 'Online' } else { 'Offline' }
            }
        }

        $totalUsers       = (Get-ADUser -Filter *).Count
        $enabledUsers     = (Get-ADUser -Filter {Enabled -eq $true}).Count
        $totalComputers   = (Get-ADComputer -Filter *).Count
        $enabledComputers = (Get-ADComputer -Filter {Enabled -eq $true}).Count

        $healthReport = [PSCustomObject]@{
            Domain = @{
                Name        = $domain.DNSRoot
                NetBIOSName = $domain.NetBIOSName
                DomainMode  = $domain.DomainMode
                Forest      = $forest.Name
                ForestMode  = $forest.ForestMode
            }
            FSMORoles = @{
                SchemaMaster       = $forest.SchemaMaster
                DomainNamingMaster = $forest.DomainNamingMaster
                PDCEmulator        = $domain.PDCEmulator
                RIDMaster          = $domain.RIDMaster
                InfrastructureMaster= $domain.InfrastructureMaster
            }
            DomainControllers = $dcStatus
            AccountCounts = @{
                TotalUsers       = $totalUsers
                EnabledUsers     = $enabledUsers
                TotalComputers   = $totalComputers
                EnabledComputers = $enabledComputers
            }
            OnlineDCs  = ($dcStatus | Where-Object Online -eq $true).Count
            OfflineDCs = ($dcStatus | Where-Object Online -eq $false).Count
        }

        Write-ADLog "AD health report generated successfully" -Level Success
        return $healthReport

    } catch {
        Write-ADLog "Failed to generate AD health report: $($_.Exception.Message)" -Level Error
        throw
    }
}

Write-ADLog "Section 4 loaded successfully" -Level Success
# SECTION 5/8 — Export & CSV (fixed)

function Export-ReportToCSV {
    param(
        [object[]]$Data,
        [string]$ReportName,
        [string]$FilePath
    )

    if (!$Data) {
        Write-ADLog "No data to export for report: $ReportName" -Level Warning
        return
    }

    try {
        if (!$FilePath) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $filename  = "${ReportName}_$timestamp.csv"
            $FilePath  = Join-Path $Script:Config.ExportPath $filename
        }

        $Data | Export-Csv -Path $FilePath -NoTypeInformation
        Write-ADLog "Report exported to: $FilePath" -Level Success
        return $FilePath

    } catch {
        Write-ADLog "Failed to export report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Export-ReportToHTML {
    param(
        [object[]]$Data,
        [string]$ReportName,
        [string]$FilePath
    )

    if (!$Data) {
        Write-ADLog "No data to export for report: $ReportName" -Level Warning
        return
    }

    try {
        if (!$FilePath) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $filename  = "${ReportName}_$timestamp.html"
            $FilePath  = Join-Path $Script:Config.ExportPath $filename
        }

$css = @"
<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #2E86C1; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #3498DB; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .summary { background-color: #EBF5FB; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
</style>
"@

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportName Report</title>
    $css
</head>
<body>
    <h1>$ReportName Report</h1>
    <div class="summary">
        <p><strong>Generated:</strong> $(Get-Date)</p>
        <p><strong>Total Records:</strong> $($Data.Count)</p>
    </div>
    $($Data | ConvertTo-Html -Fragment)
</body>
</html>
"@

        Set-Content -Path $FilePath -Value $html -Encoding UTF8
        Write-ADLog "HTML report exported to: $FilePath" -Level Success
        return $FilePath

    } catch {
        Write-ADLog "Failed to export HTML report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Show-ReportSummary {
    param(
        [object[]]$Data,
        [string]$ReportName
    )

    if (!$Data -or $Data.Count -eq 0) {
        Write-Host "`n=== $ReportName ===" -ForegroundColor Cyan
        Write-Host "No results found." -ForegroundColor Yellow
        return
    }

    Write-Host "`n=== $ReportName ===" -ForegroundColor Cyan
    Write-Host "Total Records: $($Data.Count)" -ForegroundColor Green

    $displayCount = [Math]::Min(10, $Data.Count)
    Write-Host "`nShowing first $displayCount records:" -ForegroundColor Yellow
    $Data | Select-Object -First $displayCount | Format-Table -AutoSize

    if ($Data.Count -gt 10) {
        Write-Host "... and $($Data.Count - 10) more records" -ForegroundColor Gray
    }

    Write-Host "`nExport Options:" -ForegroundColor Cyan
    Write-Host "1. Export to CSV"
    Write-Host "2. Export to HTML"
    Write-Host "3. Both formats"
    Write-Host "4. No export"

    $choice = Read-Host "Choose export option (1-4)"

    switch ($choice) {
        '1' { Export-ReportToCSV  -Data $Data -ReportName $ReportName }
        '2' { Export-ReportToHTML -Data $Data -ReportName $ReportName }
        '3' {
            Export-ReportToCSV  -Data $Data -ReportName $ReportName
            Export-ReportToHTML -Data $Data -ReportName $ReportName
        }
        '4' { Write-Host "No export performed." -ForegroundColor Gray }
        default { Write-Host "Invalid choice. No export performed." -ForegroundColor Red }
    }
}

function Import-UsersFromCSV {
    param([string]$FilePath)

    if (!(Test-Path $FilePath)) {
        Write-ADLog "CSV file not found: $FilePath" -Level Error
        throw "File not found: $FilePath"
    }

    try {
        $csvData = Import-Csv -Path $FilePath
        Write-ADLog "Imported $($csvData.Count) records from CSV: $FilePath" -Level Success
        return $csvData
    } catch {
        Write-ADLog "Failed to import CSV: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Invoke-BulkOperationFromCSV {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$FilePath)

    try {
        $csvData = Import-UsersFromCSV -FilePath $FilePath
        $results = @()

        foreach ($row in $csvData) {
            if (!$row.Username -or !$row.Operation) {
                Write-ADLog "Skipping row with missing Username or Operation" -Level Warning
                continue
            }
            try {
                switch ($row.Operation) {
                    'Enable' {
                        if ($PSCmdlet.ShouldProcess($row.Username, "Enable User")) {
                            Set-ADUser -Identity $row.Username -Enabled $true
                            $results += [PSCustomObject]@{ Username = $row.Username; Operation = 'Enable'; Status = 'Success' }
                        }
                    }
                    'Disable' {
                        if ($PSCmdlet.ShouldProcess($row.Username, "Disable User")) {
                            Set-ADUser -Identity $row.Username -Enabled $false
                            $results += [PSCustomObject]@{ Username = $row.Username; Operation = 'Disable'; Status = 'Success' }
                        }
                    }
                    'Unlock' {
                        if ($PSCmdlet.ShouldProcess($row.Username, "Unlock User")) {
                            Unlock-ADAccount -Identity $row.Username
                            $results += [PSCustomObject]@{ Username = $row.Username; Operation = 'Unlock'; Status = 'Success' }
                        }
                    }
                    'ResetPassword' {
                        if ($PSCmdlet.ShouldProcess($row.Username, "Reset Password")) {
                            $newPassword = if ($row.NewPassword) {
                                ConvertTo-SecureString $row.NewPassword -AsPlainText -Force
                            } else {
                                $generated = New-RandomPassword
                                ConvertTo-SecureString $generated.Password -AsPlainText -Force
                            }
                            Set-ADAccountPassword -Identity $row.Username -NewPassword $newPassword -Reset
                            Set-ADUser -Identity $row.Username -ChangePasswordAtLogon $true
                            $results += [PSCustomObject]@{ Username = $row.Username; Operation = 'ResetPassword'; Status = 'Success' }
                        }
                    }
                    default {
                        $results += [PSCustomObject]@{
                            Username  = $row.Username
                            Operation = $row.Operation
                            Status    = 'Failed'
                            Error     = "Unknown operation: $($row.Operation)"
                        }
                    }
                }
            } catch {
                $results += [PSCustomObject]@{
                    Username  = $row.Username
                    Operation = $row.Operation
                    Status    = 'Failed'
                    Error     = $_.Exception.Message
                }
            }
        }

        Write-ADLog "Bulk CSV operations completed" -Level Success
        return $results

    } catch {
        Write-ADLog "Bulk CSV operations failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

Write-ADLog "Section 5 loaded successfully" -Level Success
# AD Management Tool - Section 6 of 8 (Menu / UI) - UPDATED
# Save as: ADTool-Section6.ps1

function Show-MainMenu {
    Clear-Host
    $uptime = (Get-Date) - $Script:Stats.StartTime

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "              AD Management Tool v3.0 - Main Menu              " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USER MANAGEMENT" -ForegroundColor Yellow
    Write-Host "  1.  Search Users"
    Write-Host "  2.  Get User Details"
    Write-Host "  3.  Enable/Disable User"
    Write-Host "  4.  Unlock User Account"
    Write-Host "  5.  Reset User Password"
    Write-Host ""
    Write-Host "COMPUTER MANAGEMENT" -ForegroundColor Yellow
    Write-Host "  6.  Search Computers"
    Write-Host "  7.  Get Computer Details"
    Write-Host "  8.  Test Computer Connectivity"
    Write-Host ""
    Write-Host "REPORTING" -ForegroundColor Yellow
    Write-Host "  9.  Locked Out Users Report"
    Write-Host "  10. Password Expiry Report"
    Write-Host "  11. Inactive Users Report"
    Write-Host "  12. Privileged Users Report"
    Write-Host "  13. Stale Computers Report"
    Write-Host "  14. AD Health Report"
    Write-Host ""
    Write-Host "BULK OPERATIONS" -ForegroundColor Yellow
    Write-Host "  15. Bulk User Operations"
    Write-Host "  16. Import from CSV"
    Write-Host ""
    Write-Host "UTILITIES" -ForegroundColor Yellow
    Write-Host "  17. View Statistics"
    Write-Host "  18. Settings"
    Write-Host ""
    Write-Host "  H.  Help"
    Write-Host "  Q.  Quit"
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan

    Write-Host "Status: Operations: $($Script:Stats.OperationCount) | Errors: $($Script:Stats.ErrorCount) | Uptime: $($uptime.ToString('hh\:mm\:ss'))" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-MainMenuLoop {
    do {
        Show-MainMenu
        $choice = Read-Host "Enter your choice"

        try {
            switch ($choice.ToUpper()) {

                # Search Users (now with optional accurate last logon across DCs)
                '1' {
                    $searchTerm = Read-Host "Enter search term (or * for all)"
                    $includeDisabled = (Read-Host "Include disabled users? (y/N)").ToLower() -eq 'y'
                    $accurate = (Read-Host "Use accurate last logon across all DCs? (slower) (y/N)").ToLower() -eq 'y'

                    $users = Search-ADUsers -SearchTerm $searchTerm -IncludeDisabled:$includeDisabled -Accurate:$accurate
                    Show-ReportSummary -Data $users -ReportName "User Search Results"
                    Read-Host "`nPress Enter to continue"
                }

                '2' {
                    $username = Read-Host "Enter username"
                    if ($username) { Get-UserDetails -Username $username | Format-List }
                    Read-Host "`nPress Enter to continue"
                }

                '3' {
                    $username = Read-Host "Enter username"
                    if ($username) {
                        $action  = Read-Host "Enable or Disable? (E/D)"
                        $enabled = $action.ToUpper() -eq 'E'
                        Set-UserEnabled -Username $username -Enabled $enabled
                    }
                    Read-Host "`nPress Enter to continue"
                }

                '4' {
                    $username = Read-Host "Enter username"
                    if ($username) { Unlock-ADUserAccount -Username $username }
                    Read-Host "`nPress Enter to continue"
                }

                '5' {
                    $username = Read-Host "Enter username"
                    if ($username) {
                        $generate = (Read-Host "Generate random password? (Y/n)").ToUpper() -ne 'N'
                        Reset-ADUserPassword -Username $username -GeneratePassword:$generate
                    }
                    Read-Host "`nPress Enter to continue"
                }

                # Search Computers (now with optional accurate last logon + private-IP preference)
                '6' {
                    $searchTerm = Read-Host "Enter computer search term (or * for all)"
                    $includeDisabled = (Read-Host "Include disabled computers? (y/N)").ToLower() -eq 'y'
                    $accurate = (Read-Host "Use accurate last logon across all DCs? (slower) (y/N)").ToLower() -eq 'y'

                    $computers = Search-ADComputers -SearchTerm $searchTerm -IncludeDisabled:$includeDisabled -Accurate:$accurate
                    Show-ReportSummary -Data $computers -ReportName "Computer Search Results"
                    Read-Host "`nPress Enter to continue"
                }

                '7' {
                    $computerName = Read-Host "Enter computer name"
                    if ($computerName) { Get-ComputerDetails -ComputerName $computerName | Format-List }
                    Read-Host "`nPress Enter to continue"
                }

                '8' {
                    $computerNames = Read-Host "Enter computer names (comma separated)"
                    if ($computerNames) {
                        $names   = $computerNames -split ',' | ForEach-Object { $_.Trim() }
                        $results = Test-ComputerConnectivity -ComputerNames $names
                        Show-ReportSummary -Data $results -ReportName "Connectivity Test Results"
                    }
                    Read-Host "`nPress Enter to continue"
                }

                '9'  { $results = Get-LockedOutUsers;        Show-ReportSummary -Data $results -ReportName "Locked Out Users";        Read-Host "`nPress Enter to continue" }
                '10' {
                    $days = Read-Host "Days threshold (default: 30)"; if (!$days -or $days -notmatch '^\d+$') { $days = 30 }
                    $results = Get-PasswordExpiryReport -DaysThreshold $days
                    Show-ReportSummary -Data $results -ReportName "Password Expiry Report"
                    Read-Host "`nPress Enter to continue"
                }
                '11' {
                    $days = Read-Host "Inactive days threshold (default: 90)"; if (!$days -or $days -notmatch '^\d+$') { $days = 90 }
                    $results = Get-InactiveUsersReport -InactiveDays $days
                    Show-ReportSummary -Data $results -ReportName "Inactive Users Report"
                    Read-Host "`nPress Enter to continue"
                }
                '12' { $results = Get-PrivilegedUsersReport; Show-ReportSummary -Data $results -ReportName "Privileged Users Report"; Read-Host "`nPress Enter to continue" }
                '13' {
                    $days = Read-Host "Stale days threshold (default: 90)"; if (!$days -or $days -notmatch '^\d+$') { $days = 90 }
                    $results = Get-StaleComputersReport -InactiveDays $days
                    Show-ReportSummary -Data $results -ReportName "Stale Computers Report"
                    Read-Host "`nPress Enter to continue"
                }
                '14' {
                    Write-Host "Generating AD Health Report..." -ForegroundColor Gray
                    $healthReport = Get-ADHealthReport
                    Write-Host "`n=== AD HEALTH REPORT ===" -ForegroundColor Cyan
                    Write-Host "Domain: $($healthReport.Domain.Name)" -ForegroundColor White
                    Write-Host "Forest: $($healthReport.Domain.Forest)" -ForegroundColor White
                    Write-Host "Domain Mode: $($healthReport.Domain.DomainMode)" -ForegroundColor White
                    Write-Host "Forest Mode: $($healthReport.Domain.ForestMode)" -ForegroundColor White
                    Write-Host "`nFSMO Roles:" -ForegroundColor Yellow
                    Write-Host "  Schema Master: $($healthReport.FSMORoles.SchemaMaster)"
                    Write-Host "  Domain Naming Master: $($healthReport.FSMORoles.DomainNamingMaster)"
                    Write-Host "  PDC Emulator: $($healthReport.FSMORoles.PDCEmulator)"
                    Write-Host "  RID Master: $($healthReport.FSMORoles.RIDMaster)"
                    Write-Host "  Infrastructure Master: $($healthReport.FSMORoles.InfrastructureMaster)"
                    Write-Host "`nDomain Controllers:" -ForegroundColor Yellow
                    $healthReport.DomainControllers | Format-Table Name, Site, Online, Status -AutoSize
                    Write-Host "Account Summary:" -ForegroundColor Yellow
                    Write-Host "  Total Users: $($healthReport.AccountCounts.TotalUsers)"
                    Write-Host "  Enabled Users: $($healthReport.AccountCounts.EnabledUsers)"
                    Write-Host "  Total Computers: $($healthReport.AccountCounts.TotalComputers)"
                    Write-Host "  Enabled Computers: $($healthReport.AccountCounts.EnabledComputers)"
                    Read-Host "`nPress Enter to continue"
                }

                '15' {
                    Write-Host "`n=== BULK USER OPERATIONS ===" -ForegroundColor Cyan
                    Write-Host "1. Enable Users"
                    Write-Host "2. Disable Users"
                    Write-Host "3. Unlock Users"
                    Write-Host "4. Reset Passwords"
                    $bulkChoice = Read-Host "Choose operation (1-4)"
                    $userList   = Read-Host "Enter usernames (comma separated)"
                    if ($userList) {
                        $usernames = $userList -split ',' | ForEach-Object { $_.Trim() }
                        $operation = switch ($bulkChoice) { '1' {'Enable'} '2' {'Disable'} '3' {'Unlock'} '4' {'ResetPassword'} default {$null} }
                        if ($operation) {
                            $generatePasswords = if ($operation -eq 'ResetPassword') { (Read-Host "Generate random passwords? (Y/n)").ToUpper() -ne 'N' } else { $false }
                            $results = Invoke-BulkUserOperation -Usernames $usernames -Operation $operation -GeneratePasswords:$generatePasswords
                            Show-ReportSummary -Data $results -ReportName "Bulk Operation Results"
                        }
                    }
                    Read-Host "`nPress Enter to continue"
                }

                '16' {
                    $csvPath = Read-Host "Enter CSV file path"
                    if ($csvPath -and (Test-Path $csvPath)) {
                        Write-Host "Processing CSV file..." -ForegroundColor Gray
                        $results = Invoke-BulkOperationFromCSV -FilePath $csvPath
                        Show-ReportSummary -Data $results -ReportName "CSV Import Results"
                    } else {
                        Write-Host "File not found or path not specified" -ForegroundColor Red
                    }
                    Read-Host "`nPress Enter to continue"
                }

                '17' { Show-Statistics; Read-Host "`nPress Enter to continue" }
                '18' { Show-Settings;   Read-Host "`nPress Enter to continue" }
                'H'  { Show-Help;       Read-Host "`nPress Enter to continue" }
                'Q'  { Write-Host "`nExiting AD Management Tool..." -ForegroundColor Yellow; break }

                default {
                    Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
        } catch {
            Write-ADLog "Menu operation failed: $($_.Exception.Message)" -Level Error
            Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
            Read-Host "Press Enter to continue"
        }
    } while ($choice.ToUpper() -ne 'Q')
}

Write-ADLog "Section 6 loaded successfully" -Level Success

# SECTION 7/8 — Settings / Help

function Show-Statistics {
    Clear-Host
    $uptime = (Get-Date) - $Script:Stats.StartTime

    Write-Host "=== AD TOOL STATISTICS ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Session Information:" -ForegroundColor Yellow
    Write-Host "  Start Time: $($Script:Stats.StartTime)"
    Write-Host "  Uptime: $($uptime.ToString('hh\:mm\:ss'))"
    Write-Host "  Operations: $($Script:Stats.OperationCount)"
    Write-Host "  Errors: $($Script:Stats.ErrorCount)"
    Write-Host "  Success Rate: $([math]::Round((($Script:Stats.OperationCount - $Script:Stats.ErrorCount) / [math]::Max($Script:Stats.OperationCount, 1)) * 100, 2))%"
    Write-Host "`nConfiguration:" -ForegroundColor Yellow
    Write-Host "  Log Path: $($Script:Config.LogPath)"
    Write-Host "  Export Path: $($Script:Config.ExportPath)"
    Write-Host "  Logging Enabled: $($Script:Config.EnableLogging)"
}

function Show-Settings {
    Clear-Host
    Write-Host "=== SETTINGS ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current Settings:" -ForegroundColor Yellow
    Write-Host "  1. Enable Logging: $($Script:Config.EnableLogging)"
    Write-Host "  2. Export Path: $($Script:Config.ExportPath)"
    Write-Host "  3. Log Path: $($Script:Config.LogPath)"
    Write-Host ""
    Write-Host "Actions:" -ForegroundColor Yellow
    Write-Host "  4. Toggle Logging"
    Write-Host "  5. Change Export Path"
    Write-Host "  6. View Log File"
    Write-Host "  Q. Back to Main Menu"
    Write-Host ""

    $choice = Read-Host "Enter your choice"

    switch ($choice.ToUpper()) {
        '4' {
            $Script:Config.EnableLogging = -not $Script:Config.EnableLogging
            Write-Host "Logging is now: $($Script:Config.EnableLogging)" -ForegroundColor Green
        }
        '5' {
            $newPath = Read-Host "Enter new export path"
            if ($newPath -and (Test-Path (Split-Path $newPath -Parent) -ErrorAction SilentlyContinue)) {
                $Script:Config.ExportPath = $newPath
                if (!(Test-Path $newPath)) { New-Item -ItemType Directory -Path $newPath -Force | Out-Null }
                Write-Host "Export path updated to: $newPath" -ForegroundColor Green
            } else {
                Write-Host "Invalid path or parent directory doesn't exist" -ForegroundColor Red
            }
        }
        '6' {
            if (Test-Path $Script:Config.LogPath) {
                Write-Host "`nLast 20 log entries:" -ForegroundColor Yellow
                Get-Content -Path $Script:Config.LogPath -Tail 20 | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
            } else {
                Write-Host "Log file not found: $($Script:Config.LogPath)" -ForegroundColor Red
            }
        }
    }
}

function Show-Help {
    Clear-Host
    Write-Host "=== AD MANAGEMENT TOOL HELP ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "OVERVIEW:" -ForegroundColor Yellow
    Write-Host "This tool provides comprehensive Active Directory management capabilities"
    Write-Host "including user management, computer management, reporting, and bulk operations."
    Write-Host ""
    Write-Host "KEY FEATURES:" -ForegroundColor Yellow
    Write-Host "- User search, enable/disable, unlock, password reset"
    Write-Host "- Computer search, connectivity testing, details"
    Write-Host "- Comprehensive reporting (locked users, password expiry, inactive accounts)"
    Write-Host "- Bulk operations for multiple users"
    Write-Host "- CSV import/export capabilities"
    Write-Host "- Detailed logging and statistics"
    Write-Host ""
    Write-Host "BULK OPERATIONS CSV FORMAT:" -ForegroundColor Yellow
    Write-Host "Required columns: Username, Operation"
    Write-Host "Optional columns: NewPassword"
    Write-Host "Valid operations: Enable, Disable, Unlock, ResetPassword"
    Write-Host ""
    Write-Host "Example CSV content:"
    Write-Host "Username,Operation,NewPassword"
    Write-Host "jdoe,Enable"
    Write-Host "asmith,ResetPassword,TempPass123!"
    Write-Host "bwilson,Unlock"
    Write-Host ""
    Write-Host "KEYBOARD SHORTCUTS:" -ForegroundColor Yellow
    Write-Host "- Q: Quit from any menu"
    Write-Host "- H: Help from main menu"
    Write-Host ""
    Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "- Ensure ActiveDirectory PowerShell module is installed"
    Write-Host "- Verify you have appropriate AD permissions"
    Write-Host "- Check network connectivity to domain controllers"
    Write-Host "- Review log file for detailed error information"
}

Write-ADLog "Section 7 loaded successfully" -Level Success
# SECTION 8/8 — Main Launcher (single-file mode)

function Test-ModuleFiles {
    param([string]$Path)
    # Single-file mode: nothing to check
    return @()
}

function Initialize-ADToolModules {
    param([string]$Path)
    # Single-file mode: all functions are already in this script
    Write-Host "Initializing AD Management Tool v3.0 (single-file mode)..." -ForegroundColor Cyan
    Write-Host "All modules are embedded; skipping external loads." -ForegroundColor Green
    return $true
}

function Show-WelcomeScreen {
    Clear-Host
    Write-Host @"
================================================================
               AD Management Tool v3.0
================================================================

Welcome to the comprehensive Active Directory management solution!

This tool provides:
- User management (search, enable/disable, password reset)
- Computer management and connectivity testing
- Comprehensive reporting (password expiry, inactive accounts)
- Bulk operations and CSV import/export
- AD health monitoring
- Detailed logging

================================================================
"@ -ForegroundColor Cyan

    Write-Host "`nSystem Check:" -ForegroundColor Yellow

    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Write-Host "  PowerShell Version: $($psVersion.Major).$($psVersion.Minor) - OK" -ForegroundColor Green
    } else {
        Write-Host "  PowerShell Version: $($psVersion.Major).$($psVersion.Minor) - FAILED (5.0+ required)" -ForegroundColor Red
        return $false
    }

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Host "  ActiveDirectory module - OK" -ForegroundColor Green
    } else {
        Write-Host "  ActiveDirectory module - MISSING" -ForegroundColor Red
        Write-Host "  Install RSAT tools or AD PowerShell module" -ForegroundColor Yellow
        return $false
    }

    if (!$SkipInitCheck) {
        Write-Host "  Checking AD connectivity..." -ForegroundColor Gray
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $domain = Get-ADDomain -ErrorAction Stop
            Write-Host "  Connected to domain: $($domain.Name) - OK" -ForegroundColor Green
        } catch {
            Write-Host "  Cannot connect to Active Directory - FAILED" -ForegroundColor Red
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    }

    Write-Host "`nPress Enter to continue to the main menu..." -NoNewline -ForegroundColor White
    Read-Host
    return $true
}

function Show-StartupError {
    param([string]$ErrorMessage)

    Clear-Host
    Write-Host @"
================================================================
               AD Management Tool v3.0 - STARTUP ERROR
================================================================

$ErrorMessage

Troubleshooting:
- Ensure you are running with sufficient permissions
- Verify ActiveDirectory PowerShell module is installed
- Check domain connectivity and permissions
- Run PowerShell as Administrator if needed

================================================================
"@ -ForegroundColor Red

    Read-Host "`nPress Enter to exit"
}

# MAIN EXECUTION
try {
    if (!(Show-WelcomeScreen)) {
        Show-StartupError "System requirements not met or AD connectivity failed."
        exit 1
    }

    if (!(Initialize-ADToolModules -Path $ModulePath)) {
        Show-StartupError "Failed to initialize embedded modules."
        exit 1
    }

    if (!(Initialize-ADTool)) {
        Show-StartupError "AD Tool initialization failed."
        exit 1
    }

    Write-Host "Starting main menu..." -ForegroundColor Green
    Start-Sleep -Seconds 1
    Invoke-MainMenuLoop

} catch {
    Show-StartupError "Unexpected error during startup: $($_.Exception.Message)"
    Write-Host "`nFull Error Details:" -ForegroundColor Yellow
    Write-Host $_.Exception.ToString() -ForegroundColor Gray
    exit 1
} finally {
    Write-Host "`nSession Summary:" -ForegroundColor Cyan
    if ($Script:Stats) {
        $finalUptime = (Get-Date) - $Script:Stats.StartTime
        Write-Host "  Runtime: $($finalUptime.ToString('hh\:mm\:ss'))"
        Write-Host "  Operations: $($Script:Stats.OperationCount)"
        Write-Host "  Errors: $($Script:Stats.ErrorCount)"
        if ($Script:Config -and $Script:Config.LogPath) {
            Write-Host "  Log File: $($Script:Config.LogPath)"
        }
    }
    Write-Host "`nThank you for using AD Management Tool v3.0!" -ForegroundColor Green
}
