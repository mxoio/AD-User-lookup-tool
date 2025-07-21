# check_user.ps1
# Check if Active Directory module is available
if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ERROR: Active Directory module not found. Please install RSAT tools." -ForegroundColor Red
    exit
}

Import-Module ActiveDirectory

try {
    $nameSearch = Read-Host "Enter part of a name or username (e.g. 'mxi', 'Michael', or 'Vickers')"
    
    # Validate input
    if ([string]::IsNullOrWhiteSpace($nameSearch)) {
        Write-Host "ERROR: Search term cannot be empty." -ForegroundColor Red
        exit
    }
    
    # Get matching users with error handling
    $users = Get-ADUser -Filter "SamAccountName -like '*$nameSearch*' -or Name -like '*$nameSearch*' -or DisplayName -like '*$nameSearch*'" -Properties DisplayName, SamAccountName, Name, LastLogonDate -ErrorAction Stop
    
    # Convert to array if single result
    if ($users -is [Microsoft.ActiveDirectory.Management.ADUser]) {
        $users = @($users)
    }
    
    if (!$users -or $users.Length -eq 0) {
        Write-Host "ERROR: No users found matching '$nameSearch'" -ForegroundColor Red
        exit
    }
    
    # If only one user match, use it
    if ($users.Length -eq 1) {
        $selectedUser = $users[0]
    } else {
        Write-Host "`nMultiple users found:`n"
        $i = 1
        foreach ($user in $users) {
            $displayName = if ($user.DisplayName) { $user.DisplayName } else { $user.Name }
            Write-Host "$i. $displayName ($($user.SamAccountName))"
            $i++
        }
        
        do {
            $choice = Read-Host "`nEnter the number of the user to view login info (1-$($users.Length))"
            $validChoice = $false
            
            # Check if input is numeric
            $choiceInt = 0
            if ([int]::TryParse($choice, [ref]$choiceInt)) {
                if ($choiceInt -ge 1 -and $choiceInt -le $users.Length) {
                    $validChoice = $true
                }
            }
            
            if (!$validChoice) {
                Write-Host "ERROR: Invalid selection. Please enter a number between 1 and $($users.Length)." -ForegroundColor Red
            }
        } while (!$validChoice)
        
        $selectedUser = $users[$choiceInt - 1]
    }
    
    # Show last login with better formatting
    Write-Host "`nSUCCESS: User: $($selectedUser.SamAccountName)" -ForegroundColor Green
    
    $displayName = if ($selectedUser.DisplayName) { $selectedUser.DisplayName } else { $selectedUser.Name }
    Write-Host "  Name: $displayName"
    
    if ($selectedUser.LastLogonDate) {
        Write-Host "  Last Logon: $($selectedUser.LastLogonDate)" -ForegroundColor Cyan
    } else {
        Write-Host "  Last Logon: Never logged in or data not available" -ForegroundColor Yellow
    }
    
} catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
    Write-Host "ERROR: Cannot connect to Active Directory server. Check network connectivity and permissions." -ForegroundColor Red
} catch [Microsoft.ActiveDirectory.Management.ADException] {
    $errorMessage = $_.Exception.Message
    Write-Host "ERROR: Active Directory error: $errorMessage" -ForegroundColor Red
} catch {
    $errorMessage = $_.Exception.Message
    Write-Host "ERROR: An unexpected error occurred: $errorMessage" -ForegroundColor Red
}