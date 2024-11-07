<#
.SYNOPSIS
    This script identifies inactive user accounts from both Active Directory and Azure AD (Entra ID) based on logon dates.

.DESCRIPTION
    The script searches all domains in a forest for Active Directory user accounts that have not logged on within a specified number of days based on the LastLogonDate attribute.
    Additionally, it fetches user accounts from Azure AD (Entra ID) and compares their last sign-in activity.
    User accounts from both sources are merged, and the latest logon date is determined by comparing AD's LastLogonDate and Entra's LastSignInDate.
    Inactive accounts (those whose latest logon date is earlier than a specified threshold) are displayed in a GridView for easy review.
    Accounts listed in an exception list (by ObjectSID) are excluded from the results.

.PARAMETER InactivityDays
    The number of days of inactivity after which a user account will be considered inactive. The script calculates the threshold date by subtracting the number of days from the current date.

.PARAMETER ExceptionListPath
    Path to a text file containing the ObjectSIDs of user accounts that should be excluded from the analysis, regardless of their activity status.

.PARAMETER LogFilePath
    Path to the log file where actions, errors, and status updates will be recorded.

.EXAMPLE
    .\Get-InactiveADAccounts.ps1 -InactivityDays 365 -ExceptionListPath "C:\Path\To\ExceptionList.txt" -LogFilePath "C:\Path\To\LogFile.txt"

    This example identifies all user accounts in the AD forest that have been inactive for more than 365 days, excluding any users listed in the specified exception file. The results are displayed in a GridView, and actions are logged to the specified log file.

.NOTES
    Author: Frederik Leed
    Date: 2024-08-26
    Version: 1.2

    The script utilizes the Microsoft Graph SDK to connect to Azure AD (Entra ID) and retrieve user sign-in activity.
    It requires appropriate Graph API permissions, such as `AuditLog.Read.All` and `Directory.Read.All`.
    It requires PowerShell modules ActiveDirectory, Microsoft.Graph
#>

param (
    [Parameter(Mandatory=$true)]
    [int]$InactivityDays,

    [Parameter(Mandatory=$false)]
    [string]$ExceptionListPath,

    [Parameter(Mandatory=$false)]
    [string]$LogFilePath
)

# Default log file logic
if (-not $LogFilePath) {
    # Get the script name and directory
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDirectory = Split-Path -Path $scriptPath
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($scriptPath)
    
    # Set default log file path
    $LogFilePath = Join-Path -Path $scriptDirectory -ChildPath "$scriptName.log"
}

# Function to log messages
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFilePath -Value "$timestamp - $Message"
    #Write-Output "$timestamp - $Message"
}

# Import the exception list
if($ExceptionListPath) {
    if (-Not (Test-Path $ExceptionListPath)) {
        Write-Log "ERROR: Exception list file not found at $ExceptionListPath"
    }

    Try{
        $ExceptionList = Get-Content -Path $ExceptionListPath -ErrorAction Break | ForEach-Object { $_.Trim() }
        Write-Log "Loaded exception list from $ExceptionListPath"
    }catch{
        Write-Log "Failed loaded exception list"
    }    
}

# Get the date threshold for inactivity
$thresholdDate = (Get-Date).AddDays(-$InactivityDays)
Write-Log "Inactivity threshold date: $thresholdDate"

# Connect to the Graph SDK with the correct permissions
Connect-MgGraph -NoWelcome -Scopes AuditLog.Read.All, Directory.Read.All

# Find licensed entra user accounts
$Headers = @{ConsistencyLevel="Eventual"}  
$Uri = "https://graph.microsoft.com/beta/users?`$count=true&`$filter=(userType eq 'Member')&$`top=999&`$select=id, displayName, usertype, signInActivity, onPremisesImmutableId"
[array]$Data = Invoke-MgGraphRequest -Uri $Uri -Headers $Headers
[array]$Users = $Data.Value

If (!($Users)) {
    Write-Host "Can't find any users... exiting!" ; break
}

# Paginate until we have all the user accounts
While ($Null -ne $Data.'@odata.nextLink') {
    Write-Host ("Fetching more user accounts - currently at {0}" -f $Users.count)
    $Uri = $Data.'@odata.nextLink'
    [array]$Data = Invoke-MgGraphRequest -Uri $Uri -Headers $Headers
    $Users = $Users + $Data.Value
 }
 Write-Host ("All available user accounts fetched ({0}) - now processing sign in report" -f $Users.count)

 # And report what we've found
$EntraUsers = [System.Collections.Generic.List[Object]]::new()
ForEach ($User in $Users) {
    $onPremisesImmutableIdObjectID = $Null
    $DaysSinceLastSignIn = $Null; $DaysSinceLastSuccessfulSignIn = $Null
    $DaysSinceLastSignIn = "N/A"; $DaysSinceLastSuccessfulSignIn = "N/A"
    $LastSuccessfulSignIn = $User.signInActivity.lastSuccessfulSignInDateTime
    $LastSignIn = $User.signInActivity.lastSignInDateTime
    If (!([string]::IsNullOrWhiteSpace($LastSuccessfulSignIn))) {
        $DaysSinceLastSuccessfulSignIn = (New-TimeSpan $LastSuccessfulSignIn).Days 
    }
    If (!([string]::IsNullOrWhiteSpace($LastSignIn))) {
        $DaysSinceLastSignIn = (New-TimeSpan $LastSignIn).Days
    }
    If ($User.onPremisesImmutableId){
        $onPremisesImmutableIdObjectID = [Guid]([Convert]::FromBase64String($User.onPremisesImmutableId))
    }
    
    $DataLine = [PSCustomObject][Ordered]@{
        User                             = $User.displayName
        UserId                           = $User.ID
        onPremisesImmutableId            = ($User.onPremisesImmutableId)
        onPremisesImmutableIdObjectID    = $onPremisesImmutableIdObjectID
        LastLogonDate                    = $LastSuccessfulSignIn
        'Last successful sign in'        = $LastSuccessfulSignIn
        'Last sign in'                   = $LastSignIn
        'Days since successful sign in'  = $DaysSinceLastSuccessfulSignIn
        'Days since sign in'             = $DaysSinceLastSignIn
    }
    $EntraUsers.Add($DataLine)
}

# Initialize an array to hold the output data
$ADUsers = @()

# Search all domains in the forest
$domains = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains
foreach ($domain in $domains) {
    try {
        # Get all enabled user accounts in the domain
        $users = Get-ADUser -Filter { Enabled -eq $true } -Server $domain.Name -Properties DistinguishedName, Description, SamAccountName, DisplayName, Manager, ObjectSID, ObjectGuid, lastlogondate, adminDescription, ExtensionAttribute15

        foreach ($user in $users) {
            if ($ExceptionList -contains $user.ObjectSID.Value) {
                Write-Log "Skipping user $($user.SamAccountName) - found in exception list"
            } else {

                # Reverse Distinguished Name
                # Split the string, reverse the array, and join it back together
                $components = $user.DistinguishedName -split ","
                [Array]::Reverse($components)
                $reverseDN = $components -join ","
                
                $ADUsers += [PSCustomObject]@{
                    DistinguishedName    = $user.DistinguishedName
                    SamAccountName       = $user.SamAccountName
                    DisplayName          = $user.DisplayName
                    adminDescription     = $user.adminDescription
                    ExtensionAttribute15 = $user.ExtensionAttribute15
                    LastLogonDate        = $user.lastlogondate
                    ObjectSID            = $user.ObjectSID.Value
                    ObjectGuid           = $user.ObjectGuid
                    ReverseDN            = $reverseDN
                    Description          = $user.Description
                }
            }
        }
    } catch {
        Write-Log "ERROR: Failed to process domain $($domain.Name). Error: $_"
    }
}

# Initialize an array to hold the merged output data
$MergedUsers = @()

foreach ($adUser in $ADUsers) {
    # Reset the variables for each iteration to avoid carrying over from the previous object
    $lastLogonDate = $null
    $entraLastLogonDate = $null
    $matchingEntraUser = $null
    $LatestLogonDate = $null

    # Find the corresponding Entra user based on the onPremisesImmutableIdObjectID and ObjectGuid match
    $matchingEntraUser = $EntraUsers | Where-Object { $_.onPremisesImmutableIdObjectID -eq $adUser.ObjectGuid }
    
    # Create a new PSCustomObject starting with the AD user properties
    $MergedUser = [PSCustomObject]@{}

    # Dynamically add properties from the AD user
    $adUser | Get-Member -MemberType Properties | ForEach-Object {
        $MergedUser | Add-Member -MemberType NoteProperty -Name $_.Name -Value $adUser.$($_.Name)
    }

    # If there is a matching Entra user, add its properties as well
    if ($matchingEntraUser) {
        $matchingEntraUser | Get-Member -MemberType Properties | ForEach-Object {
            $MergedUser | Add-Member -MemberType NoteProperty -Name ("Entra_" + $_.Name) -Value $matchingEntraUser.$($_.Name)
        }
    } else {
        # If no matching Entra user, add null values for Entra-related fields
        $EntraUserProperties = $EntraUsers[0] | Get-Member -MemberType Properties
        foreach ($property in $EntraUserProperties) {
            $MergedUser | Add-Member -MemberType NoteProperty -Name ("Entra_" + $property.Name) -Value $null
        }
    }

    if ($MergedUser.LastLogonDate) {
        try {
            # Attempt to parse the date in both formats for safety
            $lastLogonDate = [datetime]$MergedUser.LastLogonDate
        } catch {
            Write-Warning "Could not parse LastLogonDate for user: $($MergedUser.DisplayName)"
        }
    }

    if ($MergedUser.Entra_LastLogonDate) {
        try {
            # Attempt to parse the Entra LastLogonDate
            $entraLastLogonDate = [datetime]$MergedUser.Entra_LastLogonDate
        } catch {
            Write-Warning "Could not parse Entra_LastLogonDate for user: $($MergedUser.DisplayName)"
        }
    }    
    # Compare the two dates and return the latest one, if both exist
    if ($lastLogonDate -and $entraLastLogonDate) {
        if ($lastLogonDate -gt $entraLastLogonDate) {
            $LatestLogonDate = $lastLogonDate
        } else {
            $LatestLogonDate = $entraLastLogonDate
        }
    } elseif ($lastLogonDate) {
        $LatestLogonDate = $lastLogonDate
    } elseif ($entraLastLogonDate) {
        $LatestLogonDate = $entraLastLogonDate
    } else {
        $LatestLogonDate = $null
    }

    # Add the calculated LatestLogonDate to the merged object
    $MergedUser | Add-Member -MemberType NoteProperty -Name "LatestLogonDate" -Value $LatestLogonDate

    # Add the merged object to the MergedUsers array
    $MergedUsers += $MergedUser
}

# Filter users based on LatestLogonDate being less than the threshold date
$filteredUsers = $MergedUsers | Where-Object { $_.LatestLogonDate -and $_.LatestLogonDate -lt $thresholdDate }

# Display the filtered data in a GridView - 
#$filteredUsers | Select-Object samaccountname, LastLogonDate, Entra_LastLogonDate, LatestLogonDate, ReverseDN, Description, DistinguishedName | Out-GridView

# Export the filtered data to a CSV file
$formattedThresholdDate = $thresholdDate.ToString("yyyyMMdd")
$csvFileName = "$scriptName" + "_$formattedThresholdDate.csv"
$csvFilePath = Join-Path -Path $scriptDirectory -ChildPath $csvFileName

$filteredUsers | Select-Object samaccountname, @{Name="LastLogonDate";Expression={$_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss")}} , @{Name="Entra_LastLogonDate";Expression={$_.Entra_LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss")}}, @{Name="LatestLogonDate";Expression={$_.LatestLogonDate.ToString("yyyy-MM-dd HH:mm:ss")}} , ReverseDN, Description, adminDescription, ExtensionAttribute15, DistinguishedName | Export-Csv -Path $csvFilePath -NoTypeInformation -Delimiter ";"

# Log the export process
Write-Log "Data exported to $csvFilePath"