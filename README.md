# Get-InactiveADAccounts.ps1

This PowerShell script identifies inactive user accounts from both Active Directory and Entra ID (Azure AD) by comparing the last logon dates. It searches all domains in an AD forest and merges the results with Entra ID user sign-in activity to identify accounts that have been inactive for a specified number of days.

## Features

- Searches all Active Directory domains in a forest for inactive user accounts.
- Retrieves Azure AD user sign-in activity using Microsoft Graph API.
- Merges AD and Azure AD results, displaying the latest logon date.
- Excludes users listed in an exception list.
- Displays inactive accounts in a GridView for easy review.

## Requirements

- PowerShell modules: `ActiveDirectory`, `Microsoft.Graph`
- Appropriate Graph API permissions: `AuditLog.Read.All`, `Directory.Read.All`

## Parameters

- `-InactivityDays` (Required): Number of days of inactivity to consider an account inactive.
- `-ExceptionListPath` (Optional): Path to a text file with ObjectSIDs to exclude from analysis.
- `-LogFilePath` (Optional): Path to the log file for recording actions and errors.

## Usage

```powershell
.\Get-InactiveADAccounts.ps1 -InactivityDays 365
