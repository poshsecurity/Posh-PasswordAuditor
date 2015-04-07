# Posh-PasswordAuditor
Simple Active Directory account password auditing with Powershell

## Introduction
I originally developed this code as part of a project to audit Active Directory users to ensure that safe passwords had been
adopted. This functionality can be found in the Scripts InvokeADUserPasswordAudit.ps1 and 
Invoke-EnhancedADUserPasswordAudit.ps1.

During its development, I discovered Andy Arismendi Test-UserCredential function, and developed the Find-UserPassword CMDLet.
I have extended the use of the Find-UserPassword to support the searching/finding of Active Directory Domain as well as local 
Windows User accounts.

A full write up of this code will be provided on my blog, PoshSecurity.com.

## Separate Script Versions
Two scripts are included in this repository, both perform the same functionality, however Invoke-EnhancedADUserPasswordAudit 
makes use of the EnhancedScriptEnvironment code that I had written previously. For most users, Invoke-ADUserPasswordAudit 
is the script script you should be using.

ScriptName | Description
---------- | ------------
Invoke-ADUserPasswordAudit.ps1 | For use in standalone environments
Invoke-EnhancedADUserPasswordAudit.ps1 | For use with EnhancedScriptEnvironment

## Included PowerShell Modules
There is a single PowerShell module included, Posh-PasswordAuditor. I have included a PSD1 file as recommended.

## Included PowerShell CMDLets
CMDLet | Synopsis
------ | ------------
Test-UserCredential | Validates credentials for local or domain user.
Find-UserPassword | Test a user account against entries in a specified file. Users could be local or domain user accounts.

PowerShell Get-Help comment based help has been included in each script and CMDLet.
