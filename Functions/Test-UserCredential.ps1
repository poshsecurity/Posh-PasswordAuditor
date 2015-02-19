﻿Set-StrictMode -Version 2

function Test-UserCredential 
{
    	<#
		.SYNOPSIS
			Validates credentials for local or domain user.
		
		.PARAMETER  Username
			The user's username.
	
		.PARAMETER  Password
			The user's password.
			
		.PARAMETER  Credential
			A PSCredential object created by Get-Credential. This can be pipelined to Test-UserCredential.

		.PARAMETER  Domain
			If this flag is set the user credentials should be a domain user account.
			
		.PARAMETER  UseKerberos
			By default NTLM is used. Specify this switch to attempt kerberos authentication. 
			
			This is only used with the 'Domain' parameter.
			
			You may need to specify domain\user.
	
		.EXAMPLE
			PS C:\> Test-UserCredential -Username andy -password (Read-Host -AsSecureString)
	
		.EXAMPLE
			PS C:\> Test-UserCredential -Username 'mydomain\andy' -password (Read-Host -AsSecureString) -domain -UseKerberos

		.EXAMPLE
			PS C:\> Test-UserCredential -Username 'andy' -password (Read-Host -AsSecureString) -domain
			
		.EXAMPLE
			PS C:\> Get-Credential | Test-UserCredential
	
		.INPUTS
			None.
	
		.OUTPUTS
			System.Boolean.

		.LINK
			http://msdn.microsoft.com/en-us/library/system.directoryservices.accountmanagement.principalcontext.aspx

        .LINK
            http://andyarismendi.blogspot.fr/2011/08/powershell-test-usercredential.html
	
		.NOTES
			Revision History
				2011-08-21: Andy Arismendi - Created.
				2011-08-22: Andy Arismendi - Add pipelining support for Get-Credential.
				2011-08-22: Andy Arismendi - Add support for NTLM/kerberos switch.	
	#>

	[CmdletBinding(DefaultParameterSetName = "set1")]
	[OutputType("set1", [System.Boolean])]
	[OutputType("PSCredential", [System.Boolean])]

	param(
		[Parameter(Mandatory=$true, ParameterSetName="set1", position=0)] 
		[ValidateNotNullOrEmpty()]
		[String] $Username,

		[Parameter(Mandatory=$true, ParameterSetName="set1", position=1)] 
		[ValidateNotNullOrEmpty()]
		[System.Security.SecureString] $Password,
		
		[Parameter(Mandatory=$true, ParameterSetName="PSCredential", ValueFromPipeline=$true, position=0)] 
		[ValidateNotNullOrEmpty()]
		[Management.Automation.PSCredential] $Credential,
		
		[Parameter(position=2)]
		[Switch] $Domain,
		
		[Parameter(position=3)]
		[Switch] $UseKerberos
	)
	
	Begin {
		try { 
			$assemType = 'System.DirectoryServices.AccountManagement'
			$assem = [reflection.assembly]::LoadWithPartialName($assemType) }
		catch { throw 'Failed to load assembly "System.DirectoryServices.AccountManagement". The error was: "{0}".' -f $_ }
		
		$system = Get-WmiObject -Class Win32_ComputerSystem
		
		if (0, 2 -contains $system.DomainRole -and $Domain) {
			throw 'This computer is not a member of a domain.'
		}
	}
	
	Process {
		try {
			switch ($PSCmdlet.ParameterSetName) {
				'PSCredential' {
					if ($Domain) {
						$Username = $Credential.UserName.TrimStart('\')
					} else {
						$Username = $Credential.GetNetworkCredential().UserName
					}
					$PasswordText = $Credential.GetNetworkCredential().Password
				}
				'set1' {
						# Decrypt secure string.
					$PasswordText = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
							[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
						)
				}
			}
					
			if ($Domain) {
				$pc = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext 'Domain', $system.Domain
			} else {
				$pc = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext 'Machine', $env:COMPUTERNAME
			}
			
			if ($Domain -and $UseKerberos) {
				return $pc.ValidateCredentials($Username, $PasswordText)
			} else {
				return $pc.ValidateCredentials($Username, $PasswordText, [DirectoryServices.AccountManagement.ContextOptions]::Negotiate)
			}
		} catch {
			throw 'Failed to test user credentials. The error was: "{0}".' -f $_
		} finally {
			Remove-Variable -Name Username -ErrorAction SilentlyContinue
			Remove-Variable -Name Password -ErrorAction SilentlyContinue
		}
	}
}