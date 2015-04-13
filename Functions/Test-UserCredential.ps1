Set-StrictMode -Version 2

function Test-UserCredential 
{
    <#
        .SYNOPSIS
        Validates credentials for local or domain user.

        .DESCRIPTION
        This CMDLet validates a set of credentials against a local user or domain user. The CMDLet was developed by Andy Arismendi.

        The credentials to validate can be specified by username and password or credential object. 

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
        2015-03-11: Kieran Jacobsen - Removed WMI call to get domain details.
        2015-03-21: Kieran Jacobsen - General Reformat and move to best practice.
        2015-04-05: Kieran Jacobsen - Restored WMI call as it is more reliable. Additional validation of parameters.
    #>

    [CmdletBinding(DefaultParameterSetName = 'UserPass')]
    [OutputType('UserPass', [System.Boolean])]
    [OutputType('PSCredential', [System.Boolean])]

    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'UserPass', position = 0)] 
        [ValidateNotNullOrEmpty()]
        [String] $Username,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserPass', position = 1)] 
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString] $Password,

        [Parameter(Mandatory = $true, ParameterSetName = 'PSCredential', ValueFromPipeline = $true, position = 0)] 
        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential] $Credential,

        [Parameter(Mandatory = $false, position = 2)]
        [Switch] $Domain,

        [Parameter(Mandatory = $false, position = 3)]
        [Switch] $UseKerberos
    )

    Begin 
    {
        try 
        { 
            $assemType = 'System.DirectoryServices.AccountManagement'
            $assem = [reflection.assembly]::LoadWithPartialName($assemType) 
        }
        catch
        { throw 'Failed to load assembly "System.DirectoryServices.AccountManagement". The error was: "{0}".' -f $_ }

        #TODO: Test if the computer is only part of a workgroup, then we should throw an error if -domain is specified.
        $Computersystem = Get-WmiObject -Class Win32_Computersystem
        if (($Computersystem.Workgroup -ne $null) -and $Domain)
        { throw 'This computer is not a member of a domain.' }

        # If -domain isn't specified, then we don't need -UseKerberos
        if (-not $Domain -and $UseKerberos)
        { throw 'You can only specify -UserKerberos with -Domain' }
    }

    Process
    {
        try 
        {
            if ($PSCmdlet.ParameterSetName -eq 'PSCredential')
            {
                if ($Domain) 
                { $Username = $Credential.UserName.TrimStart('\') } 
                else 
                { $Username = $Credential.GetNetworkCredential().UserName }

                $PasswordText = $Credential.GetNetworkCredential().Password
            }
            else
            { $PasswordText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)) }
            
            if ($Domain)
            { $pc = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ('Domain', $Computersystem.Workgroup) } 
            else 
            { $pc = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ('Machine', $ENV:COMPUTERNAME) }

            if ($Domain -and $UseKerberos) 
            { return $pc.ValidateCredentials($Username, $PasswordText) } 
            else 
            { return $pc.ValidateCredentials($Username, $PasswordText, [DirectoryServices.AccountManagement.ContextOptions]::Negotiate) }
        }
        catch 
        { throw 'Failed to test user credentials. The error was: "{0}".' -f $_ } 
        finally 
        {
            Remove-Variable -Name Username -ErrorAction SilentlyContinue
            Remove-Variable -Name Password -ErrorAction SilentlyContinue
        }
    }
}
