Set-StrictMode -Version 2

function Find-UserPassword
{
    <#
		.SYNOPSIS
            Determine if a user's password is contained in a specified file.

        .DESCRIPTION
            This tool is basically a password file/dictionary attack tool.
            
            Find-UserPassword will test the passwords contained in the specified file against the active directory user.
		
		.PARAMETER Identity
		    Active Directory Identity.
	
		.PARAMETER PasswordFile
		    Password list/file.
	
		.EXAMPLE
            PS C:\> Find-UserPassword -Identify kieran.jacobsen -Password c:\passwordlist.txt
	
		.INPUTS
        Microsoft.ActiveDirectory.Management.ADUser.
	
		.OUTPUTS
		System.Boolean.

		.LINK
        http://poshsecurity.com
	#>

    [CmdletBinding()]
#TODO:    [OutputType("PSCredential", [System.Boolean])]
    Param
    (
        [Parameter(Mandatory = $True, valuefrompipeline = $true, ParameterSetName = 'ADIdentity')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.ActiveDirectory.Management.ADUser] 
        $Identity,

        [Parameter(Mandatory = $True, valuefrompipeline = $true, ParameterSetName = 'Username')]
        [ValidateNotNullOrEmpty()]
        [String] 
        $Username,

        [Parameter(Mandatory = $True)]
        [ValidateScript({Test-Path $_})]
        [String]
        $PasswordFile,

        [Parameter(Mandatory=$False, ParameterSetName = 'Username')]
        [Switch] $Domain,
		
        [Parameter(Mandatory=$False)]
        [Switch] $UseKerberos

    )

    Begin
    {
        Write-Verbose -Message "Using Password File $PasswordFile"
        $Passwords = Get-Content -Path $PasswordFile
        
        $TotalPasswords =  ($passwords | Measure-Object).count

        Write-Verbose -Message "Total Passwords is $TotalPasswords"
        
        if ($TotalPasswords -eq 0)
        { throw "No Passwords Provided" }
    }

    Process 
    {
        if ($PSCmdlet.ParameterSetName -eq 'ADIdentity')
        {           
            $ReturnUser = Get-ADUser -Identity $Identity
            $Username = $ReturnUser.SamAccountName
            $Domain = $true
        }
        else
        {
            #TODO: $ReturnUser = New-Object
        }

        Write-Verbose -Message "Testing Passwords for user $Username"
        
        $PasswordsProcessed = 0
        $PasswordFound = $false

        While ((-not $PasswordFound) -and ($PasswordsProcessed -le $TotalPasswords))
        {            
            if ($TotalPasswords -ne 1) 
            { 
                $PasswordPercentage = $PasswordsProcessed / $TotalPasswords * 100
                Write-Progress -Activity 'Testing Password' -PercentComplete $PasswordPercentage -Status "$PasswordPercentage % Complete" -ParentId 1 
            }
            $PasswordAttempt = $Passwords[($PasswordsProcessed )]
            Write-Verbose -Message "Attempting password $PasswordAttempt"

            $SecureStringPassword = ConvertTo-SecureString -String $PasswordAttempt -AsPlainText -Force

            $PasswordFound = Test-UserCredential -Username $Username -Password $SecureStringPassword -Domain:$Domain -UseKerberos:$UseKerberos

            $PasswordsProcessed++
        }

        if ($TotalPasswords -ne 1) 
        { Write-Progress -Activity 'Testing Password' -ParentId 1 -Completed }

        if (-not $PasswordFound) 
        { $PasswordAttempt = '<> Password Not Found <>' }

        # Update the pipelined object       
        $ReturnUser = $ReturnUser | Add-Member -NotePropertyName PasswordFound -NotePropertyValue $PasswordFound -Force -PassThru 
        $ReturnUser = $ReturnUser | Add-Member -NotePropertyName Password -NotePropertyValue $PasswordAttempt -Force -PassThru

        $ReturnUser
    }
    
}


