Set-StrictMode -Version 2

function Find-ADUserPassword
{
    [CmdletBinding()]
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
        Write-Verbose "Using Password File $PasswordFile"
        $Passwords = Get-Content -Path $PasswordFile
        
        $TotalPasswords =  ($passwords | Measure-Object).count
        
        if ($TotalPasswords -eq 0)
        {
            throw "No Passwords Provided"
        }
    }

    Process 
    {
        $User = Get-ADUser $Identity

        Write-Verbose "Testting Passwords for user $( $User.SamAccountName )"
        
        $PasswordsProcessed = 0
        $PasswordFound = $false

        While ((-not $PasswordFound) -and ($PasswordsProcessed -ne $TotalPasswords))
        {
            $PasswordsProcessed++
            $PasswordPercentage = $PasswordsProcessed / $TotalPasswords * 100

            if ($TotalPasswords -ne 1) { Write-Progress -Activity 'Testing Password' -PercentComplete $PasswordPercentage -Status "$PasswordPercentage % Complete" -ParentId 1}

            $PasswordAttempt = $Passwords[($PasswordsProcessed -1)]
            Write-Verbose "Attempting password $PasswordAttempt"
            $SecureStringPassword = ConvertTo-SecureString -String $PasswordAttempt -AsPlainText -Force
            $PasswordFound = Test-UserCredential -Username $User.SamAccountName -Password $SecureStringPassword -Domain
        }

        if ($TotalPasswords -ne 1) { Write-Progress -Activity 'Testing Password' -ParentId 1 -Completed}

        if (-not $PasswordFound) { $PasswordAttempt = ''}

        $User | Add-Member NoteProperty PasswordFound $PasswordFound -Force -PassThru | Add-Member NoteProperty Password $PasswordAttempt -Force -PassThru
    }
    
}


