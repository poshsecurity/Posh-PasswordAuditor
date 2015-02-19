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

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String]
        $PasswordFile
    )

    Process 
    {
        $User = Get-ADUser $Identity

        Write-Verbose "Testting Passwords for user $( $User.SamAccountName )"
        
        $Passwords = Get-Content -Path $PasswordFile
        $TotalPasswords =  ($passwords | Measure-Object).count
        $PasswordsProcessed = 0
        $PasswordFound = $false

        While ((-not $PasswordFound) -and ($PasswordsProcessed -ne $TotalPasswords))
        {
            $PasswordsProcessed++
            $PasswordPercentage = $PasswordsProcessed / $TotalPasswords * 100

            if ($TotalPasswords -ne 1) { Write-Progress -Activity 'Testing Password' -PercentComplete $PasswordPercentage -Status "$PasswordPercentage % Complete" -ParentId 1}

            $Password = $Passwords[($PasswordsProcessed -1)]
            Write-Verbose "Attempting password $Password"
            $SecureStringPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $PasswordFound = Test-UserCredential -Username $User.SamAccountName -Password $SecureStringPassword -Domain
        }

        if ($TotalPasswords -ne 1) { Write-Progress -Activity 'Testing Password' -ParentId 1 -Completed}

        if (-not $PasswordFound) { $Password = ''}

        $User | Add-Member NoteProperty PasswordFound $PasswordFound -Force -PassThru | Add-Member NoteProperty Password $Password -Force -PassThru
    }
    
}


