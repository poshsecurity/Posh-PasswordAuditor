[CMDLetBinding(DefaultParametersetName='FindByIdentity')]
Param
(

    [Parameter(Mandatory = $True, ParameterSetName='FindByIdentity')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Identity,

    [Parameter(Mandatory = $false, ParameterSetName='FindBySearch')]
    [ValidateNotNullOrEmpty()]
    [String]
    $SearchBase,

    [Parameter(Mandatory = $false, ParameterSetName='FindBySearch')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [String]
    $SearchScope = 'OneLevel',

    [Parameter(Mandatory = $True, ParameterSetName='FindBySearch')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Filter,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_})]
    [String]
    $PasswordFile,


    [Parameter(Mandatory = $false)]
    [Switch]
    $SendResultsViaEmail,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SMTPSubject = 'User Audit Results',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SMTPServer,

    [Parameter(Mandatory = $false,
    Position = 19)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SMTPFrom,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SMTPTo,

    [Parameter(Mandatory = $false)]
    [Switch]
    $SMTPUseSSL,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]
    $SMTPCredentials,

    [Parameter(mandatory=$false)]
	[ValidateNotNullOrEmpty()]
    [UInt16]
	$SMTPPort = 25,
    
    [Parameter(Mandatory = $false)]
    [Switch]
    $WriteResultsToFile,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $LogFile,

    [Parameter(Mandatory = $false)]
    [Switch]
    $DoNotStorePasswords

)

Set-StrictMode -Version 2

import-module PowerShellUtilities
import-module EnhancedScriptEnvironment
import-module .\Posh-PasswordAuditor.psm1

send-scriptnotification -message 'Ad User Password Audit start' -Severity 'debug'

$ADUsers = $null

if ($Identity -ne '')
{
    Write-verbose 'Single User Mode'

    try
    {
        $ADUsers = Get-ADUser -Identity $Identity
    }
    catch
    {
        Send-ScriptNotification -Message "Error occured getting user via -identity, error was $_" -Severity 'Alert'
        Exit 1
    }
} 
else 
{
    Write-Verbose -Message 'Search Mode'

    try
    {
        $ADUsers = Get-ADUser -SearchBase $SearchBase -SearchScope $SearchScope -Filter $Filter
    }
    catch
    {
        Send-ScriptNotification -Message "An error occured getting users via filter/searchscope/searchbase, error was $_" -Severity 'Alert'
        Exit 2
    }
}


$TotalUsers = ($ADUsers | Measure-Object).count

if ($TotalUsers -eq 0)
{
    Send-ScriptNotification -Message 'No users were found' -Severity 'Alert'
    Exit 3
}

$UsersProcessed = 0
Write-Verbose "Total users $TotalUsers"

#Test the passwords
$ADUsers = $ADUsers | ForEach-Object {
    $UsersProcessed++
    $UserPercentage = $UsersProcessed / $TotalUsers * 100

    if ($TotalUsers -ne 1) { Write-Progress -Activity 'Testing passwords of users' -PercentComplete $UserPercentage -Status "$UserPercentage % Complete" -id 1}
    
    try
    {
        Find-ADUserPassword -identity $_ -PasswordFile $PasswordFile
    }
    catch
    {
        Send-ScriptNotification -Message "Error with Find-ADUserPassword, $_" -Severity 'Error'
    }
}

if ($TotalUsers -ne 1) { Write-Progress -Activity 'Testing passwords of users' -id 1 -Completed }


#these are the users we found passwords for
$UsersWithPasswordsFound = ($ADUsers | Where-Object -FilterScript {$_.PasswordFound})
    

if ($UsersWithPasswordsFound -ne $null)
{
    Write-Verbose -Message 'User passwords found'
    if ($SendResultsViaEmail)
    {
        if ($DoNotStorePasswords)
        {
            Write-Verbose -Message 'Email will be sent without passwords'
            $HTMLBody = $ADUsers | ConvertTo-Html -Property SamAccountName -PreContent 'The following users passwords were found in the specified password list' -PostContent 'Note: Actual Passwords will not be displayed'
        }
        else
        {
            Write-Verbose -Message 'Email will be sent with passwords'
            $HTMLBody = $ADUsers | ConvertTo-Html -Property SamAccountName, Password -PreContent 'The following users passwords were found in the specified password list'
        }

        Send-MailMessage -To $SMTPTo -From $SMTPFrom -Subject $SMTPSubject -SmtpServer $SMTPServer -Body ("" + $HTMLBody) -BodyAsHtml -UseSsl:$SMTPUseSSL -Credential $SMTPCredential -Port $SMTPPort
    }
}
else
{
    Write-Verbose -Message 'No user passwords found'
        
    if ($SendResultsViaEmail)
    {
        $HTMLBody = ConvertTo-Html -Body 'No user passwords were found in the specified password list'
        Send-MailMessage -To $SMTPTo -From $SMTPFrom -Subject $SMTPSubject -SmtpServer $SMTPServer -Body ("" + $HTMLBody) -BodyAsHtml -UseSsl:$SMTPUseSSL -Credential $SMTPCredential -Port $SMTPPort
    }
}

if ($WriteResultsToFile)
{
    if ($DoNotStorePasswords)
    {
        Write-Verbose -Message 'Log file written without passwords'
        $ADUsers |
        Select-Object -Property SamAccountName |
        ConvertTo-Csv -NoTypeInformation |
        Out-File -FilePath $LogFile
    }
    else
    {
        Write-Verbose -Message 'Log file written with passwords'
        $ADUsers |
        Select-Object -Property SamAccountName, Password |
        ConvertTo-Csv -NoTypeInformation |
        Out-File -FilePath $LogFile
    }
}

send-scriptnotification -message 'Ad User Password Audit End' -Severity 'debug'