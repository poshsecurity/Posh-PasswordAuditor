<#
	.SYNOPSIS

    .DESCRIPTION
		
	.PARAMETER
	
	.PARAMETER
	
	.EXAMPLE
			
	.EXAMPLE
	
	.INPUTS
	
	.OUTPUTS
	System.Boolean.

	.LINK
    http://poshsecurity.com
#>

[CMDLetBinding(DefaultParametersetName='FindByIdentity')]
Param
(

    [Parameter(Mandatory = $True, ParameterSetName='FindByIdentity')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Identity,

    [Parameter(Mandatory = $True, ParameterSetName='FindBySearch')]
    [ValidateNotNullOrEmpty()]
    [String]
    $SearchBase,

    [Parameter(Mandatory = $True, ParameterSetName='FindBySearch')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Filter,

    [Parameter(Mandatory = $True, ParameterSetName='FindBySearch')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [String]
    $SearchScope,

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
    $SMTPSubject = 'User Password Audit Results',
    
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

import-module -Name PowerShellUtilities
import-module -Name EnhancedScriptEnvironment
import-module -Name .\Posh-PasswordAuditor.psm1

send-scriptnotification -message 'AD User Password Audit start' -Severity 'debug'

if ((-not $SendResultsViaEmail) -and (-not $DoNotStorePasswords))
{ 
    Send-ScriptNotification -Message "Select something for this script to do: -SendResultsViaEmail and/or -DoNotStorePasswords" -Severity 'Alert'
    Exit 1
}

$ADUsers = $null

if ($Identity -ne '')
{
    Write-verbose 'Single User Mode'

    try
    { $ADUsers = Get-ADUser -Identity $Identity }
    catch
    {
        Send-ScriptNotification -Message "Error occured getting user via -identity, error was $_" -Severity 'Alert'
        Exit 2
    }
} 
else 
{
    Write-Verbose -Message 'Search Mode'

    try
    { $ADUsers = Get-ADUser -SearchBase $SearchBase -SearchScope $SearchScope -Filter $Filter }
    catch
    {
        Send-ScriptNotification -Message "An error occured getting users via filter/searchscope/searchbase, error was $_" -Severity 'Alert'
        Exit 3
    }
}

$TotalUsers = ($ADUsers | Measure-Object).count

if ($TotalUsers -eq 0)
{
    Send-ScriptNotification -Message 'No users were found' -Severity 'Alert'
    Exit 4
}

$UsersProcessed = 0
Write-Verbose -Message "Total users $TotalUsers"

$ADUsers = $ADUsers | ForEach-Object {
    $UsersProcessed++
    $UserPercentage = $UsersProcessed / $TotalUsers * 100

    if ($TotalUsers -ne 1) { Write-Progress -Activity 'Testing passwords of users' -PercentComplete $UserPercentage -Status "$UserPercentage % Complete" -id 1}
    
    try
    { Find-UserPassword -username $_.SamAccountName -PasswordFile $PasswordFile -Domain}
    catch
    {
        Send-ScriptNotification -Message "Error with Find-ADUserPassword, $_" -Severity 'Error' 
        Exit 5
    }
}

if ($TotalUsers -ne 1) { Write-Progress -Activity 'Testing passwords of users' -id 1 -Completed }

$UsersWithPasswordsFound = ($ADUsers | Where-Object -FilterScript {$_.PasswordFound}) 

if ($null -ne $UsersWithPasswordsFound)
{
    Write-Verbose -Message 'User passwords found'
    if ($SendResultsViaEmail)
    {
        if ($DoNotStorePasswords)
        {
            Write-Verbose -Message 'Email will be sent without passwords'

            $Pre  = 'The following users passwords were found in the specified password list'
            $Post = 'Note: Actual Passwords will not be displayed'

            $HTMLBody = ConvertTo-Html -InputObject $UsersWithPasswordsFound -Property SamAccountName, DistinguishedName -PreContent $Pre -PostContent $Post
        }
        else
        {
            Write-Verbose -Message 'Email will be sent with passwords'

            $Pre = 'The following users passwords were found in the specified password list'

            $HTMLBody = ConvertTo-Html -InputObject $UsersWithPasswordsFound -Property SamAccountName, Password, DistinguishedName -PreContent $Pre
        }

        $HTMLSMTPParameters = $SMTPParameters.clone()
        $HTMLSMTPParameters['Body'] = ("" + $HTMLBody)
	    $HTMLSMTPParameters['Subject'] = $SMTPSubject
        $HTMLSMTPParameters.add('BodyAsHtml', $True)

	    try 
        { Send-MailMessage @HTMLSMTPParameters } 
        catch 
        { Send-ScriptNotification -Message "Error sending mail message, $_" -Severity 'Error' }
    }
}
else
{
    Write-Verbose -Message 'No user passwords found'
        
    if ($SendResultsViaEmail)
    {
        $HTMLBody = ConvertTo-Html -Body 'No user passwords were found in the specified password list'

        $HTMLSMTPParameters = $SMTPParameters.clone()
        $HTMLSMTPParameters['Body'] = ("" + $HTMLBody)
	    $HTMLSMTPParameters['Subject'] = $SMTPSubject
        $HTMLSMTPParameters.add('BodyAsHtml', $True)
        
        try 
        { Send-MailMessage @HTMLSMTPParameters } 
        catch 
        { Send-ScriptNotification -Message "Error sending mail message, $_" -Severity 'Error' }
    }
}

if ($WriteResultsToFile)
{
    if ($DoNotStorePasswords)
    {
        Write-Verbose -Message 'Log file written without passwords'

  	    try 
        { 
            $ADUsers |
                Select-Object -Property SamAccountName, DistinguishedName |
                ConvertTo-Csv -NoTypeInformation |
                Out-File -FilePath $LogFile        
        } 
        catch 
        { Send-ScriptNotification -Message "Error saving user log, $_" -Severity 'Error' }
        
    }
    else
    {
        Write-Verbose -Message 'Log file written with passwords'

        try 
        { 
            $ADUsers |
                Select-Object -Property SamAccountName, Password, DistinguishedName |
                ConvertTo-Csv -NoTypeInformation |
                Out-File -FilePath $LogFile        
        } 
        catch 
        { Send-ScriptNotification -Message "Error saving user log, $_" -Severity 'Error' }

    }
}

Send-ScriptNotification -Message 'Ad User Password Audit End' -Severity 'debug'