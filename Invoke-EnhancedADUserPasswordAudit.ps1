<#
    .SYNOPSIS
    Audits Active Directory user accounts against a specified list of plaintext passwords. Results either stored to file or sent via email.
    This script integrates with Kieran Jacobsen's Enhanced Script Environment and requires its presence on the system.

    .DESCRIPTION
    This script provides a method for the automation of auditing domain user account credentials against a list of passwords. 

    This script would be useful to:
    1) Administrators wishing to know if their users have obvious/stupid/guessable
    2) Security researchers/Security Administrators/Pentesters/Red Team/Blue Team as part of the seuciryt processes
    3) Bad guys trying to gain additional access to an environment.

    You can automate the discovery/testing for a specific account by specifying an Active Directory Identity, or you can audit a large group
    by specifying a SearchBase, Filter and SearchScope.

    The script can either email the results, or save the results to a file.

    It should be noted that this script could trigger account lockouts if they have been enabled, the process is also extremely noisy and activity
    like this should quite evident in log files on the domain controllers.

    This script integrates with Kieran Jacobsen's Enhanced Script Environment and requires its presence on the system.

    .PARAMETER Identity
    Identify as defined in ActiveDirectory Module->
    Specifies an Active Directory user object by providing one of the following property values. The identifier in
    parentheses is the LDAP display name for the attribute. The acceptable values for this parameter are:

    -- A Distinguished Name
    -- A GUID (objectGUID)
    -- A Security Identifier (objectSid)
    -- A SAM Account Name (sAMAccountName)

    The cmdlet searches the default naming context or partition to find the object. If two or more objects are
    found, the cmdlet returns a non-terminating error.

    This parameter can also get this object through the pipeline or you can set this parameter to an object
    instance.

    .PARAMETER SearchBase
    Filter as defined in ActiveDirectory Module ->
    Specifies an Active Directory path to search under.

    When you run a cmdlet from an Active Directory provider drive, the default value of this parameter is the
    current path of the drive.

    When you run a cmdlet outside of an Active Directory provider drive against an AD DS target, the default value
    of this parameter is the default naming context of the target domain.

    When you run a cmdlet outside of an Active Directory provider drive against an AD LDS target, the default
    value is the default naming context of the target LDS instance if one has been specified by setting the
    msDS-defaultNamingContext property of the Active Directory directory service agent (DSA) object (nTDSDSA) for
    the AD LDS instance. If no default naming context has been specified for the target AD LDS instance, then this
    parameter has no default value.

    When the value of the SearchBase parameter is set to an empty string and you are connected to a GC port, all
    partitions will be searched. If the value of the SearchBase parameter is set to an empty string and you are
    not connected to a GC port, an error will be thrown.
    
    .PARAMETER Filter
    Filter as defined in ActiveDirectory Module ->
    Specifies a query string that retrieves Active Directory objects. This string uses the PowerShell Expression
    Language syntax. The PowerShell Expression Language syntax provides rich type-conversion support for value
    types received by the Filter parameter. The syntax uses an in-order representation, which means that the
    operator is placed between the operand and the value. For more information about the Filter parameter, type
    Get-Help about_ActiveDirectory_Filter.

    Syntax:

    The following syntax uses Backus-Naur form to show how to use the PowerShell Expression Language for this
    parameter.

    <filter>  ::= "{" <FilterComponentList> "}"

    <FilterComponentList> ::= <FilterComponent> | <FilterComponent> <JoinOperator> <FilterComponent> |
    <NotOperator>  <FilterComponent>

    <FilterComponent> ::= <attr> <FilterOperator> <value> | "(" <FilterComponent> ")"

    <FilterOperator> ::= "-eq" | "-le" | "-ge" | "-ne" | "-lt" | "-gt"| "-approx" | "-bor" | "-band" |
    "-recursivematch" | "-like" | "-notlike"

    <JoinOperator> ::= "-and" | "-or"

    <NotOperator> ::= "-not"

    <attr> ::= <PropertyName> | <LDAPDisplayName of the attribute>

    <value>::= <compare this value with an <attr> by using the specified <FilterOperator>>

    For a list of supported types for <value>, type Get-Help about_ActiveDirectory_ObjectModel.

    Note: PowerShell wildcards other than *, such as ?, are not supported by the Filter syntax.

    .PARAMETER SearchScope
    Filter as defined in ActiveDirectory Module ->
    Specifies the scope of an Active Directory search. The acceptable values for this parameter are: 

    -- Base or 0
    -- OneLevel or 1
    -- Subtree or 2

    A Base query searches only the current path or object. A OneLevel query searches the immediate children of
    that path or object. A Subtree query searches the current path or object and all children of that path or
    object.

    .PARAMETER SendResultsViaEmail
    Specifies if the results of the audit will be sent via email. If this option is selected, you must specify SMTP messages details such as server, from and to. Subject is optional. 
    The email will contain a list of user accounts, if the password was detected, and what the password is (can be switched off). 
    If no user passwords were found, an email stating that will be sent.
    The email will be formatted as a HTML message.

    .PARAMETER SMTPTo
    SMTP message will be sent to this address.

    .PARAMETER SMTPSubject
    Subject of SMTP message

    .PARAMETER WriteResultsToFile
    Specifies if the results of the audit will be saved to a log file. If this option is selected, you need to specify a log file.

    .PARAMETER LogFile
    File name to write a list of users, if their password has been detected, and the password (this can be switched off).

    .PARAMETER PasswordFile
    File containing 1 or more passwords to test user accounts against.

    .PARAMETER DoNotStorePasswords
    Specify this option if you only want to know if a users password was in the specified password file, and you do not want to know the password.

    .EXAMPLE
    Invoke-ADUserPasswordAudit.ps1 -Identity administrator -SendResultsViaEmail -SMTPServer smtp.server.com -SMTPFrom me@company.com -SMTPTo me@company.com -PasswordFile c:\passwordlists\passwordlist.txt -DoNotStorePasswords
    Tests the account, administrator, against all passwords in the file, c:\passwordlists\passwordlist.txt, result will be emailed, however the password will not be sent.

    .EXAMPLE
    Invoke-ADUserPasswordAudit.ps1 -Identity administrator -WriteResultsToFile -LogFile c:\logs\password-audit.txt -PasswordFile c:\passwordlists\passwordlist.txt
    Tests the account, administrator, against all passwords in the file, c:\passwordlists\passwordlist.txt, result will be stored in the file, c:\logs\password-audit.txt, the password will be stored in this log file.

    .EXAMPLE
    Invoke-ADUserPasswordAudit.ps1 -SearchBase 'DC=MyCompany,DC=Corp' -Filter * -SearchScope SubTree -WriteResultsToFile -LogFile c:\logs\password-audit.txt -PasswordFile c:\passwordlists\passwordlist.txt
    Tests every account from the root of the domain MyCompany.corp, against the password file, c:\passwordlists\passwordlist.txt, storing results (with password) in the log file c:\logs\password-audit.txt.

    .INPUTS
    None

    .OUTPUTS
    None

    .LINK
    http://poshsecurity.com
#>

[CMDLetBinding(DefaultParametersetName = 'FindByIdentityEmail')]
Param
(

    [Parameter(Mandatory = $True, ParameterSetName = 'FindByIdentityEmail')]
    [Parameter(Mandatory = $True, ParameterSetName = 'FindByIdentityLog')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Identity,

    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchEmail')]
    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchLog')]
    [ValidateNotNullOrEmpty()]
    [String]
    $SearchBase,

    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchEmail')]
    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchLog')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Filter,

    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchEmail')]
    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchLog')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Base', 'OneLevel', 'Subtree')]
    [String]
    $SearchScope,

    [Parameter(Mandatory = $True, ParameterSetName = 'FindByIdentityEmail')]
    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchEmail')]
    [Switch]
    $SendResultsViaEmail,

    [Parameter(Mandatory = $False, ParameterSetName = 'FindByIdentityEmail')]
    [Parameter(Mandatory = $False, ParameterSetName = 'FindBySearchEmail')]
    [ValidateNotNullOrEmpty()]
    [String]
    $SMTPSubject = 'User Password Audit Results',
    
    [Parameter(Mandatory = $True, ParameterSetName = 'FindByIdentityLog')]
    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchLog')]
    [Switch]
    $WriteResultsToFile,

    [Parameter(Mandatory = $True, ParameterSetName = 'FindByIdentityLog')]
    [Parameter(Mandatory = $True, ParameterSetName = 'FindBySearchLog')]
    [ValidateNotNullOrEmpty()]
    [String]
    $LogFile,

    [Parameter(Mandatory = $True)]
    [ValidateScript({Test-Path $_})]
    [String]
    $PasswordFile,

    [Parameter(Mandatory = $False)]
    [Switch]
    $DoNotStorePasswords

)

Set-StrictMode -Version 2

Import-Module -Name PowerShellUtilities
Import-Module -Name EnhancedScriptEnvironment
Import-Module -Name ActiveDirectory
Import-Module -Name .\Posh-PasswordAuditor.psd1

$ADUsers = $null

if ($Identity -ne '')
{
    Write-Verbose -Message 'Single User Mode'

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

$ADUsers = $ADUsers | ForEach-Object -Process {
    $UsersProcessed++
    $UserPercentage = $UsersProcessed / $TotalUsers * 100

    if ($TotalUsers -ne 1) 
    { Write-Progress -Activity 'Testing passwords of users' -PercentComplete $UserPercentage -Status "$UserPercentage % Complete" -Id 1 }
    
    try
    { Find-UserPassword -Username $_.SamAccountName -PasswordFile $PasswordFile -Domain }
    catch
    {
        Send-ScriptNotification -Message "Error with Find-ADUserPassword, $_" -Severity 'Error' 
        Exit 5
    }
}

if ($TotalUsers -ne 1) 
{ Write-Progress -Activity 'Testing passwords of users' -Id 1 -Completed }

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

            $HTMLBody = ConvertTo-Html -InputObject $UsersWithPasswordsFound -Property Username -PreContent $Pre -PostContent $Post
        }
        else
        {
            Write-Verbose -Message 'Email will be sent with passwords'

            $Pre = 'The following users passwords were found in the specified password list'

            $HTMLBody = ConvertTo-Html -InputObject $UsersWithPasswordsFound -Property Username, Password -PreContent $Pre
        }

        $HTMLSMTPParameters = $SMTPParameters.clone()
        $HTMLSMTPParameters['Body'] = ('' + $HTMLBody)
        $HTMLSMTPParameters['Subject'] = $SMTPSubject
        $HTMLSMTPParameters.add('BodyAsHtml', $True)

        try 
        { Send-MailMessage @HTMLSMTPParameters } 
        catch 
        {
            Send-ScriptNotification -Message "Error sending mail message, $_" -Severity 'Error' 
            Exit 6
        }
    }

    if ($WriteResultsToFile)
    {
        if ($DoNotStorePasswords)
        {
            Write-Verbose -Message 'Log file written without passwords'

            try 
            { 
                $UsersWithPasswordsFound |
                    Select-Object -Property Username |
                    ConvertTo-Csv -NoTypeInformation |
                    Out-File -FilePath $LogFile        
            } 
            catch 
            {
                Send-ScriptNotification -Message "Error saving user log, $_" -Severity 'Error' 
                Exit 8
            }
        }
        else
        {
            Write-Verbose -Message 'Log file written with passwords'

            try 
            {
                $UsersWithPasswordsFound |
                    Select-Object -Property Username, Password |
                    ConvertTo-Csv -NoTypeInformation |
                    Out-File -FilePath $LogFile} 
            catch 
            {
                Send-ScriptNotification -Message "Error saving user log, $_" -Severity 'Error' 
                Exit 9
            }
        }
    }
}
else
{
    Write-Verbose -Message 'No user passwords found'
        
    if ($SendResultsViaEmail)
    {
        $HTMLBody = ConvertTo-Html -Body 'No user passwords were found in the specified password list'

        $HTMLSMTPParameters = $SMTPParameters.clone()
        $HTMLSMTPParameters['Body'] = ('' + $HTMLBody)
        $HTMLSMTPParameters['Subject'] = $SMTPSubject
        $HTMLSMTPParameters.add('BodyAsHtml', $True)

        try 
        { Send-MailMessage @HTMLSMTPParameters } 
        catch 
        {
            Send-ScriptNotification -Message "Error sending mail message, $_" -Severity 'Error' 
            Exit 7
        }
    }
}
