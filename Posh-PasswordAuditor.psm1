#
# Export the module members - KUDOS to the chocolatey project for this efficent code
# 


#get the path of where the module is saved (if module is at c:\myscripts\module.psm1, then c:\myscripts\)
$mypath = (Split-Path -Parent -Path $MyInvocation.MyCommand.Definition)

#find all the ps1 files in the subfolder functions
Resolve-Path -Path $mypath\functions\*.ps1 | ForEach-Object -Process {
    . $_.ProviderPath
}

#export as module members the functions we specify
Export-ModuleMember -Function Test-UserCredential, Find-ADUserPassword
